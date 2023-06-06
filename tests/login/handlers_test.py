import base64
import json
import os
from http import HTTPStatus
from typing import Any
from typing import Callable
from typing import Dict
from typing import Optional
from unittest import mock
from unittest.mock import call
from unittest.mock import Mock
from unittest.mock import patch

import pytest

from cdh_utils.constants import AuthMethodStage
from cdh_utils.constants import CDH_AUTH_INT_URL
from cdh_utils.constants import IdentityCode
from cdh_utils.constants import IDP_AUTH_URL
from cdh_utils.constants import JwtType
from cdh_utils.constants import KeyringIdentity
from cdh_utils.login.handlers import LoginHandlerCdh
from cdh_utils.login.jwt_cache import JwtCache
from cdh_utils.login.jwt_response import JwtResponse
from cdh_utils.utils.browser_handler import BrowserHandler
from cdh_utils.utils.cdhconfig import CdhConfig
from cdh_utils.utils.exceptions import ScriptError
from tests.requests_test import MocksSetup
from tests.utils.json_response_mock import get_fake_json_response
from tests.utils.json_response_mock import JsonResponseMock

FAKE_STATE_TOKEN = "Fake_state_token"
FAKE_REQUEST_ID = "Fake_request_id"
FAKE_TEST_IDP_RESPONSE_PATH = os.path.dirname(__file__) + "/fake_test_idp_response.txt"
with open(FAKE_TEST_IDP_RESPONSE_PATH) as json_file:
    FAKE_TEST_IDP_RESPONSE = json.load(json_file)

FAKE_TOKEN_PATH = os.path.dirname(__file__) + "/fake_idp_token_value.txt"
with open(FAKE_TOKEN_PATH, "r") as token_file:
    TOKEN_VALUE = token_file.read()

CDH_IDP_URL = AuthMethodStage.PROD.get_stage_idp_auth_endpoint()
CDH_AUTH_URL_STATE = AuthMethodStage.PROD.get_stage_state_endpoint()
CDH_AUTH_URL_TOKEN = AuthMethodStage.PROD.get_stage_token_endpoint()
CDH_AUTH_URL_REQUESTER = AuthMethodStage.PROD.get_stage_requester_endpoint()


def build_get_fake_server_response_for_cdh_url(
    jwt_payload: Optional[Dict] = None,
) -> Callable[[str, Optional[Dict]], Optional[JsonResponseMock]]:
    if not jwt_payload:
        jwt_payload = {}

    def get_fake_server_response_for_cdh_url(
        endpoint: str, request_parameters: Optional[Dict] = None, **kwargs: Any
    ) -> Optional[JsonResponseMock]:
        if endpoint == CDH_AUTH_URL_STATE:
            return get_fake_json_response(
                status_code=HTTPStatus.OK, json_data={"state": FAKE_STATE_TOKEN, "requestId": FAKE_REQUEST_ID}
            )
        elif endpoint == IDP_AUTH_URL:
            return get_fake_json_response(status_code=HTTPStatus.OK, json_data=FAKE_TEST_IDP_RESPONSE)
        elif endpoint == CDH_AUTH_URL_TOKEN:
            fake_jwt_payload_encoded = base64.b64encode(json.dumps(jwt_payload).encode("utf-8")).decode("utf-8")
            return get_fake_json_response(
                status_code=HTTPStatus.OK,
                json_data={
                    "name": "fake_name",
                    "value": f"fakejwt-header.{fake_jwt_payload_encoded}.fakejwt-signature",
                },
            )
        elif endpoint == CDH_AUTH_URL_REQUESTER:
            return get_fake_json_response(
                status_code=HTTPStatus.UNAUTHORIZED,
                json_data={},
            )
        return None

    return get_fake_server_response_for_cdh_url


class MocksCdhSetup(MocksSetup):
    def setup_method(self) -> None:
        super().setup_method()
        self.get_response = self.connection_handler.session_get
        self.post_response = self.connection_handler.session_post
        self.get_response.side_effect = build_get_fake_server_response_for_cdh_url()
        self.post_response.side_effect = build_get_fake_server_response_for_cdh_url()
        self.connection_handler.session = Mock()
        self.connection_handler.session.post.side_effect = build_get_fake_server_response_for_cdh_url
        fake_response = build_get_fake_server_response_for_cdh_url()(CDH_AUTH_URL_TOKEN, None)
        assert fake_response
        fake_jwt_response = fake_response.json()
        self.jwt_response = JwtResponse(
            jwt_name=fake_jwt_response["name"],
            jwt_value=fake_jwt_response["value"],
        )
        browser_handler = Mock(BrowserHandler(CdhConfig(ignore_config=True, ignore_keyring=True)))
        self.jwt_cache = Mock(JwtCache)
        self.jwt_cache.load_jwt.return_value = None
        self.login_handler = LoginHandlerCdh(
            self.connection_handler, browser_handler, AuthMethodStage.PROD, self.jwt_cache
        )
        self.setup.login_handler = self.login_handler


# time.sleep is mocked as it is used internally by polling2.
# This mocking process helps to create the time-out scenario without actually waiting till time-out.
@mock.patch("time.sleep", Mock())
class TestCdhLogin(MocksCdhSetup):
    def test_get_state_token_for_nonce(self) -> None:
        NONCE = "XWmGh5izhCQnLECB-B69hv4cpROfObh9p-USS9_fcMY"
        state_token = self.login_handler.get_state_token_and_request_id_for_nonce(NONCE, JwtType.INTERNAL)[0]
        request_id = self.login_handler.get_state_token_and_request_id_for_nonce(NONCE, JwtType.INTERNAL)[1]
        assert state_token == FAKE_STATE_TOKEN
        assert request_id == FAKE_REQUEST_ID

    def test_get_state_token_for_nonce_error(self) -> None:
        NONCE = "XWmGh5izhCQnLECB-B69hv4cpROfObh9p-USS9_fcMY"
        NOT_OK_STATUS_CODE = 502
        self.get_response.side_effect = lambda endpoint, params: Mock(status_code=NOT_OK_STATUS_CODE, ok=False)
        with pytest.raises(ScriptError):
            self.login_handler.get_state_token_and_request_id_for_nonce(NONCE, JwtType.INTERNAL)

    def test_skip_login_if_jwt_cached(self) -> None:
        self.jwt_cache.load_jwt.return_value = self.get_fake_jwt_response()

        self.login_handler.login()

        self.connection_handler.session_get.assert_not_called()

    def test_store_latest_jwt_if_jwt_cached(self) -> None:
        jwt_response = self.get_fake_jwt_response()
        self.jwt_cache.load_jwt.return_value = jwt_response

        self.login_handler.login()

        self.jwt_cache.store_jwt.assert_called_once_with(jwt_response)

    def test_perform_idp_login_using_jwt_response(self) -> None:
        fake_jwt_response = self.get_fake_jwt_response()
        assert self.login_handler.perform_idp_login_using_jwt_response(fake_jwt_response).saml == TOKEN_VALUE

    def test_idp_login_returns_not_ok_status_code(self) -> None:
        fake_jwt_response = self.get_fake_jwt_response()
        self.connection_handler.session_post.side_effect = lambda endpoint, params, headers: get_fake_json_response(
            status_code=HTTPStatus.NOT_FOUND, json_data={}
        )
        with pytest.raises(ScriptError):
            self.login_handler.perform_idp_login_using_jwt_response(fake_jwt_response)

    @pytest.mark.parametrize("tag_email", [True, False])
    def test_login_without_mail_tagging(self, tag_email: bool) -> None:
        fake_jwt_response = self.get_fake_jwt_response()

        self.login_handler.perform_idp_login_using_jwt_response(fake_jwt_response, disable_mail_tagging=not tag_email)

        self.connection_handler.session_post.assert_called_once_with(
            endpoint=CDH_IDP_URL,
            headers={"cookie": fake_jwt_response.cookies, "origin": fake_jwt_response.jwt_name},
            params={"tag_email": tag_email},
        )

    def test_login_success(self) -> None:
        assert self.login_handler.login().saml == TOKEN_VALUE

    def test_login_caches_jwt(self) -> None:
        self.login_handler.login()

        self.jwt_cache.store_jwt.assert_called_once_with(self.jwt_response)

    def test_login_reject(self) -> None:
        def get_reject_server_response_scenario_for_url(
            endpoint: str, params: Optional[Dict] = None
        ) -> Optional[JsonResponseMock]:
            return self.get_error_code_scenario_for_url(HTTPStatus.FORBIDDEN, endpoint, params)

        self.get_response.side_effect = get_reject_server_response_scenario_for_url
        with pytest.raises(ScriptError):
            self.login_handler.login()

    def test_login_timeout(self) -> None:
        def get_time_out_scenario_for_url(endpoint: str, params: Optional[Dict] = None) -> Optional[JsonResponseMock]:
            return self.get_error_code_scenario_for_url(HTTPStatus.NOT_FOUND, endpoint, params)

        self.get_response.side_effect = get_time_out_scenario_for_url
        with pytest.raises(ScriptError):
            self.login_handler.login()

    def test_login_connection_error(self) -> None:
        self.get_response.side_effect = ConnectionError()
        with pytest.raises(ScriptError):
            self.login_handler.login()

    def test_clear_invalid_jwt(self) -> None:
        self.jwt_cache.load_jwt.return_value = self.get_fake_jwt_response()
        self.post_response.side_effect = ScriptError()

        with pytest.raises(ScriptError):
            self.login_handler.login()

        self.jwt_cache.clear_jwt.assert_called_once_with(KeyringIdentity(jwt_type=JwtType.INTERNAL, identity_code=None))

    def test_unexpected_jwt_endpoint_status_code(self) -> None:
        def get_jwt_endpoint_error_code_scenario_for_url(
            endpoint: str, params: Optional[Dict] = None
        ) -> Optional[JsonResponseMock]:
            UNDEFINED_ERROR_CODE = 502
            return self.get_error_code_scenario_for_url(UNDEFINED_ERROR_CODE, endpoint, params)

        self.get_response.side_effect = get_jwt_endpoint_error_code_scenario_for_url
        with pytest.raises(ScriptError):
            self.login_handler.login()

    def get_error_code_scenario_for_url(
        self, error_code_token_endpoint: int, endpoint: str, params: Optional[Dict] = None
    ) -> Optional[JsonResponseMock]:
        if endpoint == CDH_AUTH_URL_STATE:
            return get_fake_json_response(
                status_code=HTTPStatus.OK, json_data={"state": FAKE_STATE_TOKEN, "requestId": FAKE_REQUEST_ID}
            )
        elif endpoint == CDH_AUTH_URL_TOKEN:
            return get_fake_json_response(status_code=error_code_token_endpoint, json_data={})
        else:
            pytest.fail(f"{endpoint} is not a supported endpoint.")
            return None

    def get_fake_jwt_response(self) -> JwtResponse:
        fake_jwt_response = Mock(JwtResponse)
        fake_jwt_response.jwt_name = "cdh_prod_internal"
        fake_jwt_response.jwt_value = "fake_jwt_value"
        return fake_jwt_response


class TestCdhLoginIntStage(MocksCdhSetup):
    def setup_method(self) -> None:
        super().setup_method()
        browser_handler = Mock(BrowserHandler(CdhConfig(ignore_config=True, ignore_keyring=True)))
        self.login_handler = LoginHandlerCdh(
            self.connection_handler, browser_handler, AuthMethodStage.INT, self.jwt_cache
        )
        self.setup.login_handler = self.login_handler

    def test_using_int_endpoints(self) -> None:
        assert self.login_handler.cdh_auth_url_state == CDH_AUTH_INT_URL + "/cli/state"
        assert self.login_handler.cdh_auth_url_login == CDH_AUTH_INT_URL + "/cli/login"
        assert self.login_handler.cdh_auth_url_token == CDH_AUTH_INT_URL + "/cli/token"


class TestCdhLoginAuthIdp(MocksCdhSetup):
    def setup_method(self) -> None:
        super().setup_method()
        self.browser_handler = Mock(BrowserHandler)

    def test_auth_idp_set(self) -> None:
        idp_name = IdentityCode.BMW
        self.login_handler = LoginHandlerCdh(
            self.connection_handler, self.browser_handler, AuthMethodStage.PROD, self.jwt_cache, idp_name
        )
        self.setup.login_handler = self.login_handler
        expected_link = (
            f"{AuthMethodStage.PROD.get_stage_login_endpoint()}?state={FAKE_STATE_TOKEN}&" f"idp_name={idp_name.value}"
        )

        self.login_handler.login()

        self.browser_handler.open_new.assert_called_once_with(expected_link)

    def test_auth_idp_not_set_for_implicit_idp(self) -> None:
        idp_name = IdentityCode.IMPLICIT_CDH_AUTH
        self.login_handler = LoginHandlerCdh(
            self.connection_handler, self.browser_handler, AuthMethodStage.PROD, self.jwt_cache, idp_name
        )
        self.setup.login_handler = self.login_handler
        expected_link = f"{AuthMethodStage.PROD.get_stage_login_endpoint()}?state={FAKE_STATE_TOKEN}"

        self.login_handler.login()

        self.browser_handler.open_new.assert_called_once_with(expected_link)

    def test_auth_idp_not_set(self) -> None:
        self.login_handler = LoginHandlerCdh(
            self.connection_handler, self.browser_handler, AuthMethodStage.PROD, self.jwt_cache, None
        )
        self.setup.login_handler = self.login_handler

        expected_link = f"{AuthMethodStage.PROD.get_stage_login_endpoint()}?state={FAKE_STATE_TOKEN}"

        self.login_handler.login()

        self.browser_handler.open_new.assert_called_once_with(expected_link)

    @pytest.mark.parametrize("identity_code", [IdentityCode.BMW, IdentityCode.BBA])
    def test_extract_idp_from_jwt(self, identity_code: IdentityCode) -> None:
        self.get_response.side_effect = build_get_fake_server_response_for_cdh_url(
            jwt_payload={"idp": identity_code.value}
        )
        self.login_handler = LoginHandlerCdh(
            self.connection_handler, self.browser_handler, AuthMethodStage.PROD, self.jwt_cache
        )
        self.setup.login_handler = self.login_handler
        self.get_response.return_value = ""

        login_response = self.login_handler.login()

        assert login_response.actual_idp_name == identity_code

    def test_extract_idp_from_jwt_no_value(self) -> None:
        self.get_response.side_effect = build_get_fake_server_response_for_cdh_url(jwt_payload={"no_idp": "other"})
        self.login_handler = LoginHandlerCdh(
            self.connection_handler, self.browser_handler, AuthMethodStage.PROD, self.jwt_cache
        )
        self.setup.login_handler = self.login_handler
        self.get_response.return_value = ""

        login_response = self.login_handler.login()

        assert login_response.actual_idp_name is None


class TestCdhGetJwtAuthIdp(MocksCdhSetup):
    def setup_method(self) -> None:
        super().setup_method()
        self.browser_handler = Mock(BrowserHandler)
        self.nonce = "some_nonce_value"

    @pytest.mark.parametrize("jwt_type", [JwtType.API, JwtType.INTERNAL])
    def test_get_api_token(self, jwt_type: JwtType) -> None:
        idp_name = IdentityCode.BMW
        self.login_handler = LoginHandlerCdh(
            self.connection_handler, self.browser_handler, AuthMethodStage.PROD, self.jwt_cache, idp_name
        )
        self.setup.login_handler = self.login_handler

        result = self.login_handler.get_jwt(jwt_type)

        assert result == self.jwt_response

    @pytest.mark.parametrize("jwt_type", [JwtType.API, JwtType.INTERNAL])
    def test_auth_idp_set(self, jwt_type: JwtType) -> None:
        idp_name = IdentityCode.BMW
        self.login_handler = LoginHandlerCdh(
            self.connection_handler, self.browser_handler, AuthMethodStage.PROD, self.jwt_cache, idp_name
        )
        self.setup.login_handler = self.login_handler
        expected_link = (
            f"{AuthMethodStage.PROD.get_stage_login_endpoint()}?state={FAKE_STATE_TOKEN}&" f"idp_name={idp_name.value}"
        )

        with patch("secrets.token_urlsafe") as mocked_nonce_generation:
            mocked_nonce_generation.return_value = self.nonce
            self.login_handler.get_jwt(jwt_type)

        self.browser_handler.open_new.assert_called_once_with(expected_link)
        assert self.connection_handler.session_get.mock_calls[0] == call(
            endpoint=AuthMethodStage.PROD.get_stage_state_endpoint(),
            params={"code": self.nonce, "jwt_type": jwt_type.value},
        )

    @pytest.mark.parametrize("jwt_type", [JwtType.API, JwtType.INTERNAL])
    def test_auth_idp_not_set_for_implicit_idp(self, jwt_type: JwtType) -> None:
        idp_name = IdentityCode.IMPLICIT_CDH_AUTH
        self.login_handler = LoginHandlerCdh(
            self.connection_handler, self.browser_handler, AuthMethodStage.PROD, self.jwt_cache, idp_name
        )
        self.setup.login_handler = self.login_handler
        expected_link = f"{AuthMethodStage.PROD.get_stage_login_endpoint()}?state={FAKE_STATE_TOKEN}"

        with patch("secrets.token_urlsafe") as mocked_nonce_generation:
            mocked_nonce_generation.return_value = self.nonce
            self.login_handler.get_jwt(jwt_type)

        self.browser_handler.open_new.assert_called_once_with(expected_link)
        assert self.connection_handler.session_get.mock_calls[0] == call(
            endpoint=AuthMethodStage.PROD.get_stage_state_endpoint(),
            params={"code": self.nonce, "jwt_type": jwt_type.value},
        )

    @pytest.mark.parametrize("jwt_type", [JwtType.API, JwtType.INTERNAL])
    def test_auth_idp_not_set(self, jwt_type: JwtType) -> None:
        self.login_handler = LoginHandlerCdh(
            self.connection_handler, self.browser_handler, AuthMethodStage.PROD, self.jwt_cache, None
        )
        self.setup.login_handler = self.login_handler

        expected_link = f"{AuthMethodStage.PROD.get_stage_login_endpoint()}?state={FAKE_STATE_TOKEN}"

        with patch("secrets.token_urlsafe") as mocked_nonce_generation:
            mocked_nonce_generation.return_value = self.nonce
            self.login_handler.get_jwt(jwt_type)

        self.browser_handler.open_new.assert_called_once_with(expected_link)
        assert self.connection_handler.session_get.mock_calls[0] == call(
            endpoint=AuthMethodStage.PROD.get_stage_state_endpoint(),
            params={"code": self.nonce, "jwt_type": jwt_type.value},
        )

    @pytest.mark.parametrize("jwt_type", [JwtType.API, JwtType.INTERNAL])
    def test_check_valid_jwt_verified(self, jwt_type: JwtType) -> None:
        self.jwt_cache.load_jwt.return_value = self.jwt_response
        self.get_response.side_effect = lambda endpoint, headers: get_fake_json_response(
            status_code=HTTPStatus.OK, json_data={}
        )
        self.login_handler = LoginHandlerCdh(
            self.connection_handler, self.browser_handler, AuthMethodStage.PROD, self.jwt_cache, None
        )
        self.setup.login_handler = self.login_handler

        self.login_handler.get_jwt(jwt_type)

        self.browser_handler.open_new.assert_not_called()
        self.get_response.assert_called_once_with(
            endpoint=CDH_AUTH_URL_REQUESTER, headers={"Cookie": self.jwt_response.cookies}
        )

    @pytest.mark.parametrize("jwt_type", [JwtType.API, JwtType.INTERNAL])
    def test_check_invalid_jwt_verified(self, jwt_type: JwtType) -> None:
        self.jwt_cache.load_jwt.return_value = self.jwt_response
        self.login_handler = LoginHandlerCdh(
            self.connection_handler, self.browser_handler, AuthMethodStage.PROD, self.jwt_cache, None
        )
        self.setup.login_handler = self.login_handler

        self.login_handler.get_jwt(jwt_type)

        self.browser_handler.open_new.assert_called_once_with(
            f"{AuthMethodStage.PROD.get_stage_login_endpoint()}?state={FAKE_STATE_TOKEN}"
        )
