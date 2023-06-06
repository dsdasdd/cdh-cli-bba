import base64
import logging
import secrets
import typing
from dataclasses import dataclass
from functools import lru_cache
from http import HTTPStatus
from typing import List
from typing import Optional
from typing import Tuple
from urllib.parse import urlencode

import polling2 as polling2
from bs4 import BeautifulSoup
from bs4 import Tag
from polling2 import MaxCallException
from requests import Response
from requests.exceptions import RequestException

from cdh_utils.constants import AuthMethodStage
from cdh_utils.constants import IdentityCode
from cdh_utils.constants import JwtType
from cdh_utils.constants import KeyringIdentity
from cdh_utils.login.jwt_cache import JwtCache
from cdh_utils.login.jwt_response import JwtResponse
from cdh_utils.saml.identities import Role
from cdh_utils.utils.browser_handler import BrowserHandler
from cdh_utils.utils.connection_handler import ConnectionHandler
from cdh_utils.utils.exceptions import ScriptError
from cdh_utils.utils.helpers import ConsolePrinter

LOG = logging.getLogger(__name__)
POLLING_NUMBER_OF_TRIALS = 60
POLLING_TRIAL_TIME = 1


@dataclass
class LoginResponse:
    saml: str
    roles: List[Role]
    actual_idp_name: Optional[IdentityCode] = None


def extract_saml_from_response(http_response: Response) -> str:
    form = BeautifulSoup(http_response.text, "lxml").findChild("form")
    if not isinstance(form, Tag):
        raise AttributeError("form attribute is not of type Tag")
    saml_responses = [saml.attrs["value"] for saml in form.findChildren("input", attrs={"name": "SAMLResponse"})]
    if len(saml_responses) == 0:
        raise AttributeError("The HTTP response did not contain a saml.")
    elif len(saml_responses) > 1:
        LOG.error(f"The HTTP response contains {len(saml_responses)} saml responses. The first one will be used")
    return saml_responses[0]


class LoginHandlerCdh:
    def __init__(
        self,
        connection_handler: ConnectionHandler,
        browser_handler: BrowserHandler,
        auth_stage: AuthMethodStage,
        jwt_cache: JwtCache,
        idp_name: Optional[IdentityCode] = None,
    ):
        self.connection_handler = connection_handler
        self.browser_handler = browser_handler
        self.console_printer = ConsolePrinter()
        self.idp_name = idp_name
        self.jwt_cache = jwt_cache

        self.cdh_auth_url_state = auth_stage.get_stage_state_endpoint()
        self.cdh_auth_url_login = auth_stage.get_stage_login_endpoint()
        self.cdh_auth_url_token = auth_stage.get_stage_token_endpoint()
        self.cdh_auth_url_requester = auth_stage.get_stage_requester_endpoint()
        self.idp_auth_url = auth_stage.get_stage_idp_auth_endpoint()

    def login(self, disable_mail_tagging: bool = False) -> LoginResponse:
        keyring_identity = self._get_keyring_identity(JwtType.INTERNAL)
        jwt_response = self._check_for_jwt_in_keyring(keyring_identity)
        if jwt_response:
            try:
                response = self.perform_idp_login_using_jwt_response(jwt_response, disable_mail_tagging)
                # Overwrite the latest jwt with this one - we only do this if the idp login worked
                self.jwt_cache.store_jwt(jwt_response)
                return response
            except ScriptError:
                self._clear_jwt_from_keyring(keyring_identity)

        jwt_response = self._get_jwt_and_store_in_cache(JwtType.INTERNAL)
        login_response = self.perform_idp_login_using_jwt_response(jwt_response, disable_mail_tagging)
        LOG.debug("Request granted")
        return login_response

    def get_jwt(self, jwt_type: JwtType) -> JwtResponse:
        keyring_identity = self._get_keyring_identity(jwt_type)
        jwt_response = self._check_for_jwt_in_keyring(keyring_identity)
        if isinstance(jwt_response, JwtResponse) and self._is_valid_jwt(jwt_response):
            return jwt_response
        else:
            return self._get_jwt_and_store_in_cache(jwt_type=jwt_type)

    @lru_cache()
    def _get_jwt_and_store_in_cache(self, jwt_type: JwtType) -> JwtResponse:
        try:
            nonce = secrets.token_urlsafe()
            LOG.debug(f"Getting state token for nonce starting with: {nonce[:2]}")
            state_token, request_id = self.get_state_token_and_request_id_for_nonce(nonce, jwt_type)
            self.console_printer.print_console("*======================*")
            self.console_printer.print_console(f"| Request ID: {request_id:>8} |")
            self.console_printer.print_console("*======================*")
            query_parameters = {"state": state_token}
            if self.idp_name and self.idp_name != IdentityCode.IMPLICIT_CDH_AUTH:
                query_parameters["idp_name"] = self.idp_name.value
            cdh_login_link = f"{self.cdh_auth_url_login}?{urlencode(query_parameters)}"
            self.console_printer.print_console(f"Please continue the auth process on: {cdh_login_link}")
            self.browser_handler.open_new(cdh_login_link)

            poll_jwt_response = self.poll_cdh_auth_token(nonce, state_token)
            LOG.debug(f"The following status code has been polled for JWT response: {poll_jwt_response.status_code}")
            if poll_jwt_response.status_code != HTTPStatus.OK:
                LOG.debug(f"Response text: {poll_jwt_response.text}")
            self._check_jwt_for_error_response_code(poll_jwt_response.status_code)
            jwt_response = self._parse_jwt_response(poll_jwt_response)

            self.jwt_cache.store_jwt(jwt_response)
            LOG.debug("Request granted")
            return jwt_response

        except (ConnectionError, RequestException) as e:
            self._raise_contact_helpdesk_error_for_exception(e)
        except MaxCallException:
            raise ScriptError("Request timeout: Auth-request was not accepted by the user within the time frame.")

    def _check_for_jwt_in_keyring(self, keyring_identity: KeyringIdentity) -> Optional[JwtResponse]:
        LOG.debug(f"Checking keyring for cached JWT with identity {keyring_identity}")
        return self.jwt_cache.load_jwt(keyring_identity)

    def _clear_jwt_from_keyring(self, keyring_identity: KeyringIdentity) -> None:
        LOG.debug("Could not log in with jwt from keyring. Proceeding with a new login.")
        self.jwt_cache.clear_jwt(keyring_identity)

    def _get_keyring_identity(self, jwt_type: JwtType) -> KeyringIdentity:
        identity_code = self.idp_name if self.idp_name != IdentityCode.IMPLICIT_CDH_AUTH else None
        return KeyringIdentity(identity_code=identity_code, jwt_type=jwt_type)

    def _check_jwt_for_error_response_code(self, poll_jwt_response_status_code: int) -> None:
        if poll_jwt_response_status_code == HTTPStatus.OK:
            return
        elif poll_jwt_response_status_code == HTTPStatus.FORBIDDEN:
            raise ScriptError("Auth-request declined by the user") from None
        else:
            self._raise_contact_helpdesk_error_for_exception(
                Exception(f"received unexpected status code from endpoint {poll_jwt_response_status_code}")
            )

    def get_state_token_and_request_id_for_nonce(self, nonce: str, jwt_type: JwtType) -> Tuple[str, str]:
        http_response = self.connection_handler.session_get(
            endpoint=self.cdh_auth_url_state, params={"code": nonce, "jwt_type": jwt_type.value}
        )
        if not http_response.ok:
            if http_response.status_code == HTTPStatus.FORBIDDEN:
                raise ScriptError(
                    "Could not connect to authentication server. Please note that CDH CLI can only be "
                    "used from inside BMW networks.\nIf you are connected to an external network only, "
                    "you need to use a BMW VPN tunnel or BMW proxy server (Note: CDH cannot provide "
                    "assistance with those)."
                )
            raise ScriptError("HTTP status code not between 200 and 400.")
        json_response = http_response.json()
        return json_response["state"], json_response["requestId"]

    def poll_cdh_auth_token(self, nonce: str, state_token: str) -> Response:
        return polling2.poll(
            lambda: self.connection_handler.session_get(
                endpoint=self.cdh_auth_url_token, params={"code": nonce, "state": state_token}
            ),
            step=POLLING_TRIAL_TIME,
            max_tries=POLLING_NUMBER_OF_TRIALS,
            check_success=lambda response: response.status_code != HTTPStatus.NOT_FOUND,
        )

    def perform_idp_login_using_jwt_response(
        self, jwt_response: JwtResponse, disable_mail_tagging: bool = False
    ) -> LoginResponse:
        saml_response = self.connection_handler.session_post(
            endpoint=self.idp_auth_url,
            headers={"cookie": jwt_response.cookies, "origin": jwt_response.jwt_name},
            params={"tag_email": not disable_mail_tagging},
        )
        if saml_response.status_code != HTTPStatus.OK:
            self._raise_contact_helpdesk_error_for_exception(
                Exception(f"IDP Endpoint returned the following status code: {saml_response.status_code}")
            )
        document = saml_response.json()["document"]
        roles_json_data = saml_response.json()["roles"]
        roles = sorted(
            [Role(role.get("roleArn"), role.get("principalArn"), role.get("guestRole")) for role in roles_json_data]
        )
        return LoginResponse(
            self._encode_base64(document), roles, actual_idp_name=jwt_response.actual_idp_name  # type:ignore
        )

    def _parse_jwt_response(self, http_response: Response) -> JwtResponse:
        LOG.debug("Performing IDP login using polled JWT response")
        jwt_response_json = http_response.json()
        jwt_name = jwt_response_json["name"]
        jwt_value = jwt_response_json["value"]
        jwt_response = JwtResponse(
            jwt_name=jwt_name,
            jwt_value=jwt_value,
        )
        LOG.debug(f"Note: Received actual identity idp {jwt_response.actual_idp_name}")
        return jwt_response

    def _encode_base64(self, document: str) -> str:
        return base64.b64encode(bytearray(document, "utf-8")).decode("utf-8")

    def _is_valid_jwt(self, jwt_response: Optional[JwtResponse]) -> bool:
        if not jwt_response:
            return False
        response = self.connection_handler.session_get(
            endpoint=self.cdh_auth_url_requester, headers={"Cookie": jwt_response.cookies}
        )
        LOG.debug(f"Checked stored token, received validation response {response.json()}")
        return response.status_code == HTTPStatus.OK

    def _raise_contact_helpdesk_error_for_exception(self, e: Exception) -> typing.NoReturn:
        raise ScriptError(
            f"CONNECTION PROBLEM: There is a connection problem. Please try again or contact helpdesk. ({e})"
        )
