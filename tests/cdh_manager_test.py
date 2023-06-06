import configparser
import os
from datetime import datetime
from datetime import timedelta
from random import choice
from typing import Any
from typing import Optional
from typing import Tuple
from unittest.mock import ANY
from unittest.mock import call
from unittest.mock import Mock
from unittest.mock import patch

import pytest

from cdh_utils.constants import AuthMethodStage
from cdh_utils.constants import DEFAULT_AUTH_METHOD_STAGE
from cdh_utils.constants import DEFAULT_REGION
from cdh_utils.constants import IdentityCode
from cdh_utils.constants import IdentityType
from cdh_utils.constants import IdentityTypes
from cdh_utils.constants import REGULAR_IDENTITY_TYPES
from cdh_utils.login.handlers import LoginHandlerCdh
from cdh_utils.login.handlers import LoginResponse
from cdh_utils.saml.identities import BotoCredentials
from cdh_utils.saml.identities import Credentials
from cdh_utils.saml.identities import InvalidRoleArn
from cdh_utils.saml.identities import Role
from cdh_utils.saml.identities import SamlProfile
from cdh_utils.saml.identities import SamlProfileWithAlias
from cdh_utils.saml.identities import SamlProfileWithName
from cdh_utils.saml.identities import SignInTarget
from cdh_utils.utils.browser_handler import BrowserHandler
from cdh_utils.utils.cdh_manager import CdhManager
from cdh_utils.utils.cdhconfig import CdhConfig
from cdh_utils.utils.cdhconfig import IdentitySpecificSettings
from cdh_utils.utils.cdhconfig import UserConfigProfile
from cdh_utils.utils.connection_handler import ConnectionHandler
from cdh_utils.utils.exceptions import AccessDeniedError
from cdh_utils.utils.exceptions import ProfileNotFoundInResponseError
from cdh_utils.utils.helpers import ConsolePrinter
from cdh_utils.utils.helpers import FileHandler
from cdh_utils.utils.helpers import Prompter
from cdh_utils.utils.setup import Setup
from tests.cdh_test import get_fake_credentials
from tests.cdh_test import get_old_saml

IDENTITY_TYPES_WITHOUT_BMW = [
    identity_type_e for identity_type_e in REGULAR_IDENTITY_TYPES if identity_type_e is not IdentityTypes.BMW.value
]

ROLE_WITH_MATCHING_USER_PROFILE = Role.from_arn("arn:aws:iam::111111111111:role/user_profile_role")
ROLE_WITH_ANOTHER_MATCHING_USER_PROFILE = Role.from_arn("arn:aws:iam::444444444444:role/user_profile2_role")
ROLE_NO_MATCHING_USER_PROFILE = Role.from_arn("arn:aws:iam::222222222222:role/role_no_matching_profile")

FAKE_AUTH_URL_END = "/url1"
FAKE_AUTH_RESPONSE = f'<html><body><authmethods><method url="{FAKE_AUTH_URL_END}"></method></authmethods></body></html>'
FAKE_POSTBACK_1_URL_END = "/p/u/doAuthentication.do"
FAKE_POSTBACK_1_RESPONSE = (
    f"<?xml?><AuthenticateResponse><AuthenticationRequirements><PostBack>"
    f"{FAKE_POSTBACK_1_URL_END}</PostBack></AuthenticationRequirements></AuthenticateResponse>"
)
FAKE_POSTBACK_2_URL_END = "/p/u/doAuthentication.do2"
FAKE_POSTBACK_2_RESPONSE = (
    f"<?xml?><AuthenticateResponse><AuthenticationRequirements><PostBack>"
    f"{FAKE_POSTBACK_2_URL_END}</PostBack></AuthenticationRequirements></AuthenticateResponse>"
)

FAKE_TEST_SAML_PATH = os.path.dirname(__file__) + "/fake_test_saml.txt"
MAX_SESSION_DURATION = timedelta(hours=5)
NOW = datetime(2020, 1, 1)

AWS_CONFIG = {
    "invalid": {
        "aws_access_key_id": "123",
        "aws_secret_access_key": "456",
        "aws_session_token": "token1",
        "valid_until": (NOW - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"),
        "region": DEFAULT_REGION,
    },
    "valid": {
        "aws_access_key_id": "321",
        "aws_secret_access_key": "654",
        "aws_session_token": "token2",
        "valid_until": (NOW + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"),
        "region": DEFAULT_REGION,
    },
}


def inject_fake_identity_settings(
    manager: CdhManager, identity_type: IdentityType, identity_settings: IdentitySpecificSettings
) -> None:
    manager._identity_settings_map[identity_type.code] = identity_settings  # noqa: deliberately breaking encapsulation


def build_role_arn(account_id: str, role_name: str) -> str:
    return f"arn:aws:iam::{account_id}:role/{role_name}"


def check_config_file(config: configparser.RawConfigParser, filename: str) -> None:
    assert config.get("default", "aws_access_key_id") == "123"
    assert config.get("default", "aws_secret_access_key") == "456"
    assert config.get("default", "aws_session_token") == "token1"


def build_credentials(token: Optional[str] = None) -> Credentials:
    return Credentials(
        boto_credentials=BotoCredentials(
            access_key="321",
            secret_key="654",
            session_token=token or "sessiontoken123",
        ),
        time_of_request=datetime.now(),
        max_session_duration=timedelta(hours=1),
        region=DEFAULT_REGION,
    )


def assert_not_called_with(mock: Mock, *args: Any, **kwargs: Any) -> None:
    try:
        mock.assert_any_call(*args, **kwargs)
    except AssertionError:
        return
    raise AssertionError(f"Should not have been called but was: {mock._format_mock_call_signature(args, kwargs)}")


class ClickPrompterSetup:
    def setup_method(self) -> None:
        self.click_prompter = Mock(spec=Prompter)
        self.click_prompter.prompt_select_from_dict.return_value = IdentityTypes.BBA.value


class UserProfileSetup:
    def setup_method(self) -> None:
        self.user_config_profile = UserConfigProfile(
            account_id="111111111111",
            role_name="user_profile_role",
            name="profile1",
            region="us-east-1",
            sub_role="arn:aws:iam::333333333333:role/user_profile_subrole",
            session_length=15,
            exclude_from_get_all=False,
        )
        self.another_user_config_profile = UserConfigProfile(
            account_id="444444444444",
            role_name="user_profile2_role",
            name="another_profile",
            region="eu-west-1",
            sub_role=None,
            session_length=None,
            exclude_from_get_all=False,
        )
        unused_profile = UserConfigProfile(
            account_id="777777777777",
            role_name="other_profile_role",
            name="other_profile",
            region="cn-north-1",
            sub_role="arn:aws:iam::888888888888:role/other_profile_subrole",
            session_length=24,
            exclude_from_get_all=False,
        )
        self.identity_settings = IdentitySpecificSettings(
            aws_profiles=[unused_profile, self.user_config_profile, self.another_user_config_profile],
            region="eu-central-1",
        )


class TestBuildSamlProfile(UserProfileSetup):
    def build_manager(self, subrole: Optional[str] = None, session_length: Optional[int] = None) -> CdhManager:
        setup = Setup(
            sub_role=subrole,
            session_length=session_length,
            alias=None,
        )
        manager = CdhManager(setup=setup, identity_type=IdentityTypes.BMW.value)
        inject_fake_identity_settings(manager, IdentityTypes.BMW.value, self.identity_settings)
        return manager

    def test_profile_from_config_returns_saml_profile(self) -> None:
        manager = self.build_manager()

        result = manager.build_saml_profile(ROLE_WITH_MATCHING_USER_PROFILE, IdentityTypes.BMW.value)

        assert isinstance(result, SamlProfileWithName)
        assert result.role == ROLE_WITH_MATCHING_USER_PROFILE
        assert result.name == self.user_config_profile.name
        assert result.region == self.user_config_profile.region

    def test_profile_from_config_set_subrole_from_config(self) -> None:
        manager = self.build_manager()

        result = manager.build_saml_profile(ROLE_WITH_MATCHING_USER_PROFILE, IdentityTypes.BMW.value)

        assert isinstance(result, SamlProfile)
        assert result.sub_role == self.user_config_profile.sub_role

    def test_profile_from_config_set_subrole_from_cli(self) -> None:
        manager = self.build_manager(subrole="subrole4")

        result = manager.build_saml_profile(ROLE_WITH_MATCHING_USER_PROFILE, IdentityTypes.BMW.value)

        assert isinstance(result, SamlProfile)
        assert result.sub_role == "arn:aws:iam::111111111111:role/subrole4"

    def test_profile_from_config_set_subrole_arn_from_cli(self) -> None:
        subrole = "arn:aws:iam::333333333333:role/subrole3"
        manager = self.build_manager(subrole=subrole)

        result = manager.build_saml_profile(ROLE_WITH_MATCHING_USER_PROFILE, IdentityTypes.BMW.value)

        assert isinstance(result, SamlProfile)
        assert result.sub_role == subrole

    def test_profile_from_config_set_session_length_from_config(self) -> None:
        manager = self.build_manager()

        result = manager.build_saml_profile(ROLE_WITH_MATCHING_USER_PROFILE, IdentityTypes.BMW.value)

        assert result.session_length == self.user_config_profile.session_length

    def test_profile_from_config_set_session_length_from_cli(self) -> None:
        manager = self.build_manager(session_length=30)

        result = manager.build_saml_profile(ROLE_WITH_MATCHING_USER_PROFILE, IdentityTypes.BMW.value)

        assert result.session_length == 30

    def test_profile_not_in_config_returns_ad_hoc_profile(self) -> None:
        manager = self.build_manager()
        role = Role.from_arn("arn:aws:iam::222222222222:role/role_no_matching_profile")

        result = manager.build_saml_profile(role, IdentityTypes.BMW.value)

        assert result.get_representative_name() == "role_no_matching_profile_222222222222"
        assert result.role == role
        assert result.region == self.identity_settings.region
        assert result.sub_role is None
        assert result.session_length is None

    def test_profile_not_in_config_returns_ad_hoc_profile_with_suffix_for_bba(self) -> None:
        manager = self.build_manager()
        bba_identity_settings = IdentitySpecificSettings(aws_profiles=[], region="cn-north-1")
        inject_fake_identity_settings(manager, IdentityTypes.BBA.value, bba_identity_settings)

        role = Role.from_arn("arn:aws-cn:iam::666666666666:role/role_no_matching_profile")

        result = manager.build_saml_profile(role, IdentityTypes.BBA.value)

        assert result.get_representative_name() == "role_no_matching_profile_666666666666_bba"

    def test_profile_not_in_config_returns_ad_hoc_profile_with_subrole_from_cli(self) -> None:
        manager = self.build_manager(subrole="subrole_cli")
        role = Role.from_arn("arn:aws:iam::222222222222:role/role_no_matching_profile")

        result = manager.build_saml_profile(role, IdentityTypes.BMW.value)

        assert result.role == role
        assert result.sub_role == "arn:aws:iam::222222222222:role/subrole_cli"

    def test_profile_not_in_config_returns_ad_hoc_profile_with_subrole_arn_from_cli(self) -> None:
        manager = self.build_manager(subrole="arn:aws:iam::333333333333:role/subrole_arn_cli")

        result = manager.build_saml_profile(ROLE_NO_MATCHING_USER_PROFILE, IdentityTypes.BMW.value)

        assert result.role == ROLE_NO_MATCHING_USER_PROFILE
        assert result.sub_role == "arn:aws:iam::333333333333:role/subrole_arn_cli"

    def test_profile_not_in_config_returns_ad_hoc_profile_with_session_length_from_cli(self) -> None:
        manager = self.build_manager(session_length=30)

        result = manager.build_saml_profile(ROLE_NO_MATCHING_USER_PROFILE, IdentityTypes.BMW.value)

        assert result.role == ROLE_NO_MATCHING_USER_PROFILE
        assert result.session_length == 30

    def test_profile_from_config_with_name_returns_saml_profile(self) -> None:
        manager = self.build_manager()

        target = SignInTarget(account_id=None, role_name=None, name=self.user_config_profile.name)

        result = manager.build_saml_profile(ROLE_WITH_MATCHING_USER_PROFILE, IdentityTypes.BMW.value, target)

        assert isinstance(result, SamlProfile)
        assert result.role == ROLE_WITH_MATCHING_USER_PROFILE
        assert result.get_representative_name() == self.user_config_profile.name

    def test_profile_from_config_with_name_returns_ad_hoc_if_name_mismatched(self) -> None:
        manager = self.build_manager()

        target = SignInTarget(account_id=None, role_name=None, name="different_name")

        result = manager.build_saml_profile(ROLE_WITH_MATCHING_USER_PROFILE, IdentityTypes.BMW.value, target)

        assert isinstance(result, SamlProfile)
        assert result.role == ROLE_WITH_MATCHING_USER_PROFILE
        assert result.get_representative_name() != self.user_config_profile.name
        assert result.get_representative_name() == "user_profile_role_111111111111"

    def test_profile_from_config_with_name_picks_matching_name_profile(self) -> None:
        matching_account_id = "111111111111"
        matching_role_name = "role1"
        matching_profile = UserConfigProfile(
            account_id=matching_account_id,
            role_name=matching_role_name,
            name="correct_name",
            region="us-east-1",
            sub_role="arn:aws:iam::333333333333:role/user_profile_subrole0",
            session_length=None,
            exclude_from_get_all=False,
        )
        same_account_role_profile_1 = UserConfigProfile(
            account_id=matching_account_id,
            role_name=matching_role_name,
            name="different_name1",
            region="us-east-1",
            sub_role="arn:aws:iam::333333333333:role/user_profile_subrole1",
            session_length=None,
            exclude_from_get_all=False,
        )
        same_account_role_profile_2 = UserConfigProfile(
            account_id=matching_account_id,
            role_name=matching_role_name,
            name="different_name2",
            region="us-east-1",
            sub_role="arn:aws:iam::333333333333:role/user_profile_subrole2",
            session_length=None,
            exclude_from_get_all=False,
        )
        self.identity_settings = IdentitySpecificSettings(
            aws_profiles=[same_account_role_profile_1, matching_profile, same_account_role_profile_2],
            region="eu-central-1",
        )
        matching_signin_target = SignInTarget(account_id=None, role_name=None, name=matching_profile.name)
        manager = self.build_manager()
        role = Role.from_arn(f"arn:aws:iam::{matching_account_id}:role/{matching_role_name}")

        result = manager.build_saml_profile(role, IdentityTypes.BMW.value, matching_signin_target)

        assert isinstance(result, SamlProfile)
        assert result.role == role
        assert result.get_representative_name() == matching_profile.name


class TestGetAllActiveProfiles(UserProfileSetup):
    def test_returns_user_profile_if_role_matches(self) -> None:
        manager = CdhManager(
            setup=Setup(alias=None, sub_role=None, sanity_check=False),
            identity_type=IdentityTypes.BMW.value,
        )
        inject_fake_identity_settings(manager, IdentityTypes.BMW.value, self.identity_settings)

        saml_roles = [ROLE_WITH_MATCHING_USER_PROFILE, ROLE_WITH_ANOTHER_MATCHING_USER_PROFILE]
        result = manager.get_all_active_profiles_for_stage(
            saml_roles, IdentityTypes.BMW.value, DEFAULT_AUTH_METHOD_STAGE
        )

        assert len(result) == 2
        assert result[0].get_representative_name() == self.user_config_profile.name
        assert result[1].get_representative_name() == self.another_user_config_profile.name

    def test_does_not_return_user_profile_if_role_does_not_match(self, caplog: Any) -> None:
        manager = CdhManager(
            setup=Setup(alias=None, sub_role=None, sanity_check=False),
            identity_type=IdentityTypes.BMW.value,
        )
        self.user_config_profile = UserConfigProfile(
            name="profile1",
            account_id="111111111111",
            role_name="user_profile_role",
            region="eu-west-1",
            sub_role=None,
            session_length=None,
            exclude_from_get_all=False,
        )
        identity_settings = IdentitySpecificSettings(aws_profiles=[self.user_config_profile])
        inject_fake_identity_settings(manager, IdentityTypes.BMW.value, identity_settings)

        saml_roles = [ROLE_NO_MATCHING_USER_PROFILE]
        result = manager.get_all_active_profiles_for_stage(
            saml_roles, IdentityTypes.BMW.value, DEFAULT_AUTH_METHOD_STAGE
        )

        assert len(result) == 0
        assert "User profile profile1 has no match in saml" in caplog.text


class TestGetRoles:
    def test_no_role_specified(self) -> None:
        role = None
        saml_b64 = get_old_saml()
        click_prompter = Mock(spec=Prompter)
        click_prompter.prompt_select_role_id.return_value = 0
        click_prompter.prompt_select_from_dict.return_value = IdentityTypes.BMW.value
        mock_printer = Mock(spec=ConsolePrinter)
        manager = CdhManager(
            setup=Setup(target_raw=role),
            config=CdhConfig(True, True),
            click_prompter=click_prompter,
            console_printer=mock_printer,
            target=None,
        )

        with patch("cdh_utils.utils.cdh_manager.CdhManager._get_account_friendly_names") as mock_get_friendly_names:
            mock_get_friendly_names.return_value = {}
            result = manager.select_profile(saml_b64)

        assert result.role.role_arn == "arn:aws:iam::555555555555:role/CDH-Developer"
        assert result.role.principal_arn == "arn:aws:iam::555555555555:saml-provider/authorization.bmw.cloud"

    def test_role_specified(self) -> None:
        role = "arn:aws:iam::555555555555:role/CDH-Developer"
        principal = "arn:aws:iam::555555555555:saml-provider/authorization.bmw.cloud"
        role_target = SignInTarget.from_arn(role, IdentityTypes.BMW.value)
        saml_b64 = ""
        click_prompter = Mock(spec=Prompter)
        mock_printer = Mock(spec=ConsolePrinter)
        manager = CdhManager(
            setup=Setup(target_raw=role),
            config=CdhConfig(True, True),
            click_prompter=click_prompter,
            console_printer=mock_printer,
            target=role_target,
        )
        result = manager.select_profile(saml_b64)
        assert result.role.role_arn == role
        assert result.role.principal_arn == principal

    def test_invalid_role_specified(self) -> None:
        role = "xxx:iam::555555555555:role/CDH-Developer"

        with pytest.raises(InvalidRoleArn, match=r"INVALID ROLE: The role you provided is not valid!"):
            # noinspection PyTypeChecker
            SignInTarget.from_arn(role, IdentityTypes.BMW.value)

    def test_raises_ProfileNotFoundInResponseError(self) -> None:
        role_target = SignInTarget(
            "012345678901", "fake-role", "not_existing_in_saml_response", IdentityTypes.BMW.value
        )
        saml_b64 = get_old_saml()
        click_prompter = Mock(spec=Prompter)
        mock_printer = Mock(spec=ConsolePrinter)
        manager = CdhManager(
            setup=Setup(),
            config=CdhConfig(True, True),
            click_prompter=click_prompter,
            console_printer=mock_printer,
            target=role_target,
        )
        with pytest.raises(ProfileNotFoundInResponseError):
            manager.select_profile(saml_b64)


class TestWriteAllCredentialsStaged:
    def setup_method(self) -> None:
        self.connection_handler = Mock(spec=ConnectionHandler)
        self.browser_handler = Mock(BrowserHandler)
        self.file_handler = Mock(FileHandler)
        self.login_handler = Mock(LoginHandlerCdh)
        self.manager = CdhManager(
            setup=Setup(),
            config=CdhConfig(True, True),
            connection_handler=self.connection_handler,
            browser_handler=self.browser_handler,
            file_handler=self.file_handler,
        )
        self.manager.login_handler_per_stage[AuthMethodStage.PROD] = self.login_handler
        self.credentials = Mock(Credentials)
        self.connection_handler.get_temp_credentials.return_value = self.credentials
        self.credentials.max_session_duration.seconds = 0
        self.login_response = Mock(spec=LoginResponse)
        self.login_handler.login.return_value = self.login_response
        self.login_response.saml = ""

    def test_write_all_credentials_for_stage(self) -> None:
        identity_type = choice(REGULAR_IDENTITY_TYPES)
        stage = AuthMethodStage.PROD
        self.login_response.actual_idp_name = identity_type.code
        saml_profile = Mock(SamlProfileWithName)
        saml_profile.region = "eu-central-1"

        with patch("cdh_utils.utils.cdh_manager.boto3.client") as mock_client:
            with patch.object(CdhManager, "get_all_active_profiles_for_stage", return_value=[saml_profile]):
                self.manager.write_all_credentials_for_stage_profiles(identity_type, stage)

        self.connection_handler.get_temp_credentials.assert_called_once_with(
            saml_b64=self.login_response.saml, profile=saml_profile, sts_client=mock_client()
        )

    def test_write_all_credentials_for_stage_untagged_fallback(self) -> None:
        identity_type = choice(REGULAR_IDENTITY_TYPES)
        self.login_response.actual_idp_name = identity_type.code
        stage = AuthMethodStage.PROD
        saml_profile = Mock(SamlProfileWithName)
        saml_profile.region = "eu-central-1"
        untagged_login_response = Mock(spec=LoginResponse)
        untagged_login_response.saml = "untagged"
        untagged_login_response.actual_idp_name = identity_type.code
        self.login_handler.login.side_effect = self.login_response, untagged_login_response
        self.connection_handler.get_temp_credentials.side_effect = AccessDeniedError, self.credentials

        with patch("cdh_utils.utils.cdh_manager.boto3.client") as mock_client:
            with patch.object(CdhManager, "get_all_active_profiles_for_stage", return_value=[saml_profile]):
                self.manager.write_all_credentials_for_stage_profiles(identity_type, stage)

        self.connection_handler.get_temp_credentials.assert_has_calls(
            calls=[
                call(saml_b64=self.login_response.saml, profile=saml_profile, sts_client=mock_client()),
                call(saml_b64=untagged_login_response.saml, profile=saml_profile, sts_client=mock_client()),
            ],
        )

    def test_update_identity_type(self) -> None:
        identity_type = IdentityTypes.of_code(IdentityCode.IMPLICIT_CDH_AUTH)
        stage = AuthMethodStage.PROD
        actual_idp_name = choice(REGULAR_IDENTITY_TYPES).code
        self.login_response.actual_idp_name = actual_idp_name
        actual_identity = IdentityTypes.of_code(actual_idp_name)

        with patch("cdh_utils.utils.cdh_manager.boto3.client"):
            with patch.object(CdhManager, "get_all_active_profiles_for_stage", return_value=[]) as get_active_profiles:
                self.manager.write_all_credentials_for_stage_profiles(identity_type, stage)

        get_active_profiles.assert_called_once_with([], actual_identity, stage)


class TestWriteAllCredentials:
    def setup_method(self) -> None:
        user_profile = UserConfigProfile(
            account_id="",
            role_name="",
            name="",
            region="",
            exclude_from_get_all=False,
            sub_role=None,
            session_length=None,
        )
        self.settings = IdentitySpecificSettings(aws_profiles=[user_profile])
        self.config = CdhConfig(True, True)

    @pytest.mark.parametrize("identity_type", REGULAR_IDENTITY_TYPES)
    def test_check_profiles_regular_identity(self, identity_type: IdentityType) -> None:
        self.config.identity_settings = {IdentityCode.BMW: self.settings, IdentityCode.BBA: self.settings}
        manager = self._build_manager()

        with patch.object(CdhManager, "write_all_credentials_for_stage_profiles") as get_credentials:
            manager.write_all_credentials(identity_type)

        get_credentials.assert_called_once()

    @pytest.mark.parametrize("existing_identity_type", REGULAR_IDENTITY_TYPES)
    def test_check_profiles_implicit_identity(self, existing_identity_type: IdentityType) -> None:
        identity_type = IdentityTypes.of_code(IdentityCode.IMPLICIT_CDH_AUTH)
        self.config.identity_settings = {existing_identity_type.code: self.settings}
        manager = self._build_manager()

        with patch.object(CdhManager, "write_all_credentials_for_stage_profiles") as get_credentials:
            manager.write_all_credentials(identity_type)

        get_credentials.assert_called_once()

    @pytest.mark.parametrize("identity_type", list(IdentityTypes))
    def test_no_write_without_profile(self, identity_type: IdentityTypes) -> None:
        manager = self._build_manager()

        with patch.object(CdhManager, "write_all_credentials_for_stage_profiles") as get_credentials:
            manager.write_all_credentials(identity_type.value)

        get_credentials.assert_not_called()

    def _build_manager(self) -> CdhManager:
        return CdhManager(
            setup=Setup(),
            config=self.config,
        )


class TestProcessLogin:
    def setup_method(self) -> None:
        self.login_handler = Mock(spec=LoginHandlerCdh)
        console_printer = Mock(spec=ConsolePrinter)
        self.manager = CdhManager(
            setup=Setup(),
            config=CdhConfig(True, True),
            console_printer=console_printer,
            identity_type=IdentityTypes.IMPLICIT_CDH_AUTH.value,
            login_handler=self.login_handler,
        )

    def test_process_login(self) -> None:
        login_response = LoginResponse(saml="test-saml", roles=[])
        self.login_handler.login.return_value = login_response

        response, identity_type = self.manager.process_login_and_get_saml()

        assert response == login_response
        assert identity_type is None

    def test_update_identity_type(self) -> None:
        actual_identity_type = choice(REGULAR_IDENTITY_TYPES)
        login_response = LoginResponse(saml="test-saml", roles=[], actual_idp_name=actual_identity_type.code)
        self.login_handler.login.return_value = login_response

        _, identity_type = self.manager.process_login_and_get_saml()

        assert identity_type == actual_identity_type
        assert self.manager.identity_type == actual_identity_type


class TestDetermineIdentity(ClickPrompterSetup):
    def setup_method(self) -> None:
        super().setup_method()
        self.manager = CdhManager(setup=Setup(), config=CdhConfig(True, True), click_prompter=self.click_prompter)

    @pytest.mark.parametrize("idp_code", list(IdentityCode))
    def test_determine_idp_identity(self, idp_code: IdentityCode) -> None:
        type = self.manager.determine_identity(idp_code)

        assert type == IdentityTypes.of_code(idp_code)

    @pytest.mark.parametrize("identity_type", list(IdentityTypes))
    def test_unique_identity(self, identity_type: IdentityTypes) -> None:
        self.manager.identity_types_enabled = [identity_type.value]

        type = self.manager.determine_identity(None)

        assert type == identity_type.value

    def test_implicit_type(self) -> None:

        type = self.manager.determine_identity(None)

        assert type == IdentityTypes.IMPLICIT_CDH_AUTH.value


class TestDetermineEnabledIdentities:
    def setup_method(self) -> None:
        self.config = CdhConfig(True, True)

    def test_all_identities_enabled_by_default_without_config_or_cli_options(self) -> None:
        self.config.identity_settings = {}

        result = CdhManager.determine_enabled_identities(self.config)

        assert result == [IdentityTypes.BMW.value, IdentityTypes.BBA.value]

    @pytest.mark.parametrize("identity_type", REGULAR_IDENTITY_TYPES)
    def test_not_enabled_if_disable_by_default_set_in_config(self, identity_type: IdentityType) -> None:
        self.config.identity_settings = {identity_type.code: IdentitySpecificSettings(disable_by_default=True)}

        result = CdhManager.determine_enabled_identities(self.config)

        assert identity_type not in result

    def test_all_enabled(self) -> None:
        self.config.identity_settings = {
            identity_type.code: IdentitySpecificSettings() for identity_type in REGULAR_IDENTITY_TYPES
        }

        result = CdhManager.determine_enabled_identities(self.config)

        assert result == REGULAR_IDENTITY_TYPES


class TestParseIdentityFromProfileName(ClickPrompterSetup):
    def setup_method(self) -> None:
        super().setup_method()
        self.manager = CdhManager(
            setup=Setup(),
            config=CdhConfig(True, True),
            click_prompter=self.click_prompter,
        )

    def test_parse_name_without_name_returns_none(self) -> None:
        assert self.manager.determine_identity_for_profile_name(None) is None

    def test_parse_ad_hoc_name_without_suffix_returns_bmw_identity_by_default(self) -> None:
        assert self.manager.determine_identity_for_profile_name("CDHX-DevOps_111111111111") == IdentityTypes.BMW.value

    def test_parse_arbitrary_name_without_suffix_returns_none(self) -> None:
        assert self.manager.determine_identity_for_profile_name("xyz") is None

    def test_parse_role_arn_returns_none(self) -> None:
        role_arn = "arn:aws:iam::11111111111:role/user_profile_role"
        assert self.manager.determine_identity_for_profile_name(role_arn) is None

    @pytest.mark.parametrize("identity_type", IDENTITY_TYPES_WITHOUT_BMW)
    def test_parse_ad_hoc_name_with_identity_suffix_returns_identity(self, identity_type: IdentityType) -> None:
        profile_name = f"CDHX-DevOps_111111111111_{identity_type.auto_profile_suffix}"
        assert self.manager.determine_identity_for_profile_name(profile_name) == identity_type

    @pytest.mark.parametrize("identity_type", REGULAR_IDENTITY_TYPES)
    def test_parse_known_profile_name_returns_known_identity(self, identity_type: IdentityType) -> None:
        self.user_config_profile = UserConfigProfile(
            name="profile1",
            account_id="111111111111",
            role_name="user_profile_role",
            region="eu-west-1",
            sub_role=None,
            session_length=None,
            exclude_from_get_all=False,
        )
        self.identity_settings = IdentitySpecificSettings(aws_profiles=[self.user_config_profile])
        inject_fake_identity_settings(self.manager, identity_type, self.identity_settings)

        assert self.manager.determine_identity_for_profile_name(self.user_config_profile.name) == identity_type


class TestTargetHasSubrole(ClickPrompterSetup):
    def test_profile_with_subrole_returns_true(self) -> None:
        manager = CdhManager(
            setup=Setup(),
            config=CdhConfig(True, True),
            click_prompter=self.click_prompter,
        )
        profile_with_subrole = UserConfigProfile(
            name="profile1",
            account_id="111111111111",
            role_name="user_profile_role",
            region="eu-west-1",
            sub_role="arn:aws:iam::333333333333:role/user_profile_subrole1",
            session_length=None,
            exclude_from_get_all=False,
        )
        identity_settings = IdentitySpecificSettings(aws_profiles=[profile_with_subrole])
        inject_fake_identity_settings(manager, IdentityTypes.BMW.value, identity_settings)

        assert manager.target_has_subrole(profile_with_subrole.name, IdentityTypes.BMW.value)

    def test_unknown_profile_with_cli_subrole_returns_true(self) -> None:
        manager = CdhManager(
            setup=Setup(sub_role="arn:aws:iam::333333333333:role/subrole1"),
            config=CdhConfig(True, True),
            click_prompter=self.click_prompter,
        )

        assert manager.target_has_subrole("ad-hoc-profile", IdentityTypes.BMW.value)

    def test_unknown_profile_without_cli_subrole_returns_true(self) -> None:
        manager = CdhManager(
            setup=Setup(alias=None),
            config=CdhConfig(True, True),
            click_prompter=self.click_prompter,
        )

        assert not manager.target_has_subrole("ad-hoc-profile", IdentityTypes.BMW.value)


@patch("boto3.client", new=Mock)
class TestFriendlyNames:
    def setup_method(self) -> None:
        self.connection_handler = Mock(spec=ConnectionHandler)
        self.saml_b64 = Mock()
        self.cdh_manager = CdhManager(
            Setup(),
            CdhConfig(ignore_keyring=True, ignore_config=True),
            connection_handler=self.connection_handler,
        )

    def test_gets_credentials_and_calls_friendly_names(self) -> None:
        profiles = [(SamlProfile.from_arn(build_role_arn("111111111111", "CDH-Developer")))]
        self.connection_handler.get_temp_credentials.side_effect = (
            lambda saml_b64, profile, sts_client: build_credentials(f"token-for_{profile.role.role_arn}")
        )
        self.connection_handler.get_account_friendly_names.side_effect = (
            lambda profile, saml_b64, sts_client, identity_type, force_cache_update: {"account1": "friendly name 1"}
        )

        self.cdh_manager._get_account_friendly_names(self.saml_b64, profiles)

        self.connection_handler.get_account_friendly_names.assert_called_with(profiles[0], self.saml_b64, ANY, ANY, ANY)

    def test_returns_merged_friendly_names(self) -> None:
        profiles = [
            (SamlProfile.from_arn(build_role_arn("111111111111", "CDH-Developer"))),
            (SamlProfile.from_arn(build_role_arn("101010101010", "CDH-Developer"))),
        ]
        self.connection_handler.get_temp_credentials.side_effect = (
            lambda saml_b64, profile, sts_client: build_credentials(f"token-for_{profile.role.role_arn}")
        )
        self.connection_handler.are_all_account_numbers_in_cache.side_effect = [False, True]
        self.connection_handler.get_account_friendly_names.side_effect = (
            lambda profile, saml_b64, sts_client, identity_type, force_cache_update: {
                profiles[0]: {"111111111111": "friendly name 1"},
                profiles[1]: {
                    "222222222222": "friendly name 2",
                    "333333333333": "friendly name 3",
                },
            }[profile]
        )

        result = self.cdh_manager._get_account_friendly_names(self.saml_b64, profiles)

        assert result == {
            "111111111111": "friendly name 1",
            "222222222222": "friendly name 2",
            "333333333333": "friendly name 3",
        }


class TestWriteCredentials:
    def test_if_credential_info_is_printed(self) -> None:
        credentials = get_fake_credentials()
        file_handler = Mock(spec=FileHandler)
        file_handler.write_config_file.side_effect = check_config_file
        click_prompter = Mock(spec=Prompter)
        mock_printer = Mock(spec=ConsolePrinter)
        manager = CdhManager(
            setup=Setup(),
            config=CdhConfig(True, True),
            click_prompter=click_prompter,
            console_printer=mock_printer,
            file_handler=file_handler,
        )
        manager.write_credentials(SamlProfileWithName(Role("", ""), "default"), credentials)
        filename = os.path.join(os.path.expanduser("~"), ".aws", "credentials")

        mock_printer.print_credential_info.assert_called_once_with(
            "default", credentials, filename, output_credentials=False
        )

    def test_if_credentials_are_output(self) -> None:
        credentials = get_fake_credentials()
        file_handler = Mock(spec=FileHandler)
        file_handler.write_config_file.side_effect = check_config_file
        click_prompter = Mock(spec=Prompter)
        mock_printer = Mock(spec=ConsolePrinter)
        manager = CdhManager(
            setup=Setup(output_credentials=True),
            config=CdhConfig(True, True),
            click_prompter=click_prompter,
            console_printer=mock_printer,
            file_handler=file_handler,
        )
        manager.write_credentials(SamlProfileWithName(Role("", ""), "default"), credentials)
        filename = os.path.join(os.path.expanduser("~"), ".aws", "credentials")

        mock_printer.print_credential_info.assert_called_once_with(
            "default", credentials, filename, output_credentials=True
        )


class TestTargetResolve(ClickPrompterSetup):
    def test_resolve_target_from_alias(self) -> None:
        role_name = "CDH-Developer"
        account_id = "555555555555"
        alias = f"{role_name}_{account_id}"
        empty_setup = Setup()
        cdh_manager = CdhManager(setup=empty_setup, click_prompter=self.click_prompter)
        resolved_target = cdh_manager.resolve_target_from_alias(alias)
        assert resolved_target
        assert resolved_target.name is None
        assert resolved_target.role_name == role_name
        assert resolved_target.account_id == account_id

    def test_resolve_target_from_alias_with_badly_formatted_account_id(self) -> None:
        role_name = "CDH-Developer"
        account_id = "badAccountId"
        alias = f"{role_name}_{account_id}"
        empty_setup = Setup()
        cdh_manager = CdhManager(setup=empty_setup, click_prompter=self.click_prompter)
        resolved_target = cdh_manager.resolve_target_from_alias(alias)
        assert resolved_target is None

    def test_resolve_bmw_profile_target(self) -> None:
        BMW_PROFILE_NAME = "bmw_target_profile"
        setup_with_target = Setup(target_raw=BMW_PROFILE_NAME)
        manager = CdhManager(setup=setup_with_target, click_prompter=self.click_prompter)
        user_config_profile = UserConfigProfile(
            name=BMW_PROFILE_NAME,
            account_id="111111111111",
            role_name="user_profile_role",
            region="eu-west-1",
            sub_role=None,
            session_length=None,
            exclude_from_get_all=False,
        )
        bmw_identity_settings = IdentitySpecificSettings(aws_profiles=[user_config_profile])
        manager.config.identity_settings[IdentityCode.BMW] = bmw_identity_settings

        resolved_sign_in_target = manager.resolve_target(BMW_PROFILE_NAME)
        assert resolved_sign_in_target is not None
        assert resolved_sign_in_target.name == BMW_PROFILE_NAME
        assert resolved_sign_in_target.identity_type == IdentityTypes.BMW.value

    def test_resolve_bba_profile_target(self) -> None:
        BBA_PROFILE_NAME = "bba_target_profile"
        setup_with_target = Setup(target_raw=BBA_PROFILE_NAME)
        manager = CdhManager(setup=setup_with_target, click_prompter=self.click_prompter)
        user_config_profile = UserConfigProfile(
            name=BBA_PROFILE_NAME,
            account_id="111111111111",
            role_name="user_profile_role",
            region="eu-west-1",
            sub_role=None,
            session_length=None,
            exclude_from_get_all=False,
        )
        bba_identity_settings = IdentitySpecificSettings(aws_profiles=[user_config_profile])
        manager.config.identity_settings[IdentityCode.BBA] = bba_identity_settings

        resolved_sign_in_target = manager.resolve_target(BBA_PROFILE_NAME)
        assert resolved_sign_in_target is not None
        assert resolved_sign_in_target.name == BBA_PROFILE_NAME
        assert resolved_sign_in_target.identity_type == IdentityTypes.BBA.value


class TestWriteCredentialsToFile(ClickPrompterSetup):
    def create_dummy_saml_profile_with_alias(self) -> SamlProfileWithAlias:
        role_name = "CDH-Developer"
        account_id = "555555555555"
        role = Role.from_arn(f"arn:aws:iam::{account_id}:role/{role_name}")
        return SamlProfileWithAlias(role=role, identity_type=IdentityTypes.BMW.value)

    def append_dummy_credentials_to_profile(self, profile: SamlProfile) -> Tuple[SamlProfile, Credentials]:
        cred = Credentials(
            BotoCredentials("dummy_access_key", "dummy_secret_key", "dummy_session_token"),
            timedelta(hours=12),
            datetime.now(),
            "eu-west-1",
        )
        return (profile, cred)

    def test_write_all_credentials_to_file_with_default_alias(self) -> None:
        DEFAULT_ALIAS = "default"
        profile = self.create_dummy_saml_profile_with_alias()
        dummy_profile_with_cred = self.append_dummy_credentials_to_profile(profile)
        setup_with_default_alias = Setup(alias=DEFAULT_ALIAS)
        file_handler = Mock()
        cdh_manager = CdhManager(
            setup=setup_with_default_alias, file_handler=file_handler, click_prompter=self.click_prompter
        )

        cdh_manager.write_all_credentials_to_file([dummy_profile_with_cred])

        file_handler.write_config_file.assert_called()
        ((config, _), _) = file_handler.write_config_file.call_args
        assert config.has_section(DEFAULT_ALIAS)

    def test_write_all_credentials_to_file_without_alias(self) -> None:
        profile = self.create_dummy_saml_profile_with_alias()
        dummy_profile_with_cred = self.append_dummy_credentials_to_profile(profile)
        setup_with_default_alias = Setup()
        file_handler = Mock()
        cdh_manager = CdhManager(
            setup=setup_with_default_alias, file_handler=file_handler, click_prompter=self.click_prompter
        )

        cdh_manager.write_all_credentials_to_file([dummy_profile_with_cred])

        file_handler.write_config_file.assert_called()
        ((config, _), _) = file_handler.write_config_file.call_args
        assert config.has_section("CDH-Developer_555555555555")


class TestAuthIdpName(ClickPrompterSetup):
    def setup_method(self) -> None:
        super().setup_method()
        self.setup = Setup()
        self.idp_name = IdentityCode.BMW
        self.config = CdhConfig(ignore_keyring=True, ignore_config=True)
        self.manager = CdhManager(setup=self.setup, click_prompter=self.click_prompter)

    def test_determine_cdh_auth_idp(self) -> None:
        assert self.manager.determine_cdh_auth_idp(self.idp_name) == self.idp_name

    def test_cdh_auth_idp_from_profile_root(self) -> None:
        self.manager.identity_type_by_profile_name = IdentityTypes.BMW.value
        assert self.manager.determine_cdh_auth_idp(None) == IdentityCode.BMW


class TestRightLoginHandler(ClickPrompterSetup):
    def setup_method(self) -> None:
        super().setup_method()
        self.setup = Setup()
        self.config = CdhConfig(ignore_keyring=True, ignore_config=True)
        self.manager = CdhManager(setup=self.setup, config=self.config, click_prompter=self.click_prompter)

    def test_get_login_handler_for_stage_with_given_auth_method_stage_in_setup(self) -> None:
        setup = Setup(auth_method_stage=AuthMethodStage.INT.value)
        manager = CdhManager(setup=setup, click_prompter=self.click_prompter)
        login_handler = manager._get_login_handler_for_stage_regarding_setup(AuthMethodStage.PROD)
        assert login_handler.cdh_auth_url_login == AuthMethodStage.INT.get_stage_login_endpoint()

    def test_get_login_handler_for_stage_without_setup(self) -> None:
        test_auth_method_stage = AuthMethodStage.PROD
        login_handler = self.manager._get_login_handler_for_stage_regarding_setup(test_auth_method_stage)
        assert isinstance(login_handler, LoginHandlerCdh)
        assert login_handler.cdh_auth_url_login == test_auth_method_stage.get_stage_login_endpoint()

    def test_get_login_handler_return_manager_default_login_handler(self) -> None:
        login_handler = self.manager._get_login_handler_for_stage_regarding_setup(None)
        assert login_handler == self.manager.login_handler_per_stage[DEFAULT_AUTH_METHOD_STAGE]


class TestGuestRoles(ClickPrompterSetup):
    def setup_method(self) -> None:
        super().setup_method()
        self.setup = Setup()
        self.config = CdhConfig(ignore_keyring=True, ignore_config=True)
        self.manager = CdhManager(setup=self.setup, config=self.config, click_prompter=self.click_prompter)

    def test_guest_roles_are_filtered_out(self) -> None:
        mock_roles = [
            Role(
                "arn:aws:iam::555555555555:role/CDH-Developer",
                "arn:aws:iam::555555555555:saml-provider/authorization.bmw.cloud",
                True,
            )
        ]
        result = self.manager.extract_non_guest_profiles(IdentityTypes.BMW.value, mock_roles)
        assert result == []

    def test_non_guest_roles_are_kept(self) -> None:

        mock_roles = [
            Role(
                "arn:aws:iam::555555555555:role/CDH-Developer",
                "arn:aws:iam::555555555555:saml-provider/authorization.bmw.cloud",
                False,
            )
        ]
        result = self.manager.extract_non_guest_profiles(IdentityTypes.BMW.value, mock_roles)

        assert len(result) == len(mock_roles)

        assert {r.role for r in result} == set(mock_roles)
