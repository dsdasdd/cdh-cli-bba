import configparser
import json
import logging
import os
import re
import time
from concurrent import futures
from concurrent.futures.thread import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from datetime import timedelta
from functools import lru_cache
from itertools import chain
from os.path import expanduser
from typing import Any
from typing import Callable
from typing import Collection
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from urllib import parse

import boto3
import click_spinner
import requests
import urllib3
from tabulate import tabulate

from cdh_utils.constants import AuthMethodStage
from cdh_utils.constants import CHINA_REGIONS
from cdh_utils.constants import DEFAULT_AUTH_METHOD_STAGE
from cdh_utils.constants import DEFAULT_REGION
from cdh_utils.constants import IdentityCode
from cdh_utils.constants import IdentityType
from cdh_utils.constants import IdentityTypes
from cdh_utils.constants import JwtType
from cdh_utils.constants import PROXIES
from cdh_utils.constants import REGULAR_IDENTITY_TYPES
from cdh_utils.login.handlers import LoginHandlerCdh
from cdh_utils.login.handlers import LoginResponse
from cdh_utils.login.handlers import ScriptError
from cdh_utils.login.jwt_cache import JwtCache
from cdh_utils.saml.identities import BotoCredentials
from cdh_utils.saml.identities import Credentials
from cdh_utils.saml.identities import Role
from cdh_utils.saml.identities import SamlProfile
from cdh_utils.saml.identities import SamlProfileWithAlias
from cdh_utils.saml.identities import SamlProfileWithName
from cdh_utils.saml.identities import SignInTarget
from cdh_utils.saml.saml_parser import SamlParser
from cdh_utils.utils.botoclient import build_boto_default_config
from cdh_utils.utils.botoclient import build_short_timeout_config
from cdh_utils.utils.browser_handler import BrowserHandler
from cdh_utils.utils.cdhconfig import CdhConfig
from cdh_utils.utils.cdhconfig import get_role_arn_from_str
from cdh_utils.utils.cdhconfig import IdentitySpecificSettings
from cdh_utils.utils.cdhconfig import UserConfigProfile
from cdh_utils.utils.connection_handler import ConnectionHandler
from cdh_utils.utils.connection_handler import FriendlyNamesCacheHandler
from cdh_utils.utils.connection_handler import get_aws_federation_url
from cdh_utils.utils.connection_handler import get_aws_signin_url
from cdh_utils.utils.exceptions import AccessDeniedError
from cdh_utils.utils.exceptions import ProfileNotFoundInResponseError
from cdh_utils.utils.helpers import ConsolePrinter
from cdh_utils.utils.helpers import FileHandler
from cdh_utils.utils.helpers import Prompter
from cdh_utils.utils.log_context import change_identity_context
from cdh_utils.utils.log_context import get_identity_context
from cdh_utils.utils.log_context import identity_context
from cdh_utils.utils.performance import performance_timer
from cdh_utils.utils.setup import Setup

DEFAULT_AD_HOC_PROFILE_NAME_REGEX = r"^[a-zA-Z0-9+=,.@_\\-]+_[0-9]{12}$"
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

LOG = logging.getLogger(__name__)


@dataclass
class TargetSettings:
    session_length: Optional[int]
    sub_role: Optional[str]


class CdhManager:
    def __init__(
        self,
        setup: Setup,
        config: Optional[CdhConfig] = None,
        connection_handler: Optional[ConnectionHandler] = None,
        file_handler: Optional[FileHandler] = None,
        console_printer: Optional[ConsolePrinter] = None,
        click_prompter: Optional[Prompter] = None,
        identity_type: Optional[IdentityType] = None,
        target: Optional[SignInTarget] = None,
        browser_handler: Optional[BrowserHandler] = None,
        jwt_cache: Optional[JwtCache] = None,
        login_handler: Optional[LoginHandlerCdh] = None,
    ):
        self.setup = setup
        self.config = config or CdhConfig(setup.ignore_config, setup.ignore_keyring)
        self.region: Optional[str] = self.config.bmw_identity_settings.region
        self.connection_handler = connection_handler or ConnectionHandler(
            requests.Session(), self.region, FriendlyNamesCacheHandler(ignore_cache_file=self.setup.ignore_cache_file)
        )
        self.file_handler = file_handler or FileHandler()
        self.console_printer = console_printer or ConsolePrinter()
        self.browser_handler = browser_handler or BrowserHandler(self.config)
        self._click_prompter = click_prompter or Prompter()

        self._identity_settings_map = self.config.identity_settings
        self.identity_types_enabled = self.determine_enabled_identities(self.config)
        self.identity_type_by_profile_name = self.determine_identity_for_profile_name(setup.target_raw)
        self.cdh_auth_idp = self.determine_cdh_auth_idp(self.setup.auth_idp)
        self.identity_type = (
            identity_type or self.identity_type_by_profile_name or self.determine_identity(self.cdh_auth_idp)
        )
        LOG.debug(f"Starting with identity_type {self.identity_type}")
        if self.identity_type not in self.identity_types_enabled:
            self.identity_types_enabled.append(self.identity_type)
        jwt_cache = jwt_cache or JwtCache(self.config.use_keyring)

        self.login_handler_per_stage: Dict[Optional[AuthMethodStage], LoginHandlerCdh] = {
            AuthMethodStage.INT: LoginHandlerCdh(
                connection_handler=self.connection_handler,
                browser_handler=self.browser_handler,
                auth_stage=AuthMethodStage.INT,
                idp_name=self.identity_type.code,
                jwt_cache=jwt_cache,
            ),
            AuthMethodStage.PROD: LoginHandlerCdh(
                connection_handler=self.connection_handler,
                browser_handler=self.browser_handler,
                auth_stage=AuthMethodStage.PROD,
                idp_name=self.identity_type.code,
                jwt_cache=jwt_cache,
            ),
        }
        self.login_handler_per_stage[None] = login_handler or self.login_handler_per_stage[DEFAULT_AUTH_METHOD_STAGE]

        self.executor: Optional[str] = os.environ.pop("AWS_PROFILE", None)
        self.target_settings = TargetSettings(sub_role=setup.sub_role, session_length=setup.session_length)
        prepare_environment_variables()

        self.target = target

        self.config_sanity_check_enabled: bool = (
            self.setup.sanity_check if self.setup.sanity_check is not None else self.config.sanity_check
        )

    def determine_cdh_auth_idp(self, auth_idp: Optional[IdentityCode]) -> Optional[IdentityCode]:
        if auth_idp:
            return auth_idp
        if self.identity_type_by_profile_name:
            return self.identity_type_by_profile_name.code
        return None

    @staticmethod
    def determine_enabled_identities(
        config: CdhConfig,
    ) -> List[IdentityType]:
        """An identity is considered enabled if
        - either it is configured in the config (but disable-by-default is not set)
        - or an CLI option specific for that identity is given
        - BMW is enabled by default if no config is given and no cli options are set
        """
        bmw_config_identity_settings = config.bmw_identity_settings
        bba_config_identity_settings = config.bba_identity_settings

        enabled_identity_types = []
        if bmw_config_identity_settings and not bmw_config_identity_settings.disable_by_default:
            enabled_identity_types.append(IdentityTypes.BMW.value)
        if bba_config_identity_settings and not bba_config_identity_settings.disable_by_default:
            enabled_identity_types.append(IdentityTypes.BBA.value)

        if not enabled_identity_types:
            if not bmw_config_identity_settings.disable_by_default:
                enabled_identity_types.append(IdentityTypes.BMW.value)
            if not bba_config_identity_settings.disable_by_default:
                enabled_identity_types.append(IdentityTypes.BBA.value)

        return enabled_identity_types

    @property
    def bmw_identity_settings(self) -> IdentitySpecificSettings:
        """convenience accessor for bmw identity settings, will return an empty dummy if no bmw settings are set"""
        return self.identity_settings(IdentityTypes.BMW.value)

    def identity_settings(self, identity_type: IdentityType) -> IdentitySpecificSettings:
        """convenience accessor for identity settings,
        will return an empty dummy if no settings are set for identity_type"""
        return self._identity_settings_map.get(identity_type.code, IdentitySpecificSettings.build_empty())

    def build_saml_profile(
        self, role: Role, identity_type: IdentityType, target: Optional[SignInTarget] = None
    ) -> SamlProfile:
        identity_settings = self.identity_settings(identity_type)
        user_profile = identity_settings.get_fitting_profile(
            role.get_account_number(), role.get_name(), target.name if target and target.name else ""
        )
        subrole_from_target = get_role_arn_from_str(self.target_settings.sub_role, role.get_account_number())

        if user_profile:
            return SamlProfileWithName(
                role=role,
                profile_name=user_profile.name,
                region=user_profile.region,
                sub_role=subrole_from_target or user_profile.sub_role,
                session_length=self.target_settings.session_length or user_profile.session_length,
            )
        else:  # userProfile not found, build it using alias
            return SamlProfileWithAlias(
                role=role,
                region=identity_settings.region,
                sub_role=subrole_from_target,
                session_length=self.target_settings.session_length,
                identity_type=identity_type,
            )

    def determine_identity(self, cdh_auth_idp: Optional[IdentityCode]) -> IdentityType:
        """Determines the identity type for the Manager instance, if it could not be deduced from the target nor was
        specified in the constructor arguments."""
        if cdh_auth_idp:
            return IdentityTypes.of_code(cdh_auth_idp)
        if len(self.identity_types_enabled) == 1:
            identity_type = self.identity_types_enabled[0]
            LOG.debug(f"got exactly one enabled identity type ({identity_type})")
        else:
            LOG.debug("using implicit identity from IDP backend")
            identity_type = IdentityTypes.IMPLICIT_CDH_AUTH.value

        return identity_type

    def _prompt_identity(self, allowed_identity_types: List[IdentityType]) -> IdentityType:
        """Prompts the possible identity options and returns selection"""
        choices = {str(identity_type): identity_type for identity_type in allowed_identity_types}
        return self._click_prompter.prompt_select_from_dict(
            choices, "Identity", "Please select the identity to use from the list"
        )

    def determine_identity_for_profile_name(self, profile_name: Optional[str]) -> Optional[IdentityType]:
        identity_type = self._determine_identity_for_profile_name(profile_name)
        if identity_type:
            LOG.debug(f'determined identity for profile "{profile_name}" as "{identity_type}"')
        else:
            LOG.debug(f'could not determine identity from target "{profile_name}"')
        return identity_type

    def _determine_identity_for_profile_name(self, profile_name: Optional[str]) -> Optional[IdentityType]:
        if not profile_name or Role.is_valid_arn(profile_name):
            return None

        for identity_code, specific_settings in self._identity_settings_map.items():
            if specific_settings.get_profile_by_name(profile_name):
                return IdentityTypes.of_code(identity_code)

        for identity_type in REGULAR_IDENTITY_TYPES:
            suffix = f"_{identity_type.auto_profile_suffix}"
            if profile_name.endswith(suffix):
                return identity_type

        if re.match(DEFAULT_AD_HOC_PROFILE_NAME_REGEX, profile_name):
            return IdentityTypes.BMW.value

        return None

    def __enter__(self) -> "CdhManager":
        self.connection_handler.session.__enter__()
        if self.setup.proxy:
            self.connection_handler.session.proxies = PROXIES
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.connection_handler.session.__exit__(exc_type, exc_val, exc_tb)

    def target_has_subrole(self, target: str, identity_type: IdentityType) -> bool:
        if self.target_settings.sub_role:
            return True
        identity_settings = self.identity_settings(identity_type)
        user_profile = identity_settings.get_profile_by_name(target)
        if user_profile is None:
            return False
        return user_profile.sub_role is not None

    def get_all_active_profiles_for_stage(
        self, saml_roles: List[Role], identity_type: IdentityType, stage: AuthMethodStage
    ) -> List[SamlProfile]:
        saml_profiles: List[SamlProfile] = []
        bad_config_profiles = []
        for user_profile in self.identity_settings(identity_type).get_aws_profiles_for_stage(stage):
            matching_role = next(
                (
                    role
                    for role in saml_roles
                    if user_profile.role_name == role.get_name()
                    and user_profile.account_id == role.get_account_number()
                ),
                None,
            )
            if matching_role:
                saml_profiles.append(
                    SamlProfileWithName(
                        role=matching_role,
                        profile_name=user_profile.name,
                        region=user_profile.region,
                        sub_role=user_profile.sub_role,
                        session_length=user_profile.session_length,
                    )
                )
            else:
                LOG.warning(f"User profile {user_profile.name} has no match in saml")
                bad_config_profiles.append(user_profile)

        if self.config_sanity_check_enabled:
            self.config_sanity_check(identity_type, bad_config_profiles)

        return saml_profiles

    def config_sanity_check(
        self,
        identity_type: IdentityType,
        bad_config_profiles: List[UserConfigProfile],
    ) -> None:
        LOG.info(f"commenting unavailable config profile for identity: {identity_type.code.value}")
        self.config.comment_out_bad_profiles_for_identity(identity_type, bad_config_profiles)

    def resolve_target(self, target_raw: Optional[str]) -> Optional[SignInTarget]:
        if target_raw is None:
            return None

        result = (
            self.resolve_target_from_profile(target_raw)
            or self.resolve_target_from_arn(target_raw)
            or self.resolve_target_from_alias(target_raw)
        )

        if result is None:
            raise ScriptError(
                f"{target_raw} cannot be resolved! It does not fit any profile name and does not match ARN "
                f"or alias patterns"
            )

        return result

    def resolve_target_from_profile(self, target_raw: str) -> Optional[SignInTarget]:
        for identity_type in REGULAR_IDENTITY_TYPES:
            identity_code = identity_type.code
            identity_specific_settings = self.config.identity_settings.get(
                identity_code, IdentitySpecificSettings.build_empty()
            )
            for config_profile in identity_specific_settings.aws_profiles:
                if config_profile.name == target_raw:
                    return SignInTarget(
                        account_id=config_profile.account_id,
                        role_name=config_profile.role_name,
                        name=target_raw,
                        identity_type=identity_type,
                        auth_method_stage=config_profile.auth_method_stage,
                    )
        return None

    def resolve_target_from_arn(self, target_raw: str) -> Optional[SignInTarget]:
        if Role.is_valid_arn(target_raw):
            self.console_printer.print_warning(
                "Deprecation warning: Specifying the ARN directly is discouraged and "
                "will not be maintained in the future. Set up a config.yml file "
                "instead."
            )
            target_profile = SignInTarget.from_arn(
                target_raw,
                self.identity_type,
                sub_role=get_role_arn_from_str(
                    self.target_settings.sub_role, Role.get_account_number_from_arn(target_raw)
                ),
            )
            return target_profile
        return None

    def resolve_target_from_alias(self, target_raw: str) -> Optional[SignInTarget]:
        try:
            alias_role_name, alias_account_id, *alias_identity_type = target_raw.split("_", 2)
        except ValueError:
            return None

        if len(alias_account_id) != 12 or not alias_account_id.isdigit():
            return None

        return SignInTarget(account_id=alias_account_id, role_name=alias_role_name, name=None, identity_type=None)

    def get_and_write_credentials(self) -> Credentials:
        urllib3.disable_warnings()

        self.target = self.resolve_target(self.setup.target_raw)

        target_auth_method_stage = self.target.auth_method_stage if self.target else None
        login_response, _ = self.process_login_and_get_saml(target_auth_method_stage)
        saml_b64 = login_response.saml

        profile = self.select_profile(self._get_untagged_saml(auth_method_stage=target_auth_method_stage))

        show_spinner = LOG.isEnabledFor(logging.WARNING)
        with click_spinner.spinner(disable=not show_spinner):
            credentials = self._get_temp_credentials(
                saml_b64=saml_b64, profile=profile, auth_method_stage=target_auth_method_stage
            )
            self.write_credentials(profile, credentials)
            return credentials

    @lru_cache(maxsize=8)
    def process_login_and_get_saml(
        self,
        auth_method_stage: Optional[AuthMethodStage] = None,
        disable_mail_tagging: bool = False,
        log_success: bool = False,
    ) -> Tuple[LoginResponse, Optional[IdentityType]]:
        try:
            login_handler = self._get_login_handler_for_stage_regarding_setup(auth_method_stage)
            login_response = login_handler.login(disable_mail_tagging)

            updated_identity_type: Optional[IdentityType] = None
            LOG.debug(
                f"actual_idp_name: {login_response.actual_idp_name} "
                f"vs self.identity_type.code: {self.identity_type.code}"
            )
            if login_response.actual_idp_name and login_response.actual_idp_name != self.identity_type.code:
                actual_identity_type = IdentityTypes.of_code(login_response.actual_idp_name)
                LOG.debug(f"CHANGE TO: {actual_identity_type.code}")
                change_identity_context(actual_identity_type)
                self.identity_type = actual_identity_type
                updated_identity_type = actual_identity_type

            if log_success:
                LOG.info("Request granted")

            self.console_printer.print_debug(f"Response saml: {login_response.saml}")
            return login_response, updated_identity_type

        except AttributeError:
            self.console_printer.print_error("Possible login error. Maybe due to an invalid password, pin or smscode.")
            raise ScriptError(
                "AttributeError: Invalid Response. This is often caused "
                + "due to expired passwords which were stored in the keychain. "
                + "Please try again and enter your new password."
            )

    def select_profile(self, saml_b64: str) -> SamlProfile:
        if self.target is None:
            target_profile = self.prompt_roles(saml_b64)
        elif self.target.is_arn:
            target_profile = self.target.to_saml_profile()
        else:
            profiles = [
                self.build_saml_profile(role, self.identity_type, self.target) for role in self.get_all_roles(saml_b64)
            ]
            matches = [profile for profile in profiles if profile.matches(self.target, self.identity_type)]

            if len(matches) == 0:
                if self.target.name is None:
                    raise ScriptError(f"{self.setup.target_raw} is not a known profile.")
                raise ProfileNotFoundInResponseError(
                    f"{self.setup.target_raw} is a saved profile, but it was not found in the SAML message."
                )
            if len(matches) > 1:
                LOG.warning(f"Found multiple matching profiles for target {self.setup.target_raw}, will pick first one")
            target_profile = matches[0]

        debug_dict = {
            "role": str(target_profile.role),
            "subrole": target_profile.sub_role,
            "session_length": target_profile.session_length,
            "region": target_profile.region,
        }
        self.console_printer.print_debug("Chosen saml profile: " + str(debug_dict))
        return target_profile

    def prompt_roles(self, saml_b64: str) -> SamlProfile:
        profiles = [self.build_saml_profile(role, self.identity_type) for role in self.get_all_roles(saml_b64)]

        friendly_names = self._get_account_friendly_names(saml_b64, profiles)
        account_display = self.get_account_display(friendly_names)

        selected_role_id = self._click_prompter.prompt_select_role_id(profiles, account_display)
        return profiles[selected_role_id]

    def get_all_roles(self, saml_b64: str) -> List[Role]:
        if saml_b64:
            return SamlParser.from_base64(saml_b64).get_roles()
        return []

    def _get_untagged_saml(self, auth_method_stage: Optional[AuthMethodStage]) -> str:
        login_response, _ = self.process_login_and_get_saml(
            auth_method_stage=auth_method_stage,
            disable_mail_tagging=True,
            log_success=False,
        )
        return login_response.saml

    @performance_timer
    def _get_account_friendly_names(
        self, saml_b64: str, profiles: Collection[SamlProfile], force_cache_update: bool = False
    ) -> Dict[str, str]:
        sorted_profiles_by_preference = sorted(profiles, key=self._profile_key_sort_by_preferred_role_factory())
        return self._get_account_friendly_names_from_profiles(
            sorted_profiles_by_preference, saml_b64, force_cache_update
        )

    def _profile_key_sort_by_preferred_role_factory(self) -> Callable[[SamlProfile], str]:
        def _profile_key_sort_by_preferred_role(profile: SamlProfile) -> str:
            is_in_preferred_region = self.region and (profile.region == self.region or profile.region is None)
            preferred_region_key = "0" if is_in_preferred_region else "1"
            return preferred_region_key + _PROFILE_ROLE_SORT_PREFERENCES.get(profile.role.get_name(), "Z")

        return _profile_key_sort_by_preferred_role

    def _get_account_friendly_names_from_profiles(
        self, profiles: Collection[SamlProfile], saml_b64: str, force_cache_update: bool
    ) -> Dict[str, str]:
        account_numbers_to_look_up = set(profile.role.get_account_number() for profile in profiles)

        sts_clients = {
            region: boto3.client("sts", region_name=region, config=build_short_timeout_config())
            for region in {profile.region for profile in profiles}
        }
        friendly_names = {}
        with ThreadPoolExecutor(max_workers=5) as executor:
            results = {
                saml_profile: executor.submit(
                    self._get_friendly_names_with_profile,
                    saml_b64,
                    saml_profile,
                    sts_clients[saml_profile.region],
                    get_identity_context(),
                    force_cache_update,
                )
                for saml_profile in profiles
            }

            for (saml_profile, future_friendly_names) in results.items():
                try:
                    profile_friendly_names = future_friendly_names.result()
                    LOG.debug(f"adding {len(profile_friendly_names)} friendly names")
                    friendly_names.update(profile_friendly_names)
                    account_numbers_to_look_up -= profile_friendly_names.keys()

                    if self.connection_handler.are_all_account_numbers_in_cache(account_numbers_to_look_up):
                        self.connection_handler.write_cache_to_file()
                        return friendly_names
                except ScriptError as e:
                    LOG.info(
                        f'Looking up friendly names with profile "'
                        f'{saml_profile.get_representative_name()}" gave error: "{str(e)}"'
                    )

        futures.wait(results.values())
        self.connection_handler.update_accounts_without_friendly_names_cache(list(account_numbers_to_look_up))
        self.connection_handler.write_cache_to_file()

        return friendly_names

    def _get_friendly_names_with_profile(
        self,
        saml_b64: str,
        profile: SamlProfile,
        sts_client: Any,
        identity_type: Optional[IdentityType],
        force_cache_update: bool,
    ) -> Dict[str, str]:

        return self.connection_handler.get_account_friendly_names(
            profile, saml_b64, sts_client, identity_type, force_cache_update
        )

    def write_all_credentials_to_file(
        self, profile_credentials: List[Tuple[SamlProfile, Credentials]], awsconfigfile: str = ".aws"
    ) -> None:
        home = expanduser("~")
        directory = os.path.join(home, awsconfigfile)
        filename = os.path.join(directory, "credentials")

        if not self.file_handler.path_exists(directory):
            self.file_handler.make_directory(directory)

        # Read in the existing config file
        config = configparser.RawConfigParser()
        self.file_handler.read_config_file(config, filename)

        for (profile, credentials) in profile_credentials:
            profile_name = self.setup.alias or profile.get_representative_name()

            # Put the credentials into a specific profile instead of clobbering the default credentials
            if not config.has_section(profile_name):
                config.add_section(profile_name)

            # config.set('saml', 'output', outputformat)
            config.set(profile_name, "region", credentials.region)
            config.set(profile_name, "aws_access_key_id", credentials.boto_credentials.access_key)
            config.set(profile_name, "aws_secret_access_key", credentials.boto_credentials.secret_key)
            config.set(profile_name, "aws_session_token", credentials.boto_credentials.session_token)
            config.set(profile_name, "valid_until", credentials.expiry_date.strftime(TIMESTAMP_FORMAT))

            # Give the user some info as to what has just happened
            self.console_printer.print_credential_info(
                profile_name, credentials, filename, output_credentials=self.setup.output_credentials
            )

        # Write the updated config file
        self.file_handler.write_config_file(config, filename)

    def write_credentials(self, profile: SamlProfile, credentials: Credentials, awsconfigfile: str = ".aws") -> None:
        self.write_all_credentials_to_file(profile_credentials=[(profile, credentials)], awsconfigfile=awsconfigfile)

    def read_credentials_from_file(
        self,
        profile_name: Optional[str],
        aws_config_folder: str = ".aws",
        min_valid_seconds: int = 900,
    ) -> Optional[Credentials]:
        directory = os.path.join(expanduser("~"), aws_config_folder)
        file = os.path.join(directory, "credentials")

        # Read in the existing config file
        config = configparser.RawConfigParser()
        self.file_handler.read_config_file(config, file)

        if profile_name and config.has_section(profile_name):
            valid_until = datetime.strptime(config.get(profile_name, "valid_until"), TIMESTAMP_FORMAT)
            still_valid = (valid_until - datetime.now()).total_seconds() >= min_valid_seconds
            if still_valid:
                boto_credentials = BotoCredentials(
                    access_key=config.get(profile_name, "aws_access_key_id"),
                    secret_key=config.get(profile_name, "aws_secret_access_key"),
                    session_token=config.get(profile_name, "aws_session_token"),
                )
                return Credentials(
                    boto_credentials=boto_credentials,
                    region=config.get(profile_name, "region"),
                    max_session_duration=timedelta(seconds=-1),
                    time_of_request=datetime.now() - timedelta(seconds=1),
                )
        return None

    def write_all_credentials(self, identity_type: IdentityType) -> None:
        for stage in AuthMethodStage:
            profiles = self._get_profiles(identity_type, stage)
            if profiles:
                LOG.info(f"performing get-all for accounts in {stage.value} stage")
                self.write_all_credentials_for_stage_profiles(identity_type, stage)

    def write_all_credentials_for_stage_profiles(
        self, identity_type: IdentityType, auth_method_stage: AuthMethodStage
    ) -> None:
        urllib3.disable_warnings()

        login_response, updated_identity_type = self.process_login_and_get_saml(auth_method_stage)
        if updated_identity_type:
            identity_type = updated_identity_type
            LOG.debug(f"Switched identity type to {identity_type}")

        saml_b64 = login_response.saml

        show_spinner = LOG.isEnabledFor(logging.WARNING)
        with click_spinner.spinner(disable=not show_spinner):
            active_profiles = self.get_all_active_profiles_for_stage(
                self.get_all_roles(saml_b64), identity_type, auth_method_stage
            )

            sts_clients = {
                region: boto3.client("sts", region_name=region, config=build_boto_default_config())
                for region in {profile.region for profile in active_profiles}
            }

            with ThreadPoolExecutor(max_workers=10) as executor:
                results = {
                    saml_profile: executor.submit(
                        self._get_temp_credentials_with_context,
                        saml_b64,
                        saml_profile,
                        sts_clients[saml_profile.region],
                        identity_type,
                        auth_method_stage,
                    )
                    for saml_profile in active_profiles
                }

            profile_credentials = []
            for (saml_profile, future_credentials) in sorted(results.items(), key=str):
                try:
                    profile_credentials.append((saml_profile, future_credentials.result()))
                except ScriptError as e:
                    self.console_printer.print_console("\n")
                    self.console_printer.print_error(
                        f'Profile "{saml_profile.get_representative_name()}" produced error "{str(e)}"'
                    )

            self.write_all_credentials_to_file(profile_credentials)

    def _get_temp_credentials_with_context(
        self,
        saml_b64: str,
        profile: SamlProfile,
        sts_client: Any = None,
        identity_type: Optional[IdentityType] = None,
        auth_method_stage: Optional[AuthMethodStage] = None,
    ) -> Credentials:
        with identity_context(identity_type):
            return self._get_temp_credentials(
                saml_b64=saml_b64, profile=profile, sts_client=sts_client, auth_method_stage=auth_method_stage
            )

    def _get_temp_credentials(
        self,
        saml_b64: str,
        profile: SamlProfile,
        sts_client: Any = None,
        auth_method_stage: Optional[AuthMethodStage] = None,
    ) -> Credentials:
        try:
            return self.connection_handler.get_temp_credentials(
                saml_b64=saml_b64, profile=profile, sts_client=sts_client
            )
        except AccessDeniedError:
            untagged_saml = self._get_untagged_saml(auth_method_stage)
            return self.connection_handler.get_temp_credentials(
                saml_b64=untagged_saml, profile=profile, sts_client=sts_client
            )

    def perform_two_step_sub_role_login(self, target: str) -> None:
        if self.identity_type is not IdentityTypes.BMW.value:
            raise ScriptError(f"Identity {self.identity_type} is not supported for two-step subrole login")

        user_profile = self.identity_settings(self.identity_type).get_profile_by_name(target)
        if user_profile is None:
            raise ScriptError(f"{target} is no valid profile!")
        acc_id = user_profile.account_id
        role_name = user_profile.role_name
        parent_profile_name = f"{role_name}_{acc_id}"

        if self.target_settings.sub_role:
            sub_role_arn = get_role_arn_from_str(self.target_settings.sub_role, acc_id)
            self.target_settings.sub_role = None
        else:
            sub_role_arn = user_profile.sub_role

        if not isinstance(sub_role_arn, str):
            raise ScriptError("Sub Role is missing")
        else:
            if not self.target_settings.session_length:
                self.target_settings.session_length = user_profile.session_length

            region = user_profile.region or DEFAULT_REGION

            try:
                self.perform_login(parent_profile_name)
            except Exception as e:
                raise ScriptError(f'Could not log into parent role because of "{e}".')
            login_url = (
                f"{get_aws_signin_url(region)}/switchrole?roleName={Role.get_role_name_from_arn(sub_role_arn)}"
                f"&account={Role.get_account_number_from_arn(sub_role_arn)}&displayName={target}"
            )
            self.console_printer.print_login_url(login_url, output_credentials=self.setup.output_credentials)
            time.sleep(2)
            self.open_and_login_into_browser(login_url)

    def perform_login(self, target_raw: Optional[str]) -> None:
        credentials = self.read_credentials_from_file(target_raw)
        if credentials is None:
            LOG.info(f"Need to fetch new credentials for {target_raw}")
            credentials = self.get_and_write_credentials()

        login_url = self.get_federation_url(credentials)
        self.console_printer.print_login_url(login_url, output_credentials=self.setup.output_credentials)
        self.open_and_login_into_browser(login_url)

    def open_and_login_into_browser(self, login_url: str) -> None:
        target_raw = self.setup.target_raw
        self.browser_handler.open_new_with_profile(login_url, target_raw)

    def get_federation_url(self, credentials: Credentials) -> str:
        request_parameters = "?Action=getSigninToken"
        request_parameters += "&Session=" + parse.quote_plus(
            json.dumps(
                {
                    "sessionId": credentials.boto_credentials.access_key,
                    "sessionKey": credentials.boto_credentials.secret_key,
                    "sessionToken": credentials.boto_credentials.session_token,
                }
            )
        )
        # Retrieve the signin token from the federation endpoint
        federation_response = self.connection_handler.federation_url_requests_get(
            request_parameters + "&SessionDuration=43200", credentials.region
        )
        if (
            not federation_response.ok
            # China returns 200 with special text in case of errors
            or "Please clear your cookies and try the request again." in federation_response.text
        ):
            # retry without session duration
            federation_response = self.connection_handler.federation_url_requests_get(
                request_parameters, credentials.region
            )
            if not federation_response.ok:
                raise ScriptError("Federation Login URL for this role is unavailable")
        federation_response_text = federation_response.text
        signin_token = json.loads(federation_response_text)
        # Create URL where users can use the sign-in token to sign in to.
        console = (
            f"https://{credentials.region}.console.amazonaws.cn/"
            if credentials.region in CHINA_REGIONS
            else f"https://{credentials.region}.console.aws.amazon.com/"
        )
        request_parameters = "?Action=login"
        request_parameters += "&Issuer=manage.data.bmw.cloud"
        request_parameters += "&Destination=" + parse.quote_plus(console)
        request_parameters += "&SigninToken=" + signin_token["SigninToken"]
        login_url = get_aws_federation_url(credentials.region) + request_parameters
        return login_url

    def print_federation_url(self, credentials: Credentials, output_credentials: bool) -> None:
        try:
            login_url = self.get_federation_url(credentials)
        except Exception as e:
            self.console_printer.print_info(f"Could not print federation url because of {e}.")
            return
        self.console_printer.print_login_url(login_url, output_credentials=output_credentials)

    def get_account_display(self, account_friendly_names: Dict[str, str]) -> Callable[[str], str]:
        def account_display(account_id: str) -> str:
            if account_friendly_names.get(account_id):
                return f"{account_id} {account_friendly_names[account_id]}"
            else:
                return f"{account_id}"

        return account_display

    def list_profiles_for_identity(self, identity_type: IdentityType, force_cache_update: bool) -> None:
        printer = self.console_printer
        printer.print_console("------------")

        login_response, updated_identity_type = self.process_login_and_get_saml(None, disable_mail_tagging=True)
        if updated_identity_type:
            identity_type = updated_identity_type
        printer.print_console(f"Using {identity_type.code.value.upper()} identity")

        saml_b64 = login_response.saml

        profiles = self.extract_non_guest_profiles(identity_type, login_response.roles)

        excluded_targets = [
            SignInTarget(account_id=None, role_name=None, name=excluded_profile.name, identity_type=identity_type)
            for excluded_profile in self.identity_settings(identity_type).get_excluded_profiles()
        ]

        profiles_for_friendly_names = [
            profile
            for profile in profiles
            if not any([profile.matches(excluded_target, identity_type) for excluded_target in excluded_targets])
        ]

        printer.print_console("------------")
        friendly_names = self._get_account_friendly_names(saml_b64, profiles_for_friendly_names, force_cache_update)
        account_display = self.get_account_display(friendly_names)
        headers = ["Name", "Account", "Alias"]
        table = [
            [
                profile.role.get_name(),
                account_display(profile.role.get_account_number()),
                profile.get_representative_name(),
            ]
            for profile in profiles
        ]
        printer.print_console_with_identity("The following roles are available:")

        printer.print_console(tabulate(table, headers=headers))

    def get_non_guest_profiles(self) -> List[SamlProfile]:
        login_response, updated_identity_type = self.process_login_and_get_saml(None)
        identity_type = updated_identity_type or self.identity_type

        profiles = self.extract_non_guest_profiles(identity_type, login_response.roles)

        return profiles

    def _get_login_handler_for_stage_regarding_setup(
        self, auth_method_stage: Optional[AuthMethodStage]
    ) -> LoginHandlerCdh:
        if self.setup.auth_method_stage:
            return self.login_handler_per_stage[AuthMethodStage[self.setup.auth_method_stage.upper()]]
        else:
            return self.login_handler_per_stage[auth_method_stage]

    def extract_non_guest_profiles(self, identity_type: IdentityType, roles: List[Role]) -> List[SamlProfile]:
        return [self.build_saml_profile(role, identity_type) for role in roles if not role.guest_role]

    def _get_profiles(self, identity_type: IdentityType, stage: AuthMethodStage) -> List[UserConfigProfile]:
        if identity_type.code == IdentityCode.IMPLICIT_CDH_AUTH:
            return list(
                chain.from_iterable(
                    self.identity_settings(regular_identity_type).get_aws_profiles_for_stage(stage)
                    for regular_identity_type in REGULAR_IDENTITY_TYPES
                )
            )
        else:
            return self.identity_settings(identity_type).get_aws_profiles_for_stage(stage)

    def get_api_token(self) -> None:
        login_handler = self._get_login_handler_for_stage_regarding_setup(None)
        jwt_response = login_handler.get_jwt(JwtType.API)
        self.console_printer.print_console(f"{jwt_response.jwt_name}={jwt_response.jwt_value}")


def prepare_environment_variables() -> None:
    # The point of this script is to acquire credentials via SAML, so it does not make sense to use pre-existing AWS
    # credentials. Even worse, if pre-existing credentials are broken, this might crash the script (see CDHX-1512).
    for variable in ["AWS_DEFAULT_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]:
        os.environ.pop(variable, "")

    # Prevent boto from reading credentials from ~/.aws/credentials
    os.environ["AWS_SHARED_CREDENTIALS_FILE"] = ""


_PROFILE_ROLE_SORT_PREFERENCES = {"CDHX-DevOps": "A", "CDHDevOps": "B", "CDHDataEngineer": "C"}
