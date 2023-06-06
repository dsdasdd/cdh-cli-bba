from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from os.path import expanduser
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

import boto3
from ruamel.yaml import YAML
from ruamel.yaml import YAMLError

from cdh_utils.constants import AuthMethodStage
from cdh_utils.constants import BROWSER_OPEN_BEHAVIOURS
from cdh_utils.constants import BrowserOpenBehaviour
from cdh_utils.constants import DEFAULT_AUTH_METHOD_STAGE
from cdh_utils.constants import DEFAULT_BROWSER_OPEN_BEHAVIOUR
from cdh_utils.constants import DEFAULT_LOGLEVEL
from cdh_utils.constants import DEFAULT_REGION
from cdh_utils.constants import IdentityCode
from cdh_utils.constants import IdentityType
from cdh_utils.constants import IdentityTypes
from cdh_utils.saml.identities import SamlProfile
from cdh_utils.utils.exceptions import ConfigError
from migrate_config import migrate_config

ACCOUNT_NUMBER_LEN = 12

LOG = logging.getLogger(__name__)
_yaml = YAML(pure=True)
_yaml.version = (1, 1)  # type:ignore


class ConfigVersion(Enum):
    v1 = "v1"
    v2 = "v2"
    undefined = "undefined"


CURRENT_CONFIG_VERSION = ConfigVersion.v2


def get_role_arn_from_str(input_str: Optional[str], acc_id: str) -> Optional[str]:
    if input_str is None:
        return None
    if input_str.startswith("arn:aws:iam::"):
        return input_str
    if input_str.startswith("arn:aws-cn:iam::"):
        return input_str
    return f"arn:aws:iam::{acc_id}:role/{input_str}"


@dataclass
class UserConfigProfile:
    account_id: str
    role_name: str
    name: str
    region: str
    sub_role: Optional[str]
    session_length: Optional[int]
    exclude_from_get_all: bool
    auth_method_stage: AuthMethodStage = DEFAULT_AUTH_METHOD_STAGE

    def is_fitting_profile(self, acc_id: str, role_name: str, name: str = "") -> bool:
        return self.account_id == acc_id and self.role_name == role_name and name in ("", self.name)

    def get_arn(self) -> str:
        return f"arn:aws:iam::{self.account_id}:role/{self.role_name}"

    @classmethod
    def get_from_data(cls, acc_number: str, role_name: str, default_region: str, data: Any) -> UserConfigProfile:
        if isinstance(data, str):
            return UserConfigProfile(
                account_id=acc_number,
                role_name=role_name,
                name=data,
                region=default_region,
                sub_role=None,
                session_length=None,
                exclude_from_get_all=False,
            )
        elif isinstance(data, dict):
            return UserConfigProfile(
                account_id=acc_number,
                role_name=role_name,
                name=data["name"],
                region=data.get("region", default_region),
                sub_role=get_role_arn_from_str(data.get("subrole"), acc_number),
                session_length=data.get("session_length"),
                exclude_from_get_all=False,
            )
        elif isinstance(data, list):
            raise Exception(f"A list is not allowed at the position [{acc_number}][{role_name}]")
        return UserConfigProfile(
            account_id=acc_number,
            role_name=role_name,
            name=str(data),
            region=default_region,
            sub_role=None,
            session_length=None,
            exclude_from_get_all=False,
        )

    @classmethod
    def get_from_data_v2(
        cls,
        profile_name: str,
        account_id: str,
        role_name: str,
        region: str,
        subrole_spec: Optional[str],
        session_length: Optional[int],
        exclude_from_get_all: bool,
        auth_method_stage: AuthMethodStage,
    ) -> UserConfigProfile:
        return UserConfigProfile(
            account_id=account_id,
            role_name=role_name,
            name=profile_name,
            region=region,
            sub_role=get_role_arn_from_str(subrole_spec, account_id),
            session_length=session_length,
            exclude_from_get_all=exclude_from_get_all,
            auth_method_stage=auth_method_stage,
        )


@dataclass
class IdentitySpecificSettings:
    region: Optional[str]
    aws_profiles: List[UserConfigProfile]
    disable_by_default: bool

    def __init__(
        self,
        region: Optional[str] = None,
        aws_profiles: Optional[List[UserConfigProfile]] = None,
        disable_by_default: bool = False,
    ):

        self.region = region
        self.aws_profiles = aws_profiles or []
        self.disable_by_default = disable_by_default

    def __bool__(self) -> bool:
        return bool(self.region or self.aws_profiles or self.disable_by_default)

    def get_fitting_profile(self, account_id: str, role_name: str, name: str = "") -> Optional[UserConfigProfile]:
        return next(
            (profile for profile in self.aws_profiles if profile.is_fitting_profile(account_id, role_name, name)), None
        )

    def get_profile_by_name(self, name: str) -> Optional[UserConfigProfile]:
        return next((profile for profile in self.aws_profiles if profile.name == name), None)

    def get_aws_profiles_for_stage(self, stage: AuthMethodStage) -> List[UserConfigProfile]:
        return [
            profile
            for profile in self.aws_profiles
            if profile.auth_method_stage == stage and not profile.exclude_from_get_all
        ]

    def get_excluded_profiles(self) -> List[UserConfigProfile]:
        return [profile for profile in self.aws_profiles if profile.exclude_from_get_all]

    @classmethod
    def build_empty(cls) -> IdentitySpecificSettings:
        return IdentitySpecificSettings(region=None, aws_profiles=[])

    def combined_settings(self, overrides: IdentitySpecificSettings) -> IdentitySpecificSettings:
        """ "
        Returns combined settings of self and overrides, where values from overrides take precedence.
        aws_profiles will be taken as a whole from either, entries will *not* be merged.
        """
        return IdentitySpecificSettings(
            region=overrides.region or self.region,
            aws_profiles=overrides.aws_profiles or self.aws_profiles,
        )


KNOWN_PROFILE_ATTRIBUTES = [
    "account",
    "role",
    "region",
    "subrole",
    "session_length",
    "exclude-from-get-all",
    "auth-method-stage",
]


def _get_browser_open_behaviour(browser_open_behaviour: Optional[str]) -> BrowserOpenBehaviour:
    if not browser_open_behaviour:
        LOG.warning(f"Defaulting to '{DEFAULT_BROWSER_OPEN_BEHAVIOUR}'")
        lower_browser_open_behaviour = DEFAULT_BROWSER_OPEN_BEHAVIOUR
    else:
        lower_browser_open_behaviour = browser_open_behaviour.lower()
        if lower_browser_open_behaviour not in BROWSER_OPEN_BEHAVIOURS:
            LOG.warning(
                f"unknown browser-open-behaviour '{lower_browser_open_behaviour}' defined in config.yaml, "
                f"defaulting to '{DEFAULT_BROWSER_OPEN_BEHAVIOUR}'"
            )
            lower_browser_open_behaviour = DEFAULT_BROWSER_OPEN_BEHAVIOUR
    return BrowserOpenBehaviour(lower_browser_open_behaviour)


class CdhConfig:
    def __init__(self, ignore_config: bool, ignore_keyring: bool):

        self.version, yaml_config = (CURRENT_CONFIG_VERSION, {}) if ignore_config else self.get_version_yaml_dict()
        self.identity_settings: Dict[IdentityCode, IdentitySpecificSettings] = self._parse_identity_config(yaml_config)

        self.use_firefox_containers: bool = yaml_config.get("use-firefox-containers", False)
        self.use_chrome_multiple_windows: bool = yaml_config.get("use-chrome-multiple-windows", False)
        self.use_chrome_multiple_windows_default: Optional[str] = yaml_config.get(
            "use-chrome-multiple-windows-default",
        )
        self.set_browser: Optional[str] = yaml_config.get("set-browser")
        self.use_keyring: bool = False if ignore_keyring else yaml_config.get("use-keyring", True)
        self.loglvl: str = yaml_config.get("loglvl", DEFAULT_LOGLEVEL)
        self.browser_open_behaviour: BrowserOpenBehaviour = _get_browser_open_behaviour(
            yaml_config.get("browser-open-behaviour", DEFAULT_BROWSER_OPEN_BEHAVIOUR)
        )
        self._check_browser_setting()
        self.sanity_check: bool = yaml_config.get("sanity-check", True)

    @staticmethod
    def get_config_path() -> str:
        home = expanduser("~")
        return os.path.join(home, ".config", "cdh", "config.yml")

    def _parse_identity_config(self, yaml_config: Dict) -> Dict[IdentityCode, IdentitySpecificSettings]:
        identity_configs = self._parse_identity_config_v2(yaml_config)
        bmw_identity_config = identity_configs.get(IdentityCode.BMW) or IdentitySpecificSettings.build_empty()

        identity_configs[IdentityCode.BMW] = bmw_identity_config

        self._validate_no_duplicate_profile_names(identity_configs)
        return identity_configs

    def get_version_yaml_dict(self) -> Tuple[ConfigVersion, Dict]:
        config_file = self.get_config_path()
        if os.path.isfile(config_file):
            yaml_config = self.get_yaml_config(config_file)
            if not yaml_config:
                version: ConfigVersion = CURRENT_CONFIG_VERSION
                yaml_config = {}
            else:
                version = ConfigVersion(yaml_config.get("version", ConfigVersion.undefined.value))
                if version != CURRENT_CONFIG_VERSION:
                    LOG.error(
                        "This version of cdh cli only supports config version v2,"
                        + " attempting to migrate your config..."
                    )
                    migrate_config.main()
                    LOG.warning(
                        "Please retry your last command. If you see this message again please contact the CDH Team."
                    )
                    # This is the happy case. No Exception during migration
                    exit(1)  # exit 1 is still necessary because the original call to cdh can not easily be recovered
        else:
            LOG.info('Could not find a config file. You can create and open config file by using "cdh open_config".')
            version = CURRENT_CONFIG_VERSION
            yaml_config = {}
        return (version, yaml_config)

    @staticmethod
    def create_config_file(profiles_with_identities: Dict[IdentityType, List[SamlProfile]]) -> None:
        identities_dict = {}
        for identity, profiles in profiles_with_identities.items():
            aws_profiles_dict = {}

            for profile in profiles:
                profile_data = {"account": profile.role.get_account_number(), "role": profile.role.get_name()}
                if profile.region:
                    profile_data.update({"region": profile.region})

                aws_profiles_dict.update({profile.get_representative_name(): profile_data})

            identities_dict.update({identity.code.value: {"aws-profiles": aws_profiles_dict}})

        yaml_config = {"version": "v2", "identities": identities_dict}

        with open(CdhConfig.get_config_path(), "w") as yaml_config_file:
            _yaml.dump(yaml_config, yaml_config_file)

    def comment_out_bad_profiles_for_identity(
        self, identity_type: IdentityType, bad_config_profiles: List[UserConfigProfile]
    ) -> None:
        with open(CdhConfig.get_config_path()) as yaml_file:
            yaml_str = yaml_file.read()

        yaml_data = _yaml.load(yaml_str)
        yaml_lines = yaml_str.split("\n")

        processed_data = self._comment_bad_profiles_in_config(bad_config_profiles, yaml_data, identity_type, yaml_lines)

        with open(CdhConfig.get_config_path(), "w") as yaml_file:
            yaml_file.write(processed_data)

    def _comment_bad_profiles_in_config(
        self,
        bad_config_profiles: List[UserConfigProfile],
        yaml_data: Dict,
        identity_type: IdentityType,
        yaml_lines: List[str],
    ) -> str:
        for bad_config_profile in bad_config_profiles:
            start_line = (
                yaml_data["identities"][identity_type.code.value]["aws-profiles"][bad_config_profile.name].lc.line - 1
            )
            start_indentation = len(yaml_lines[start_line]) - len(yaml_lines[start_line].lstrip())

            yaml_lines[start_line] = "#" + yaml_lines[start_line]

            for i, yaml_line in enumerate(yaml_lines):
                if i < start_line + 1:
                    continue
                current_indentation = len(yaml_line) - len(yaml_line.lstrip())
                if current_indentation <= start_indentation:
                    break
                yaml_lines[i] = "#" + yaml_line
        identity_profiles_in_config = yaml_data["identities"][identity_type.code.value]["aws-profiles"]
        if len(bad_config_profiles) == len(identity_profiles_in_config):
            header_index = identity_profiles_in_config.lc.line - 1
            yaml_lines[header_index] = "#" + yaml_lines[header_index]
        processed_data = "\n".join(yaml_lines)
        return processed_data

    def _check_browser_setting(self) -> None:
        if not self.set_browser and self.use_chrome_multiple_windows:
            raise ConfigError(
                'The flag "use-chrome-multiple-windows" requires "set-browser" (full path to executable) to be set.'
            )

    def _parse_identity_config_v2(self, yaml_config: Dict) -> Dict[IdentityCode, IdentitySpecificSettings]:
        config = {}
        identities_section = yaml_config.get("identities")
        if identities_section and type(identities_section) == dict:
            for key, section in identities_section.items():
                if section and type(section) == dict:
                    try:
                        identity_type = IdentityTypes.of(key)
                        config[identity_type.code] = self._parse_identity_config_v2_section(
                            section, f"identities.{key}"
                        )
                    except ValueError:
                        LOG.warning(
                            f"Configuration under section identities.{key} was not recognized "
                            f"as any known identity type, possibly a typo?"
                        )
                else:
                    raise ConfigError(f"Invalid config structure under identities.{key}")
        return config

    @staticmethod
    def _get_identity_type(code: str) -> Optional[IdentityType]:
        try:
            return IdentityTypes.of(code)
        except ValueError:
            return None

    def _parse_identity_config_v2_section(self, identities_section: Dict, config_path: str) -> IdentitySpecificSettings:
        region = identities_section.get("region")

        profile_region = region or DEFAULT_REGION
        self._check_region(profile_region)

        profiles = self.load_profiles_v2(
            identities_section.get("aws-profiles", {}), profile_region, f"{config_path}.aws-profiles"
        )
        disable_by_default = identities_section.get("disable-by-default", False)
        return IdentitySpecificSettings(
            region=region,
            aws_profiles=profiles,
            disable_by_default=disable_by_default,
        )

    @property
    def bmw_identity_settings(self) -> IdentitySpecificSettings:
        """convenience accessor for bmw identity settings, will return empty dummy settings if
        no bmw settings are set"""
        return self.identity_settings.get(IdentityCode.BMW, IdentitySpecificSettings.build_empty())

    @property
    def bba_identity_settings(self) -> IdentitySpecificSettings:
        """convenience accessor for bba identity settings, will return empty dummy settings if
        no bba settings are set"""
        return self.identity_settings.get(IdentityCode.BBA, IdentitySpecificSettings.build_empty())

    @classmethod
    def get_yaml_config(cls, file: str) -> Dict:
        with open(file, "r") as stream:
            try:
                yaml = YAML(typ="safe", pure=True)
                yaml.version = (1, 1)  # type:ignore
                spec = yaml.load(stream)
            except YAMLError as exc:
                LOG.error(f"Invalid YAML file {file}")
                raise ConfigError(f"Error in user configuration file: {str(exc)}")
        if type(spec) != dict:
            raise ConfigError("Invalid content in user configuration file")
        return spec

    @classmethod
    def load_profiles_v2(
        cls, profiles_v2: Dict[str, Dict[str, Any]], default_region: str, config_path: str
    ) -> List[UserConfigProfile]:
        result = []
        for profile_name, profile_data in profiles_v2.items():
            cls._check_profile_name_nonempty(profile_name, config_path)
            cls._check_profile_is_dict(profile_name, profile_data, config_path)
            cls._log_unknown_attributes(profile_name, profile_data, config_path)

            account_id, role_name = cls._extract_account_id_and_role_name(profile_name, profile_data, config_path)
            region = profile_data.get("region", default_region)
            cls._check_region(region)
            subrole_spec = profile_data.get("subrole")
            session_length = profile_data.get("session_length")
            exclude_from_get_all = profile_data.get("exclude-from-get-all", False)
            auth_method_stage = profile_data.get("auth-method-stage")
            if auth_method_stage:
                auth_method_stage = AuthMethodStage[auth_method_stage.upper()]
            else:
                auth_method_stage = DEFAULT_AUTH_METHOD_STAGE

            result.append(
                UserConfigProfile.get_from_data_v2(
                    profile_name=profile_name,
                    account_id=account_id,
                    role_name=role_name,
                    region=region,
                    subrole_spec=subrole_spec,
                    session_length=session_length,
                    exclude_from_get_all=exclude_from_get_all,
                    auth_method_stage=auth_method_stage,
                )
            )

        return result

    @classmethod
    def _log_unknown_attributes(cls, profile_name: str, profile_data: Dict, config_path: str) -> None:
        for attribute in [
            profile_attribute
            for profile_attribute in profile_data.keys()
            if profile_attribute not in KNOWN_PROFILE_ATTRIBUTES
        ]:
            LOG.warning(
                f"Config: Unknown attribute '{attribute}' will be ignored " f"(defined in {config_path}.{profile_name})"
            )

    @classmethod
    def _check_profile_is_dict(cls, profile_name: str, profile_data: Any, config_path: str) -> None:
        if type(profile_data) != dict:
            raise ConfigError(
                f"Error parsing profile: Invalid type for {config_path}.{profile_name} "
                f"(expecting dict, got {type(profile_data)})"
            )

    @classmethod
    def _extract_account_id_and_role_name(
        cls, profile_name: str, profile_data: Dict, config_path: str
    ) -> Tuple[Any, Any]:
        try:
            account_id_raw = profile_data["account"]
            role_name = profile_data["role"]
        except KeyError as e:
            raise ConfigError(f"Error parsing profile: {e} missing in {config_path}.{profile_name}")
        return cls._get_account_as_padded_str_with_ambiguity_check(account_id_raw), role_name

    @classmethod
    def _get_account_as_padded_str_with_ambiguity_check(cls, account_id_raw: Any) -> str:
        if cls._ambiguous_as_octal(account_id_raw):
            octal = f"{int(account_id_raw):o}"
            padded = str(account_id_raw).rjust(ACCOUNT_NUMBER_LEN, "0")
            octal_padded = octal.rjust(ACCOUNT_NUMBER_LEN, "0")
            raise ConfigError(
                f"Parsed account number {account_id_raw} is too short, could be coming from either "
                f"{padded} (in decimal) or {octal_padded} (in octal). Please quote account numbers "
                f"with leading zeroes using double quotes '\"' to ensure correct interpretation."
            )
        return str(account_id_raw).rjust(ACCOUNT_NUMBER_LEN, "0")

    @classmethod
    def _check_profile_name_nonempty(cls, profile_name: str, config_path: str) -> None:
        if not profile_name:
            raise ConfigError(f"Error parsing profile: empty profile name is not allowed in {config_path}")

    @classmethod
    def _ambiguous_as_octal(cls, account_id: Any) -> bool:
        if type(account_id) == int:
            octal = f"{int(account_id):o}"
            return len(str(account_id)) < ACCOUNT_NUMBER_LEN and len(octal) < ACCOUNT_NUMBER_LEN
        else:
            return False

    @classmethod
    def _validate_no_duplicate_profile_names(cls, config_v2: Dict[IdentityCode, IdentitySpecificSettings]) -> None:
        all_profile_names = [profile.name for config in config_v2.values() for profile in config.aws_profiles]

        for profile_name in all_profile_names:
            if all_profile_names.count(profile_name) > 1:
                raise ConfigError(
                    f'Profile name "{profile_name}" is used multiple times. '
                    f"Please note that profile names need to be globally unique."
                )

    @classmethod
    @lru_cache()
    def _get_regions(cls) -> List[str]:
        session = boto3.Session()
        partitions = session.get_available_partitions()
        return [region for part in partitions for region in session.get_available_regions("s3", partition_name=part)]

    @classmethod
    def _check_region(cls, region: str) -> None:
        if region not in cls._get_regions():
            raise ConfigError(f"unknown region: {region}")
