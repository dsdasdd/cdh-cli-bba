from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

from ruamel.yaml import YAML
from ruamel.yaml import YAMLError

from .constants_for_migration import DEFAULT_LOGLEVEL
from .constants_for_migration import DEFAULT_REGION
from .constants_for_migration import IdentityCode
from .constants_for_migration import IdentityTypes
from .exceptions_for_migration import ConfigError
from .exceptions_for_migration import ScriptError

ACCOUNT_NUMBER_LEN = 12

LOG = logging.getLogger(__name__)
yaml = YAML(typ="safe", pure=True)
yaml.version = (1, 1)  # type:ignore


def get_role_arn_from_str(input_str: Optional[str], acc_id: str) -> Optional[str]:
    if input_str is None:
        return None
    if input_str.startswith("arn:aws:iam::"):
        return input_str
    if input_str.startswith("arn:aws-cn:iam::"):
        return input_str
    return f"arn:aws:iam::{acc_id}:role/{input_str}"


class ConfigVersion(Enum):
    v1 = "v1"
    v2 = "v2"
    undefined = "undefined"


@dataclass
class UserConfigProfile:
    account_id: str
    role_name: str
    name: str
    region: str
    sub_role: Optional[str]
    session_length: Optional[int]

    @classmethod
    def get_from_data(cls, acc_number: str, role_name: str, default_region: str, data: Any) -> UserConfigProfile:
        if isinstance(data, str):
            return UserConfigProfile(acc_number, role_name, data, default_region, None, None)
        elif isinstance(data, dict):
            return UserConfigProfile(
                acc_number,
                role_name,
                data["name"],
                data.get("region", default_region),
                get_role_arn_from_str(data.get("subrole"), acc_number),
                data.get("session_length"),
            )
        elif isinstance(data, list):
            raise Exception(f"A list is not allowed at the position [{acc_number}][{role_name}]")
        return UserConfigProfile(acc_number, role_name, str(data), default_region, None, None)

    @classmethod
    def get_from_data_v2(
        cls,
        profile_name: str,
        account_id: str,
        role_name: str,
        region: str,
        subrole_spec: Optional[str],
        session_length: Optional[int],
    ) -> UserConfigProfile:
        return UserConfigProfile(
            account_id=account_id,
            role_name=role_name,
            name=profile_name,
            region=region,
            sub_role=get_role_arn_from_str(subrole_spec, account_id),
            session_length=session_length,
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

    @classmethod
    def build_empty(cls) -> IdentitySpecificSettings:
        return IdentitySpecificSettings(region=None, aws_profiles=[])

    def to_dict_v2(self) -> Dict[str, Any]:
        dict_v2: Dict[str, Any] = {}
        if self.region:
            dict_v2["region"] = self.region
        if self.disable_by_default:
            dict_v2["disable-by-default"] = self.disable_by_default
        dict_v2["aws-profiles"] = {}
        for profile in self.aws_profiles:
            profile_dict = {
                "account": str(profile.account_id),
                "role": profile.role_name,
                "region": profile.region,
                "subrole": profile.sub_role,
                "session_length": profile.session_length,
            }
            dict_v2["aws-profiles"][profile.name] = {key: value for key, value in profile_dict.items() if value}

        return dict_v2


KNOWN_PROFILE_ATTRIBUTES = ["account", "role", "region", "subrole", "session_length"]


class CdhConfig:
    def __init__(self, yaml_config: dict):
        self.version: ConfigVersion = ConfigVersion.undefined
        self.identity_settings: Dict[IdentityCode, IdentitySpecificSettings] = self._parse_identity_config(yaml_config)
        self.use_firefox_containers: bool = yaml_config.get("use-firefox-containers", False)
        self.use_chrome_multiple_windows: bool = yaml_config.get("use-chrome-multiple-windows", False)
        self.use_chrome_multiple_windows_default: Optional[str] = yaml_config.get("use-chrome-multiple-windows-default")
        self.set_browser: Optional[str] = yaml_config.get("set-browser")
        self.use_keyring: bool = yaml_config.get("use-keyring", True)
        self.loglvl: str = yaml_config.get("loglvl", DEFAULT_LOGLEVEL)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, CdhConfig):
            if self.bmw_identity_settings != other.bmw_identity_settings:
                return False
            if self.bba_identity_settings != other.bba_identity_settings:
                return False
            if self.use_firefox_containers != other.use_firefox_containers:
                return False
            if self.use_chrome_multiple_windows != other.use_chrome_multiple_windows:
                return False
            if self.use_chrome_multiple_windows_default != other.use_chrome_multiple_windows_default:
                return False
            if self.set_browser != other.set_browser:
                return False
            if self.use_keyring != other.use_keyring:
                return False
            if self.loglvl != other.loglvl:
                return False
            return True
        return False

    def _parse_identity_config(self, yaml_config: dict) -> Dict[IdentityCode, IdentitySpecificSettings]:
        identity_configs_v2 = self._parse_identity_config_v2(yaml_config)
        if identity_configs_v2:
            self.version = ConfigVersion.v2
        bmw_identity_config_v1 = self._parse_identity_config_v1(yaml_config)
        if bmw_identity_config_v1:
            self.version = ConfigVersion.v1
        bmw_identity_config_v2 = identity_configs_v2.get(IdentityCode.BMW) or IdentitySpecificSettings.build_empty()

        if bmw_identity_config_v2 and bmw_identity_config_v1:
            bmw_key = IdentityCode.BMW.value
            raise ConfigError(
                f"Both identities.{bmw_key}.* and top-level attributes for bmw identity are set.\n"
                f"Please move all of the following attributes under identities.{bmw_key}.*:\n"
                f"- qnumber\n"
                f"- pintype\n"
                f"- region\n"
                f"- aws-profiles\n"
            )

        identity_configs_v2[IdentityCode.BMW] = bmw_identity_config_v2 or bmw_identity_config_v1

        self._validate_no_duplicate_profile_names(identity_configs_v2)
        return identity_configs_v2

    def _parse_identity_config_v1(self, yaml_config: dict) -> IdentitySpecificSettings:
        region = yaml_config.get("region")
        profiles = self.load_profiles_v1(yaml_config.get("aws-profiles", {}), region or DEFAULT_REGION)
        return IdentitySpecificSettings(region=region, aws_profiles=profiles)

    def _parse_identity_config_v2(self, yaml_config: dict) -> Dict[IdentityCode, IdentitySpecificSettings]:
        config = {}
        identities_section = yaml_config.get("identities")
        if identities_section and type(identities_section) == dict:
            for key, section in identities_section.items():
                if section and type(section) == dict:
                    try:
                        identity_type = IdentityTypes.of(key)
                        username_alt_key = identity_type.username_alternative_name
                        config[identity_type.code] = self._parse_identity_config_v2_section(
                            section, f"identities.{key}", username_alt_key
                        )
                    except ValueError:
                        LOG.warning(
                            f"Configuration under section identities.{key} was not recognized "
                            f"as any known identity type, possibly a typo?"
                        )
                else:
                    raise ConfigError(f"Invalid config structure under identities.{key}")
        return config

    def _parse_identity_config_v2_section(
        self, identities_section: dict, config_path: str, username_alternative_key: Optional[str]
    ) -> IdentitySpecificSettings:
        region = identities_section.get("region")
        profiles = self.load_profiles_v2(
            identities_section.get("aws-profiles", {}), region or DEFAULT_REGION, f"{config_path}.aws-profiles"
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
    def create_from_yaml(cls, file: str) -> CdhConfig:
        with open(file, "r") as stream:
            try:
                spec = yaml.load(stream)
            except YAMLError as exc:
                LOG.error(f"Invalid YAML file {file}")
                raise ConfigError(f"Error in user configuration file: {str(exc)}")

        if not spec:
            return CdhConfig({})

        if type(spec) != dict:
            raise ConfigError("Invalid content in user configuration file")
        return CdhConfig(spec)

    @classmethod
    def load_profiles_v1(cls, profiles: Dict[str, Dict[str, Any]], default_region: str) -> List[UserConfigProfile]:
        result = []
        for account_id, account_dict in profiles.items():
            acc_number = cls._get_account_as_padded_str_with_ambiguity_check(account_id)
            for role_name, role_profiles in account_dict.items():
                try:
                    # changes all profile dicts to a UserConfigProfile object
                    if isinstance(role_profiles, list):
                        for profile in role_profiles:
                            result.append(
                                UserConfigProfile.get_from_data(acc_number, role_name, default_region, profile)
                            )
                    else:
                        result.append(
                            UserConfigProfile.get_from_data(acc_number, role_name, default_region, role_profiles)
                        )
                except KeyError:
                    raise ScriptError(f'The role "{role_name}" in account "{acc_number}" has no name specified.')
                except TypeError:
                    raise ScriptError("Something went wrong during parsing of aws-account config.")
        cls.validate_profiles_v1(result)
        return result

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
            subrole_spec = profile_data.get("subrole")
            session_length = profile_data.get("session_length")
            result.append(
                UserConfigProfile.get_from_data_v2(
                    profile_name=profile_name,
                    account_id=account_id,
                    role_name=role_name,
                    region=region,
                    subrole_spec=subrole_spec,
                    session_length=session_length,
                )
            )

        return result

    @classmethod
    def _log_unknown_attributes(cls, profile_name: str, profile_data: dict, config_path: str) -> None:
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
        cls, profile_name: str, profile_data: dict, config_path: str
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
    def validate_profiles_v1(cls, profiles: List[UserConfigProfile]) -> None:
        friendly_role_names = []
        for profile in profiles:
            friendly_role_names.append(profile.name)
        if len(friendly_role_names) != len(set(friendly_role_names)):
            duplicated_names = set([name for name in friendly_role_names if friendly_role_names.count(name) > 1])
            raise ScriptError(f"INVALID CONFIG FILE: Following friendly role names are not unique: {duplicated_names}.")

    @classmethod
    def _validate_no_duplicate_profile_names(cls, config_v2: Dict[IdentityCode, IdentitySpecificSettings]) -> None:
        all_profile_names = [profile.name for config in config_v2.values() for profile in config.aws_profiles]

        for profile_name in all_profile_names:
            if all_profile_names.count(profile_name) > 1:
                raise ConfigError(
                    f'Profile name "{profile_name}" is used multiple times. '
                    f"Please note that profile names need to be globally unique."
                )
