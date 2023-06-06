import copy
from logging import WARNING
from pathlib import Path
from typing import Any
from typing import Dict
from typing import Tuple
from unittest.mock import patch

import pytest
from ruamel.yaml import YAML
from ruamel.yaml import YAMLError

from cdh_utils.constants import DEFAULT_AUTH_METHOD_STAGE
from cdh_utils.constants import DEFAULT_CHINA_REGION
from cdh_utils.constants import IdentityTypes
from cdh_utils.saml.identities import Role
from cdh_utils.saml.identities import SamlProfileWithName
from cdh_utils.utils.cdh_manager import CdhManager
from cdh_utils.utils.cdhconfig import CdhConfig
from cdh_utils.utils.cdhconfig import ConfigVersion
from cdh_utils.utils.cdhconfig import UserConfigProfile
from cdh_utils.utils.exceptions import ConfigError
from cdh_utils.utils.setup import Setup

yaml = YAML(typ="safe", pure=True)
yaml.version = (1, 1)  # type:ignore

role_arn1 = "arn:aws:iam::555555555555:role/CDHX-DevOps"
role_arn2 = "arn:aws:iam::020202020202:role/CDHX-DevOps"

basic_config_dict_bmw_only_v2: Dict[str, Any] = {
    "version": "v2",
    "identities": {
        "bmw": {
            "username": "q494729",
            "pintype": "yk",
            "region": "eu-central-1",
            "aws-profiles": {
                "cdh-dev": {
                    "account": "555555555555",
                    "role": "CDHX-DevOps",
                },
                "cdh-tooling": {
                    "account": "020202020202",
                    "role": "CDHX-DevOps",
                    "region": "us-east-1",
                },
                "cdh-tooling-default": {
                    "account": "020202020202",
                    "role": "CDHX-DevOps",
                    "region": "us-east-1",
                },
                "cdh-tooling-us": {"account": "121212121212", "role": "CDHX-DevOps", "region": "us-west-1"},
                "cdh-tooling-eu": {
                    "account": "121212121212",
                    "role": "CDHX-DevOps",
                    "region": "eu-west-1",
                },
                "cdh-tooling-eu-2": {
                    "account": "121212121212",
                    "role": "CDHX-DevOps",
                },
                "cdh-tooling-slave-role": {
                    "account": "121212121212",
                    "role": "CDHX-DevOps",
                    "subrole": "test_slave_role",
                    "region": "eu-central-1",
                },
                "cdh-tooling-short": {
                    "account": "121212121212",
                    "role": "CDHX-DevOps",
                    "region": "eu-central-1",
                    "session_length": 15,
                },
            },
        }
    },
}

basic_config_dict_bmw_bba_v2: Dict[str, Any] = {
    "version": "v2",
    "identities": {
        "bmw": {
            "username": "q494729",
            "pintype": "yk",
            "region": "eu-central-1",
            "aws-profiles": {
                "cdh-dev-bmw": {
                    "account": "333333333333",
                    "role": "CDHX-DevOps",
                },
            },
        },
        "bba": {
            "username": "my.digital.id",
            "region": "cn-northwest-1",
            "aws-profiles": {
                "cdh-dev": {
                    "account": "454545454545",
                    "role": "CDHX-DevOps",
                },
                "cdh-tooling": {
                    "account": "020202020202",
                    "role": "CDHX-DevOps",
                    "region": "us-east-1",
                },
                "cdh-tooling-default": {
                    "account": "020202020202",
                    "role": "CDHX-DevOps",
                },
                "cdh-tooling-us": {
                    "account": "121212121212",
                    "role": "CDHX-DevOps",
                    "region": "us-west-1",
                },
                "cdh-tooling-eu": {
                    "account": "121212121212",
                    "role": "CDHX-DevOps",
                    "region": "eu-west-1",
                },
                "cdh-tooling-eu-2": {
                    "account": "121212121212",
                    "role": "CDHX-DevOps",
                },
                "cdh-tooling-slave-role": {
                    "account": "121212121212",
                    "role": "CDHX-DevOps",
                    "region": "eu-central-1",
                    "subrole": "test_slave_role",
                },
                "cdh-tooling-short": {
                    "account": "121212121212",
                    "role": "CDHX-DevOps",
                    "region": "eu-central-1",
                    "session_length": 15,
                },
            },
        },
    },
}


def mock_get_version_yaml_dict(self: CdhConfig) -> Tuple[ConfigVersion, Any]:
    return (ConfigVersion.v1, pytest.config_yml_dict)


def load_yaml(text: str) -> Dict[Any, Any]:
    try:
        spec = yaml.load(text)
    except YAMLError:
        raise ConfigError()
    if not isinstance(spec, dict):
        raise ConfigError("Invalid content in user configuration file")
    return spec


def create_config_from_dict(config_yml_dict: dict) -> CdhConfig:
    pytest.config_yml_dict = config_yml_dict
    with patch.object(CdhConfig, "get_version_yaml_dict", new=mock_get_version_yaml_dict):
        return CdhConfig(False, False)


class TestParseConfigYamlGeneral:
    def test_get_config_path(self) -> None:
        p = Path("/.config/cdh/config.yml")
        assert Path(CdhConfig.get_config_path()[-23:]) == p

    def test_empty_yaml_does_not_raise_an_error(self) -> None:
        create_config_from_dict({})

    def test_unknown_key_does_not_raise_an_error(self) -> None:
        basic_config_dict_changed = copy.deepcopy(basic_config_dict_bmw_only_v2)
        basic_config_dict_changed["unknownKey"] = "abc"
        create_config_from_dict(basic_config_dict_changed)

    def test_parse_file_works(self) -> None:
        create_config_from_dict(basic_config_dict_bmw_only_v2)


class TestParseConfigYamlV2LegacyTestsBmw:
    def test_get_profile_region_name(self) -> None:
        cdh_config = create_config_from_dict(basic_config_dict_bmw_only_v2)
        profile = cdh_config.bmw_identity_settings.get_fitting_profile("020202020202", "CDHX-DevOps")
        assert profile
        assert profile.region == "us-east-1"

    def test_basic_config_file_input(self) -> None:
        cdh_config = create_config_from_dict(basic_config_dict_bmw_only_v2)
        assert cdh_config.bmw_identity_settings.region == basic_config_dict_bmw_only_v2["identities"]["bmw"]["region"]

    def test_get_user_default_region_name(self) -> None:
        cdh_config = create_config_from_dict(basic_config_dict_bmw_only_v2)
        profile = cdh_config.bmw_identity_settings.get_fitting_profile("555555555555", "CDHX-DevOps")
        assert profile
        assert profile.region == basic_config_dict_bmw_only_v2["identities"]["bmw"]["region"]

    @pytest.mark.parametrize(
        "profile_name,account_number,expected",
        [
            ("cdh-dev", "555555555555", "eu-central-1"),
            ("cdh-tooling", "020202020202", "us-east-1"),
            ("cdh-tooling-us", "121212121212", "us-west-1"),
            ("cdh-tooling-eu", "121212121212", "eu-west-1"),
            ("cdh-tooling-eu-2", "121212121212", "eu-central-1"),
        ],
    )
    def test_get_profile_region(self, profile_name: str, account_number: str, expected: str) -> None:
        cdh_config = create_config_from_dict(basic_config_dict_bmw_only_v2)
        profile = cdh_config.bmw_identity_settings.get_fitting_profile(account_number, "CDHX-DevOps", profile_name)
        assert profile
        assert profile.name == profile_name
        assert profile.region == expected
        assert profile.session_length is None

    def test_get_nonexistent_user_profile_name(self) -> None:
        acc_id = "111111111111"
        role_name = "cdhx-test-role"
        user_profile_name = "cdhx-tooling"
        cdh_config = create_config_from_dict(basic_config_dict_bmw_only_v2)
        role = Role.from_arn(f"arn:aws:iam::{acc_id}:role/{role_name}")
        profile = cdh_config.bmw_identity_settings.get_fitting_profile(
            role.get_account_number(), role.get_name(), user_profile_name
        )
        assert profile is None

    def test_get_profile_with_sub_role(self) -> None:
        acc_id = "121212121212"
        user_profile_name = "cdh-tooling-slave-role"
        cdh_config = create_config_from_dict(basic_config_dict_bmw_only_v2)
        role = Role.from_arn(f"arn:aws:iam::{acc_id}:role/CDHX-DevOps")
        profile = cdh_config.bmw_identity_settings.get_fitting_profile(
            role.get_account_number(), role.get_name(), user_profile_name
        )
        assert profile
        assert profile.sub_role == f"arn:aws:iam::{acc_id}:role/test_slave_role"
        assert profile.region == "eu-central-1"
        assert profile.name == user_profile_name

    def test_get_profile_with_session_length(self) -> None:
        acc_id = "121212121212"
        user_profile_name = "cdh-tooling-short"
        cdh_config = create_config_from_dict(basic_config_dict_bmw_only_v2)
        role = Role.from_arn(f"arn:aws:iam::{acc_id}:role/CDHX-DevOps")
        profile = cdh_config.bmw_identity_settings.get_fitting_profile(
            role.get_account_number(), role.get_name(), user_profile_name
        )
        assert profile
        assert profile.sub_role is None
        assert profile.region == cdh_config.bmw_identity_settings.region
        assert profile.name == user_profile_name
        assert profile.session_length == 15

    def test_get_profile_from_name(self) -> None:
        profile_name = "cdh-tooling-slave-role"
        cdh_config = create_config_from_dict(basic_config_dict_bmw_only_v2)

        target_user_profile = cdh_config.bmw_identity_settings.get_profile_by_name(profile_name)
        assert target_user_profile
        assert target_user_profile.name == profile_name
        assert target_user_profile.sub_role == "arn:aws:iam::121212121212:role/test_slave_role"
        assert target_user_profile.region == "eu-central-1"
        assert target_user_profile.account_id == "121212121212"
        assert target_user_profile.role_name == "CDHX-DevOps"

    def test_get_profile_from_name_nonexistent(self) -> None:
        profile_name = "cdh-tooling-role-nonexistent"
        cdh_config = create_config_from_dict(basic_config_dict_bmw_only_v2)

        target_user_profile = cdh_config.bmw_identity_settings.get_profile_by_name(profile_name)
        assert target_user_profile is None

    def test_get_all_active_profiles(self) -> None:
        cdh_config = create_config_from_dict(basic_config_dict_bmw_only_v2)
        manager = CdhManager(setup=Setup(sanity_check=False), config=cdh_config)

        saml_roles = [
            Role.from_arn(role_arn1),
            Role.from_arn(role_arn2),
            Role.from_arn("arn:aws:iam::121212121212:role/test-role"),
        ]
        active_profiles = manager.get_all_active_profiles_for_stage(
            saml_roles=saml_roles, identity_type=IdentityTypes.BMW.value, stage=DEFAULT_AUTH_METHOD_STAGE
        )

        assert len(active_profiles) == 3

    @pytest.mark.parametrize(
        "target_region,expected_region",
        [
            ("eu-west-1", DEFAULT_CHINA_REGION),
            (DEFAULT_CHINA_REGION, DEFAULT_CHINA_REGION),
            ("cn-northwest-1", "cn-northwest-1"),
        ],
    )
    def test_china_role_has_correct_region(self, target_region: str, expected_region: str) -> None:
        profile_name = "china-dev-ops"
        role_name = "CDHX-DevOps"
        account_number = "232323232323"
        cdh_config = create_config_from_dict(
            {
                "identities": {
                    "bmw": {
                        "aws-profiles": {
                            profile_name: {"account": account_number, "role": role_name, "region": target_region}
                        }
                    }
                }
            }
        )
        manager = CdhManager(setup=Setup(), config=cdh_config)
        role = Role.from_arn(f"arn:aws-cn:iam::{account_number}:role/CDHX-DevOps")
        saml_profile = manager.build_saml_profile(role, IdentityTypes.BMW.value)
        assert isinstance(saml_profile, SamlProfileWithName)
        assert saml_profile.region == expected_region
        assert saml_profile.name == profile_name


FULL_CONFIG_CONTENTS_V2 = """
loglvl: warning
use-firefox-containers: true
version: v2

identities:
  bba:
    username: user123@partner.bmwgroup.com
    region: cn-northwest-1
    aws-profiles:
      bba_simple:
        account: 777777777777
        role: CDHX-CDHDataEngineer
  bmw:
    qnumber: QX12345
    pintype: mp
    region: eu-central-1
    aws-profiles:
      bmw_simple:
        account: 111111111111
        role: CDHX-DevOps
      with-params:
        account: 222222222222
        role: CDHX-DevOps
        region: cn-north-1
        session_length: 21
      multiple-per-account-role1-subrole1:
        account: 333333333333
        role: CDHX-DevResourceAccountDevOps
        subrole: arn:aws-cn:iam::444444444444:role/CDHX-DevResourceAccountDevOps
      multiple-per-account-role1-subrole2:
        account: 333333333333
        role: CDHX-DevResourceAccountDevOps
        subrole: arn:aws-cn:iam::555555555555:role/CDHX-DevResourceAccountDevOps
      multiple-per-account-role2:
        account: 333333333333
        role: CDHX-DevResourceAccountDevOpsReadOnly
        """

DUMMY_CONFIG_V1 = """
    qnumber: qxxxxxx
    pintype: yk #yk # or mp
    region: eu-west-1
    use-firefox-containers: true
    aws-profiles:
     "123456789012":
       CDHX-DevOps: test1
     "012345670123":
       CDHX-DevOps: octal
     "234567890123":
       CDHX-DevOps:
          - name: test2
            region: eu-west-1
          - name: test2_subrole
            subrole: arn:aws:iam::234567890123:role/subrole
        """
CONFIG_VERSION_UNDEFINED = """
    loglvl: warning
    use-firefox-containers: true
    identities:
      bba:
        username: user123@partner.bmwgroup.com
        region: cn-northwest-1
        aws-profiles:
          bba_simple:
            account: 777777777777
            role: CDHX-CDHDataEngineer
            """


class TestParseConfigYamlV2:
    @pytest.mark.parametrize(
        "config_dict",
        [
            pytest.param({"identities": {"bmw": "asdf"}}, id="string"),
            pytest.param({"identities": {"bmw": ["x"]}}, id="list"),
            pytest.param({"identities": {"bmw": None}}, id="empty section"),
        ],
    )
    def test_fail_on_invalid_identity_section_structure(self, config_dict: dict) -> None:
        with pytest.raises(Exception):
            create_config_from_dict(config_dict)

    def test_unknown_identity_type_is_allowed_for_forward_compatibility_but_logged_as_warning(
        self, caplog: Any
    ) -> None:
        caplog.set_level(WARNING)

        cdh_config = create_config_from_dict({"identities": {"unknown_id_type": {"username": "irrelevant"}}})

        assert cdh_config.identity_settings
        assert "Configuration under section identities.unknown_id_type was not recognized" in caplog.text

    def test_parse_file_basic(self) -> None:
        cdh_config = create_config_from_dict(load_yaml(FULL_CONFIG_CONTENTS_V2))

        assert cdh_config.loglvl == "warning"
        assert cdh_config.use_firefox_containers is True

        assert cdh_config.bba_identity_settings.region == "cn-northwest-1"
        assert cdh_config.bmw_identity_settings.region == "eu-central-1"

    def test_fails_on_invalid_profiles_type(self) -> None:
        config_contents = """
version: v2
identities:
  bmw:
    aws-profiles:
      invalid_profile: "should not be a string"
"""
        with pytest.raises(
            ConfigError, match="Error parsing profile: Invalid type " "for identities.bmw.aws-profiles.invalid_profile"
        ):
            create_config_from_dict(load_yaml(config_contents))

    def test_fails_on_empty_profile_name(self) -> None:
        config_contents = """
version: v2
identities:
  bmw:
    aws-profiles:
      "":
        account: 111111111111
        role: CDHX-DevOps
"""
        with pytest.raises(
            ConfigError,
            match="Error parsing profile: empty profile name is not allowed " "in identities.bmw.aws-profiles",
        ):
            create_config_from_dict(load_yaml(config_contents))

    def test_fails_on_missing_account(self) -> None:
        config_contents = """
version: v2
identities:
  bmw:
    aws-profiles:
      no-account-id:
        role: CDHX-DevOps
"""
        with pytest.raises(
            ConfigError,
            match="Error parsing profile: 'account' missing " "in identities.bmw.aws-profiles.no-account-id",
        ):
            create_config_from_dict(load_yaml(config_contents))

    def test_fails_on_missing_role(self) -> None:
        config_contents = """
version: v2
identities:
  bmw:
    aws-profiles:
      no-role:
        account: 111111111111
"""
        with pytest.raises(
            ConfigError, match="Error parsing profile: 'role' missing " "in identities.bmw.aws-profiles.no-role"
        ):
            create_config_from_dict(load_yaml(config_contents))

    def test_warn_for_unknown_attributes(self, caplog: Any) -> None:
        config_contents = """
version: v2
identities:
  bmw:
    aws-profiles:
      unknown_attribute_profile:
        account: 111111111111
        role: CDHX-DevOps
        something_else: abc
        some_other: 1
"""
        caplog.set_level(WARNING)
        create_config_from_dict(load_yaml(config_contents))
        assert (
            "Unknown attribute 'something_else' will be ignored "
            "(defined in identities.bmw.aws-profiles.unknown_attribute_profile)" in caplog.text
        )
        assert (
            "Unknown attribute 'some_other' will be ignored "
            "(defined in identities.bmw.aws-profiles.unknown_attribute_profile)" in caplog.text
        )

    def test_parse_file_profiles(self) -> None:
        cdh_config = create_config_from_dict(load_yaml(FULL_CONFIG_CONTENTS_V2))

        assert len(cdh_config.bba_identity_settings.aws_profiles) == 1
        assert cdh_config.bba_identity_settings.get_profile_by_name("bba_simple") == UserConfigProfile(
            account_id="777777777777",
            role_name="CDHX-CDHDataEngineer",
            name="bba_simple",
            region="cn-northwest-1",
            sub_role=None,
            session_length=None,
            exclude_from_get_all=False,
            auth_method_stage=DEFAULT_AUTH_METHOD_STAGE,
        )

        assert len(cdh_config.bmw_identity_settings.aws_profiles) == 5
        assert cdh_config.bmw_identity_settings.get_profile_by_name("bmw_simple") == UserConfigProfile(
            account_id="111111111111",
            role_name="CDHX-DevOps",
            name="bmw_simple",
            region="eu-central-1",
            sub_role=None,
            session_length=None,
            exclude_from_get_all=False,
            auth_method_stage=DEFAULT_AUTH_METHOD_STAGE,
        )
        assert cdh_config.bmw_identity_settings.get_profile_by_name("with-params") == UserConfigProfile(
            account_id="222222222222",
            role_name="CDHX-DevOps",
            name="with-params",
            region="cn-north-1",
            sub_role=None,
            session_length=21,
            exclude_from_get_all=False,
            auth_method_stage=DEFAULT_AUTH_METHOD_STAGE,
        )
        assert cdh_config.bmw_identity_settings.get_profile_by_name(
            "multiple-per-account-role1-subrole1"
        ) == UserConfigProfile(
            account_id="333333333333",
            role_name="CDHX-DevResourceAccountDevOps",
            name="multiple-per-account-role1-subrole1",
            region="eu-central-1",
            sub_role="arn:aws-cn:iam::444444444444:role/CDHX-DevResourceAccountDevOps",
            session_length=None,
            exclude_from_get_all=False,
            auth_method_stage=DEFAULT_AUTH_METHOD_STAGE,
        )
        assert cdh_config.bmw_identity_settings.get_profile_by_name(
            "multiple-per-account-role1-subrole2"
        ) == UserConfigProfile(
            account_id="333333333333",
            role_name="CDHX-DevResourceAccountDevOps",
            name="multiple-per-account-role1-subrole2",
            region="eu-central-1",
            sub_role="arn:aws-cn:iam::555555555555:role/CDHX-DevResourceAccountDevOps",
            session_length=None,
            exclude_from_get_all=False,
            auth_method_stage=DEFAULT_AUTH_METHOD_STAGE,
        )
        assert cdh_config.bmw_identity_settings.get_profile_by_name("multiple-per-account-role2") == UserConfigProfile(
            account_id="333333333333",
            role_name="CDHX-DevResourceAccountDevOpsReadOnly",
            name="multiple-per-account-role2",
            region="eu-central-1",
            sub_role=None,
            session_length=None,
            exclude_from_get_all=False,
            auth_method_stage=DEFAULT_AUTH_METHOD_STAGE,
        )

    def test_parse_account_number_octal_looking_yields_error(self) -> None:
        config_contents = """
version: v2
identities:
  bmw:
    aws-profiles:
      leading-zero-octal-looking:
        account: 011111111111
        role: CDHX-DevOps
"""
        with pytest.raises(ConfigError):
            create_config_from_dict(load_yaml(config_contents))

    def test_parse_account_number_leading_zeroes_but_not_valid_octal_is_accepted(self) -> None:
        config_contents = """
version: v2
identities:
  bmw:
    aws-profiles:
      leading-zero-but-not-octal:
        account: 090909090909
        role: CDHX-DevOps
"""
        cdh_config = create_config_from_dict(load_yaml(config_contents))
        profile = cdh_config.bmw_identity_settings.get_profile_by_name("leading-zero-but-not-octal")
        assert profile
        assert profile.account_id == "090909090909"

    def test_parse_account_number_too_short_and_ambiguous_yields_error(self) -> None:
        config_contents = """
    version: v2
    identities:
      bmw:
        aws-profiles:
          too-short-ambiguous:
            account: 12345678
            role: CDHX-DevOps
    """
        # ambiguity: 12345678 (int val) could be coming from 000012345678 (decimal) or 000057060516 (octal)
        with pytest.raises(ConfigError):
            create_config_from_dict(load_yaml(config_contents))

    def test_parse_account_number_too_short_but_non_ambiguous_is_padded(self) -> None:
        config_contents = """
    version: v2
    identities:
      bmw:
        aws-profiles:
          too-short:
            account: 9999999999
            role: CDHX-DevOps
    """
        cdh_config = create_config_from_dict(load_yaml(config_contents))
        # non-ambiguous: 9999999999 (int value) as octal string is "0112402761777", which is 13 chars and thus too long,
        # so it must have been 9999999999 in the yaml
        profile = cdh_config.bmw_identity_settings.get_profile_by_name("too-short")
        assert profile
        assert profile.account_id == "009999999999"

    def test_fails_on_duplicate_profile_name(self) -> None:
        config_contents = """
version: v2
identities:
  bmw:
    aws-profiles:
      duplicate-profile:
        account: 111111111111
        role: CDHX-DevOps
  bba:
    aws-profiles:
      duplicate-profile:
        account: 222222222222
        role: CDHX-DevOpsReadOnly
"""
        with pytest.raises(ConfigError, match='Profile name "duplicate-profile" is used multiple times'):
            create_config_from_dict(load_yaml(config_contents))


class TestParseConfigYamlV2Bba:
    def test_basic_config_file_input(self) -> None:
        cdh_config = create_config_from_dict(basic_config_dict_bmw_bba_v2)
        assert cdh_config.bba_identity_settings.region == basic_config_dict_bmw_bba_v2["identities"]["bba"]["region"]

    @pytest.mark.parametrize(
        "profile_name,account_number,expected",
        [
            ("cdh-dev", "454545454545", "cn-northwest-1"),
            ("cdh-tooling", "020202020202", "us-east-1"),
            ("cdh-tooling-us", "121212121212", "us-west-1"),
            ("cdh-tooling-eu", "121212121212", "eu-west-1"),
            ("cdh-tooling-eu-2", "121212121212", "cn-northwest-1"),
        ],
    )
    def test_get_profile_region(self, profile_name: str, account_number: str, expected: str) -> None:
        cdh_config = create_config_from_dict(basic_config_dict_bmw_bba_v2)
        profile = cdh_config.bba_identity_settings.get_fitting_profile(account_number, "CDHX-DevOps", profile_name)
        assert profile
        assert profile.name == profile_name
        assert profile.region == expected
        assert profile.session_length is None

    def test_get_nonexistent_user_profile_name(self) -> None:
        acc_id = "111111111111"
        role_name = "cdhx-test-role"
        user_profile_name = "cdhx-tooling"
        cdh_config = create_config_from_dict(basic_config_dict_bmw_bba_v2)
        role = Role.from_arn(f"arn:aws:iam::{acc_id}:role/{role_name}")
        profile = cdh_config.bba_identity_settings.get_fitting_profile(
            role.get_account_number(), role.get_name(), user_profile_name
        )
        assert not profile

    def test_get_profile_with_sub_role(self) -> None:
        acc_id = "121212121212"
        user_profile_name = "cdh-tooling-slave-role"
        cdh_config = create_config_from_dict(basic_config_dict_bmw_bba_v2)
        role = Role.from_arn(f"arn:aws:iam::{acc_id}:role/CDHX-DevOps")
        profile = cdh_config.bba_identity_settings.get_fitting_profile(
            role.get_account_number(), role.get_name(), user_profile_name
        )
        assert profile
        assert profile.sub_role == f"arn:aws:iam::{acc_id}:role/test_slave_role"
        assert profile.region == "eu-central-1"
        assert profile.name == user_profile_name

    def test_get_profile_with_session_length(self) -> None:
        acc_id = "121212121212"
        user_profile_name = "cdh-tooling-short"
        cdh_config = create_config_from_dict(basic_config_dict_bmw_bba_v2)
        role = Role.from_arn(f"arn:aws:iam::{acc_id}:role/CDHX-DevOps")
        profile = cdh_config.bba_identity_settings.get_fitting_profile(
            role.get_account_number(), role.get_name(), user_profile_name
        )
        assert profile
        assert profile.sub_role is None
        assert profile.name == user_profile_name
        assert profile.session_length == 15

    @pytest.mark.parametrize(
        "target,expected",
        [("cdh-tooling-slave-role", True), ("cdh-tooling-us", False), ("nonexistent_target_name", False)],
    )
    def test_is_target_sub_role(self, target: str, expected: bool) -> None:
        cdh_config = create_config_from_dict(basic_config_dict_bmw_bba_v2)

        found_profile = cdh_config.bba_identity_settings.get_profile_by_name(target)
        assert bool(found_profile and found_profile.sub_role is not None) == expected


class TestParseConfigRegion:
    def test_unknown_profile_region(self) -> None:
        config_contents = """
    version: v2
    identities:
      bmw:
        aws-profiles:
          with-unknown-region:
            account: 9999999999
            role: CDHX-DevOps
            region: unkown-region-1
    """
        with pytest.raises(ConfigError):
            create_config_from_dict(load_yaml(config_contents))

    def test_unknown_default_region(self) -> None:
        config_contents = """
    version: v2
    identities:
      bmw:
        region: unkown-region-1
        aws-profiles:
          with-unknown-region:
            account: 9999999999
            role: CDHX-DevOps
    """
        with pytest.raises(ConfigError):
            create_config_from_dict(load_yaml(config_contents))
