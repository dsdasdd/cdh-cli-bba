from logging import WARNING
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from unittest.mock import ANY
from unittest.mock import Mock
from unittest.mock import mock_open
from unittest.mock import patch

import pytest

from cdh_utils.constants import AuthMethodStage
from cdh_utils.constants import DEFAULT_AUTH_METHOD_STAGE
from cdh_utils.constants import IdentityType
from cdh_utils.constants import IdentityTypes
from cdh_utils.saml.identities import Role
from cdh_utils.saml.identities import SamlProfile
from cdh_utils.saml.identities import SamlProfileWithAlias
from cdh_utils.utils.cdhconfig import CdhConfig
from cdh_utils.utils.cdhconfig import IdentitySpecificSettings
from cdh_utils.utils.cdhconfig import UserConfigProfile
from cdh_utils.utils.exceptions import ConfigError


def _build_user_config_profile(
    index: int,
    account_id: Optional[str] = None,
    role_name: Optional[str] = None,
    name: Optional[str] = None,
    sub_role: Optional[str] = None,
    session_length: Optional[int] = None,
    exclude_from_get_all: bool = False,
    auth_method_stage: AuthMethodStage = DEFAULT_AUTH_METHOD_STAGE,
) -> UserConfigProfile:
    return UserConfigProfile(
        account_id=account_id or f"{index:012}",
        role_name=role_name or f"role_name_{index}",
        region="eu-west-1",
        name=name or f"profile_{index}",
        sub_role=sub_role,
        session_length=session_length,
        exclude_from_get_all=exclude_from_get_all,
        auth_method_stage=auth_method_stage,
    )


class TestIdentitySpecificSettings:
    def setup_method(self) -> None:
        self.profile1 = _build_user_config_profile(1)
        self.profile2 = _build_user_config_profile(2)

    def test_combined_settings_should_combine_contents(self) -> None:
        primary = IdentitySpecificSettings(region="us-east-1", aws_profiles=[])
        override = IdentitySpecificSettings(region=None, aws_profiles=[self.profile2])
        merged = primary.combined_settings(override)

        assert merged.region == primary.region
        assert merged.aws_profiles == override.aws_profiles

    def test_combined_settings_should_combine_contents_varied(self) -> None:
        primary = IdentitySpecificSettings(region=None, aws_profiles=[self.profile1])
        override = IdentitySpecificSettings(region="us-east-1", aws_profiles=[])
        merged = primary.combined_settings(override)

        assert merged.region == override.region
        assert merged.aws_profiles == primary.aws_profiles

    def test_combined_settings_should_combine_empty(self) -> None:
        primary = IdentitySpecificSettings(region=None, aws_profiles=[])
        override = IdentitySpecificSettings(region="eu-central-1", aws_profiles=[self.profile2])

        merged = primary.combined_settings(override)

        assert merged.region == override.region
        assert merged.aws_profiles == override.aws_profiles

    def test_combined_settings_should_prefer_overrides(self) -> None:
        primary = IdentitySpecificSettings(region="us-east-1", aws_profiles=[self.profile1])
        override = IdentitySpecificSettings(region="eu-central-1", aws_profiles=[self.profile2])
        merged = primary.combined_settings(override)

        assert merged.region == override.region
        assert merged.aws_profiles == override.aws_profiles

    @pytest.mark.parametrize(
        "identity_specific_settings",
        [
            (IdentitySpecificSettings(region="us-east-1", aws_profiles=[])),
            (IdentitySpecificSettings(region=None, aws_profiles=[_build_user_config_profile(1)])),
        ],
    )
    def test_bool_is_true_if_any_attribute_is_set(self, identity_specific_settings: IdentitySpecificSettings) -> None:
        assert identity_specific_settings

    def test_bool_is_false_if_no_attribute_set(self) -> None:
        identity_specific_settings = IdentitySpecificSettings(region=None, aws_profiles=[])
        assert not identity_specific_settings


class TestGetFittingProfile:
    def setup_method(self) -> None:
        self.profile1 = _build_user_config_profile(1)
        self.profile2 = _build_user_config_profile(2)
        self.profile3 = _build_user_config_profile(3)
        self.profile3_altered = _build_user_config_profile(3, sub_role="subrole3", name="profile_3_altered")
        self.identity_specific_settings = IdentitySpecificSettings(
            region="us-east-1",
            aws_profiles=[
                _build_user_config_profile(333),
                self.profile1,
                _build_user_config_profile(444),
                self.profile2,
                self.profile3,
                self.profile3_altered,
                _build_user_config_profile(555),
            ],
        )

    def test_not_found(self) -> None:
        assert not self.identity_specific_settings.get_fitting_profile("999999999999", self.profile1.role_name)
        assert not self.identity_specific_settings.get_fitting_profile(self.profile1.account_id, "unknown_role")
        assert not IdentitySpecificSettings.build_empty().get_fitting_profile(
            self.profile1.account_id, self.profile1.role_name
        )

    def test_not_found_with_name(self) -> None:
        assert not self.identity_specific_settings.get_fitting_profile(
            self.profile1.account_id, self.profile1.role_name, "wrong_name"
        )

    def test_found(self) -> None:
        assert self.identity_specific_settings.get_fitting_profile(self.profile1.account_id, self.profile1.role_name)
        assert self.identity_specific_settings.get_fitting_profile(self.profile2.account_id, self.profile2.role_name)

    def test_returns_first_on_multiple_matches(self) -> None:
        assert (
            self.identity_specific_settings.get_fitting_profile(self.profile3.account_id, self.profile3.role_name)
            is self.profile3
        )

    def test_found_with_name(self) -> None:
        assert self.identity_specific_settings.get_fitting_profile(
            self.profile1.account_id, self.profile1.role_name, self.profile1.name
        )
        assert self.identity_specific_settings.get_fitting_profile(
            self.profile2.account_id, self.profile2.role_name, self.profile2.name
        )


class TestGetProfileByName:
    def setup_method(self) -> None:
        self.profile1 = _build_user_config_profile(1)
        self.identity_specific_settings = IdentitySpecificSettings(
            region="us-east-1",
            aws_profiles=[
                _build_user_config_profile(333),
                self.profile1,
                _build_user_config_profile(444),
                _build_user_config_profile(555),
            ],
        )

    def test_not_found(self) -> None:
        assert not self.identity_specific_settings.get_profile_by_name("unknown")

    def test_found(self) -> None:
        assert self.identity_specific_settings.get_profile_by_name(self.profile1.name) is self.profile1


class TestCdhConfigDetails:
    """
    Specific tests for CdhConfig. Please note that component-level tests for CdhConfig can be found in test_yaml.py
    """

    def setup_method(self) -> None:
        self.default_region = "eu-west-1"
        self.config_path = "identities.unittest.aws-profiles"

    def test_load_profiles_v2_parses_empty_profiles(self) -> None:
        profiles_dict: Dict[str, Any] = {}

        result = CdhConfig.load_profiles_v2(profiles_dict, self.default_region, self.config_path)

        assert result == []

    def test_load_profiles_v2_raises_on_empty_profile_name(self) -> None:
        profiles_dict = {
            "": {
                "account": "111111111111",
                "role": "CDHX-DevOps",
            }
        }

        with pytest.raises(ConfigError):
            CdhConfig.load_profiles_v2(profiles_dict, self.default_region, self.config_path)

    def test_load_profiles_v2_raises_on_profile_not_dict(self) -> None:
        profiles_dict = {"not-dict": {"key": "is_invalid"}}

        with pytest.raises(ConfigError):
            CdhConfig.load_profiles_v2(
                profiles_dict, self.default_region, self.config_path
            )  # noqa: deliberately mistyped

    def test_load_profiles_v2_loads_minimum_profile(self) -> None:
        profiles_dict = {
            "simple": {
                "account": "111111111111",
                "role": "CDHX-DevOps",
            }
        }

        result = CdhConfig.load_profiles_v2(profiles_dict, self.default_region, self.config_path)

        assert result == [
            UserConfigProfile(
                account_id="111111111111",
                role_name="CDHX-DevOps",
                name="simple",
                region=self.default_region,
                sub_role=None,
                session_length=None,
                exclude_from_get_all=False,
                auth_method_stage=DEFAULT_AUTH_METHOD_STAGE,
            )
        ]

    def test_load_profiles_v2_loads_multiple_profiles_in_order(self) -> None:
        profiles_dict = {
            "one": {
                "account": "111111111111",
                "role": "CDHX-DevOps",
            },
            "two": {
                "account": "222222222222",
                "role": "CDHX-DevOps2",
            },
            "three": {
                "account": "333333333333",
                "role": "CDHX-DevOps3",
            },
        }

        result = CdhConfig.load_profiles_v2(profiles_dict, self.default_region, self.config_path)

        assert len(result) == 3
        assert result[0].name == "one"
        assert result[0].account_id == "111111111111"
        assert result[1].name == "two"
        assert result[1].account_id == "222222222222"
        assert result[2].name == "three"
        assert result[2].account_id == "333333333333"

    def test_load_profiles_v2_sets_session_length(self) -> None:
        profiles_dict = {
            "simple": {
                "account": "111111111111",
                "role": "CDHX-DevOps",
                "session_length": 15,
            }
        }

        result = CdhConfig.load_profiles_v2(profiles_dict, self.default_region, self.config_path)

        assert len(result) == 1
        assert result[0].session_length == 15

    def test_load_profiles_v2_sets_region_if_given(self) -> None:
        profiles_dict = {
            "simple": {
                "account": "111111111111",
                "role": "CDHX-DevOps",
                "region": "us-east-1",
            }
        }

        result = CdhConfig.load_profiles_v2(profiles_dict, self.default_region, self.config_path)

        assert len(result) == 1
        assert result[0].region == "us-east-1"

    def test_load_profiles_v2_computes_subrole_arn_for_simple_subrole(self) -> None:
        profiles_dict = {"simple": {"account": "111111111111", "role": "CDHX-DevOps", "subrole": "subrole1"}}

        result = CdhConfig.load_profiles_v2(profiles_dict, self.default_region, self.config_path)

        assert len(result) == 1
        assert result[0].sub_role == "arn:aws:iam::111111111111:role/subrole1"

    def test_load_profiles_v2_sets_subrole_arn_if_given(self) -> None:
        profiles_dict = {
            "simple": {
                "account": "111111111111",
                "role": "CDHX-DevOps",
                "subrole": "arn:aws:iam::222222222222:role/subrole2",
            }
        }

        result = CdhConfig.load_profiles_v2(profiles_dict, self.default_region, self.config_path)

        assert len(result) == 1
        assert result[0].sub_role == "arn:aws:iam::222222222222:role/subrole2"

    def test_load_profiles_v2_warns_for_unknown_attributes(self, caplog: Any) -> None:
        profiles_dict = {
            "unknown_attribute_profile": {
                "account": "111111111111",
                "role": "CDHX-DevOps",
                "something_else": "this is unknown",
                "some_other": "this is also unknown",
            }
        }
        caplog.set_level(WARNING)

        result = CdhConfig.load_profiles_v2(profiles_dict, self.default_region, self.config_path)

        assert len(result) == 1
        assert (
            "Unknown attribute 'something_else' will be ignored "
            "(defined in identities.unittest.aws-profiles.unknown_attribute_profile)" in caplog.text
        )
        assert (
            "Unknown attribute 'some_other' will be ignored "
            "(defined in identities.unittest.aws-profiles.unknown_attribute_profile)" in caplog.text
        )


class TestGetAllUnexcludedProfiles:
    def test_get_unexculded_all_aws_profiles(self) -> None:
        included_profile = _build_user_config_profile(0, exclude_from_get_all=False)
        excluded_profile = _build_user_config_profile(1, exclude_from_get_all=True)

        aws_profiles = [included_profile, excluded_profile]

        identity_specific_settings = IdentitySpecificSettings(aws_profiles=aws_profiles)
        unexcluded_profiles = identity_specific_settings.get_aws_profiles_for_stage(DEFAULT_AUTH_METHOD_STAGE)

        assert included_profile in unexcluded_profiles
        assert excluded_profile not in unexcluded_profiles

    def test_get_all_profiles_in_stage(self) -> None:
        stage = AuthMethodStage.INT
        included_profile = _build_user_config_profile(0, exclude_from_get_all=False, auth_method_stage=stage)
        excluded_profile = _build_user_config_profile(1, exclude_from_get_all=True)

        aws_profiles = [included_profile, excluded_profile]

        identity_specific_settings = IdentitySpecificSettings(aws_profiles=aws_profiles)
        unexcluded_profiles = identity_specific_settings.get_aws_profiles_for_stage(stage)

        assert included_profile in unexcluded_profiles
        assert excluded_profile not in unexcluded_profiles


@patch("builtins.open", new_callable=mock_open)
class TestGenerateConfig:
    def test_create_config_file_writes_to_config_file(self, mocked_config_file: Mock) -> None:
        CdhConfig.create_config_file({})
        mocked_config_file.assert_called_with(CdhConfig.get_config_path(), "w")

    @patch("ruamel.yaml.YAML.dump")
    def test_create_config_file_handles_version_information(
        self, mocked_yaml_dump: Mock, mocked_config_file: Mock
    ) -> None:
        CdhConfig.create_config_file({})
        mocked_yaml_dump.assert_called_once_with({"version": "v2", "identities": {}}, ANY)

    @patch("ruamel.yaml.YAML.dump")
    def test_create_config_file_handles_account_information_for_bmw_accounts(
        self, mocked_yaml_dump: Mock, mocked_config_file: Mock
    ) -> None:
        fake_role1 = Role.from_arn("arn:aws:iam::012345678901:role/fake-role")
        fake_role2 = Role.from_arn("arn:aws:iam::109876543210:role/fake-role")
        profiles_list: List[SamlProfile] = [
            SamlProfileWithAlias(role=fake_role1, identity_type=IdentityTypes.BMW.value),
            SamlProfileWithAlias(role=fake_role2, identity_type=IdentityTypes.BMW.value),
        ]
        fake_profiles_with_identities: Dict[IdentityType, List[SamlProfile]] = {IdentityTypes.BMW.value: profiles_list}

        CdhConfig.create_config_file(fake_profiles_with_identities)

        expected_config_dict = {
            "version": "v2",
            "identities": {
                "bmw": {
                    "aws-profiles": {
                        profiles_list[0].get_representative_name(): {
                            "account": fake_role1.get_account_number(),
                            "role": fake_role1.get_name(),
                        },
                        profiles_list[1].get_representative_name(): {
                            "account": fake_role2.get_account_number(),
                            "role": fake_role2.get_name(),
                        },
                    }
                }
            },
        }

        mocked_yaml_dump.assert_called_once_with(expected_config_dict, ANY)


CONFIG_CONTENTS_WITH_USER_COMMENTS_V2 = """
# first line comment
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
      bmw_first:
        account: 111111111111
        role: CDHX-DevOps
    # between profiles comment
      bad_profile:
        account: 222222222222
        role: CDHX-DevOps
        region: cn-north-1
        session_length: 21
      last_profile:
        account: 111111111111
        role: CDHX-DevOps
        """

CONFIG_CONTENTS_WITH_COMMENTED_BAD_PROFILES_V2 = """
# first line comment
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
      bmw_first:
        account: 111111111111
        role: CDHX-DevOps
    # between profiles comment
#      bad_profile:
#        account: 222222222222
#        role: CDHX-DevOps
#        region: cn-north-1
#        session_length: 21
      last_profile:
        account: 111111111111
        role: CDHX-DevOps
        """


@patch("builtins.open", new_callable=mock_open, read_data=CONFIG_CONTENTS_WITH_USER_COMMENTS_V2)
class TestConfigSanityCheck:
    def test_comment_out_bad_profiles(self, mocked_config_file: Mock) -> None:
        bad_profiles_list = [UserConfigProfile("empty", "empty", "bad_profile", "empty", None, None, False)]
        CdhConfig(True, True).comment_out_bad_profiles_for_identity(IdentityTypes.BMW.value, bad_profiles_list)
        mocked_config_file().write.assert_called_once_with(CONFIG_CONTENTS_WITH_COMMENTED_BAD_PROFILES_V2)
