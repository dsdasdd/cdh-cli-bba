from typing import Dict

from cdh_utils.constants import IdentityCode
from cdh_utils.utils.autocomplete import AutoCompleter
from cdh_utils.utils.cdh_manager import CdhManager
from cdh_utils.utils.cdhconfig import CdhConfig
from cdh_utils.utils.cdhconfig import IdentitySpecificSettings
from cdh_utils.utils.cdhconfig import UserConfigProfile
from cdh_utils.utils.setup import Setup

ACCOUNT_NAME_0 = "test_name1"
ACCOUNT_NAME_1 = "test_name2"
ACCOUNT_NAME_UNCOMMON = "false_test_name"

account_names = [ACCOUNT_NAME_0, ACCOUNT_NAME_1, ACCOUNT_NAME_UNCOMMON]


class TestAutocomplete:
    def setup_method(self) -> None:
        manager = create_dummy_manager()
        self.autocompleter = AutoCompleter(manager.config)

    def test_get_sign_in_targets(self) -> None:
        incomplete = "t"
        correct_suggestions = [ACCOUNT_NAME_0, ACCOUNT_NAME_1]
        autocomplete_suggestions = self.autocompleter.get_sign_in_targets(incomplete)
        assert autocomplete_suggestions == correct_suggestions

    def test_get_sign_in_targets_with_empty_string(self) -> None:
        incomplete = ""
        correct_suggestions = account_names
        autocomplete_suggestions = self.autocompleter.get_sign_in_targets(incomplete)
        assert autocomplete_suggestions == correct_suggestions


def create_dummy_user_config_profile_with_name(name: str) -> UserConfigProfile:
    return UserConfigProfile(
        account_id="444444444444",
        role_name="cdh_dev",
        name=name,
        region="us-east-1",
        sub_role="arn:aws:iam::333333333333:role/user_profile_subrole0",
        session_length=None,
        exclude_from_get_all=False,
    )


def create_dummy_bmw_identity_settings() -> Dict[IdentityCode, IdentitySpecificSettings]:
    aws_profiles = [create_dummy_user_config_profile_with_name(account_name) for account_name in account_names]
    identity_settings = IdentitySpecificSettings(
        aws_profiles=aws_profiles,
        region="eu-central-1",
    )

    return {IdentityCode.BMW: identity_settings}


def create_dummy_manager() -> CdhManager:
    config = CdhConfig(ignore_config=False, ignore_keyring=True)
    config.identity_settings = create_dummy_bmw_identity_settings()
    manager = CdhManager(setup=Setup(ignore_config=False), config=config)
    return manager
