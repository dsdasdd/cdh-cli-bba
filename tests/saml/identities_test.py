from typing import Any

import pytest

from cdh_utils.constants import IdentityTypes
from cdh_utils.saml.identities import Role
from cdh_utils.saml.identities import SamlProfileWithAlias
from cdh_utils.saml.identities import SamlProfileWithName
from cdh_utils.saml.identities import SignInTarget


class TestRole:
    @pytest.mark.parametrize(
        "arn_str", ["arn:aws:iam::11111111111:role/subrole2", "arn:aws-cn:iam::11111111111:role/subrole2"]
    )
    def test_is_valid_arn_valid_input(self, arn_str: str) -> None:
        assert Role.is_valid_arn(arn_str)

    @pytest.mark.parametrize("invalid_arn_str", ["", "arn:aws:s3::11111111111:something", None])
    def test_is_valid_arn_invalid_input(self, invalid_arn_str: Any) -> None:
        assert not Role.is_valid_arn(invalid_arn_str)


class TestSamlProfileWithName:
    def test_matches(self) -> None:
        matching_name = "correct_name"
        dummy_role = Role.from_arn("arn:aws:iam::121212121212:role/test-role")
        profile = SamlProfileWithName(profile_name=matching_name, role=dummy_role)
        sign_in_target = SignInTarget(
            name=matching_name, account_id=None, role_name=None, identity_type=IdentityTypes.BMW.value
        )
        assert profile.matches(sign_in_target, identity_type=IdentityTypes.BMW.value)

    def test_not_matches_different_names(self) -> None:
        dummy_role = Role.from_arn("arn:aws:iam::121212121212:role/test-role")
        profile = SamlProfileWithName(profile_name="correct_name", role=dummy_role)
        sign_in_target = SignInTarget(name="different_name", account_id=None, role_name=None)
        assert not profile.matches(sign_in_target, identity_type=IdentityTypes.BMW.value)

    def test_not_matches_different_identity_types(self) -> None:
        matching_name = "correct_name"
        dummy_role = Role.from_arn("arn:aws:iam::121212121212:role/test-role")
        profile = SamlProfileWithName(profile_name=matching_name, role=dummy_role)
        sign_in_target = SignInTarget(
            name=matching_name, account_id=None, role_name=None, identity_type=IdentityTypes.BBA.value
        )
        assert not profile.matches(sign_in_target, identity_type=IdentityTypes.BMW.value)


class TestSamlProfileWithAlias:
    def test_matches(self) -> None:
        role_name = "CDH-Developer"
        account_id = "555555555555"
        role = Role.from_arn(f"arn:aws:iam::{account_id}:role/{role_name}")
        profile = SamlProfileWithAlias(role=role, identity_type=IdentityTypes.BMW.value)
        sign_in_target = SignInTarget(role_name=role_name, account_id=account_id, name=None)
        assert profile.matches(sign_in_target, identity_type=IdentityTypes.BMW.value)

    def test_not_matches_different_role_names(self) -> None:
        role_name = "CDH-Developer"
        account_id = "555555555555"
        role = Role.from_arn(f"arn:aws:iam::{account_id}:role/{role_name}")
        profile = SamlProfileWithAlias(role=role, identity_type=IdentityTypes.BMW.value)
        sign_in_target = SignInTarget(role_name="different_role", account_id=account_id, name=None)
        assert not profile.matches(sign_in_target, identity_type=IdentityTypes.BMW.value)

    def test_not_matches_different_account_ids(self) -> None:
        role_name = "CDH-Developer"
        account_id = "555555555555"
        role = Role.from_arn(f"arn:aws:iam::{account_id}:role/{role_name}")
        profile = SamlProfileWithAlias(role=role, identity_type=IdentityTypes.BMW.value)
        sign_in_target = SignInTarget(role_name=role_name, account_id="666666666666", name=None)
        assert not profile.matches(sign_in_target, identity_type=IdentityTypes.BMW.value)
