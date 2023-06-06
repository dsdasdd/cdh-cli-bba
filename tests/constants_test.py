import pytest

from cdh_utils.constants import IdentityTypes


class TestIdentityTypes:
    @pytest.mark.parametrize("identity_type_enum", IdentityTypes)
    def test_of_returns_value_from_code_str(self, identity_type_enum: IdentityTypes) -> None:
        assert IdentityTypes.of(identity_type_enum.value.code.value) is identity_type_enum.value

    def test_raises_for_unknown_code(self) -> None:
        with pytest.raises(ValueError):
            IdentityTypes.of("unknown")

    @pytest.mark.parametrize("identity_type_enum", IdentityTypes)
    def test_of_returns_value_from_code(self, identity_type_enum: IdentityTypes) -> None:
        assert IdentityTypes.of_code(identity_type_enum.value.code) is identity_type_enum.value
