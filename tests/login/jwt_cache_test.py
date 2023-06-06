from unittest.mock import call
from unittest.mock import Mock
from unittest.mock import patch

import keyring
import pytest

from cdh_utils.constants import IdentityCode
from cdh_utils.constants import JwtType
from cdh_utils.constants import KeyringIdentity
from cdh_utils.login.jwt_cache import JwtCache
from cdh_utils.login.jwt_response import JwtResponse


IDENTITY_KEYS = [
    (
        KeyringIdentity(identity_code=IdentityCode.BMW, jwt_type=JwtType.INTERNAL),
        f"jwt-{IdentityCode.BMW.value}-{JwtType.INTERNAL.value}",
    ),
    (
        KeyringIdentity(identity_code=IdentityCode.BMW, jwt_type=JwtType.API),
        f"jwt-{IdentityCode.BMW.value}-{JwtType.API.value}",
    ),
    (
        KeyringIdentity(identity_code=IdentityCode.BBA, jwt_type=JwtType.INTERNAL),
        f"jwt-{IdentityCode.BBA.value}-{JwtType.INTERNAL.value}",
    ),
    (
        KeyringIdentity(identity_code=None, jwt_type=JwtType.INTERNAL),
        JwtCache.LATEST_JWT_KEY_BY_JWT_TYPE[JwtType.INTERNAL],
    ),
    (
        KeyringIdentity(identity_code=None, jwt_type=JwtType.API),
        JwtCache.LATEST_JWT_KEY_BY_JWT_TYPE[JwtType.API],
    ),
]


class BaseJwtCacheTest:
    def setup_method(self) -> None:
        self.test_service_name = "test-service"

    def build_cache_with_enabled_keyring(self) -> JwtCache:
        with patch("cdh_utils.login.jwt_cache.keyring.get_keyring"):
            return JwtCache(use_keyring=True, keyring_service_name=self.test_service_name)


class TestKeyringCheck(BaseJwtCacheTest):
    def test_disable_unavailable_keyring(self) -> None:
        with patch("cdh_utils.login.jwt_cache.keyring.get_keyring") as mock_keyring:
            mock_keyring.return_value = keyring.backends.fail.Keyring()

            jwt_cache = JwtCache(use_keyring=True, keyring_service_name=self.test_service_name)

        with patch("cdh_utils.login.jwt_cache.keyring") as mock_keyring:
            jwt_response = jwt_cache.load_jwt(
                KeyringIdentity(identity_code=IdentityCode.BMW, jwt_type=JwtType.INTERNAL)
            )

        assert jwt_response is None
        mock_keyring.get_password.assert_not_called()


class TestStoreToJwtCache(BaseJwtCacheTest):
    def setup_method(self) -> None:
        super().setup_method()
        self.jwt_response = Mock(JwtResponse)
        self.serialized_response = "test-response"
        self.jwt_response.serialize.return_value = self.serialized_response

    def test_ignore_keyring_for_store(self) -> None:
        jwt_cache = JwtCache(use_keyring=False)

        with patch("cdh_utils.login.jwt_cache.keyring") as keyring:
            jwt_cache.store_jwt(self.jwt_response)

        keyring.set_password.assert_not_called()

    def test_store_jwt(self) -> None:
        identity = IdentityCode.BMW
        jwt_type = JwtType.INTERNAL
        self.jwt_response.actual_idp_name = identity
        self.jwt_response.jwt_type = jwt_type
        jwt_cache = self.build_cache_with_enabled_keyring()

        with patch("cdh_utils.login.jwt_cache.keyring") as keyring:
            jwt_cache.store_jwt(self.jwt_response)

        keyring.set_password.assert_has_calls(
            calls=[
                call(self.test_service_name, f"jwt-{identity.value}-{jwt_type.value}", self.serialized_response),
                call(self.test_service_name, jwt_cache.LATEST_JWT_KEY_BY_JWT_TYPE[jwt_type], self.serialized_response),
            ]
        )

    def test_store_jwt_unknown_identity(self) -> None:
        jwt_cache = self.build_cache_with_enabled_keyring()
        jwt_type = JwtType.INTERNAL
        self.jwt_response.jwt_type = jwt_type

        with patch("cdh_utils.login.jwt_cache.keyring") as keyring:
            jwt_cache.store_jwt(self.jwt_response)

        keyring.set_password.assert_has_calls(
            calls=[
                call(self.test_service_name, jwt_cache.LATEST_JWT_KEY_BY_JWT_TYPE[jwt_type], self.serialized_response),
            ]
        )


class TestLoadFromJwtCache(BaseJwtCacheTest):
    def setup_method(self) -> None:
        super().setup_method()
        self.jwt_response = JwtResponse(
            jwt_name="test-name",
            jwt_value="test-value",
        )
        self.serialized_response = self.jwt_response.serialize()

    def test_ignore_keyring_for_load(self) -> None:
        jwt_cache = JwtCache(use_keyring=False)
        keyring_identity = KeyringIdentity(jwt_type=JwtType.INTERNAL, identity_code=IdentityCode.BMW)

        jwt_response = jwt_cache.load_jwt(keyring_identity)

        assert jwt_response is None

    @pytest.mark.parametrize(["keyring_identity", "key"], IDENTITY_KEYS)
    def test_load_jwt(self, keyring_identity: KeyringIdentity, key: str) -> None:
        jwt_cache = self.build_cache_with_enabled_keyring()

        with patch("cdh_utils.login.jwt_cache.keyring") as keyring:
            keyring.get_password.return_value = self.serialized_response
            jwt_response = jwt_cache.load_jwt(keyring_identity)

        keyring.get_password.assert_called_once_with(self.test_service_name, key)
        assert jwt_response == self.jwt_response

    def test_load_jwt_no_stored_value(self) -> None:
        jwt_cache = self.build_cache_with_enabled_keyring()

        with patch("cdh_utils.login.jwt_cache.keyring") as keyring:
            keyring.get_password.return_value = None
            jwt_response = jwt_cache.load_jwt(KeyringIdentity(jwt_type=JwtType.INTERNAL, identity_code=None))

        assert jwt_response is None


class TestClearJwt(BaseJwtCacheTest):
    def setup_method(self) -> None:
        super().setup_method()

    @pytest.mark.parametrize(["keyring_identity", "key"], IDENTITY_KEYS)
    def test_clear_jwt(self, keyring_identity: KeyringIdentity, key: str) -> None:
        jwt_cache = self.build_cache_with_enabled_keyring()

        with patch("cdh_utils.login.jwt_cache.keyring") as keyring:
            jwt_cache.clear_jwt(keyring_identity)

        keyring.delete_password.assert_called_once_with(self.test_service_name, key)

    def test_clear_all_jwts(self) -> None:
        jwt_cache = self.build_cache_with_enabled_keyring()

        with patch("cdh_utils.login.jwt_cache.keyring") as keyring:
            jwt_cache.clear_all_jwts()

        keyring.delete_password.assert_has_calls(
            [call(self.test_service_name, key) for _, key in IDENTITY_KEYS], any_order=True
        )

    def test_no_clear_if_keyring_disabled(self) -> None:
        jwt_cache = JwtCache(use_keyring=False)

        with patch("cdh_utils.login.jwt_cache.keyring") as keyring:
            jwt_cache.clear_all_jwts()

        keyring.delete_password.assert_not_called()
