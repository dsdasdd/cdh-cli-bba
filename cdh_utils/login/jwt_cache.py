import logging
from typing import Optional

import keyring

from cdh_utils.constants import IdentityCode
from cdh_utils.constants import JwtType
from cdh_utils.constants import KEYRING_SERVICE_NAME
from cdh_utils.constants import KeyringIdentity
from cdh_utils.login.jwt_response import JwtResponse

LOG = logging.getLogger(__name__)


class JwtCache:
    LATEST_JWT_KEY_BY_JWT_TYPE = {
        JwtType.INTERNAL: "latest-jwt-internal",
        JwtType.API: "latest-jwt-api",
    }

    def __init__(self, use_keyring: bool, keyring_service_name: str = KEYRING_SERVICE_NAME) -> None:
        self._use_keyring = use_keyring
        self._service_name = keyring_service_name

        get_keyring = keyring.get_keyring()
        if use_keyring and isinstance(get_keyring, keyring.backends.fail.Keyring):
            LOG.warning("No usable keyring detected. Defaulting to making you enter the password every time.")
            self._use_keyring = False

    def store_jwt(self, jwt_response: JwtResponse) -> None:
        if self._use_keyring:
            serialized_response = jwt_response.serialize()
            if isinstance(jwt_response.actual_idp_name, IdentityCode):
                key = self._get_key_name(jwt_response.actual_idp_name, jwt_response.jwt_type)
                LOG.debug(f"Storing jwt in keyring under key {key}")
                keyring.set_password(self._service_name, key, serialized_response)
            LOG.debug(f"Storing jwt in keyring under key {self.LATEST_JWT_KEY_BY_JWT_TYPE[jwt_response.jwt_type]}")
            keyring.set_password(
                self._service_name, self.LATEST_JWT_KEY_BY_JWT_TYPE[jwt_response.jwt_type], serialized_response
            )

    def load_jwt(self, keyring_identity: KeyringIdentity) -> Optional[JwtResponse]:
        if self._use_keyring:
            key = self._get_key_of_identity(keyring_identity)
            serialized_jwt = keyring.get_password(self._service_name, key)
            if serialized_jwt:
                LOG.debug(f"Loaded jwt from keyring with key {key}")
                return JwtResponse.deserialize(serialized_jwt)
        LOG.debug("Could not find stored jwt for given identity.")
        return None

    def clear_all_jwts(self) -> None:
        for identity in list(IdentityCode) + [None]:
            for jwt_type in list(JwtType):
                try:
                    self.clear_jwt(KeyringIdentity(identity_code=identity, jwt_type=jwt_type))
                except Exception:
                    pass

    def clear_jwt(self, keyring_identity: KeyringIdentity) -> None:
        if self._use_keyring:
            key = self._get_key_of_identity(keyring_identity)
            LOG.debug(f"Removing jwt from keyring under key {key}")
            keyring.delete_password(self._service_name, key)

    def _get_key_of_identity(self, keyring_identity: KeyringIdentity) -> str:
        key = (
            self._get_key_name(identity=keyring_identity.identity_code, jwt_type=keyring_identity.jwt_type)
            if isinstance(keyring_identity.identity_code, IdentityCode)
            else self.LATEST_JWT_KEY_BY_JWT_TYPE[keyring_identity.jwt_type]
        )
        return key

    def _get_key_name(self, identity: IdentityCode, jwt_type: JwtType) -> str:
        return f"jwt-{identity.value}-{jwt_type.value}"
