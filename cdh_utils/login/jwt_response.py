import base64
import json
import logging
from dataclasses import asdict
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional

from cdh_utils.constants import IdentityCode
from cdh_utils.constants import JwtType

LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class JwtResponse:
    jwt_name: str
    jwt_value: str

    @property
    def cookies(self) -> str:
        return f"{self.jwt_name}={self.jwt_value}"

    @property
    @lru_cache(maxsize=1)
    def actual_idp_name(self) -> Optional[IdentityCode]:
        try:
            split = self.jwt_value.split(".")
            payload = json.loads(self._decode_base64(split[1]))
            jwt_idp = payload["idp"]
            return IdentityCode(jwt_idp)
        except Exception as e:
            LOG.debug(f"Error parsing JWT: {e}")
            return None

    def _decode_base64(self, encoded: str) -> str:
        return base64.b64decode(encoded + "==").decode("utf-8")

    def serialize(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def deserialize(cls, raw: str) -> "JwtResponse":
        return cls(**json.loads(raw))

    @property
    def jwt_type(self) -> JwtType:
        return JwtType.INTERNAL if "internal" in self.jwt_name else JwtType.API
