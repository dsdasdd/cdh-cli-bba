# regions
from dataclasses import dataclass
from enum import Enum
from typing import Optional

DEFAULT_REGION = "eu-west-1"
DEFAULT_CHINA_REGION = "cn-north-1"
CHINA_REGIONS = [DEFAULT_CHINA_REGION, "cn-northwest-1"]
API_REGION = DEFAULT_REGION

# config default
DEFAULT_LOGLEVEL = "info"

# keyring names
KEYRING_SERVICE_NAME = "cdh-cli"
KEYRING_BMW_PIN_NAME = "pin"
KEYRING_BMW_PASSWORD_NAME = "password"
KEYRING_BBA_PASSWORD_NAME = "password-bba"


class IdentityCode(Enum):
    BMW = "bmw"
    BBA = "bba"


@dataclass(frozen=True)
class IdentityType:
    code: IdentityCode
    keyring_service_name = KEYRING_SERVICE_NAME
    keyring_password_name: str
    keyring_pin_name: Optional[str]
    supports_pin: bool
    username_alternative_name: str
    auto_profile_suffix: str

    def __str__(self) -> str:
        return f"{self.code.value.upper()} ID"


class IdentityTypes(Enum):
    BMW = IdentityType(
        code=IdentityCode.BMW,
        keyring_password_name=KEYRING_BMW_PASSWORD_NAME,
        keyring_pin_name=KEYRING_BMW_PIN_NAME,
        supports_pin=True,
        username_alternative_name="qnumber",
        auto_profile_suffix="",
    )
    BBA = IdentityType(
        code=IdentityCode.BBA,
        keyring_password_name=KEYRING_BBA_PASSWORD_NAME,
        keyring_pin_name=None,
        supports_pin=False,
        username_alternative_name="digital_id",
        auto_profile_suffix="bba",
    )

    @staticmethod
    def of(code_str: str) -> IdentityType:
        try:
            return next(
                identity_type.value for identity_type in IdentityTypes if identity_type.value.code.value == code_str
            )
        except StopIteration:
            raise ValueError(f'No IdentityType found for "{code_str}"') from None

    @staticmethod
    def of_code(code: IdentityCode) -> IdentityType:
        return IdentityTypes.of(code.value)
