# regions
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Optional

import importlib_metadata

DEFAULT_REGION = "eu-west-1"
DEFAULT_CHINA_REGION = "cn-north-1"
CHINA_REGIONS = [DEFAULT_CHINA_REGION, "cn-northwest-1"]
API_REGION = DEFAULT_REGION

# endpoints
CORE_API_ACCOUNTS_URL = "https://api.data.bmw.cloud/accounts"

CDH_AUTH_URL = "https://authentication.iam.data.bmw.cloud"
CDH_AUTH_INT_URL = "https://authentication.iam-int.data.bmw.cloud"
IDP_AUTH_URL = "https://idp.iam.data.bmw.cloud/saml"
IDP_AUTH_INT_URL = "https://idp.iam-int.data.bmw.cloud/saml"

AWS_FEDERATION_URL_CHINA = "https://signin.amazonaws.cn/federation"
AWS_FEDERATION_URL = "https://signin.aws.amazon.com/federation"

AWS_SIGNIN_URL_CHINA = "https://signin.amazonaws.cn"
AWS_SIGNIN_URL = "https://signin.aws.amazon.com/"

# proxy default settings
PROXY = "socks5://localhost:8888"
PROXIES = {"https": PROXY}

# config default
DEFAULT_LOGLEVEL = "info"
DEFAULT_BROWSER_OPEN_BEHAVIOUR = "default"

# keyring names
KEYRING_SERVICE_NAME = "cdh-cli"


def _get_version() -> str:
    try:
        # executable case: Temp folder is created by PyInstaller, its path is stored in _MEIPASS
        base_path = sys._MEIPASS  # type: ignore
        version_path = os.path.join(base_path, "VERSION-BINARY")
        with open(version_path) as version_bin_file:
            return version_bin_file.readline().strip()
    except (FileNotFoundError, AttributeError):
        return importlib_metadata.version("cdh")


CLI_VERSION = _get_version()


class IdentityCode(str, Enum):
    BMW = "bmw"
    BBA = "bba"
    IMPLICIT_CDH_AUTH = "implicit-cdh-auth"


IDENTITY_CODES = [x.value for x in IdentityCode]


class JwtType(str, Enum):
    INTERNAL = "internal"
    API = "api"


@dataclass(frozen=True)
class KeyringIdentity:
    jwt_type: JwtType
    identity_code: Optional[IdentityCode]


@dataclass(frozen=True)
class IdentityType:
    code: IdentityCode
    auto_profile_suffix: str

    def __str__(self) -> str:
        return f"{self.code.value.upper()} ID"


class IdentityTypes(Enum):
    BMW = IdentityType(
        code=IdentityCode.BMW,
        auto_profile_suffix="",
    )
    BBA = IdentityType(
        code=IdentityCode.BBA,
        auto_profile_suffix="bba",
    )
    IMPLICIT_CDH_AUTH = IdentityType(
        code=IdentityCode.IMPLICIT_CDH_AUTH,
        auto_profile_suffix="",
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


REGULAR_IDENTITY_TYPES = [IdentityTypes.BMW.value, IdentityTypes.BBA.value]


class AuthMethodStage(Enum):
    INT = "int"
    PROD = "prod"

    def get_stage_state_endpoint(self) -> str:
        auth_url = self._get_auth_url()
        return auth_url + "/cli/state"

    def get_stage_login_endpoint(self) -> str:
        auth_url = self._get_auth_url()
        return auth_url + "/cli/login"

    def get_stage_token_endpoint(self) -> str:
        auth_url = self._get_auth_url()
        return auth_url + "/cli/token"

    def get_stage_requester_endpoint(self) -> str:
        auth_url = self._get_auth_url()
        return auth_url + "/me"

    def get_stage_idp_auth_endpoint(self) -> str:
        if self == AuthMethodStage.PROD:
            return IDP_AUTH_URL
        elif self == AuthMethodStage.INT:
            return IDP_AUTH_INT_URL
        raise NotImplementedError(f"cannot get idp auth endpoint for stage: {self}")

    def _get_auth_url(self) -> str:
        if self == AuthMethodStage.PROD:
            auth_url = CDH_AUTH_URL
        elif self == AuthMethodStage.INT:
            auth_url = CDH_AUTH_INT_URL
        else:
            raise NotImplementedError(f"cannot get auth endpoints (i.e. state, login, token) for stage: {self}")
        return auth_url


AUTH_METHOD_STAGES = [x.value for x in AuthMethodStage]
DEFAULT_AUTH_METHOD_STAGE = AuthMethodStage.PROD


class BrowserOpenBehaviour(Enum):
    DEFAULT = "default"
    WINDOW = "window"
    TAB = "tab"

    def get_webbrowser_value(self) -> int:
        if self == BrowserOpenBehaviour.DEFAULT:
            return 0
        elif self == BrowserOpenBehaviour.WINDOW:
            return 1
        else:
            return 2


BROWSER_OPEN_BEHAVIOURS = [x.value for x in BrowserOpenBehaviour]
