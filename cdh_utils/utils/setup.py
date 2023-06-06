from dataclasses import dataclass
from typing import Optional

from cdh_utils.constants import IdentityCode


@dataclass
class Setup:
    def __init__(
        self,
        target_raw: Optional[str] = None,
        alias: Optional[str] = None,
        proxy: bool = False,
        ignore_config: bool = True,
        ignore_keyring: bool = True,
        output_credentials: bool = False,
        sub_role: Optional[str] = None,
        session_length: Optional[int] = None,
        auth_method_stage: Optional[str] = None,
        sanity_check: Optional[bool] = None,
        ignore_cache_file: bool = False,
        auth_idp: Optional[str] = None,
    ):
        self.target_raw = target_raw
        self.alias = alias
        self.proxy = proxy
        self.ignore_config = ignore_config
        self.ignore_keyring = ignore_keyring
        self.output_credentials = output_credentials
        self.sub_role = sub_role
        self.session_length = session_length
        self.auth_method_stage = auth_method_stage
        self.sanity_check = sanity_check
        self.ignore_cache_file = ignore_cache_file
        self.auth_idp = IdentityCode(auth_idp) if auth_idp else None
