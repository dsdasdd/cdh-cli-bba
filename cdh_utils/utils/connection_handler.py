import json
import logging
import os
import time
import uuid
from contextlib import contextmanager
from datetime import datetime
from datetime import timedelta
from functools import lru_cache
from json import JSONDecodeError
from os.path import expanduser
from typing import Any
from typing import Dict
from typing import Generator
from typing import List
from typing import Optional
from typing import Set
from urllib.parse import urlparse

import boto3
import requests
from aws_requests_auth.aws_auth import AWSRequestsAuth
from botocore.exceptions import BotoCoreError
from botocore.exceptions import ClientError
from botocore.exceptions import ParamValidationError
from requests import RequestException
from requests import Response
from requests import Session

from cdh_utils.constants import API_REGION
from cdh_utils.constants import AWS_FEDERATION_URL
from cdh_utils.constants import AWS_FEDERATION_URL_CHINA
from cdh_utils.constants import AWS_SIGNIN_URL
from cdh_utils.constants import AWS_SIGNIN_URL_CHINA
from cdh_utils.constants import CHINA_REGIONS
from cdh_utils.constants import CORE_API_ACCOUNTS_URL
from cdh_utils.constants import DEFAULT_REGION
from cdh_utils.constants import IdentityType
from cdh_utils.saml.identities import BotoCredentials
from cdh_utils.saml.identities import Credentials
from cdh_utils.saml.identities import Role
from cdh_utils.saml.identities import SamlProfile
from cdh_utils.saml.saml_parser import SamlParser
from cdh_utils.utils.botoclient import build_boto_default_config
from cdh_utils.utils.exceptions import AccessDeniedError
from cdh_utils.utils.exceptions import ScriptError
from cdh_utils.utils.helpers import ConsolePrinter
from cdh_utils.utils.log_context import identity_context
from cdh_utils.utils.performance import performance_timer

LOG = logging.getLogger(__name__)


def get_aws_federation_url(region: Optional[str]) -> str:
    if region in CHINA_REGIONS:
        return AWS_FEDERATION_URL_CHINA
    else:
        return AWS_FEDERATION_URL


def get_aws_signin_url(region: str) -> str:
    if region in CHINA_REGIONS:
        return AWS_SIGNIN_URL_CHINA
    else:
        return AWS_SIGNIN_URL


class FriendlyNamesCacheHandler:
    def __init__(self, ignore_cache_file: bool = False):
        self.ignore_cache_file = ignore_cache_file
        self._cache = {} if ignore_cache_file else FriendlyNamesCacheHandler.get_friendly_name_cache()

    def update_friendly_names_cache(self, account: str, friendly_names: Dict[str, str]) -> Dict[str, str]:
        account_block = {account: {"last_update_on": str(datetime.now()), "data": friendly_names}}
        self._cache.update(account_block)
        return friendly_names

    def update_accounts_without_friendly_names_cache(self, accounts_without_friendly_names: List[str]) -> None:
        account_block = {
            "_accounts_without_friendly_names": {
                "last_update_on": str(datetime.now()),
                "data": accounts_without_friendly_names,
            }
        }
        self._cache.update(account_block)

    def write_cache_to_file(self) -> None:
        if not self.ignore_cache_file and not self.is_cache_valid():
            self.save_account_friendly_names_to_cache(self._cache)

    @staticmethod
    def get_account_friendly_names_cache_path() -> str:
        home = expanduser("~")
        cache_folder_path = os.path.join(home, ".config", "cdh", "cache")
        os.makedirs(cache_folder_path, exist_ok=True)
        return os.path.join(cache_folder_path, ".account-friendly-names-cache.yaml")

    def save_account_friendly_names_to_cache(self, friendly_names: Dict) -> None:
        LOG.debug("Updating friendly names cache")
        cache_path = self.get_account_friendly_names_cache_path()
        try:
            with open(cache_path, "w") as cache_file:
                json.dump(friendly_names, cache_file)
        except PermissionError:
            LOG.warning("unable to write information to cache")

    @staticmethod
    def get_friendly_name_cache() -> Dict[str, Dict]:
        cache_path = FriendlyNamesCacheHandler.get_account_friendly_names_cache_path()
        try:
            with open(cache_path) as cache_file:
                cached_friendly_names = json.load(cache_file)

            return cached_friendly_names
        except (FileNotFoundError, PermissionError, JSONDecodeError):
            return {}

    def is_cache_valid(self) -> bool:
        FRIENDLY_NAMES_CACHE_MAX_LIFETIME_SECONDS = 24 * 60 * 60  # one day in seconds
        try:
            cache_lifetime = time.time() - os.path.getmtime(self.get_account_friendly_names_cache_path())
            return cache_lifetime < FRIENDLY_NAMES_CACHE_MAX_LIFETIME_SECONDS
        except OSError:
            return False

    def are_all_account_numbers_in_cache(self, query: Set[str]) -> bool:
        unavailable_cache = self._cache.get("_accounts_without_friendly_names")
        unavailable = set()
        if unavailable_cache and unavailable_cache.get("data"):
            unavailable = set(unavailable_cache["data"])
        return len(query - unavailable) == 0


class ConnectionHandler:
    def __init__(
        self, session: Session, region: Optional[str], friendly_names_cache_handler: FriendlyNamesCacheHandler
    ):
        self.session = session
        self.region = region
        self.friendly_names_cache_handler = friendly_names_cache_handler
        self.console_printer = ConsolePrinter()

    def set_additional_cookies(self, values: Dict[str, str]) -> None:
        self.session.cookies.update(values)

    @lru_cache()
    def boto3_assume_role(self, sts_client: Any, saml_b64: str, role: Role) -> BotoCredentials:
        response = sts_client.assume_role_with_saml(
            RoleArn=role.role_arn,
            PrincipalArn=role.principal_arn,
            SAMLAssertion=saml_b64,
        )
        return BotoCredentials.from_boto(response["Credentials"])

    def boto3_assume_role_with_credentials(
        self,
        role_arn: str,
        region: str,
        credentials: BotoCredentials,
        max_session_duration: timedelta = timedelta(hours=1),
        user_id: str = str(uuid.uuid4()),
    ) -> BotoCredentials:
        boto_credentials = credentials.to_boto()
        sts_client = boto3.client(
            "sts",
            aws_access_key_id=boto_credentials["aws_access_key_id"],
            aws_secret_access_key=boto_credentials["aws_secret_access_key"],
            aws_session_token=boto_credentials["aws_session_token"],
            region_name=region,
            config=build_boto_default_config(),
        )
        response = sts_client.assume_role(
            RoleArn=role_arn, RoleSessionName=user_id, DurationSeconds=max_session_duration.seconds
        )
        return BotoCredentials.from_boto(response["Credentials"])

    def boto3_assume_role_max_session_duration(
        self, sts_client: Any, saml_b64: str, role: Role, max_session_duration: timedelta
    ) -> BotoCredentials:
        response = sts_client.assume_role_with_saml(
            RoleArn=role.role_arn,
            PrincipalArn=role.principal_arn,
            SAMLAssertion=saml_b64,
            DurationSeconds=max_session_duration.seconds,
        )
        return BotoCredentials.from_boto(response["Credentials"])

    def boto3_get_role(self, iam_client: Any, role_arn: str) -> Dict[str, Any]:
        return iam_client.get_role(RoleName=role_arn.split("/")[-1])

    def federation_url_requests_get(self, request_parameters: str, region: Optional[str] = None) -> Response:
        return requests.get(get_aws_federation_url(region) + request_parameters, timeout=10)

    def session_get(self, endpoint: str, params: Optional[Dict] = None, headers: Optional[Dict] = None) -> Response:
        return self.session.get(endpoint, params=params, headers=headers)

    def session_get_dont_follow_redirects(self, endpoint: str) -> Response:
        return self.session.get(endpoint, allow_redirects=False)

    def session_post(
        self, endpoint: str, params: Optional[dict] = None, data: Optional[Dict] = None, headers: Optional[Dict] = None
    ) -> Response:
        return self.session.post(url=endpoint, params=params, data=data, headers=headers)

    @performance_timer
    def get_account_friendly_names(
        self,
        profile: SamlProfile,
        saml_b64: str,
        sts_client: Any,
        identity_type: Optional[IdentityType],
        force_cache_update: bool,
    ) -> Dict[str, str]:
        account = str(profile)
        if force_cache_update or not self.friendly_names_cache_handler.is_cache_valid():
            friendly_names = self.get_account_friendly_names_from_endpoint(saml_b64, sts_client, identity_type, profile)
            self.friendly_names_cache_handler.update_friendly_names_cache(account, friendly_names)

        cache_entry_for_account = self.friendly_names_cache_handler._cache.get(account)
        if cache_entry_for_account:
            friendly_names_entry = cache_entry_for_account.get("data")
            return friendly_names_entry if friendly_names_entry else {}

        return dict()

    def get_account_friendly_names_from_endpoint(
        self, saml_b64: str, sts_client: Any, identity_type: Optional[IdentityType], profile: SamlProfile
    ) -> Dict[str, str]:
        LOG.debug(f"Query friendly names via API {CORE_API_ACCOUNTS_URL}")

        with identity_context(identity_type):
            try:
                credentials = self.get_temp_credentials(saml_b64, profile, sts_client).boto_credentials
            except BotoCoreError as error:
                LOG.info(f"Failed to get credentials for friendly name: {error}")
                return {}

        friendly_names = {}
        try:
            auth = AWSRequestsAuth(
                aws_access_key=credentials.access_key,
                aws_secret_access_key=credentials.secret_key,
                aws_host=urlparse(CORE_API_ACCOUNTS_URL).hostname,
                aws_region=API_REGION,
                aws_service="execute-api",
                aws_token=credentials.session_token,
            )

            raw = self.session.get(CORE_API_ACCOUNTS_URL, auth=auth).json()

            accounts = raw["accounts"]
            for account in accounts:
                friendly_name = account["data"].get("account_friendly_name", None) or account["data"].get(
                    "accountFriendlyName", None
                )
                if type(friendly_name) is str:
                    friendly_names[account["id"]] = str.replace(friendly_name, "BMW CDH ", "")

        except KeyError:
            LOG.debug("No accounts could be queried")
        except RequestException as e:
            LOG.info(f"Failed to query API {CORE_API_ACCOUNTS_URL}: {e}")

        return friendly_names

    def get_max_session_duration(self, credentials: BotoCredentials, profile: SamlProfile) -> timedelta:
        if profile.session_length:
            return timedelta(minutes=profile.session_length)
        if profile.sub_role:
            # limited to 1h for role chaining; session duration generally cannot be less than 1h
            return timedelta(hours=1)

        role_arn = profile.role.role_arn
        # special treatment for the FG-25 sso role, bc max session duration is known
        if role_arn in {"arn:aws:iam::111802884793:role/sso", "arn:aws-cn:iam::265795087340:role/sso"}:
            return timedelta(hours=12)

        iam_client = boto3.client(
            "iam",
            aws_access_key_id=credentials.access_key,
            aws_secret_access_key=credentials.secret_key,
            aws_session_token=credentials.session_token,
            region_name=profile.region or DEFAULT_REGION,
            config=build_boto_default_config(),
        )
        role_props = self.boto3_get_role(iam_client, role_arn)
        return timedelta(seconds=role_props["Role"]["MaxSessionDuration"])

    @performance_timer
    def get_temp_credentials(self, saml_b64: str, profile: SamlProfile, sts_client: Any = None) -> Credentials:
        user_id = SamlParser.from_base64(saml_b64).get_user_id()
        region = profile.region or self.region or DEFAULT_REGION

        sts_client = sts_client or boto3.client("sts", region_name=region, config=build_boto_default_config())

        credentials = self._fetch_credentials(
            saml_b64=saml_b64,
            profile=profile,
            sts_client=sts_client,
            region=region,
            user_id=user_id,
        )

        return credentials

    def _fetch_credentials(
        self, saml_b64: str, profile: SamlProfile, sts_client: Any, region: str, user_id: str
    ) -> Credentials:
        role = profile.role

        with self._convert_boto_error_to_script_error(
            f"Initial retrieval of credentials for role '{role.get_name()} in {role.get_account_number()}"
        ):
            requested_at = datetime.now()
            base_credentials = self.boto3_assume_role(sts_client, saml_b64, role)

        if profile.sub_role:
            return self.get_sub_credentials(
                base_credentials=base_credentials,
                profile=profile,
                user_id=user_id,
                region=region,
            )

        try:
            return self._get_max_duration_credentials(
                base_credentials=base_credentials,
                profile=profile,
                sts_client=sts_client,
                saml_b64=saml_b64,
                region=region,
            )
        except ScriptError as e:
            self.console_printer.print_warning(
                f"Unable to increase session duration for role {role} ({e}), defaulting to one hour."
            )
            return Credentials(
                boto_credentials=base_credentials,
                max_session_duration=timedelta(hours=1),
                time_of_request=requested_at,
                region=region,
            )

    def _get_max_duration_credentials(
        self, base_credentials: BotoCredentials, profile: SamlProfile, sts_client: Any, saml_b64: str, region: str
    ) -> Credentials:
        with self._convert_boto_error_to_script_error("Getting credentials with maximum possible session duration"):
            max_session_duration = self.get_max_session_duration(
                credentials=base_credentials,
                profile=profile,
            )
            requested_at = datetime.now()
            credentials = self.boto3_assume_role_max_session_duration(
                sts_client=sts_client,
                saml_b64=saml_b64,
                role=profile.role,
                max_session_duration=max_session_duration,
            )
            return Credentials(
                boto_credentials=credentials,
                max_session_duration=max_session_duration,
                time_of_request=requested_at,
                region=region,
            )

    def get_sub_credentials(
        self, base_credentials: BotoCredentials, profile: SamlProfile, user_id: str, region: str
    ) -> Credentials:
        max_session_duration = self.get_max_session_duration(base_credentials, profile)
        if not profile.sub_role:
            raise ScriptError(f"Profile '{profile}' does not contain a subrole")

        with self._convert_boto_error_to_script_error("Getting credentials for subrole"):
            requested_at = datetime.now()
            boto_credentials = self.boto3_assume_role_with_credentials(
                role_arn=profile.sub_role,
                credentials=base_credentials,
                region=profile.region or self.region or DEFAULT_REGION,
                max_session_duration=max_session_duration,
                user_id=user_id,
            )
            return Credentials(
                boto_credentials=boto_credentials,
                max_session_duration=max_session_duration,
                time_of_request=requested_at,
                region=region,
            )

    @contextmanager
    def _convert_boto_error_to_script_error(self, action_performed: str) -> Generator[None, None, None]:
        try:
            yield
        except ClientError as e:
            error_message = e.response["Error"]["Message"]
            if e.response["Error"]["Code"] == "AccessDenied":
                raise AccessDeniedError(error_message)
            raise ScriptError(error_message)
        except ParamValidationError as e:
            raise ScriptError(f"{action_performed} failed with the following error: {e}")

    def are_all_account_numbers_in_cache(self, query: Set[str]) -> bool:
        return self.friendly_names_cache_handler.are_all_account_numbers_in_cache(query)

    def write_cache_to_file(self) -> None:
        self.friendly_names_cache_handler.write_cache_to_file()

    def update_accounts_without_friendly_names_cache(self, accounts_without_friendly_names: List[str]) -> None:
        self.friendly_names_cache_handler.update_accounts_without_friendly_names_cache(accounts_without_friendly_names)
