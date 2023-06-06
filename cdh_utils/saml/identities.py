from dataclasses import dataclass
from datetime import datetime
from datetime import timedelta
from typing import Dict
from typing import NamedTuple
from typing import Optional

from cdh_utils.constants import AuthMethodStage
from cdh_utils.constants import CHINA_REGIONS
from cdh_utils.constants import DEFAULT_CHINA_REGION
from cdh_utils.constants import IdentityType


@dataclass
class Role:
    _DEFAULT_PRINCIPAL = "arn:aws:iam::{}:saml-provider/authorization.bmw.cloud"
    _DEFAULT_PRINCIPAL_CN = "arn:aws-cn:iam::{}:saml-provider/authorization.bmw.cloud"

    role_arn: str
    principal_arn: str
    guest_role: Optional[bool]

    def __init__(self, role_arn: str, principal_arn: str, guest_role: Optional[bool] = None):
        self.role_arn = role_arn
        self.principal_arn = principal_arn
        self.guest_role = guest_role

    @classmethod
    def from_string(cls, string: str) -> "Role":
        arns = string.split(",")
        if len(arns) != 2:
            raise Exception(f"Cannot create role from {string}")
        return cls(role_arn=arns[0], principal_arn=arns[1])

    @classmethod
    def from_arn(cls, arn: str) -> "Role":
        if arn.startswith("arn:aws:iam::"):
            return Role(role_arn=arn, principal_arn=cls._DEFAULT_PRINCIPAL.format(get_account_number(arn)))
        if arn.startswith("arn:aws-cn:iam::"):
            return Role(role_arn=arn, principal_arn=cls._DEFAULT_PRINCIPAL_CN.format(get_account_number(arn)))
        else:
            raise InvalidRoleArn("INVALID ROLE: The role you provided is not valid!")

    @classmethod
    def is_valid_arn(cls, arn: Optional[str]) -> bool:
        if not arn or type(arn) != str:
            return False
        try:
            cls.from_arn(arn)
            return True
        except InvalidRoleArn:
            return False

    @classmethod
    def get_role_name_from_arn(cls, arn: str) -> str:
        return arn.split("/", 1)[1]

    @classmethod
    def get_account_number_from_arn(cls, arn: str) -> str:
        return get_account_number(arn)

    def get_name(self) -> str:
        return self.get_role_name_from_arn(self.role_arn)

    def get_account_number(self) -> str:
        return get_account_number(self.role_arn)

    def get_generic_name(self, identity_type: Optional[IdentityType]) -> str:
        suffix = f"_{identity_type.auto_profile_suffix}" if identity_type and identity_type.auto_profile_suffix else ""
        return f"{self.get_name()}_{self.get_account_number()}{suffix}"

    def __str__(self) -> str:
        return f"role {self.get_name()} in {self.get_account_number()}"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Role) and self.role_arn == other.role_arn

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Role):
            raise TypeError(f"Comparing Role and {other} not possible.")
        return self.role_arn < other.role_arn

    def __hash__(self) -> int:
        return hash(self.role_arn)


@dataclass
class SignInTarget:
    account_id: Optional[str]
    role_name: Optional[str]
    name: Optional[str]
    identity_type: Optional[IdentityType] = None
    is_arn: bool = False
    arn_role: Optional[Role] = None
    arn_sub_role: Optional[str] = None
    auth_method_stage: Optional[AuthMethodStage] = None

    @classmethod
    def from_arn(cls, arn: str, identity_type: IdentityType, sub_role: Optional[str] = None) -> "SignInTarget":
        role = Role.from_arn(arn)
        return SignInTarget(
            account_id=role.get_account_number(),
            role_name=role.get_name(),
            identity_type=identity_type,
            name=None,
            is_arn=True,
            arn_role=role,
            arn_sub_role=sub_role,
        )

    def to_saml_profile(self) -> "SamlProfileARN":
        if self.arn_role is None:
            raise ValueError("Only ARN sign in targets can be converted to saml profiles")
        return SamlProfileARN(self.arn_role, sub_role=self.arn_sub_role, identity_type=self.identity_type)


class SamlProfile:
    role: Role
    region: Optional[str]
    sub_role: Optional[str]
    session_length: Optional[int]

    def __init__(
        self,
        role: Role,
        region: Optional[str] = None,
        sub_role: Optional[str] = None,
        session_length: Optional[int] = None,
    ):
        self.role = role
        self.region = region
        if role and role.role_arn.startswith("arn:aws-cn:iam::") and (self.region not in CHINA_REGIONS):
            self.region = DEFAULT_CHINA_REGION  # TODO: is the correct place?
        self.sub_role = sub_role
        self.session_length = session_length

    @classmethod
    def get_generic_name(cls, role: Role, identity_type: Optional[IdentityType] = None) -> str:
        return f"{role.get_name()}_{role.get_account_number()}"

    @classmethod
    def from_arn(
        cls, arn: str, sub_role: Optional[str] = None, identity_type: Optional[IdentityType] = None
    ) -> "SamlProfile":
        role = Role.from_arn(arn)
        return SamlProfileARN(role, sub_role=sub_role, identity_type=identity_type)

    def matches(self, target: SignInTarget, identity_type: IdentityType) -> bool:
        raise NotImplementedError("Unable to determine Profile type")

    def get_representative_name(self) -> str:
        raise NotImplementedError("Unable to determine Profile type")


class SamlProfileWithName(SamlProfile):
    name: str

    def __init__(
        self,
        role: Role,
        profile_name: str = "",
        region: Optional[str] = None,
        sub_role: Optional[str] = None,
        session_length: Optional[int] = None,
    ):
        super().__init__(role, region, sub_role, session_length)
        self.name = profile_name

    def __repr__(self) -> str:
        return self.get_representative_name()

    def matches(self, target: SignInTarget, identity_type: IdentityType) -> bool:
        return self.name == target.name and identity_type == target.identity_type

    def get_representative_name(self) -> str:
        return self.name


class SamlProfileWithAlias(SamlProfile):
    alias: str

    def __init__(
        self,
        role: Role,
        region: Optional[str] = None,
        sub_role: Optional[str] = None,
        session_length: Optional[int] = None,
        identity_type: Optional[IdentityType] = None,
    ):
        super().__init__(role, region, sub_role, session_length)
        self.identity_type = identity_type
        self.alias = self.get_generic_name(role, identity_type)

    @classmethod
    def get_generic_name(cls, role: Role, identity_type: Optional[IdentityType] = None) -> str:
        suffix = f"_{identity_type.auto_profile_suffix}" if identity_type and identity_type.auto_profile_suffix else ""
        return f"{role.get_name()}_{role.get_account_number()}{suffix}"

    def __repr__(self) -> str:
        return self.get_representative_name()

    def matches(self, target: SignInTarget, identity_type: IdentityType) -> bool:
        role_name = self.role.get_name()
        number = self.role.get_account_number()
        return role_name == target.role_name and number == target.account_id

    def get_representative_name(self) -> str:
        return self.alias


class SamlProfileARN(SamlProfile):
    identity_type: Optional[IdentityType]

    def __init__(
        self,
        role: Role,
        identity_type: Optional[IdentityType],
        region: Optional[str] = None,
        sub_role: Optional[str] = None,
        session_length: Optional[int] = None,
    ):
        super().__init__(role, region, sub_role, session_length)
        self.identity_type = identity_type

    def get_representative_name(self) -> str:
        return self.role.get_generic_name(self.identity_type)

    def matches(self, target: SignInTarget, identity_type: IdentityType) -> bool:
        role_name = self.role.get_name()
        account_number = self.role.get_account_number()
        return (
            role_name == target.role_name
            and account_number == target.account_id
            and target.identity_type == identity_type
        )


def get_account_number(arn: str) -> str:
    if "provider" in arn:
        splitted_arn = arn.split("/")[0].split("::")[1].split(":")[0]
        return splitted_arn
    else:
        splitted_arn = arn.split("::")[1].split(":")[0]
        return splitted_arn


class InvalidRoleArn(Exception):
    pass


class AssumeRoleSamlData(NamedTuple):
    selected_role: str
    selected_principal: str


class BotoCredentials(NamedTuple):
    access_key: str
    secret_key: str
    session_token: str

    @classmethod
    def from_boto(cls, plain_dict: Dict[str, str]) -> "BotoCredentials":
        return BotoCredentials(
            access_key=plain_dict["AccessKeyId"],
            secret_key=plain_dict["SecretAccessKey"],
            session_token=plain_dict["SessionToken"],
        )

    def to_boto(self) -> Dict[str, str]:
        return {
            "aws_access_key_id": self.access_key,
            "aws_secret_access_key": self.secret_key,
            "aws_session_token": self.session_token,
        }


class Credentials(NamedTuple):
    boto_credentials: BotoCredentials
    max_session_duration: timedelta
    time_of_request: datetime
    region: str

    @property
    def expiry_date(self) -> datetime:
        return self.time_of_request + self.max_session_duration
