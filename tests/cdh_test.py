import configparser
import os
from datetime import datetime
from datetime import timedelta
from typing import Any
from typing import Callable
from typing import Dict
from typing import Optional
from unittest.mock import Mock
from unittest.mock import mock_open
from unittest.mock import patch

import pytest
from bs4 import BeautifulSoup
from bs4 import Tag
from requests.cookies import RequestsCookieJar

import cdh
from cdh_utils import saml
from cdh_utils.constants import DEFAULT_REGION
from cdh_utils.constants import IdentityTypes
from cdh_utils.saml.identities import BotoCredentials
from cdh_utils.saml.identities import Credentials
from cdh_utils.saml.identities import SamlProfile
from cdh_utils.saml.saml_parser import SamlParser
from cdh_utils.utils.browser_handler import BrowserHandler
from cdh_utils.utils.cdh_manager import CdhManager
from cdh_utils.utils.cdhconfig import CdhConfig
from cdh_utils.utils.connection_handler import ConnectionHandler
from cdh_utils.utils.helpers import ConsolePrinter
from cdh_utils.utils.helpers import Prompter
from cdh_utils.utils.setup import Setup

FAKE_TEST_SAML_PATH = os.path.dirname(__file__) + "/fake_test_saml.txt"
MAX_SESSION_DURATION = timedelta(hours=5)
SESSION_DURATION_WITH_SUBROLE = timedelta(hours=1)
NOW = datetime(2020, 1, 1)

AWS_CONFIG = {
    "invalid": {
        "aws_access_key_id": "123",
        "aws_secret_access_key": "456",
        "aws_session_token": "token1",
        "valid_until": (NOW - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"),
        "region": DEFAULT_REGION,
    },
    "valid": {
        "aws_access_key_id": "321",
        "aws_secret_access_key": "654",
        "aws_session_token": "token2",
        "valid_until": (datetime(2100, 1, 1) + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"),
        "region": DEFAULT_REGION,
    },
}


def profile_to_text(name: str, cred: dict) -> str:
    return f"[{name}]\n" + "\n".join([f"{key} = {value}" for key, value in cred.items()])


def credentials_file_content(config: Dict[str, Any]) -> str:
    res = "\n\n".join([profile_to_text(name, cred) for name, cred in config.items()])
    return res


def recover_profile_from_block(block: str) -> Dict[str, Any]:
    lines = block.splitlines()
    name = lines.pop(0).lstrip("[").rstrip("]")
    profile: Dict[str, Any] = {name: {}}
    for i, line in enumerate(lines):
        key, value = line.split("=")
        profile[name].update({key.strip(): value.strip()})
    return profile


def aws_config_from_file_content(content: str) -> Dict[str, Any]:
    config = {}
    blocks = content.split("\n\n")
    for block in blocks:
        if block.strip() != "":
            config.update(recover_profile_from_block(block))
    return config


def get_fake_credentials(
    access_key: str = "123",
    secret_key: str = "456",
    session_token: str = "token1",
    max_session_duration: timedelta = MAX_SESSION_DURATION,
    time_of_request: datetime = datetime.fromtimestamp(0),
    region: str = DEFAULT_REGION,
) -> Credentials:
    return Credentials(
        boto_credentials=BotoCredentials(
            access_key=access_key,
            secret_key=secret_key,
            session_token=session_token,
        ),
        max_session_duration=max_session_duration,
        time_of_request=time_of_request,
        region=region,
    )


def get_fake_server_response(
    value: str,
    nsc_dlge: str,
    awsalb: str,
    payload: Optional[bool] = None,
    hasCookies: bool = True,
    text: Optional[str] = None,
) -> Mock:
    response = Mock()
    response.text = text
    response.status_code = 200
    location = "https://authorization.bmw.cloud/cgi/tm?code=" + value
    if payload is not None:
        response.headers = {"Location": location, "Cookie": value, "response": payload}
    else:
        response.headers = {"Location": location, "Cookie": value}
    response.cookies = RequestsCookieJar()
    if hasCookies:
        response.cookies.set("AWSALB", awsalb)
        response.cookies.set("NSC_DLGE", nsc_dlge)
    return response


def get_old_saml() -> str:
    lxml_object = BeautifulSoup(get_old_response_saml().text, "lxml")
    form_tag = lxml_object.findChild("form")
    if not isinstance(form_tag, Tag):
        raise AttributeError("form attribute is not of type Tag")
    input_tag = form_tag.findChild("input")
    if not isinstance(input_tag, Tag):
        raise AttributeError("input attribute is not of type Tag")
    return input_tag.attrs["value"]


def get_old_response_saml() -> Mock:
    with open(FAKE_TEST_SAML_PATH, "rb") as file:
        return Mock(text=file.read(), status_code=200)


def get_config_checker(
    profile: SamlProfile, make_default: bool = False
) -> Callable[[configparser.RawConfigParser, str], None]:
    profile_name = "default" if make_default else profile.get_representative_name()

    def check_config_file(config: configparser.RawConfigParser, filename: str) -> None:
        assert config.get(profile_name, "aws_access_key_id") == "123"
        assert config.get(profile_name, "aws_secret_access_key") == "456"
        assert config.get(profile_name, "aws_session_token") == "token1"

    return check_config_file


def build_expected_valid_until(credentials: saml.identities.Credentials) -> str:
    return credentials.expiry_date.strftime("%Y-%m-%d %H:%M:%S")


class TestMain:
    def test_get_roles(self) -> None:
        role_element = Mock()
        role_element.text = None
        parser = SamlParser(b"<a></a>")
        tree = Mock()
        tree.findall.return_value = [role_element]
        parser.tree = tree
        roles = parser.get_roles()
        assert len(roles) == 0

    def test_get_roles_with_duplicates(self) -> None:
        role_element = Mock()
        role_element.text = (
            "arn:aws:iam::777777777777:role/CDHX-DevOps,"
            "arn:aws:iam::777777777777:saml-provider/authorization.bmwgroup.net "
        )
        parser = SamlParser(b"<a></a>")
        tree = Mock()
        tree.findall.return_value = [role_element, role_element]
        parser.tree = tree
        roles = parser.get_roles()
        assert len(roles) == 1


@pytest.fixture()
def click_prompter() -> Mock:
    click_prompter = Mock(spec=Prompter)
    click_prompter.prompt_select_from_dict.return_value = IdentityTypes.BMW.value
    return click_prompter


class TestLogin:
    @patch("builtins.open", new_callable=mock_open, read_data=credentials_file_content(AWS_CONFIG))
    def test_with_valid_credentials(self, mock_credentials_file: Mock) -> None:
        click_prompter = Mock(spec=Prompter)
        console_printer = Mock(spec=ConsolePrinter)
        connection_handler = Mock(ConnectionHandler)
        connection_handler.federation_url_requests_get.return_value = Mock(text='{"SigninToken": "token1"}')
        browser_handler = Mock(spec=BrowserHandler)
        manager = CdhManager(
            setup=Setup(),
            config=CdhConfig(ignore_config=True, ignore_keyring=True),
            console_printer=console_printer,
            click_prompter=click_prompter,
            connection_handler=connection_handler,
            browser_handler=browser_handler,
        )
        get_credentials_mock = Mock()
        with patch("cdh_utils.utils.cdh_manager.CdhManager.get_and_write_credentials", get_credentials_mock):
            manager.perform_login("valid")
            get_credentials_mock.assert_not_called()
            browser_handler.open_new_with_profile.assert_called_once()

    @patch("builtins.open", new_callable=mock_open, read_data=credentials_file_content(AWS_CONFIG))
    def test_with_expired_credentials(self, mock_credentials_file: Mock) -> None:
        click_prompter = Mock(spec=Prompter)
        console_printer = Mock(spec=ConsolePrinter)
        connection_handler = Mock(ConnectionHandler)
        connection_handler.federation_url_requests_get.return_value = Mock(text='{"SigninToken": "token1"}')
        browser_handler = Mock(spec=BrowserHandler)
        manager = CdhManager(
            setup=Setup(),
            config=CdhConfig(ignore_config=True, ignore_keyring=True),
            console_printer=console_printer,
            click_prompter=click_prompter,
            connection_handler=connection_handler,
            browser_handler=browser_handler,
        )
        get_credentials_mock = Mock(return_value=get_fake_credentials())
        with patch("cdh_utils.utils.cdh_manager.CdhManager.get_and_write_credentials", get_credentials_mock):
            manager.perform_login("expired")
            get_credentials_mock.assert_called_with()
            browser_handler.open_new_with_profile.assert_called_once()

    def test_login_url_region(self) -> None:
        region = "us-east-1"
        connection_handler = Mock(spec=ConnectionHandler)
        connection_handler.federation_url_requests_get.return_value = Mock(text='{"SigninToken": "token1"}')
        click_prompter = Mock(spec=Prompter)
        click_prompter.prompt_select_from_dict.return_value = IdentityTypes.BBA.value
        manager = CdhManager(
            setup=Setup(),
            config=CdhConfig(ignore_config=True, ignore_keyring=True),
            connection_handler=connection_handler,
            click_prompter=click_prompter,
        )
        credentials = get_fake_credentials(region=region)
        login_url = manager.get_federation_url(credentials)
        assert region in login_url


class TestVersionCheck:
    @pytest.mark.parametrize(
        ["latest_version", "package_version"],
        (
            # versions as provided by setuptools-scm:
            ["3.0.1", "3.0.0"],
            ["3.1.0", "3.0.9"],
            ["4.0.0", "3.9.9"],
            ["3.0.2", "3.0.1.dev3+abcdef1234"],
            ["3.0.1", "3.0.1.dev3+abcdef1234"],
            ["3.0.2", "3.0.1rc1"],
            ["3.0.1", "3.0.1rc1"],
            ["3.0.2", "3.0.1rc1.dev1+ga2fe7b8"],
            ["3.0.1", "3.0.1rc1.dev1+ga2fe7b8"],
            # actual semver versions, currently not supplied by setuptools-scm:
            ["3.0.2", "3.0.1-rc1"],
            ["3.0.1", "3.0.1-rc1"],
            ["3.0.2", "3.0.1-rc1+build1"],
            ["3.0.1", "3.0.1-rc1+build1"],
            ["3.0.2", "3.0.1+build1"],
            ["3.0.1", "3.0.1+build1"],
        ),
    )
    def test_newer_version(self, latest_version: str, package_version: str) -> None:
        assert cdh.is_newer_than_package_version(latest_version, package_version)

    @pytest.mark.parametrize(
        ["latest_version", "package_version"],
        (
            # versions as provided by setuptools-scm:
            ["3.0.0", "3.0.0"],
            ["3.0.9", "3.1.0"],
            ["2.9.9", "3.0.0"],
            ["3.0.0", "3.0.1.dev3+abcdef1234"],
            ["3.0.0", "3.0.1rc1"],
            ["3.0.0", "3.0.1rc1.dev1+abcdef12"],
            # actual semver versions, currently not supplied by setuptools-scm:
            ["3.0.0", "3.0.1-rc1"],
            ["3.0.0", "3.0.1-rc1+build1"],
            ["3.0.0", "3.0.1+build1"],
        ),
    )
    def test_not_newer_version(self, latest_version: str, package_version: str) -> None:
        assert cdh.is_newer_than_package_version(latest_version, package_version) is False

    @pytest.mark.parametrize(
        ["package_version", "expected_converted"],
        (
            # versions as provided by setuptools-scm:
            ["3.0.0", "3.0.0"],
            ["3.0.1.dev3+abcdef1234", "3.0.1+dev3-abcdef1234"],
            ["3.0.1rc1", "3.0.1+rc1"],
            ["3.0.1rc1.dev1+abcdef12", "3.0.1+rc1-dev1-abcdef12"],
            # actual semver versions, currently not supplied by setuptools-scm:
            ["3.0.1-rc1", "3.0.1+rc1"],
            ["3.0.1-rc1+build1", "3.0.1+rc1-build1"],
            ["3.0.1+build1", "3.0.1+build1"],
        ),
    )
    def test_convert_package_version_to_semver(self, package_version: str, expected_converted: str) -> None:
        assert cdh.convert_package_version_to_semver(package_version) == expected_converted
