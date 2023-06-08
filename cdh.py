#!/usr/bin/env python3
import logging
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from datetime import timedelta
from json import JSONDecodeError
from os.path import expanduser
from pathlib import Path
from sys import exit
from typing import Any
from typing import Callable
from typing import List
from typing import Optional
print("1111111111111111111")
print("232323232323232323232")
import click
import requests
import semver
import urllib3
from requests import RequestException
from requests import Response

from cdh_utils.constants import AUTH_METHOD_STAGES
from cdh_utils.constants import CLI_VERSION
from cdh_utils.constants import DEFAULT_LOGLEVEL
from cdh_utils.constants import IDENTITY_CODES
from cdh_utils.constants import IdentityTypes
from cdh_utils.constants import PROXY
from cdh_utils.constants import REGULAR_IDENTITY_TYPES
from cdh_utils.login.handlers import ScriptError
from cdh_utils.login.jwt_cache import JwtCache
from cdh_utils.utils.autocomplete import AutoCompleter
from cdh_utils.utils.cdh_manager import CdhManager
from cdh_utils.utils.cdhconfig import CdhConfig
from cdh_utils.utils.exceptions import ProfileNotFoundInResponseError
from cdh_utils.utils.helpers import ConsolePrinter
from cdh_utils.utils.helpers import Prompter
from cdh_utils.utils.log_context import add_log_factory_for_context
from cdh_utils.utils.log_context import identity_context
from cdh_utils.utils.setup import Setup

CONFIG_FILE_PATH_FOR_DISPLAY = "~/.config/cdh/config.yml"
OPTION_ALIAS_HELP = (
    "If set, the selected role will be saved in accordance" "to the specific alias in your credentials file."
)
OPTION_PROXY_HELP = "Use proxy {}".format(PROXY)
OPTION_CONFIG_HELP = "Ignore config file " + CONFIG_FILE_PATH_FOR_DISPLAY
OPTION_KEYRING_HELP = "Ignore keyring"
OPTION_LOGLVL_HELP = "debug, info or warning"
OPTION_OUTPUT_CREDENTIALS_HELP = "Output credentials to console"
OPTION_AUTH_METHOD_STAGE_HELP = (
    "Stage to perform authentication process on.\n"
    "Note that signing into accounts with Int stage is only possible for accounts that "
    "have been accordingly configured with the Int-stage IDP! This cannot be checked in "
    "the CLI. "
)
OPTION_AUTH_IDP_HELP = (
    f"Backend IDP used for authentication. This only works for auth-method 'cdh-auth'. Choose from {IDENTITY_CODES}"
)
OPTION_CACHE_UPDATE_HELP = "Force update the friendly names cache"
OPTION_SANITY_CHECK_HELP = "Strategy to handle unavailable aliases in config file"


LOG = logging.getLogger(__name__)


def compose_decorators(*decorators: Any) -> Callable[[Any], Any]:
    """
    Returns all the input functions applied in the same order.
        Parameters:
            decorators (Tuple[functions]):
        Returns:
            decorator (function): function containing all the input functions
    """

    def decorate(f: Any) -> Any:
        for dec in reversed(decorators):
            f = dec(f)
        return f

    return decorate


cli_decorators = compose_decorators(
    click.group(invoke_without_command=True),
    click.pass_context,
    click.option("--alias", default=None, help=OPTION_ALIAS_HELP),
    click.option("--proxy", default=False, help=OPTION_PROXY_HELP, type=bool, is_flag=True),
    click.option("--ignoreconfig", default=False, help=OPTION_CONFIG_HELP, type=bool, is_flag=True),
    click.option("--version", default=False, help="Show version number", type=bool, is_flag=True),
    click.option("--ignorekeyring", default=False, help=OPTION_KEYRING_HELP, type=bool, is_flag=True),
    click.option("--loglvl", default=None, help=OPTION_LOGLVL_HELP, type=str),
)


def cli_entrypoint(
    ctx: click.core.Context,
    alias: Optional[str],
    proxy: bool = False,
    ignoreconfig: bool = False,
    version: bool = False,
    ignorekeyring: bool = False,
    loglvl: Optional[str] = None,
) -> None:
    config = CdhConfig(ignoreconfig, ignorekeyring)

    # handles logging
    loglevel = loglvl or config.loglvl or None
    set_up_logger(loglevel)
    ctx.params.pop("loglvl")

    # version handling
    LOG.debug(f"Version: {CLI_VERSION}")
    if version:
        print(f"CDH CLI version {CLI_VERSION}")  # noqa: T201
        check_version()
        return
    else:
        # needed, bc commandline calls break otherwise
        ctx.params.pop("version")

    check_version_if_needed()

    if ctx.invoked_subcommand is None:
        default_alias = "default"
        ctx.params["alias"] = ctx.params["alias"] or default_alias
        ctx.forward(get)


@cli_decorators
def cli(*args: Any, **kwargs: Any) -> None:
    cli_entrypoint(*args, **kwargs)


def set_up_logger(loglevel: Optional[str]) -> None:
    loglevel = loglevel if loglevel is not None else DEFAULT_LOGLEVEL

    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ScriptError("Invalid log level: %s" % loglevel)

    # logfile path
    home = os.path.expanduser("~")
    timestr = time.strftime("%Y%m%d-%H%M%S")
    filename = f"cdh-cli-{timestr}.log"
    log_folder_path = os.path.join(home, ".local", "var", "log", "cdh")
    os.makedirs(log_folder_path, exist_ok=True)
    log_file_path = os.path.join(log_folder_path, filename)

    # deletes log files older than 7 days
    now = time.time()
    for f in os.listdir(log_folder_path):
        file_path = os.path.join(log_folder_path, f)
        if os.stat(file_path).st_mtime < now - 7 * 60 * 60 * 24:
            os.remove(file_path)

    # update logging factory to add custom context attributes
    add_log_factory_for_context()

    log_handler: List[logging.StreamHandler] = []
    if numeric_level < logging.WARNING:
        basedir = os.path.dirname(log_file_path)
        os.makedirs(basedir, exist_ok=True)
        file_handler = logging.FileHandler(log_file_path)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s - %(name)s - %(levelname)s: %(identity_info)s%(message)s")
        )
        log_handler.append(file_handler)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter("%(levelname)s: %(identity_info)s%(message)s"))
    log_handler.append(console_handler)

    logging.basicConfig(level=numeric_level, handlers=log_handler)

    if numeric_level == logging.INFO:
        # would log non-useful messages such as IMDS URL on INFO:
        logging.getLogger("botocore.utils").setLevel(logging.WARNING)

    LOG.debug(f'Logfile path: "{log_folder_path}"')


def get_autocompletion_for_target(ctx: click.core.Context, args: Any, incomplete: str) -> List[str]:
    manager = CdhManager(Setup(ignore_config=False))
    autocompleter = AutoCompleter(manager.config)
    return autocompleter.get_sign_in_targets(incomplete)


@cli.command(name="exec")
@click.argument("target", required=True, type=str, shell_complete=get_autocompletion_for_target)
@click.argument("command_fragments", required=True, nargs=-1)
@click.option("--ignoreconfig", default=False, help=OPTION_CONFIG_HELP, type=bool, is_flag=True)
@click.option("--ignorekeyring", default=False, help=OPTION_KEYRING_HELP, type=bool, is_flag=True)
@click.option("--output-credentials", default=False, help=OPTION_OUTPUT_CREDENTIALS_HELP, type=bool, is_flag=True)
@click.option(
    "--auth-method-stage",
    default=None,
    type=click.Choice(AUTH_METHOD_STAGES, case_sensitive=False),
    help=OPTION_AUTH_METHOD_STAGE_HELP,
)
@click.option(
    "--auth-idp",
    default=None,
    type=click.Choice(IDENTITY_CODES, case_sensitive=False),
    help=OPTION_AUTH_IDP_HELP,
)
def execute_command(
    target: str,
    command_fragments: List[str],
    ignoreconfig: bool = False,
    ignorekeyring: bool = False,
    output_credentials: bool = False,
    auth_method_stage: Optional[str] = None,
    auth_idp: Optional[str] = None,
) -> None:
    setup = Setup(
        target_raw=target,
        ignore_config=ignoreconfig,
        ignore_keyring=ignorekeyring,
        output_credentials=output_credentials,
        auth_method_stage=auth_method_stage,
        auth_idp=auth_idp,
    )
    manager = CdhManager(setup)
    with manager:
        with identity_context(manager.identity_type):
            try:
                credentials = manager.read_credentials_from_file(target)
                if not credentials:
                    manager.get_and_write_credentials()

                env = os.environ.copy()

                # In Setup() we set AWS_SHARED_CREDENTIALS_FILE to ''. Then, boto3 does not look up in
                # ~/.aws/credentials. We set it back to None such that boto3 does that again.
                env.pop("AWS_SHARED_CREDENTIALS_FILE")

                env.update({"AWS_PROFILE": target})
                subprocess.run(command_fragments, env=env)
            except ScriptError as err:
                _exit_with_error(str(err))


@cli.command(
    name="get",
    help=f"""
Call with an optional argument specifying the target role for which you wish to acquire
credentials. This role is specified in the format ${{ROLE_NAME}}_${{ACCOUNT_ID}}
(or ${{ROLE_NAME}}_${{ACCOUNT_ID}}_${{IDENTITY}} for additional identities)
or the custom profile name you have specified in {CONFIG_FILE_PATH_FOR_DISPLAY}.
""",
)
@click.argument("target", required=False, default=None, type=str, shell_complete=get_autocompletion_for_target)
@click.option("--alias", default=None, help=OPTION_ALIAS_HELP)
@click.option("--proxy", default=False, help=OPTION_PROXY_HELP, type=bool, is_flag=True)
@click.option("--ignoreconfig", default=False, help=OPTION_CONFIG_HELP, type=bool, is_flag=True)
@click.option("--subrole", default=None, type=str, help="Name of role, which gets assumed with target credentials")
@click.option("--session_length", default=None, type=int, help="Session length in minutes")
@click.option("--ignorekeyring", default=False, help=OPTION_KEYRING_HELP, type=bool, is_flag=True)
@click.option("--output-credentials", default=False, help=OPTION_OUTPUT_CREDENTIALS_HELP, type=bool, is_flag=True)
@click.option(
    "--auth-method-stage",
    default=None,
    type=click.Choice(AUTH_METHOD_STAGES, case_sensitive=False),
    help=OPTION_AUTH_METHOD_STAGE_HELP,
)
@click.option(
    "--auth-idp",
    default=None,
    type=click.Choice(IDENTITY_CODES, case_sensitive=False),
    help=OPTION_AUTH_IDP_HELP,
)
def get(
    target: Optional[str],
    alias: Optional[str],
    proxy: bool = False,
    ignoreconfig: bool = False,
    subrole: Optional[str] = None,
    session_length: Optional[int] = None,
    ignorekeyring: bool = False,
    output_credentials: bool = False,
    auth_method_stage: Optional[str] = None,
    auth_idp: Optional[str] = None,
) -> None:
    setup = Setup(
        target_raw=target,
        alias=alias,
        proxy=proxy,
        ignore_config=ignoreconfig,
        ignore_keyring=ignorekeyring,
        output_credentials=output_credentials,
        sub_role=subrole,
        session_length=session_length,
        auth_method_stage=auth_method_stage,
        auth_idp=auth_idp,
    )
    manager = CdhManager(setup)
    with manager:
        with identity_context(manager.identity_type):
            try:
                credentials = manager.get_and_write_credentials()
                if setup.output_credentials:
                    manager.print_federation_url(credentials, True)
            except ScriptError as e:
                _exit_with_error(str(e))


@cli.command(name="get-all", help="Like get but for everything at once")
@click.option("--proxy", default=False, help=OPTION_PROXY_HELP, type=bool, is_flag=True)
@click.option("--ignoreconfig", default=False, help=OPTION_CONFIG_HELP, type=bool, is_flag=True)
@click.option("--ignorekeyring", default=False, help=OPTION_KEYRING_HELP, type=bool, is_flag=True)
@click.option("--output-credentials", default=False, help=OPTION_OUTPUT_CREDENTIALS_HELP, type=bool, is_flag=True)
@click.option(
    "--auth-method-stage",
    default=None,
    type=click.Choice(AUTH_METHOD_STAGES, case_sensitive=False),
    help=OPTION_AUTH_METHOD_STAGE_HELP,
)
@click.option(
    "--auth-idp",
    default=None,
    type=click.Choice(IDENTITY_CODES, case_sensitive=False),
    help=OPTION_AUTH_IDP_HELP,
)
@click.option(
    "--sanity-check/--disable-sanity-check",
    default=None,
    type=bool,
    is_flag=True,
    help=OPTION_SANITY_CHECK_HELP,
)
def get_all(
    proxy: bool = False,
    ignoreconfig: bool = False,
    ignorekeyring: bool = False,
    output_credentials: bool = False,
    auth_method_stage: Optional[str] = None,
    auth_idp: Optional[str] = None,
    sanity_check: Optional[bool] = None,
) -> None:
    setup = Setup(
        target_raw=None,
        alias=None,
        proxy=proxy,
        ignore_config=ignoreconfig,
        ignore_keyring=ignorekeyring,
        output_credentials=output_credentials,
        sub_role=None,
        session_length=None,
        auth_method_stage=auth_method_stage,
        auth_idp=auth_idp,
        sanity_check=sanity_check,
    )
    manager = CdhManager(setup)
    with manager:
        identity_types_enabled = manager.identity_types_enabled
        LOG.debug(f"identity types enabled: {identity_types_enabled}")

        if not identity_types_enabled:
            LOG.warning(
                "No identity types are enabled. Please add at least one identity under identities "
                "in the config or specify at least one of --qnumber or --digital_id."
            )

        failed_identities = []
        for identity_type in identity_types_enabled:
            if identity_type.code == manager.identity_type.code:
                with identity_context(identity_type):
                    try:
                        manager.write_all_credentials(identity_type)
                    except ScriptError as e:
                        failed_identities.append(str(identity_type))
                        LOG.error(e)

        if failed_identities:
            _exit_with_error(str(f"Operation failed for identity(s) {failed_identities}. Please check output above."))


@cli.command(
    help=f"""
Call with an optional argument specifying the target role for the login to AWS management console.
This role is specified in the format ${{ROLE_NAME}}_${{ACCOUNT_ID}}
(or ${{ROLE_NAME}}_${{ACCOUNT_ID}}_${{IDENTITY}} for additional identities)
or the custom profile name you have set in {CONFIG_FILE_PATH_FOR_DISPLAY}.
If no argument is given, an attempt will be made to retrieve
the target role from the environment variable AWS_PROFILE. If your AWS Credentials file contains
valid credentials for the requested role, the login URL will be printed and a browser window opens
up at the desired destination. Otherwise, a get request will be executed first, prompting you to
authenticate.
"""
)
@click.argument(
    "target",
    required=False,
    default=os.environ.get("AWS_PROFILE"),
    type=str,
    shell_complete=get_autocompletion_for_target,
)
@click.option("--proxy", default=False, help=OPTION_PROXY_HELP, type=bool, is_flag=True)
@click.option("--ignoreconfig", default=False, help=OPTION_CONFIG_HELP, type=bool, is_flag=True)
@click.option("--subrole", default=None, type=str, help="Name of role, which gets assumed with target credentials")
@click.option("--session_length", default=None, type=int, help="Session length in minutes")
@click.option("--ignorekeyring", default=False, help=OPTION_KEYRING_HELP, type=bool, is_flag=True)
@click.option("--output-credentials", default=False, help=OPTION_OUTPUT_CREDENTIALS_HELP, type=bool, is_flag=True)
@click.option(
    "--auth-method-stage",
    default=None,
    type=click.Choice(AUTH_METHOD_STAGES, case_sensitive=False),
    help=OPTION_AUTH_METHOD_STAGE_HELP,
)
@click.option(
    "--auth-idp",
    default=None,
    type=click.Choice(IDENTITY_CODES, case_sensitive=False),
    help=OPTION_AUTH_IDP_HELP,
)
def login(
    target: Optional[str],
    proxy: bool = False,
    ignoreconfig: bool = False,
    subrole: Optional[str] = None,
    session_length: Optional[int] = None,
    ignorekeyring: bool = False,
    output_credentials: bool = False,
    auth_method_stage: Optional[str] = None,
    auth_idp: Optional[str] = None,
) -> None:
    setup = Setup(
        target_raw=target,
        alias=None,
        proxy=proxy,
        ignore_config=ignoreconfig,
        ignore_keyring=ignorekeyring,
        output_credentials=output_credentials,
        sub_role=subrole,
        session_length=session_length,
        auth_method_stage=auth_method_stage,
        auth_idp=auth_idp,
    )
    manager = CdhManager(setup)
    with manager:
        if not target:
            _exit_with_error("No target specified for the login", error_code=2)
        else:
            with identity_context(manager.identity_type):
                try:
                    if manager.target_has_subrole(target, manager.identity_type):
                        try:
                            manager.perform_login(target)
                        except ProfileNotFoundInResponseError:
                            raise
                        except (ScriptError, JSONDecodeError):
                            if manager.identity_type is IdentityTypes.BMW.value:
                                LOG.debug("Falling back to two-step subrole login")
                                manager.perform_two_step_sub_role_login(target)
                            else:
                                raise
                    else:
                        manager.perform_login(target)
                except ScriptError as e:
                    _exit_with_error(str(e))


@cli.command(name="list", help="Prints out a list of all roles available to you.")
@click.option("--proxy", default=False, help=OPTION_PROXY_HELP, type=bool, is_flag=True)
@click.option("--ignoreconfig", default=False, help=OPTION_CONFIG_HELP, type=bool, is_flag=True)
@click.option("--ignorekeyring", default=False, help=OPTION_KEYRING_HELP, type=bool, is_flag=True)
@click.option(
    "--auth-method-stage",
    default=None,
    type=click.Choice(AUTH_METHOD_STAGES, case_sensitive=False),
    help=OPTION_AUTH_METHOD_STAGE_HELP,
)
@click.option("--force-cache-update", default=False, help=OPTION_CACHE_UPDATE_HELP, type=bool, is_flag=True)
@click.option(
    "--auth-idp",
    default=None,
    type=click.Choice(IDENTITY_CODES, case_sensitive=False),
    help=OPTION_AUTH_IDP_HELP,
)
def list_roles(
    proxy: bool = False,
    ignoreconfig: bool = False,
    ignorekeyring: bool = False,
    auth_method_stage: Optional[str] = None,
    force_cache_update: bool = False,
    auth_idp: Optional[str] = None,
) -> None:
    setup = Setup(
        target_raw=None,
        alias=None,
        proxy=proxy,
        ignore_config=ignoreconfig,
        ignore_keyring=ignorekeyring,
        output_credentials=False,
        sub_role=None,
        session_length=None,
        auth_method_stage=auth_method_stage,
        auth_idp=auth_idp,
    )
    manager = CdhManager(setup)
    with manager:
        urllib3.disable_warnings()

        identity_types_enabled = manager.identity_types_enabled
        LOG.debug(f"identity types enabled: {identity_types_enabled}")

        if not identity_types_enabled:
            LOG.warning(
                "No identity types are enabled. Please add at least one identity under identities "
                "in the config or specify at least one of --qnumber or --digital_id."
            )

        failed_identities = []
        for identity_type in identity_types_enabled:
            if identity_type.code == manager.identity_type.code:
                with identity_context(identity_type):
                    try:
                        manager.list_profiles_for_identity(identity_type, force_cache_update)
                    except ScriptError as e:
                        failed_identities.append(str(identity_type))
                        LOG.error(e)

        if failed_identities:
            _exit_with_error(str(f"Operation failed for identity(s) {failed_identities}. Please check output above."))


@cli.command(name="open_config", help="Opens cli config file.")
def open_config() -> None:
    config_path = CdhConfig.get_config_path()

    # check if file exists
    if not os.path.isfile(config_path):
        if Prompter().prompt_create_config_file():
            _generate_config()
        else:
            return

    platform = sys.platform
    try:
        if platform.startswith("darwin"):
            subprocess.Popen(["open", config_path])
        elif platform.startswith("linux"):
            subprocess.Popen(["gedit", config_path])
        elif platform.startswith("win32"):
            # noinspection PyUnresolvedReferences
            os.startfile(config_path)  # type:ignore
        else:
            LOG.warning(f'This command is currently not supported for your OS "{platform}".')
    except Exception:
        _exit_with_error(
            f"Something went wrong during opening your config. "
            f'Please open it manually via "{CONFIG_FILE_PATH_FOR_DISPLAY}".'
        )


@cli.command(name="generate-config", help="Generate a basic config file for the first time.")
@click.option("--proxy", default=False, help=OPTION_PROXY_HELP, type=bool, is_flag=True)
@click.option("--loglvl", default=None, help=OPTION_LOGLVL_HELP, type=str)
def generate_config(
    proxy: bool = False,
    loglvl: Optional[str] = None,
) -> None:
    _generate_config(proxy, loglvl)


def _generate_config(proxy: bool = False, loglvl: Optional[str] = None) -> None:
    if os.path.isfile(CdhConfig.get_config_path()):
        if not Prompter().prompt_overwrite_config_file():
            LOG.info("generate config file aborted!")
            return

    setup = Setup(
        target_raw=None,
        alias=None,
        proxy=proxy,
        output_credentials=False,
        sub_role=None,
        session_length=None,
    )

    identity_types = REGULAR_IDENTITY_TYPES
    failed_identities = []
    profiles_with_identities = {}
    for identity_type in identity_types:
        with identity_context(identity_type):
            manager = CdhManager(setup, identity_type=identity_type)
            with manager:
                urllib3.disable_warnings()
                try:
                    LOG.info(
                        f"Will now prompt for credentials to determine accessible {identity_type.code.value} roles"
                    )
                    profiles = manager.get_non_guest_profiles()
                    profiles_with_identities.update({identity_type: profiles})

                except ScriptError as e:
                    failed_identities.append(str(identity_type))
                    LOG.debug(e)

    if failed_identities:
        LOG.info(str(f"Operation failed for identity(s) {failed_identities}. Omitting these in generated config."))

    CdhConfig.create_config_file(profiles_with_identities)
    LOG.info("Successfully generated a config file. You can now use CDH CLI.")


@cli.command(name="clear-cdh-keyring", help="Remove all cached JWTs from the keyring")
@click.option("--loglvl", default=None, help=OPTION_LOGLVL_HELP, type=str)
def clear_cdh_keyring(loglvl: Optional[str] = None) -> None:
    set_up_logger(loglvl)
    jwt_cache = JwtCache(use_keyring=True)
    jwt_cache.clear_all_jwts()


@cli.command(name="get-api-token", help="Get an api scoped JWT to directly call APIs")
@click.option(
    "--auth-method-stage",
    default=None,
    type=click.Choice(AUTH_METHOD_STAGES, case_sensitive=False),
    help=OPTION_AUTH_METHOD_STAGE_HELP,
)
@click.option(
    "--auth-idp",
    default=None,
    type=click.Choice(IDENTITY_CODES, case_sensitive=False),
    help=OPTION_AUTH_IDP_HELP,
)
@click.option("--ignorekeyring", default=False, help=OPTION_KEYRING_HELP, type=bool, is_flag=True)
def get_api_token(
    ignorekeyring: bool = False,
    auth_method_stage: Optional[str] = None,
    auth_idp: Optional[str] = None,
) -> None:
    setup = Setup(
        ignore_keyring=ignorekeyring,
        auth_method_stage=auth_method_stage,
        auth_idp=auth_idp,
    )
    manager = CdhManager(setup)
    with manager:
        manager.get_api_token()


def _exit_with_error(message: str, *, error_code: int = 1) -> None:
    LOG.error(message)
    exit(error_code)


def check_version_if_needed() -> None:
    if _should_check_version():
        check_version()


def check_version() -> None:
    _check_version()
    _write_last_version_check_timestamp()


def _should_check_version() -> bool:
    last_version_check_file = _get_last_version_check_file_path()
    if not os.path.exists(last_version_check_file):
        return True
    last_version_check = datetime.fromtimestamp(os.path.getmtime(last_version_check_file))
    return datetime.now() - last_version_check > timedelta(hours=12)


def _write_last_version_check_timestamp() -> None:
    last_version_check_file = ""
    try:
        last_version_check_file = _get_last_version_check_file_path()
        Path(last_version_check_file).touch(exist_ok=True)
    except OSError:
        LOG.warning(f"Failed to update last version check file {last_version_check_file}")


def _check_version() -> None:
    try:
        res = _get_version_from_endpoint()
        if not res.ok:
            ConsolePrinter().print_error(f"Checking version from repo failed with status code {res.status_code}")
            return

        newest_version = res.text.strip()
    except requests.exceptions.ConnectionError:
        # happens when outside bmw network
        return
    except RequestException as e:
        ConsolePrinter().print_error(f'Fetching newest version failed: "{str(e)}". ')
        return

    package_version = CLI_VERSION
    is_newer = is_newer_than_package_version(newest_version, package_version)
    if is_newer:
        message = (
            f'Note: Version {newest_version} is available. Please kindly update via "pip3 install '
            f'git+https://${{USER}}@atc.bmwgroup.net/bitbucket/scm/cdhx/cdh-cli.git@{newest_version}". '
            f"You can find the changelog via "
            f"https://atc.bmwgroup.net/bitbucket/projects/CDHX/repos/cdh-cli/browse/CHANGELOG.md."
        )
        ConsolePrinter().print_console(message)
    elif is_newer is None:
        ConsolePrinter().print_console(f"Note: Version {newest_version} is available")


def _get_version_from_endpoint() -> Response:
    version_file_in_repo = "https://asset.iam.data.bmw.cloud/cdh-cli/VERSION"
    return requests.get(
        version_file_in_repo,
        timeout=3,
    )


def is_newer_than_package_version(newest_version: str, package_version: str) -> Optional[bool]:
    semver_package_version = convert_package_version_to_semver(package_version)
    LOG.debug(f"VERSION {package_version} -> {semver_package_version}")
    return _is_newer_version(newest_version, semver_package_version)


def _is_newer_version(version: str, other_version: str) -> Optional[bool]:
    try:
        version_info = semver.VersionInfo.parse(version)
        other_version_info = semver.VersionInfo.parse(other_version)
        other_is_dev_build = bool(other_version_info.build or other_version_info.prerelease)
        compare_result = version_info.compare(other_version_info)
        return compare_result > 0 or (compare_result == 0 and other_is_dev_build)
    except ValueError as e:
        LOG.debug(f"Cannot compare versions: {e}")
        return None


def convert_package_version_to_semver(package_version: str) -> str:
    """
    Turns a package versions as determined by setuptools_scm into a semver-compliant version.

    setuptools_scm unfortunately does not yield semver versions, even when tags adhere to semver.

        tagged as               setuptools_scm version          converted
        3.0.0                   3.0.0                           3.0.0
        3.0.0 + commits         3.0.1.dev19+gdc5a87b            3.0.1+dev19-gdc5a87b
        3.0.1-rc1               3.0.1rc1                        3.0.1+rc1
        3.0.1-rc1 + commits     3.0.1rc1.dev1+ga2fe7b8          3.0.1+rc1-dev1-ga2fe7b8

    We simply add everything past the core version as a build identifier.

    Note that other semver-compliant styled tags will not be supported.
    """
    pattern = r"^(?P<core_version>[0-9]+[.][0-9]+[.][0-9]+)(?P<remainder>[^0-9].*)?$"
    match = re.match(pattern, package_version)
    if not match:
        return package_version
    remainder = match.group("remainder")
    if not remainder:
        return package_version
    if remainder.startswith("+") or remainder.startswith("-") or remainder.startswith("."):
        # remove leading separator
        remainder = remainder[1:]
    # insert a "+" to make the whole remainder a build version
    # this creates a valid semver version, though every pre-release info will be considered just a build
    return match.group("core_version") + "+" + remainder.replace(".", "-").replace("+", "-")


def _get_last_version_check_file_path() -> str:
    home = expanduser("~")
    return os.path.join(home, ".config", "cdh", ".last-version-check-timestamp")


if __name__ == "__main__":
    cli()
