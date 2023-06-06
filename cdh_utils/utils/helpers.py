import configparser
import logging
import os
import uuid
from datetime import datetime
from datetime import timedelta
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Tuple
from typing import TypeVar

import click
from tabulate import tabulate

from cdh_utils.saml.identities import Credentials
from cdh_utils.saml.identities import SamlProfile
from cdh_utils.utils.log_context import get_identity_context_str

LOG = logging.getLogger(__name__)


class ConsolePrinter:
    def print_credential_info(
        self, profile_name: str, credentials: Credentials, filename: str, output_credentials: bool = False
    ) -> None:
        LOG.info(
            '> Your credentials have been persisted in {0} via profile "{1}" for region {2}.'.format(
                filename, profile_name, credentials.region
            )
        )
        LOG.info(self.get_duration_string(credentials.max_session_duration))
        if output_credentials:
            self.print_console("----------------------------------------------------------------")
            self.print_console('Credentials for profile "{0}":'.format(profile_name))
            self.print_console("aws_access_key_id = " + credentials.boto_credentials.access_key)
            self.print_console("aws_secret_access_key = " + credentials.boto_credentials.secret_key)
            self.print_console("aws_session_token = " + credentials.boto_credentials.session_token)
            self.print_console("region = " + credentials.region)
            self.print_console("----------------------------------------------------------------")
            self.print_console(
                self.get_duration_string(credentials.max_session_duration)
                + " After this time you may re-run this script to refresh your credentials."
            )

    def print_login_url(self, login_url: str, output_credentials: bool = False) -> None:
        LOG.info("> Login link was generated.")
        if output_credentials:
            self.print_console("> Here is your sign-in link to the console:")
            self.print_console("----------------------------------------------------------------")
            self.print_console(login_url)
            self.print_console("----------------------------------------------------------------")

    def print_error(self, error_message: str) -> None:
        LOG.error(error_message)

    def get_duration_string(self, duration: timedelta) -> str:
        expire_hours = duration.seconds // 3600
        expire_minutes = (duration.seconds - (expire_hours * 3600)) // 60
        if expire_hours < 1:
            return str("Note that these will expire in {} minutes.".format(expire_minutes))
        else:
            return str("Note that these will expire in {} hours {} minutes.".format(expire_hours, expire_minutes))

    def print_warning(self, warning_message: str) -> None:
        LOG.warning(warning_message)

    def print_debug(self, debug_message: str) -> None:
        LOG.debug(debug_message)

    def print_info(self, info_message: str) -> None:
        LOG.info(info_message)

    def print_console(self, message: str) -> None:
        click.echo(message)

    def print_console_with_identity(self, message: str) -> None:
        self.print_console(f"{get_identity_context_str()}{message}")


PASSWORD_WARN_MIN_LEN = 5
PIN_WARN_MIN_LEN = 4
HOTP_WARN_MIN_LEN = 6


T = TypeVar("T")


class Prompter:
    def prompt_select_role_id(self, profiles: List[SamlProfile], account_display: Callable[[str], str]) -> Any:
        headers = ["ID", "Name", "Account"]
        table = [
            [index, profile.role.get_name(), account_display(profile.role.get_account_number())]
            for index, profile in enumerate(profiles)
        ]
        prompt_str = "\n" + tabulate(table, headers=headers) + "\n" + "> Select the suitable role from the list"
        return click.prompt(prompt_str, type=click.IntRange(0, len(profiles) - 1))

    def prompt_select_from_dict(self, labelled_choices: Dict[str, T], header_label: str, prompt: str) -> T:
        if len(labelled_choices) < 2:
            raise ValueError(f"Insufficient number of choices (got {len(labelled_choices)}, expected >= 2)")

        headers = ["ID", header_label]
        table: List[Tuple[int, str]] = [(index, label) for index, label in enumerate(labelled_choices.keys())]
        choices_by_index = {entry[0]: labelled_choices[entry[1]] for entry in table}
        prompt_str = "\n" + tabulate(table, headers=headers) + "\n\n" + f"> {prompt}"
        index_input = click.prompt(text=prompt_str, type=click.IntRange(0, len(labelled_choices) - 1))

        return choices_by_index[index_input]

    def prompt_create_config_file(self) -> bool:
        return click.prompt("Config file does not exist. Create one? (y/n)", type=bool)

    def prompt_overwrite_config_file(self) -> bool:
        return click.prompt("Config file exists already. Do you want to overwrite it? (y/n)", type=bool)

    def prompt_delete_keyring_entry(self, entry: str) -> bool:
        return click.prompt(self._prompt_with_identity(f'Delete keyring entry "{entry}"? (y/n)'), type=bool)

    def _prompt_with_identity(self, message: str) -> str:
        identity_info = get_identity_context_str()
        return f"{identity_info}> {message}"

    def _check_for_min_length(self, value: str, min_length: int, label: str) -> None:
        if len(value) < min_length:
            LOG.warning(
                f"{label} is too short (<{min_length}) - If you tried to paste from the clipboard, "
                f"something seems not to have worked as intended."
            )


class FileHandler:
    def read_config_file(self, config: configparser.RawConfigParser, filename: str) -> None:
        config.read(filename)

    def write_config_file(self, config: configparser.RawConfigParser, filename: str) -> None:
        with open(filename, "w+") as configfile:
            config.write(configfile)

    def path_exists(self, directory: str) -> bool:
        return os.path.exists(directory)

    def make_directory(self, directory: str) -> None:
        os.makedirs(directory)


def get_session_dict(current_time: datetime, session_duration: timedelta) -> Dict[str, Any]:
    uuid_str_session = str(uuid.uuid4())
    session_start_str = current_time.replace(microsecond=0).isoformat()
    session_end_str = (current_time + session_duration).replace(microsecond=0).isoformat()
    return {
        "Duration": 1000 * session_duration.seconds,
        "Id": uuid_str_session,
        "StartTimestamp": session_start_str,
        "StopTimestamp": session_end_str,
    }
