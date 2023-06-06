import os
from shutil import copyfile
from typing import Any
from typing import Dict
from typing import Optional

from ruamel.yaml import YAML

from .cdhconfig_for_migration import CdhConfig
from .cdhconfig_for_migration import ConfigVersion
from .cdhconfig_for_migration import IdentityCode
from .exceptions_for_migration import AbortedError
from .exceptions_for_migration import CannotMigrateError
from .exceptions_for_migration import MigrationError

yaml = YAML(pure=True)
yaml.version = (1, 1)  # type:ignore


class ConfigMigrator:
    def __init__(self, config_path: str, backup_path: str):
        self.config_path = config_path
        self.backup_path = backup_path

    def start_migration(self) -> None:
        # check if file exists
        if not os.path.isfile(self.config_path):
            print("No config found, nothing to migrate")  # noqa: T201
            exit(0)
        config = CdhConfig.create_from_yaml(self.config_path)
        if config.version == ConfigVersion.v2:
            print(f"No old config format found, consider adding 'version: v2' to {self.config_path}.")  # noqa: T201
            raise CannotMigrateError(
                "Config with a v2 structure found but no version specified, add version: v2 to your config manually."
            )
        if config.version == ConfigVersion.v1:
            print("Old config version found, this version will no longer work in this version.")  # noqa: T201
            print(f"We can automatically migrate your config {self.config_path} to the new version.")  # noqa: T201
            print(f"A backup of your current config will be created: {self.backup_path}.")  # noqa: T201
            prompted = None
            while prompted not in ["y", "n"]:
                prompted = input("Do you wish to migrate? [y/n]")
            if prompted == "y":
                self.convert_config(config=config)
                config_v2 = CdhConfig.create_from_yaml(self.config_path)
                if config == config_v2:
                    print("Migration successful! :-)")  # noqa: T201
                else:
                    print(  # noqa: T201
                        "Something went wrong with the migration of you config, restoring old version..."
                    )
                    self.restore_old_config()
                    raise MigrationError("Please contact the CDH Team!")
            else:
                raise AbortedError(
                    "Migration denied. "
                    "Either create a new config manually or restart the migration via calling cdh again. "
                    "If you want to remain on your old version you can revert back to version 2.1.0 via: "
                    "'pip install git+https://${USER}@atc.bmwgroup.net/bitbucket/scm/cdhx/cdh-cli.git@2.1.0'"
                )

    def restore_old_config(self, orig_exc: Optional[Exception] = None) -> None:
        try:
            print("restoring backed up config...")  # noqa: T201
            if not os.path.isfile(self.backup_path):
                if orig_exc:
                    raise FileNotFoundError("No backed up config found, please contact the CDH Team!") from orig_exc
                else:
                    raise FileNotFoundError("No backed up config found, please contact the CDH Team!")
            copyfile(self.backup_path, self.config_path)
            print("Your old config has been restored")  # noqa: T201
        except Exception as exc:
            print("Restoring your old config failed, please contact the CDH Team!")  # noqa: T201
            if orig_exc:
                raise exc from orig_exc
            else:
                raise exc
        finally:
            if orig_exc:
                raise orig_exc

    def convert_config(self, config: CdhConfig) -> None:
        yaml_config: Dict[str, Any] = {}
        yaml_config["version"] = ConfigVersion.v2.value
        yaml_config["use-firefox-containers"] = config.use_firefox_containers
        yaml_config["use-chrome-multiple-windows"] = config.use_chrome_multiple_windows
        yaml_config["use-chrome-multiple-windows-default"] = config.use_chrome_multiple_windows_default
        yaml_config["set-browser"] = config.set_browser
        yaml_config["use-keyring"] = config.use_keyring
        yaml_config["loglvl"] = config.loglvl
        yaml_config["identities"] = {IdentityCode.BMW.value: config.bmw_identity_settings.to_dict_v2()}

        try:
            copyfile(self.config_path, self.backup_path)
            print(f"Your old config has been backed up to {self.backup_path}")  # noqa: T201
        except Exception as exc:
            print("Backing up your old config failed. Aborting...")  # noqa: T201
            raise exc
        try:
            with open(self.config_path, "w") as stream:
                yaml.dump(yaml_config, stream=stream)
        except Exception as exc:
            print("Migrating the config failed, restoring backup...")  # noqa: T201
            self.restore_old_config(orig_exc=exc)
