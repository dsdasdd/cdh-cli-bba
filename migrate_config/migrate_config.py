import datetime
import os
from os.path import expanduser

from .config_migrator import ConfigMigrator


def get_config_path() -> str:
    home = expanduser("~")
    config_file_path = os.path.join(home, ".config", "cdh", "config.yml")
    return config_file_path


def main() -> None:
    config_path = get_config_path()
    backup_path = f"{config_path}_backup_{datetime.datetime.today().timestamp()}"
    conf_migrator = ConfigMigrator(config_path=config_path, backup_path=backup_path)
    conf_migrator.start_migration()


if __name__ == "__main__":
    main()
