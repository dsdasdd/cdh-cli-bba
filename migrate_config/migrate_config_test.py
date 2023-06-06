import datetime
import filecmp
import os
import tempfile
from pathlib import Path
from shutil import copyfile
from typing import Any

import pytest

from .config_migrator import ConfigMigrator
from .exceptions_for_migration import AbortedError


class TestConfigMigrator:

    config_path = f"{tempfile.gettempdir()}/config.yml"
    backup_path = f"{config_path}_backup_{datetime.datetime.today().timestamp()}"
    source_config = f"{os.path.dirname(__file__)}/test_config_v1.yml"
    expected_config = f"{os.path.dirname(__file__)}/expected_config.yml"

    def setup_method(self) -> None:
        self.conf_migrator = ConfigMigrator(config_path=self.config_path, backup_path=self.backup_path)

    def test_migration(self, monkeypatch: Any) -> None:
        copyfile(src=self.source_config, dst=self.config_path)
        monkeypatch.setattr("builtins.input", lambda _: "y")
        self.conf_migrator.start_migration()
        backup_file = Path(self.backup_path)
        assert backup_file.is_file()
        assert filecmp.cmp(self.backup_path, self.source_config, shallow=False)
        assert filecmp.cmp(self.config_path, self.expected_config, shallow=False)

    def test_migration_aborted(self, monkeypatch: Any) -> None:
        copyfile(src=self.source_config, dst=self.config_path)
        monkeypatch.setattr("builtins.input", lambda _: "n")
        with pytest.raises(AbortedError):
            self.conf_migrator.start_migration()
        backup_file = Path(self.backup_path)
        assert not backup_file.is_file()
        assert filecmp.cmp(self.config_path, self.source_config, shallow=False)

    def test_no_config_file_found(self) -> None:
        with pytest.raises(SystemExit) as pytest_wrapped_e:
            self.conf_migrator.start_migration()
        assert pytest_wrapped_e.value.code == SystemExit(0).code
        backup_file = Path(self.backup_path)
        assert not backup_file.is_file()
        config_file = Path(self.config_path)
        assert not config_file.is_file()

    def teardown_method(self) -> None:
        if os.path.exists(self.config_path):
            os.remove(self.config_path)
        if os.path.exists(self.backup_path):
            os.remove(self.backup_path)
