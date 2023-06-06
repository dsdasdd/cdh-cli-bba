class ScriptError(Exception):
    pass


class ConfigError(Exception):
    pass


class AbortedError(Exception):
    pass


class CannotMigrateError(Exception):
    pass


class MigrationError(Exception):
    pass
