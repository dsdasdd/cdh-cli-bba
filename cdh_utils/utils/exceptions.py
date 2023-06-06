class ScriptError(Exception):
    pass


class ConfigError(Exception):
    pass


class ProfileNotFoundInResponseError(ScriptError):
    pass


class AccessDeniedError(ScriptError):
    pass
