from botocore.config import Config


def build_boto_default_config() -> Config:
    return Config(connect_timeout=10, read_timeout=20, retries={"max_attempts": 3})


def build_short_timeout_config() -> Config:
    return Config(connect_timeout=5, read_timeout=3, retries={"max_attempts": 0})
