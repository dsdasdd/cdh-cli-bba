import logging
import threading
from contextlib import contextmanager
from typing import Any
from typing import Generator
from typing import Optional

from cdh_utils.constants import IdentityType

LOG = logging.getLogger(__name__)


_log_context_local = threading.local()
_log_context_local.active_identity_type = None  # warning: this will be only set in one (the main?) thread


@contextmanager
def identity_context(identity_type: Optional[IdentityType]) -> Generator[None, None, None]:
    if get_identity_context():
        LOG.warning("Nesting of identity contexts detected - this is likely an error")

    LOG.debug(f"Entering context for {identity_type}")
    _log_context_local.active_identity_type = identity_type
    try:
        yield
    finally:
        LOG.debug(f"Leaving context for {identity_type}")
        _log_context_local.active_identity_type = None


def change_identity_context(identity_type: IdentityType) -> None:
    LOG.debug(f"Changing context to {identity_type}")
    _log_context_local.active_identity_type = identity_type


def get_identity_context() -> Optional[IdentityType]:
    return getattr(_log_context_local, "active_identity_type", None)


def get_identity_context_str() -> str:
    active_identity_type = get_identity_context()
    if active_identity_type:
        return f"[{active_identity_type}] "
    else:
        return ""


def add_log_factory_for_context() -> None:
    old_factory = logging.getLogRecordFactory()

    def record_factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = old_factory(*args, **kwargs)

        record.identity_info = get_identity_context_str()

        return record

    logging.setLogRecordFactory(record_factory)
