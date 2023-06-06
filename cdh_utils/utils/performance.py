import logging
from datetime import datetime
from functools import wraps
from typing import Any
from typing import Callable

PERFORMANCE_LOG = logging.getLogger("Performance")


def performance_timer(callable: Callable) -> Callable:
    """Decorator to measure and log performance timings. Can optionally receive a label."""

    @wraps(callable)
    def wrapper(*args: Any, **kwargs: Any) -> Callable:
        with PerformanceTimer(f"<{callable.__name__}>"):
            return callable(*args, **kwargs)

    return wrapper


class PerformanceTimer:
    def __init__(self, label: str):
        self.label = label

    def __enter__(self) -> None:
        self.start = datetime.now()

    def __exit__(self, *args: Any) -> None:
        self.end = datetime.now()
        elapsed_millis = (self.end - self.start).total_seconds() * 1000
        PERFORMANCE_LOG.debug(f"[performance] {self.label} took {elapsed_millis:.1f}ms")
