import logging
import time
from concurrent.futures.thread import ThreadPoolExecutor
from typing import Any
from typing import Callable

from cdh_utils.constants import IdentityType
from cdh_utils.constants import IdentityTypes
from cdh_utils.utils.log_context import add_log_factory_for_context
from cdh_utils.utils.log_context import get_identity_context
from cdh_utils.utils.log_context import get_identity_context_str
from cdh_utils.utils.log_context import identity_context


class TestIdentityContext:
    def test_identity_context(self) -> None:
        assert get_identity_context() is None
        with identity_context(IdentityTypes.BMW.value):
            assert get_identity_context() == IdentityTypes.BMW.value
        assert get_identity_context() is None

    def test_identity_context_is_independent_per_thread(self) -> None:
        assert get_identity_context() is None

        with ThreadPoolExecutor(max_workers=3) as executor:
            future_bmw = executor.submit(self._build_callback_set_and_assert_identity(0.3, IdentityTypes.BMW.value))
            future_none = executor.submit(self._build_callback_assert_no_identity(0.4))
            future_bba = executor.submit(self._build_callback_set_and_assert_identity(0.5, IdentityTypes.BBA.value))

            # wait for termination with timeout
            future_bmw.result(0.6)
            future_bba.result(0.6)
            future_none.result(0.6)

    @staticmethod
    def _build_callback_set_and_assert_identity(
        delay_secs: float, identity_to_assert: IdentityType
    ) -> Callable[[], None]:
        def callback() -> None:
            assert get_identity_context() is None
            with identity_context(identity_to_assert):
                time.sleep(delay_secs)
                assert get_identity_context() == identity_to_assert
            assert get_identity_context() is None

        return callback

    @staticmethod
    def _build_callback_assert_no_identity(delay_secs: float) -> Callable[[], None]:
        def callback_assert_no_identity_context() -> None:
            time.sleep(delay_secs)
            assert get_identity_context() is None

        return callback_assert_no_identity_context

    def test_identity_context_str(self) -> None:
        assert get_identity_context_str() == ""
        with identity_context(IdentityTypes.BMW.value):
            # note: trailing space to allow use in log pattern without conditional spacing
            assert get_identity_context_str() == "[BMW ID] "
        assert get_identity_context_str() == ""

    def test_identity_context_in_logs(self, caplog: Any) -> None:
        caplog.set_level(logging.INFO)
        logger = logging.getLogger("sample")

        backup_log_factory = logging.getLogRecordFactory()
        assert get_identity_context() is None
        try:
            add_log_factory_for_context()
            logger.info("sample log entry outside context")
            with identity_context(IdentityTypes.BMW.value):
                logger.info("sample log entry inside context")
            logger.info("sample log entry outside context")

            records_inside = [
                record for record in caplog.get_records("call") if "sample log entry inside context" in record.message
            ]
            assert len(records_inside) == 1
            for record_inside in records_inside:
                assert getattr(record_inside, "identity_info") == "[BMW ID] "

            records_outside = [
                record for record in caplog.get_records("call") if "sample log entry outside context" in record.message
            ]
            assert len(records_outside) == 2
            for record_outside in records_outside:
                assert getattr(record_outside, "identity_info") == ""

        finally:
            logging.setLogRecordFactory(backup_log_factory)
