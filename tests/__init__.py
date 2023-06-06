import pytest

# Rewriting the assertions in test utilities is necessary to get extensive error output.
# Otherwise the error would just read 'AssertionError'.
pytest.register_assert_rewrite("tests.assert_raises")
