import time
from unittest.mock import Mock
from unittest.mock import mock_open
from unittest.mock import patch

import requests
from botocore.exceptions import ReadTimeoutError

from cdh_utils.constants import IdentityType
from cdh_utils.saml.identities import SamlProfileWithName
from cdh_utils.utils.connection_handler import ConnectionHandler
from cdh_utils.utils.connection_handler import FriendlyNamesCacheHandler


class TestFriendlyNamesCacheHandler:
    @patch("os.path.getmtime")
    def test_is_cache_valid_unavailable_cache(self, getmtime_mock: Mock) -> None:
        cache_handler = FriendlyNamesCacheHandler()
        getmtime_mock.side_effect = OSError
        assert cache_handler.is_cache_valid() is False
        getmtime_mock.assert_called()

    @patch("os.path.getmtime")
    def test_is_cache_valid_old_cache(self, getmtime_mock: Mock) -> None:
        cache_handler = FriendlyNamesCacheHandler()
        getmtime_mock.return_value = 0  # mock file creation date to epochs beginning
        assert cache_handler.is_cache_valid() is False
        getmtime_mock.assert_called()

    @patch("os.path.getmtime")
    def test_is_cache_valid_new_cache(self, getmtime_mock: Mock) -> None:
        cache_handler = FriendlyNamesCacheHandler()
        getmtime_mock.return_value = time.time()
        assert cache_handler.is_cache_valid()
        getmtime_mock.assert_called()

    @patch("builtins.open", new_callable=mock_open, read_data='{"test_id": "test_friendly_name"}')
    def test_get_friendly_name_cache(self, mock_open_friendly_name_cache: Mock) -> None:
        cache_handler = FriendlyNamesCacheHandler()
        friendly_name_cache = FriendlyNamesCacheHandler.get_friendly_name_cache()
        assert {"test_id": "test_friendly_name"} == friendly_name_cache

        friendly_names_cache_path = cache_handler.get_account_friendly_names_cache_path()
        mock_open_friendly_name_cache.assert_called_with(friendly_names_cache_path)

    @patch("builtins.open", new_callable=mock_open)
    @patch("json.dump")
    def test_save_account_friendly_names_to_cache(self, mocked_json_dump: Mock, mocked_cache_file: Mock) -> None:
        cache_handler = FriendlyNamesCacheHandler(ignore_cache_file=True)

        test_data = {"test_id": "test_friendly_name"}
        cache_handler.save_account_friendly_names_to_cache(test_data)

        friendly_names_cache_path = cache_handler.get_account_friendly_names_cache_path()
        mocked_cache_file.assert_called_with(friendly_names_cache_path, "w")

        mocked_json_dump.assert_called_with(test_data, mocked_cache_file())

    @patch("builtins.open", new_callable=mock_open)
    @patch("json.dump")
    def test_save_account_friendly_names_to_cache_failed(self, mocked_json_dump: Mock, mocked_cache_file: Mock) -> None:
        mocked_cache_file.side_effect = PermissionError

        cache_handler = FriendlyNamesCacheHandler(ignore_cache_file=True)

        test_data = {"test_id": "test_friendly_name"}
        cache_handler.save_account_friendly_names_to_cache(test_data)

        friendly_names_cache_path = cache_handler.get_account_friendly_names_cache_path()
        mocked_cache_file.assert_called_with(friendly_names_cache_path, "w")
        mocked_json_dump.assert_not_called()

    @patch("cdh_utils.utils.connection_handler.ConnectionHandler.get_temp_credentials")
    def test_returns_empty_on_timeout(self, get_temp_credentials_patched: Mock) -> None:
        mocked_profile = Mock(spec=SamlProfileWithName)
        mocked_identity_type = Mock(spec=IdentityType)

        get_temp_credentials_patched.side_effect = ReadTimeoutError(
            "mock exception", endpoint_url="https://dummy.example"
        )

        connection_handler = ConnectionHandler(
            Mock(spec=requests.Session), "test_region", FriendlyNamesCacheHandler(ignore_cache_file=True)
        )
        result = connection_handler.get_account_friendly_names(
            mocked_profile, "saml_b64", "sts_client", mocked_identity_type, force_cache_update=True
        )

        assert not result

    @patch("builtins.open", new_callable=mock_open)
    def test_empty_cache_if_permission_to_read_cache_file_is_denied(self, mock_open_friendly_name_cache: Mock) -> None:
        mock_open_friendly_name_cache.side_effect = PermissionError
        cache_handler = FriendlyNamesCacheHandler()
        cache_content = cache_handler.get_friendly_name_cache()

        friendly_names_cache_path = cache_handler.get_account_friendly_names_cache_path()
        mock_open_friendly_name_cache.assert_called_with(friendly_names_cache_path)

        assert cache_content == {}

    @patch("builtins.open", new_callable=mock_open)
    @patch("cdh_utils.utils.connection_handler.ConnectionHandler.get_account_friendly_names_from_endpoint")
    def test_call_endpoint_if_permission_to_read_cache_file_is_denied(
        self, get_account_friendly_names_from_endpoint_patched: Mock, mock_open_friendly_name_cache: Mock
    ) -> None:
        mock_open_friendly_name_cache.side_effect = PermissionError
        cache_handler = FriendlyNamesCacheHandler()

        get_account_friendly_names_from_endpoint_patched.side_effect = {"test_id": "test_friendly_name"}

        mocked_profile = Mock(spec=SamlProfileWithName)
        mocked_identity_type = Mock(spec=IdentityType)
        connection_handler = ConnectionHandler(Mock(spec=requests.Session), "test_region", cache_handler)
        connection_handler.get_account_friendly_names(
            mocked_profile, "saml_b64", "sts_client", mocked_identity_type, force_cache_update=True
        )

        friendly_names_cache_path = cache_handler.get_account_friendly_names_cache_path()
        mock_open_friendly_name_cache.assert_called_with(friendly_names_cache_path)
        get_account_friendly_names_from_endpoint_patched.assert_called()

    @patch("builtins.open", new_callable=mock_open, read_data="{some_invalid:json")
    def test_get_friendly_name_cache_corrupt_cache(self, mock_open_friendly_name_cache: Mock) -> None:
        cache_handler = FriendlyNamesCacheHandler()
        friendly_name_cache = FriendlyNamesCacheHandler.get_friendly_name_cache()
        assert friendly_name_cache == {}

        friendly_names_cache_path = cache_handler.get_account_friendly_names_cache_path()
        mock_open_friendly_name_cache.assert_called_with(friendly_names_cache_path)
