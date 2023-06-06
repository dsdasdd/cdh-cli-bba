from unittest.mock import ANY
from unittest.mock import Mock
from unittest.mock import patch

from cdh_utils.constants import BrowserOpenBehaviour
from cdh_utils.utils.browser_handler import BrowserHandler
from cdh_utils.utils.cdhconfig import CdhConfig


class TestBrowserHandler:
    URL = "https://fakeurl.test"

    def setup_method(self) -> None:
        self.config = CdhConfig(ignore_config=True, ignore_keyring=True)

    def test_determine_browser_from_config_no_set_browser_with_firefox_containers(self) -> None:
        self.config.set_browser = None
        self.config.use_firefox_containers = True
        browser_handler = BrowserHandler(self.config)
        assert browser_handler.base_config_browser == "firefox"

    def test_determine_browser_from_config_no_set_firefox_browser_with_firefox_containers(self) -> None:
        self.config.set_browser = "A:\\ny\\path\\to\\browser.exe"
        self.config.use_firefox_containers = True
        browser_handler = BrowserHandler(self.config)
        assert browser_handler.base_config_browser == "firefox"

    def test_determine_browser_from_config_set_firefox_browser_with_firefox_containers(self) -> None:
        firefox_path = "A:\\ny\\path\\to\\firefox.exe"
        self.config.set_browser = firefox_path
        self.config.use_firefox_containers = True
        browser_handler = BrowserHandler(self.config)
        assert browser_handler.base_config_browser == f'"{firefox_path}" %s'

    def test_determine_browser_from_config_set_browser_with_chrome_profiles(self) -> None:
        browser_path = "A:\\ny\\path\\to\\browser.exe"
        self.config.set_browser = browser_path
        self.config.use_firefox_containers = False
        self.config.use_chrome_multiple_windows = True
        browser_handler = BrowserHandler(self.config)
        assert browser_handler.base_config_browser == f'"{browser_path}" %s'

    def test_determine_browser_from_config_set_browser_without_firefox_containers_nor_chrome_profiles(self) -> None:
        browser_path = "A:\\ny\\path\\to\\browser.exe"
        self.config.set_browser = browser_path
        self.config.use_firefox_containers = False
        self.config.use_chrome_multiple_windows = False
        browser_handler = BrowserHandler(self.config)
        assert browser_handler.base_config_browser == f'"{browser_path}" %s'

    @patch("cdh_utils.utils.browser_handler.webbrowser")
    def test_calls_webbrowsers_implementation_when_use_default_behavior_is_expected(
        self, webbrowser_module_mock: Mock
    ) -> None:
        self.config.set_browser = None
        self.config.use_firefox_containers = False
        self.config.use_chrome_multiple_windows = False
        browser_handler = BrowserHandler(self.config)
        browser_handler.open_new(self.URL)
        assert browser_handler.base_config_browser is None
        webbrowser_module_mock.open.assert_called_once()

    @patch("cdh_utils.utils.browser_handler.webbrowser")
    def test_firefox_without_set_browser_should_use_direct_call(self, webbrowser_module_mock: Mock) -> None:
        self.config.set_browser = None
        self.config.use_firefox_containers = True
        self.config.use_chrome_multiple_windows = False
        browser_handler = BrowserHandler(self.config)
        browser_implementation_mock = Mock()
        webbrowser_module_mock.get.return_value = browser_implementation_mock

        browser_handler.open_new(self.URL)

        webbrowser_module_mock.get.assert_called_once_with("firefox")
        browser_implementation_mock.open.assert_called_once_with(self.URL, new=ANY)

    @patch("cdh_utils.utils.browser_handler.webbrowser")
    def test_firefox_with_set_browser_should_use_binary_path_with_placeholder(
        self, webbrowser_module_mock: Mock
    ) -> None:
        self.config.set_browser = "/path/to/firefox"
        self.config.use_firefox_containers = True
        self.config.use_chrome_multiple_windows = False
        browser_handler = BrowserHandler(self.config)
        browser_implementation_mock = Mock()
        webbrowser_module_mock.get.return_value = browser_implementation_mock

        browser_handler.open_new(self.URL)

        webbrowser_module_mock.get.assert_called_once_with('"/path/to/firefox" %s')
        browser_implementation_mock.open.assert_called_once_with(self.URL, new=ANY)

    @patch("cdh_utils.utils.browser_handler.webbrowser")
    def test_chrome_multiple_windows_should_use_binary_path_with_profile_dir_and_placeholder(
        self, webbrowser_module_mock: Mock
    ) -> None:
        self.config.set_browser = "/path/to/chrome"
        self.config.use_firefox_containers = False
        self.config.use_chrome_multiple_windows = True
        browser_handler = BrowserHandler(self.config)
        browser_implementation_mock = Mock()
        webbrowser_module_mock.get.return_value = browser_implementation_mock

        browser_handler.open_new_with_profile(self.URL, "myprofile")

        webbrowser_module_mock.get.assert_called_once_with(
            '"/path/to/chrome" ' '--args --profile-directory="CDH Profile myprofile" %s'
        )
        browser_implementation_mock.open.assert_called_once_with(self.URL, new=ANY)

    def test_set_browser_firefox_by_name(self) -> None:
        self.config.set_browser = "firefox"
        self.config.use_firefox_containers = True
        browser_handler = BrowserHandler(self.config)
        assert browser_handler.base_config_browser == "firefox"

    @patch("cdh_utils.utils.browser_handler.webbrowser")
    def test_browser_open_firefox_open_behaviour_default(self, webbrowser_module_mock: Mock) -> None:
        self.config.set_browser = None
        self.config.use_firefox_containers = True
        self.config.use_chrome_multiple_windows = False
        self.config.browser_open_behaviour = BrowserOpenBehaviour.DEFAULT
        WEBBROWSER_OPEN_DEFAULT = 0

        browser_handler = BrowserHandler(self.config)
        browser_implementation_mock = Mock()
        webbrowser_module_mock.get.return_value = browser_implementation_mock

        browser_handler.open_new(self.URL)

        browser_implementation_mock.open.assert_called_once_with(self.URL, new=WEBBROWSER_OPEN_DEFAULT)

    @patch("cdh_utils.utils.browser_handler.webbrowser")
    def test_browser_open_firefox_open_behaviour_window(self, webbrowser_module_mock: Mock) -> None:
        self.config.set_browser = None
        self.config.use_firefox_containers = True
        self.config.use_chrome_multiple_windows = False
        self.config.browser_open_behaviour = BrowserOpenBehaviour.WINDOW
        WEBBROWSER_OPEN_WINDOW = 1

        browser_handler = BrowserHandler(self.config)
        browser_implementation_mock = Mock()
        webbrowser_module_mock.get.return_value = browser_implementation_mock

        browser_handler.open_new(self.URL)

        browser_implementation_mock.open.assert_called_once_with(self.URL, new=WEBBROWSER_OPEN_WINDOW)

    @patch("cdh_utils.utils.browser_handler.webbrowser")
    def test_browser_open_firefox_open_behaviour_tab(self, webbrowser_module_mock: Mock) -> None:
        self.config.set_browser = None
        self.config.use_firefox_containers = True
        self.config.use_chrome_multiple_windows = False
        self.config.browser_open_behaviour = BrowserOpenBehaviour.TAB
        WEBBROWSER_OPEN_TAB = 2

        browser_handler = BrowserHandler(self.config)
        browser_implementation_mock = Mock()
        webbrowser_module_mock.get.return_value = browser_implementation_mock

        browser_handler.open_new(self.URL)

        browser_implementation_mock.open.assert_called_once_with(self.URL, new=WEBBROWSER_OPEN_TAB)

    @patch("cdh_utils.utils.browser_handler.webbrowser")
    def test_browser_open_chrome_open_behaviour_tab(self, webbrowser_module_mock: Mock) -> None:
        self.config.use_chrome_multiple_windows = True
        self.config.browser_open_behaviour = BrowserOpenBehaviour.TAB
        WEBBROWSER_OPEN_TAB = 2

        browser_handler = BrowserHandler(self.config)
        browser_implementation_mock = Mock()
        webbrowser_module_mock.get.return_value = browser_implementation_mock

        browser_handler.open_new_with_profile(self.URL, "TEST-PROFILE")

        browser_implementation_mock.open.assert_called_once_with(self.URL, new=WEBBROWSER_OPEN_TAB)
