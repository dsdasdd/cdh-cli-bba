import hashlib
import logging
import urllib
import webbrowser
from typing import List
from typing import Optional
from typing import Tuple

from cdh_utils.utils.cdhconfig import CdhConfig

LOG = logging.getLogger(__name__)


class BrowserHandler:
    def __init__(self, config: CdhConfig):
        self._config = config
        self.base_config_browser = self._determine_browser_from_config(self._config)
        self.browser_open_behaviour = config.browser_open_behaviour

    def _determine_browser_from_config(self, config: CdhConfig) -> Optional[str]:
        if config.use_firefox_containers:
            if config.set_browser and "firefox" in config.set_browser:
                return self._handle_path_and_name_browser(config.set_browser)
            return "firefox"

        if config.set_browser:
            return self._handle_path_and_name_browser(config.set_browser)

        return None

    def _handle_path_and_name_browser(self, browser_name_or_path: str) -> str:
        if "\\" in browser_name_or_path or "/" in browser_name_or_path:
            return f'"{browser_name_or_path}" %s'
        else:
            return browser_name_or_path

    def open_new(self, url: str) -> None:
        tab_behaviour = self.browser_open_behaviour.get_webbrowser_value()
        try:
            if self.base_config_browser:
                webbrowser.get(self.base_config_browser).open(url, new=tab_behaviour)
            else:
                webbrowser.open(url, new=tab_behaviour)
        except webbrowser.Error:
            LOG.warning("could not open the browser")

    def _firefox_get_random_color_icon_combination(self, account_name: str) -> Tuple[str, str]:
        color_options: List[str] = ["blue", "turquoise", "green", "yellow", "orange", "red", "pink", "purple"]
        icon_options: List[str] = [
            "fingerprint",
            "briefcase",
            "dollar",
            "cart",
            "circle",
            "gift",
            "vacation",
            "food",
            "fruit",
            "pet",
            "tree",
            "chill",
        ]
        selector = int(hashlib.sha256(str.encode(account_name)).hexdigest(), 16)
        color = color_options[selector % len(color_options)]
        icon = icon_options[selector % len(icon_options)]
        return color, icon

    def open_new_with_profile(self, login_url: str, profile: Optional[str]) -> None:
        if self._config.use_firefox_containers and isinstance(profile, str):
            self._open_new_with_profile_firefox(login_url, profile)
        elif self._config.use_chrome_multiple_windows and isinstance(profile, str):
            self._open_new_with_profile_chrome(login_url, profile)
        else:
            # browser is set, but not firefox nor chrome profiles
            self.open_new(login_url)

    def _open_new_with_profile_firefox(self, login_url: str, profile: str) -> None:
        color, icon = self._firefox_get_random_color_icon_combination(profile)
        url = (
            f"ext+container:"
            f'color={color}&icon={icon}&url={urllib.parse.quote(login_url, safe="")}'
            f"&name={profile}"
        )
        self.open_new(url)

    def _open_new_with_profile_chrome(self, login_url: str, profile: str) -> None:
        tab_behaviour = self.browser_open_behaviour.get_webbrowser_value()

        if self._config.use_chrome_multiple_windows_default == profile:
            webbrowser.get(f'"{self._config.set_browser}" --args --profile-directory="Default" %s').open(
                login_url, new=tab_behaviour
            )

        else:
            webbrowser.get(
                f'"{self._config.set_browser}" --args ' f'--profile-directory="CDH Profile {profile}" %s'
            ).open(login_url, new=tab_behaviour)
