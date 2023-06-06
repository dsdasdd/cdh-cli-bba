from typing import List

from cdh_utils.utils.cdhconfig import CdhConfig
from cdh_utils.utils.cdhconfig import UserConfigProfile


class AutoCompleter:
    def __init__(self, config: CdhConfig):
        self.config = config

    def get_sign_in_targets(self, incomplete: str) -> List[str]:
        profiles = self._get_all_profiles()
        profiles_names = [profile.name for profile in profiles]
        return [x for x in profiles_names if x.startswith(incomplete)]

    def _get_all_profiles(self) -> List[UserConfigProfile]:
        return self.config.bba_identity_settings.aws_profiles + self.config.bmw_identity_settings.aws_profiles
