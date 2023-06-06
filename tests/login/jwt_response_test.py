import base64
import json
from random import choice

from cdh_utils.constants import IDENTITY_CODES
from cdh_utils.constants import IdentityCode
from cdh_utils.login.jwt_response import JwtResponse


class TestJwtResponse:
    def test_determine_actual_idp_name(self) -> None:
        idp_name = choice(IDENTITY_CODES)
        test_value = "." + base64.b64encode(json.dumps({"idp": idp_name}).encode()).decode()
        response = JwtResponse(jwt_name="test-name", jwt_value=test_value)

        actual_idp_name = response.actual_idp_name

        assert isinstance(actual_idp_name, IdentityCode)
        assert actual_idp_name.value == idp_name
