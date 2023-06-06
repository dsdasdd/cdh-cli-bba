from http import HTTPStatus
from unittest.mock import Mock

import pytest
from requests import Response

from cdh_utils.login.handlers import extract_saml_from_response
from cdh_utils.utils.connection_handler import ConnectionHandler


class MocksSetup:
    def setup_method(self) -> None:
        self.setup = Mock()
        self.connection_handler = Mock(spec=ConnectionHandler)
        self.setup.connection_handler = self.connection_handler


class TestExtractSaml(MocksSetup):
    def setup_method(self) -> None:
        super().setup_method()
        self.get_response = Mock(spec=Response)
        self.get_response.status_code = HTTPStatus.OK
        self.get_response.text = '<test><form><input name="SAMLResponse" value="Value1"></input></form></test>'

    def test_valid_response(self) -> None:
        result = extract_saml_from_response(self.get_response)
        assert result == "Value1"

    def test_invalid_response(self) -> None:
        self.get_response.text = "<test><form></form></test>"
        with pytest.raises(AttributeError):
            extract_saml_from_response(self.get_response)

    def test_multiple_samls(self) -> None:
        self.get_response.text = (
            '<HTML><BODY><FORM><INPUT NAME="SAMLResponse" VALUE="other"/>'
            '<INPUT NAME="SAMLResponse" VALUE="PHN"/></FORM></BODY></HTML>'
        )
        result = extract_saml_from_response(self.get_response)
        assert result == "other"
