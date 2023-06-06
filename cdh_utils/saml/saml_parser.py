import base64
import logging
from typing import List
from xml.etree import ElementTree

from cdh_utils.saml.identities import Role

LOG = logging.getLogger(__name__)


class SamlParser:
    def __init__(self, response: bytes):
        self.response = response
        try:
            self.tree = ElementTree.fromstring(response)
        except ElementTree.ParseError:
            raise SamlResponseInvalid("Invalid XML")

    def get_user_id(self) -> str:
        attribute = "https://aws.amazon.com/SAML/Attributes/RoleSessionName"
        element = self.tree.find(self._query_for_attribute_value(attribute))
        if element is None or not element.text:
            raise SamlResponseInvalid("User id not found")
        return element.text

    def get_roles(self) -> List[Role]:
        attribute = "https://aws.amazon.com/SAML/Attributes/Role"
        role_elements = self.tree.findall(self._query_for_attribute_value(attribute))
        roles = [Role.from_string(element.text) for element in role_elements if element.text]
        roles = list(set(roles))
        roles.sort(key=lambda p: p.get_account_number())
        LOG.debug(f'Roles in saml: {", ".join(map(str, roles))}')
        return roles

    def _query_for_attribute_value(self, attribute_name: str) -> str:
        return (
            "{urn:oasis:names:tc:SAML:2.0:assertion}Assertion/"
            "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement/"
            "{urn:oasis:names:tc:SAML:2.0:assertion}Attribute"
            f'[@Name="{attribute_name}"]/'
            "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue"
        )

    @staticmethod
    def from_base64(saml_b64: str) -> "SamlParser":
        saml = base64.b64decode(saml_b64)
        return SamlParser(saml)


class SamlParserError(Exception):
    pass


class SamlResponseMissing(SamlParserError):
    pass


class SamlResponseEncodingInvalid(SamlParserError):
    pass


class SamlResponseInvalid(SamlParserError):
    def __init__(self, reason: str):
        super().__init__("Invalid SAML response: " + reason)
