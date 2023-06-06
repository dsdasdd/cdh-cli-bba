from typing import Any
from unittest.mock import Mock
from unittest.mock import patch

import pytest

from cdh_utils.utils.helpers import Prompter

VALUE_INDEX_0 = 100
VALUE_INDEX_1 = "x"
VALUE_INDEX_2 = object()


@patch("cdh_utils.utils.helpers.click.prompt")
class TestPromptDict:
    def setup_method(self) -> None:
        self.prompter = Prompter()
        self.choices = {
            "label a": VALUE_INDEX_0,
            "label b": VALUE_INDEX_1,
            "label c": VALUE_INDEX_2,
        }

    @pytest.mark.parametrize("user_input, expected_value", [(0, VALUE_INDEX_0), (1, VALUE_INDEX_1), (2, VALUE_INDEX_2)])
    def test_valid_choice_returns_value_any_type(
        self, click_prompt_mock: Mock, user_input: int, expected_value: Any
    ) -> None:
        click_prompt_mock.return_value = user_input

        result = self.prompter.prompt_select_from_dict(self.choices, "my labels", "please choose stuff")

        assert result == expected_value

    def test_prompt_contains_labelled_choices(self, click_prompt_mock: Mock) -> None:
        click_prompt_mock.return_value = 0

        self.prompter.prompt_select_from_dict(self.choices, "my labels", "please choose stuff")

        _, kwargs = click_prompt_mock.call_args
        assert "0  label a" in kwargs["text"]
        assert "1  label b" in kwargs["text"]
        assert "2  label c" in kwargs["text"]

    def test_prompt_contains_header(self, click_prompt_mock: Mock) -> None:
        click_prompt_mock.return_value = 0

        self.prompter.prompt_select_from_dict(self.choices, "my header", "please choose stuff")

        _, kwargs = click_prompt_mock.call_args
        assert "ID  my header" in kwargs["text"]

    def test_prompt_contains_prompt(self, click_prompt_mock: Mock) -> None:
        click_prompt_mock.return_value = 0

        self.prompter.prompt_select_from_dict(self.choices, "my header", "please choose stuff")

        _, kwargs = click_prompt_mock.call_args
        assert "> please choose stuff" in kwargs["text"]

    @pytest.mark.parametrize("choices", [{}, {"only label": "only value"}], ids=str)
    def test_raises_error_for_insufficient_choices(self, click_prompt_mock: Mock, choices: dict) -> None:
        with pytest.raises(ValueError):
            self.prompter.prompt_select_from_dict(choices, "my header", "please choose stuff")
