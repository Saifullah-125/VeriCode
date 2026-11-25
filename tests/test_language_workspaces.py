import pytest
from app import validate_workspace_request


def test_valid_languages_accepted():
    for lang, expected in [
        ("C", "C"),
        ("cpp", "C++"),
        ("C++", "C++"),
        ("Python", "Python"),
        ("py", "Python"),
        ("Java", "Java"),
    ]:
        norm_lang, src, err = validate_workspace_request(
            {"language": lang, "source_code": "int x = 1;"}
        )
        assert err is None
        assert norm_lang == expected
        assert src == "int x = 1;"


def test_rejects_unsupported_language():
    norm_lang, _, err = validate_workspace_request(
        {"language": "Ruby", "source_code": "puts 1"}
    )
    assert norm_lang is None
    assert "Unsupported language" in err


def test_rejects_empty_or_whitespace_source():
    _, _, err = validate_workspace_request(
        {"language": "Python", "source_code": "   \n\t  "}
    )
    assert err == "Source code cannot be empty."
