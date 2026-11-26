"""Phase 3: Context-aware analysis for extracted literals."""

import re
from dataclasses import dataclass
from typing import Optional

from .literal_extractor import ExtractedLiteral

PASSWORD_KEYWORDS = {
    "password",
    "passwd",
    "pwd",
    "pass",
    "db_pass",
    "db_password",
    "admin_pass",
    "user_password",
    "secret_pass",
}

API_KEY_KEYWORDS = {
    "api_key",
    "apikey",
    "api_secret",
    "client_secret",
    "app_secret",
    "secret_key",
    "secretkey",
    "access_key",
    "aws_secret_access_key",
    "stripe_key",
    "openai_api_key",
}

TOKEN_KEYWORDS = {
    "token",
    "access_token",
    "auth_token",
    "bearer_token",
    "refresh_token",
    "api_token",
    "admin_token",
    "jwt",
    "session_token",
    "private_token",
}

PRIVATE_KEY_KEYWORDS = {
    "private_key",
    "priv_key",
    "rsa_key",
    "pem_key",
    "signing_key",
}

DB_KEYWORDS = {
    "db_url",
    "database_url",
    "conn_str",
    "connection_string",
    "jdbc_url",
    "mongo_uri",
    "redis_url",
    "postgres_url",
    "mysql_url",
}

PLACEHOLDER_VALUES = {
    "example",
    "sample",
    "dummy",
    "changeme",
    "change_me",
    "test",
    "testing",
    "placeholder",
    "your_api_key",
    "your_password",
    "your_token",
    "replace_me",
    "todo",
    "none",
    "null",
    "undefined",
    "xxx",
    "xxxx",
    "123456",
    "password",
    "secret",
}

PLACEHOLDER_SUBSTRINGS = (
    "example",
    "dummy",
    "changeme",
    "change-me",
    "your_",
    "<your",
    "replace_me",
    "placeholder",
    "sample_key",
    "test_key",
    "fake_",
    "mock_",
)

_ENV_VAR_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,}$")


@dataclass
class ContextAssessment:
    is_placeholder: bool
    is_env_reference: bool
    matched_category: Optional[str]
    context_strength: str
    normalized_identifier: str


def is_placeholder_literal(value: str) -> bool:
    if not value:
        return True
    trimmed = value.strip()
    if len(trimmed) < 4:
        return True
    lower = trimmed.lower()
    if lower in PLACEHOLDER_VALUES:
        return True
    if any(sub in lower for sub in PLACEHOLDER_SUBSTRINGS):
        return True
    if len(set(trimmed)) <= 2 and len(trimmed) >= 4:
        return True
    return False


def analyze_literal_context(lit: ExtractedLiteral) -> ContextAssessment:
    raw_id = (lit.context_name or "").strip()
    norm_id = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", raw_id).lower()

    if lit.is_env_lookup or (
        lit.context_kind == "call_arg" and _ENV_VAR_NAME_RE.match(lit.value.strip())
    ):
        return ContextAssessment(
            is_placeholder=False,
            is_env_reference=True,
            matched_category=None,
            context_strength="NONE",
            normalized_identifier=norm_id,
        )

    if is_placeholder_literal(lit.value):
        return ContextAssessment(
            is_placeholder=True,
            is_env_reference=False,
            matched_category=None,
            context_strength="NONE",
            normalized_identifier=norm_id,
        )

    if not norm_id:
        return ContextAssessment(
            is_placeholder=False,
            is_env_reference=False,
            matched_category=None,
            context_strength="NONE",
            normalized_identifier="",
        )

    strength = "HIGH" if lit.context_kind in ("assignment", "dict_key") else "MEDIUM"

    if norm_id in PRIVATE_KEY_KEYWORDS or "private_key" in norm_id:
        return ContextAssessment(False, False, "private_key", strength, norm_id)

    if norm_id in PASSWORD_KEYWORDS or any(k in norm_id for k in ("password", "passwd", "pwd")):
        return ContextAssessment(False, False, "password", strength, norm_id)

    if norm_id in API_KEY_KEYWORDS or any(k in norm_id for k in ("api_key", "apikey", "secret_key", "client_secret", "access_key")):
        return ContextAssessment(False, False, "api_key", strength, norm_id)

    if norm_id in TOKEN_KEYWORDS or any(k in norm_id for k in ("token", "bearer", "jwt")):
        return ContextAssessment(False, False, "token", strength, norm_id)

    if norm_id in DB_KEYWORDS or any(k in norm_id for k in ("database_url", "db_url", "connection_string", "conn_str")):
        return ContextAssessment(False, False, "db_url", strength, norm_id)

    if "secret" in norm_id or "credential" in norm_id or "auth" in norm_id:
        return ContextAssessment(False, False, "api_key", "MEDIUM", norm_id)

    return ContextAssessment(False, False, None, "NONE", norm_id)
