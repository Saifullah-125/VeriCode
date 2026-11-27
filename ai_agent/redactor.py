"""Strict secret redaction before any AI processing or external LLM call."""

import copy
import re
from typing import Any, Dict, List


_SECRET_LITERAL_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b(?:sk|rk)-(?:live|test|proj)?-?[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z\-_]{12,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{12,}\b"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|xox[baprs])_[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/=]{12,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\b(?:mysql|postgres|postgresql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^:\s\"']+:([^@\s\"']+)@[^\s\"']+", re.I),
]

_ASSIGNED_SECRET_RE = re.compile(
    r'(?i)(\b(?:password|passwd|pwd|secret|api_key|apikey|token|access_token|auth_token|db_password|private_key)\b\s*(?:\[[^\]]*\])?\s*=\s*)(["\'])([^"\']{4,})(\2)'
)

_PROMPT_INJECTION_RE = re.compile(
    r"(?i)(ignore\s+previous\s+instructions|system\s+prompt|reveal\s+secrets|exfiltrate|bypass\s+security)"
)


def _mask_token(val: str) -> str:
    s = (val or "").strip()
    if len(s) <= 4:
        return "****"
    if len(s) <= 8:
        return f"{s[0]}****{s[-1]}"
    return f"{s[:3]}****{s[-3:]}"


def redact_secrets_in_text(text: str) -> str:
    """Mask raw credentials and neutralize prompt-injection strings inside source text."""
    if not text:
        return ""
    redacted = str(text)

    def _repl_assign(m: re.Match) -> str:
        return f"{m.group(1)}{m.group(2)}{_mask_token(m.group(3))}{m.group(4)}"

    redacted = _ASSIGNED_SECRET_RE.sub(_repl_assign, redacted)

    for pat in _SECRET_LITERAL_PATTERNS:
        redacted = pat.sub(lambda m: _mask_token(m.group(0)), redacted)

    redacted = _PROMPT_INJECTION_RE.sub("[UNTRUSTED_COMMENT_REDACTED]", redacted)
    return redacted


def sanitize_findings_for_agent(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return deep-copied findings with all raw secrets masked."""
    clean_list: List[Dict[str, Any]] = []
    for f in findings or []:
        item = copy.deepcopy(f)
        for key in ("lexeme", "evidence", "description", "recommendation"):
            if key in item and isinstance(item[key], str):
                item[key] = redact_secrets_in_text(item[key])
        clean_list.append(item)
    return clean_list
