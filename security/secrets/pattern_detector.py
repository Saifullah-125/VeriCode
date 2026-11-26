"""Phase 3: Known secret format signatures, private-key blocks, DB URLs, and sensitive URL parameters."""

import re
from dataclasses import dataclass
from typing import List, Tuple
from urllib.parse import urlparse, parse_qs


@dataclass
class PatternMatch:
    rule_id: str
    pattern_name: str
    matched_value: str
    confidence: str


_KNOWN_SIGNATURES: List[Tuple[str, str, str, re.Pattern]] = [
    (
        "SECRET.PRIVATE_KEY",
        "PEM Private Key Header",
        "HIGH",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    ),
    (
        "SECRET.HARDCODED.API_KEY",
        "OpenAI / Stripe Style Secret Key",
        "HIGH",
        re.compile(r"\b(?:sk|rk)-(?:live|test|proj)?-?[A-Za-z0-9_-]{16,}\b"),
    ),
    (
        "SECRET.HARDCODED.API_KEY",
        "Google API Key",
        "HIGH",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{16,}\b"),
    ),
    (
        "SECRET.HARDCODED.API_KEY",
        "AWS Access Key ID",
        "HIGH",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    (
        "SECRET.HARDCODED.TOKEN",
        "GitHub Personal Access Token",
        "HIGH",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"),
    ),
    (
        "SECRET.HARDCODED.TOKEN",
        "Slack Token",
        "HIGH",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{16,}\b"),
    ),
    (
        "SECRET.HARDCODED.TOKEN",
        "Bearer Authorization Token",
        "HIGH",
        re.compile(r"(?i)\bBearer\s+([A-Za-z0-9\-._~+/]{16,}=*)"),
    ),
    (
        "SECRET.HARDCODED.TOKEN",
        "JWT Token",
        "MEDIUM",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
]

_DB_URI_RE = re.compile(
    r"\b(?:mysql|postgres|postgresql|mongodb|mongodb\+srv|redis|amqp|mssql|oracle)://[^:\s\"']+:([^@\s\"']+)@[^\s\"']+",
    re.IGNORECASE,
)

_SENSITIVE_QUERY_KEYS = {
    "api_key",
    "apikey",
    "token",
    "access_token",
    "secret",
    "password",
    "passwd",
    "pwd",
    "key",
}


def detect_patterns(literal_value: str) -> List[PatternMatch]:
    if not literal_value or len(literal_value.strip()) < 6:
        return []

    matches: List[PatternMatch] = []
    text = literal_value.strip()

    for rule_id, name, conf, regex in _KNOWN_SIGNATURES:
        m = regex.search(text)
        if m:
            secret_piece = m.group(1) if m.lastindex else m.group(0)
            matches.append(
                PatternMatch(
                    rule_id=rule_id,
                    pattern_name=name,
                    matched_value=secret_piece,
                    confidence=conf,
                )
            )

    db_m = _DB_URI_RE.search(text)
    if db_m:
        pwd = db_m.group(1)
        if pwd.lower() not in ("password", "pass", "changeme", "example", "dummy", "test", "xxx"):
            matches.append(
                PatternMatch(
                    rule_id="SECRET.DATABASE.CONNECTION_URL",
                    pattern_name="Database URI Credentials",
                    matched_value=pwd,
                    confidence="HIGH",
                )
            )

    if "://" in text and "?" in text:
        try:
            parsed = urlparse(text)
            qs = parse_qs(parsed.query)
            for k, vals in qs.items():
                if k.lower() in _SENSITIVE_QUERY_KEYS and vals:
                    val = vals[0].strip()
                    if len(val) >= 4 and val.lower() not in ("example", "dummy", "test", "changeme", "xxx"):
                        matches.append(
                            PatternMatch(
                                rule_id="SECRET.URL.SENSITIVE_PARAM",
                                pattern_name=f"Sensitive URL Parameter ({k})",
                                matched_value=val,
                                confidence="MEDIUM",
                            )
                        )
                        break
        except Exception:
            pass

    return matches
