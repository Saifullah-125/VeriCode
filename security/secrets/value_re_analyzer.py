"""Value-based Regular Expression analyzer (independent of variable/identifier names)."""

import ast
import io
import math
import re
import tokenize
from typing import Any, Dict, List, Tuple


def _mask(val: str) -> str:
    s = (val or "").strip()
    if len(s) <= 4:
        return "*" * len(s)
    if len(s) <= 8:
        return f"{s[0]}****{s[-1]}"
    return f"{s[:3]}****{s[-3:]}"


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


_VALUE_PATTERNS = [
    (
        "SECRET.PRIVATE_KEY",
        "CRITICAL",
        "HIGH",
        "PEM Private Key Block",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    ),
    (
        "SECRET.HARDCODED.API_KEY",
        "HIGH",
        "HIGH",
        "Secret API/Service Key",
        re.compile(r"\b(?:sk|rk)-(?:live|test|proj)?-?[A-Za-z0-9_-]{12,}\b"),
    ),
    (
        "SECRET.HARDCODED.API_KEY",
        "HIGH",
        "HIGH",
        "Google API Key",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{12,}\b"),
    ),
    (
        "SECRET.HARDCODED.API_KEY",
        "HIGH",
        "HIGH",
        "AWS Access Key",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{12,}\b"),
    ),
    (
        "SECRET.HARDCODED.TOKEN",
        "HIGH",
        "HIGH",
        "Access/Service Token",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|xox[baprs])_[A-Za-z0-9_-]{12,}\b"),
    ),
    (
        "SECRET.HARDCODED.TOKEN",
        "HIGH",
        "HIGH",
        "Bearer Token",
        re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/=]{12,}\b"),
    ),
    (
        "SECRET.HARDCODED.TOKEN",
        "MEDIUM",
        "MEDIUM",
        "JWT Token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    ),
    (
        "SECRET.DATABASE.CONNECTION_URL",
        "HIGH",
        "HIGH",
        "Database Connection URI Credential",
        re.compile(
            r"\b(?:mysql|postgres|postgresql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^:\s\"']+:([^@\s\"']{4,})@[^\s\"']+",
            re.IGNORECASE,
        ),
    ),
    (
        "SECRET.URL.SENSITIVE_PARAM",
        "MEDIUM",
        "MEDIUM",
        "Sensitive URL Query Parameter",
        re.compile(
            r"https?://[^\s\"']+[?&](?:api_key|apikey|token|access_token|secret|password|passwd|pwd)=([^&\s\"']{4,})",
            re.IGNORECASE,
        ),
    ),
]

_COMPLEX_SECRET_RE = re.compile(
    r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?~])[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?~]{8,}$"
)
_TOKEN_LIKE_RE = re.compile(
    r"^(?=[A-Za-z0-9._-]{16,}$)(?=.*[A-Za-z])(?=.*\d)(?=.*[_-])[A-Za-z0-9._-]+$"
)

_IGNORE_VALUES = {
    "changeme",
    "change_me",
    "password",
    "secret",
    "example",
    "dummy",
    "test",
    "your_api_key",
    "your_token",
    "your_password",
    "select * from users",
}

_QUOTE_LITERAL_RE = re.compile(r'"((?:\\.|[^"\\])*)"|\'((?:\\.|[^\'\\])*)\'')


def _extract_literals_for_re(code: str, language: str) -> List[Tuple[str, int]]:
    lang = (language or "").strip().lower()
    items: List[Tuple[str, int]] = []

    if lang == "python":
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    items.append((node.value, getattr(node, "lineno", 1)))
            if items:
                return items
        except SyntaxError:
            pass
        try:
            for tok in tokenize.generate_tokens(io.StringIO(code).readline):
                if tok.type == tokenize.STRING:
                    try:
                        val = ast.literal_eval(tok.string)
                    except Exception:
                        val = tok.string.strip("'\"")
                    if isinstance(val, str):
                        items.append((val, tok.start[0]))
            return items
        except Exception:
            pass

    for line_no, line_txt in enumerate(code.splitlines(), start=1):
        s = line_txt.strip()
        if s.startswith("//") or s.startswith("#"):
            continue
        for m in _QUOTE_LITERAL_RE.finditer(line_txt):
            val = m.group(1) if m.group(1) is not None else m.group(2)
            if val:
                items.append((val, line_no))
    return items


def analyze_values_with_re(code: str, language: str) -> List[Dict[str, Any]]:
    """Analyze literal values directly using Regular Expressions (independent of identifier names)."""
    if not code or not code.strip():
        return []

    findings: List[Dict[str, Any]] = []
    seen = set()

    for raw_val, line_no in _extract_literals_for_re(code, language):
        val = (raw_val or "").strip()
        if not val or len(val) < 6 or val.lower() in _IGNORE_VALUES:
            continue
        if re.fullmatch(r"[A-Z][A-Z0-9_]{2,}", val):
            continue

        matched_finding = None

        for rule_id, sev, conf, label, pat in _VALUE_PATTERNS:
            m = pat.search(val)
            if m:
                target = m.group(1) if m.lastindex else m.group(0)
                if target.lower() in _IGNORE_VALUES:
                    continue
                masked = _mask(target)
                matched_finding = {
                    "rule_id": rule_id,
                    "title": f"{label} (Value RE)",
                    "severity": sev,
                    "confidence": conf,
                    "language": language,
                    "line": line_no,
                    "lexeme": masked,
                    "evidence": f"Line {line_no}: RE matched [{label}] on literal value -> {masked}",
                    "evidence_masked": masked,
                    "description": f"Literal value matched regular expression pattern for {label}.",
                    "recommendation": "Move sensitive values out of source code into environment variables or a secret manager.",
                }
                break

        if not matched_finding and (
            _COMPLEX_SECRET_RE.match(val) or (_TOKEN_LIKE_RE.match(val) and _entropy(val) >= 3.8)
        ):
            masked = _mask(val)
            matched_finding = {
                "rule_id": "SECRET.VALUE.PATTERN",
                "title": "Secret-Like Literal Value (Value RE)",
                "severity": "MEDIUM",
                "confidence": "MEDIUM",
                "language": language,
                "line": line_no,
                "lexeme": masked,
                "evidence": f"Line {line_no}: RE value-shape match (mixed/complex literal) -> {masked}",
                "evidence_masked": masked,
                "description": "Literal value matches secret/credential pattern regardless of variable/identifier name.",
                "recommendation": "Verify whether this literal is a password, key, or token and store it securely in environment configuration.",
            }

        if matched_finding:
            key = (line_no, matched_finding["rule_id"], matched_finding["lexeme"])
            if key not in seen:
                seen.add(key)
                findings.append(matched_finding)

    return findings
