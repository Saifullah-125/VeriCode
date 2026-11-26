"""Rule definitions, severity/confidence defaults, and masking utilities."""

from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class SecretRule:
    rule_id: str
    category: str
    title: str
    severity: str
    confidence: str
    description: str
    recommendation: str


SECRET_RULES: Dict[str, SecretRule] = {
    "SECRET.PRIVATE_KEY": SecretRule(
        rule_id="SECRET.PRIVATE_KEY",
        category="Private key material",
        title="Hardcoded Private Key Block",
        severity="CRITICAL",
        confidence="HIGH",
        description="PEM-formatted private key material is embedded directly in source code.",
        recommendation="Remove the private key from source control immediately, revoke/reissue the key pair, and load it from a secure vault or file outside the repository.",
    ),
    "SECRET.HARDCODED.API_KEY": SecretRule(
        rule_id="SECRET.HARDCODED.API_KEY",
        category="API key / service credential",
        title="Hardcoded API Key or Service Credential",
        severity="HIGH",
        confidence="HIGH",
        description="A likely API key or service credential literal is embedded in source code.",
        recommendation="Rotate the credential if genuine and load it via environment variables or a dedicated secret manager.",
    ),
    "SECRET.HARDCODED.TOKEN": SecretRule(
        rule_id="SECRET.HARDCODED.TOKEN",
        category="Access token / bearer token",
        title="Hardcoded Access or Bearer Token",
        severity="HIGH",
        confidence="HIGH",
        description="An authentication token or bearer credential literal is hardcoded in source code.",
        recommendation="Revoke the exposed token and inject runtime tokens through secure environment configuration or a secret store.",
    ),
    "SECRET.HARDCODED.PASSWORD": SecretRule(
        rule_id="SECRET.HARDCODED.PASSWORD",
        category="Hardcoded password",
        title="Hardcoded Password Literal",
        severity="HIGH",
        confidence="MEDIUM",
        description="A non-placeholder password literal is assigned directly in source code.",
        recommendation="Replace hardcoded passwords with runtime environment variables or secret-manager lookups.",
    ),
    "SECRET.DATABASE.CONNECTION_URL": SecretRule(
        rule_id="SECRET.DATABASE.CONNECTION_URL",
        category="Database credentials",
        title="Database Connection String with Embedded Credentials",
        severity="HIGH",
        confidence="HIGH",
        description="A database connection URI containing an embedded username and password was detected.",
        recommendation="Move database credentials out of connection URIs in source code and load them from secure environment configuration.",
    ),
    "SECRET.URL.SENSITIVE_PARAM": SecretRule(
        rule_id="SECRET.URL.SENSITIVE_PARAM",
        category="Sensitive URL parameter",
        title="Sensitive Credential in URL Query Parameter",
        severity="MEDIUM",
        confidence="MEDIUM",
        description="A URL literal contains a credential-bearing query parameter such as api_key, token, or password.",
        recommendation="Pass credentials via secure headers or secret-store configuration rather than embedding them in URLs.",
    ),
    "SECRET.HIGH_ENTROPY.LITERAL": SecretRule(
        rule_id="SECRET.HIGH_ENTROPY.LITERAL",
        category="High-entropy literal",
        title="Suspicious High-Entropy String Literal",
        severity="LOW",
        confidence="LOW",
        description="A high-entropy random-looking string literal was found; it may represent an unlabelled secret or key.",
        recommendation="Verify whether this literal is a real secret; if so, rotate it and move it to a secret manager.",
    ),
}


def mask_secret(value: str, visible_prefix: int = 3, visible_suffix: int = 3) -> str:
    """Return a masked representation of a secret so raw values are never exposed."""
    if not value:
        return "****"
    clean = str(value).strip()
    if "BEGIN" in clean and "PRIVATE KEY" in clean:
        first_line = clean.splitlines()[0].strip()
        return f"{first_line[:27]}...****"
    length = len(clean)
    if length <= 4:
        return "*" * length
    if length <= 8:
        return f"{clean[0]}****{clean[-1]}"
    return f"{clean[:visible_prefix]}****{clean[-visible_suffix:]}"
