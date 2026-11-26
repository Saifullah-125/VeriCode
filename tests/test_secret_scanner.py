from security.secrets import scan_secrets
from security.secrets.value_re_analyzer import analyze_values_with_re
from security.risk_evaluator import merge_and_deduplicate_findings, calculate_risk_profile


def test_detects_secret_even_when_identifier_renamed():
    code = 'random_var_name = "P@ssw0rd_Secret_2026!"'
    findings = analyze_values_with_re(code, "Python")
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SECRET.VALUE.PATTERN"
    assert "P@ssw0rd_Secret_2026!" not in str(findings[0])


def test_detects_api_key_under_ordinary_variable_name():
    code = 'val = "sk-live-9876543210abcdef999"'
    findings = scan_secrets(code, "Python")
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SECRET.HARDCODED.API_KEY"
    assert "****" in findings[0]["evidence_masked"]


def test_ignores_placeholders_and_env_lookups():
    code = """
import os
password = "changeme"
api_key = "your_api_key_here"
real_key = os.getenv("SERVICE_API_KEY")
"""
    assert scan_secrets(code, "Python") == []
    assert analyze_values_with_re(code, "Python") == []


def test_deduplication_prevents_double_scoring():
    legacy = [{
        "rule_id": "PY.HARDCODED.TOKEN",
        "title": "Hardcoded Secret Token",
        "severity": "HIGH",
        "line": 3,
        "lexeme": "admin_token",
    }]
    secret = analyze_values_with_re('\n\nadmin_token = "ghp_1234567890abcdefghij1234"', "Python")
    merged = merge_and_deduplicate_findings(legacy, secret)
    assert len(merged) == 1
    assert calculate_risk_profile(merged)["total_findings"] == 1
