"""Phase 6 Integration QA & Acceptance Tests (AI Agent, Secrets, Risk Reduction, Multi-Language)."""

from ai_agent.redactor import redact_secrets_in_text
from ai_agent.remediator import generate_remediation_suggestions
from ai_agent.translation_hardener import harden_translations
from security.risk_evaluator import calculate_risk_profile, merge_and_deduplicate_findings
from security.secrets import scan_secrets
from security.secrets.value_re_analyzer import analyze_values_with_re


def test_secret_redaction_masks_credentials_before_ai():
    raw = 'char password[32] = "SuperSecret_2026!"; const char *k = "sk-live-1234567890abcdef999";'
    redacted = redact_secrets_in_text(raw)
    assert "SuperSecret_2026!" not in redacted
    assert "sk-live-1234567890abcdef999" not in redacted
    assert "****" in redacted


def test_ai_agent_suggests_safe_alternatives_for_c_risky_functions():
    c_code = """
int main() {
    char buf[32];
    gets(buf);
    strcpy(buf, "hello");
    printf(buf);
    return 0;
}
"""
    suggestions = generate_remediation_suggestions(c_code, "C", [])
    keywords = [item["risky_keyword"] for item in suggestions["alternatives"]]
    alts = " ".join(item["safe_alternative"] for item in suggestions["alternatives"])
    assert "gets()" in keywords
    assert "strcpy()" in keywords
    assert "fgets" in alts
    assert "snprintf" in alts


def test_translation_hardening_reduces_risk_score_and_adds_headers():
    risky_c = """
int main() {
    char password[32] = "super_secret_123";
    char user_input[100];
    gets(user_input);
    strcpy(user_input, "dangerous");
    return 0;
}
"""
    sec_findings = merge_and_deduplicate_findings(
        scan_secrets(risky_c, "C"),
        analyze_values_with_re(risky_c, "C"),
    )
    translations = {
        "C++": """
int main() {
    char password[32] = "super_secret_123";
    char user_input[100];
    gets(user_input);
    strcpy(user_input, "dangerous");
    return 0;
}
""",
        "Python": """
password = "super_secret_123"
val = eval("2 + 2")
""",
    }

    hardened, summary = harden_translations(translations, "C", sec_findings)
    assert summary["targets_hardened"] == 2

    cpp_entry = hardened["C++"]
    assert "gets(" not in cpp_entry["code"]
    assert "fgets(" in cpp_entry["code"]
    assert "super_secret_123" not in cpp_entry["code"]
    assert "#include <cstdio>" in cpp_entry["code"]
    assert cpp_entry["risk_after"] < cpp_entry["risk_before"]

    py_entry = hardened["Python"]
    assert "ast.literal_eval(" in py_entry["code"]
    assert "super_secret_123" not in py_entry["code"]
    assert py_entry["risk_after"] <= py_entry["risk_before"]


def test_value_re_detects_renamed_secret_identifier():
    code = 'completely_renamed_var = "P@ssw0rd_Secret_2026!"'
    findings = analyze_values_with_re(code, "Python")
    assert len(findings) == 1
    assert calculate_risk_profile(findings)["score"] > 0
