# Phase 4 Integration Snippet for app.py
# 1) Add these imports near the top of app.py:
#    from security.secrets import scan_secrets
#    from security.risk_evaluator import merge_and_deduplicate_findings, calculate_risk_profile
#
# 2) Add this helper to app.py and wrap the return value of run_pipeline(code, language=normalized_lang):

def attach_secret_findings(result: dict, code: str) -> dict:
    """Merge literal/context-aware secret findings into any successful analysis result."""
    if not result or not result.get("success"):
        return result

    target_lang = result.get("language", "General")
    secret_findings = scan_secrets(code, target_lang)
    merged_findings = merge_and_deduplicate_findings(
        result.get("findings", []),
        secret_findings,
    )
    result["findings"] = merged_findings
    result["risk_profile"] = calculate_risk_profile(merged_findings)
    return result

# Example in /analyze route:
#   result = run_pipeline(code, language=normalized_lang)
#   result = attach_secret_findings(result, code)
