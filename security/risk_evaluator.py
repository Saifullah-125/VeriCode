"""Phase 4: Merge, deduplicate, and score static findings alongside secret findings."""

from typing import Any, Dict, List


SEVERITY_WEIGHTS = {
    "CRITICAL": 35,
    "HIGH": 25,
    "MEDIUM": 12,
    "LOW": 5,
}

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
}


def merge_and_deduplicate_findings(
    existing_findings: List[Dict[str, Any]],
    secret_findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Merge legacy static findings with secret findings without double-counting the same line/secret."""
    merged: List[Dict[str, Any]] = []
    seen_signatures = set()
    secret_lines = set()

    for sf in secret_findings or []:
        line = int(sf.get("line", 0))
        rule_id = str(sf.get("rule_id", ""))
        masked = str(sf.get("evidence_masked") or sf.get("lexeme") or "")
        sig = (line, rule_id, masked)
        if sig in seen_signatures:
            continue
        seen_signatures.add(sig)
        secret_lines.add(line)
        merged.append(sf)

    for ef in existing_findings or []:
        line = int(ef.get("line", 0))
        rule_id = str(ef.get("rule_id", ""))
        title_lower = str(ef.get("title", "")).lower()
        if line in secret_lines and any(
            kw in title_lower or kw in rule_id.lower()
            for kw in ("password", "secret", "token", "api_key", "apikey", "credential", "hardcoded")
        ):
            continue
        lex = str(ef.get("lexeme", ""))
        sig = (line, rule_id, lex)
        if sig in seen_signatures:
            continue
        seen_signatures.add(sig)
        merged.append(ef)

    merged.sort(key=lambda item: (SEVERITY_ORDER.get(str(item.get("severity", "LOW")).upper(), 9), int(item.get("line", 0))))
    return merged


def calculate_risk_profile(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate deterministic 0-100 risk score and tier metadata from deduplicated findings."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    raw_score = 0

    for f in findings or []:
        sev = str(f.get("severity", "LOW")).upper()
        if sev not in counts:
            sev = "LOW"
        counts[sev] += 1
        raw_score += SEVERITY_WEIGHTS.get(sev, 5)

    score = min(100, raw_score)
    total = len(findings or [])
    high_plus = counts["CRITICAL"] + counts["HIGH"]

    if score == 0:
        level = "CLEAN"
        pdf_color = "#10B981"
        summary = "No security vulnerabilities or exposed secrets were detected."
    elif score >= 75 or counts["CRITICAL"] > 0:
        level = "CRITICAL"
        pdf_color = "#DC2626"
        summary = f"Critical exposure detected ({high_plus} high/critical issues). Immediate remediation required."
    elif score >= 45 or counts["HIGH"] > 0:
        level = "HIGH"
        pdf_color = "#EF4444"
        summary = f"High-risk security issues detected ({counts['HIGH']} high, {counts['MEDIUM']} medium)."
    elif score >= 20:
        level = "MODERATE"
        pdf_color = "#F59E0B"
        summary = f"Moderate security weaknesses detected ({total} total findings)."
    else:
        level = "LOW"
        pdf_color = "#3B82F6"
        summary = f"Low-severity advisory findings detected ({total} total)."

    ui_counts = {
        "CRITICAL": counts["CRITICAL"],
        "HIGH": counts["HIGH"] + counts["CRITICAL"],
        "MEDIUM": counts["MEDIUM"],
        "LOW": counts["LOW"],
    }

    return {
        "score": score,
        "level": level,
        "pdf_color": pdf_color,
        "summary": summary,
        "counts": ui_counts,
        "total_findings": total,
    }
