"""Phase 3: Secret detection coordinator, evidence correlator, allowlist filter, and masker."""

from typing import Any, Dict, List

from .context_analyzer import analyze_literal_context
from .entropy_analyzer import is_high_entropy_candidate
from .literal_extractor import extract_literals
from .pattern_detector import detect_patterns
from .secret_rules import SECRET_RULES, mask_secret


def _build_finding(
    rule_id: str,
    language: str,
    line: int,
    column: int,
    raw_secret: str,
    context_name: str,
    confidence_override: str = None,
    severity_override: str = None,
) -> Dict[str, Any]:
    rule = SECRET_RULES[rule_id]
    masked_val = mask_secret(raw_secret)
    lexeme = f'{context_name} = "{masked_val}"' if context_name else f'"{masked_val}"'
    evidence = f"Line {line}, Col {column}: {lexeme} [masked]"

    return {
        "rule_id": rule.rule_id,
        "category": rule.category,
        "title": rule.title,
        "severity": severity_override or rule.severity,
        "confidence": confidence_override or rule.confidence,
        "language": language,
        "line": line,
        "column": column,
        "lexeme": lexeme,
        "evidence": evidence,
        "evidence_masked": masked_val,
        "source": "literal_context",
        "description": rule.description,
        "recommendation": rule.recommendation,
    }


def scan_secrets(code: str, language: str) -> List[Dict[str, Any]]:
    """Scan source code for hardcoded secrets using syntax-aware literals, patterns, context, and entropy."""
    literals = extract_literals(code, language)
    findings: List[Dict[str, Any]] = []
    seen_keys = set()

    for lit in literals:
        ctx = analyze_literal_context(lit)
        if ctx.is_env_reference or ctx.is_placeholder:
            continue

        pattern_matches = detect_patterns(lit.value)
        high_ent, ent_score = is_high_entropy_candidate(lit.value)

        chosen_rule_id = None
        chosen_secret = lit.value
        confidence = None
        severity = None

        if pattern_matches:
            top = pattern_matches[0]
            chosen_rule_id = top.rule_id
            chosen_secret = top.matched_value
            confidence = "HIGH" if (top.confidence == "HIGH" or ctx.context_strength in ("HIGH", "MEDIUM")) else "MEDIUM"
            if top.rule_id == "SECRET.PRIVATE_KEY":
                severity = "CRITICAL"
            elif top.rule_id in ("SECRET.HARDCODED.API_KEY", "SECRET.HARDCODED.TOKEN") and ctx.context_strength == "HIGH":
                severity = "HIGH"
        elif ctx.matched_category == "private_key":
            chosen_rule_id = "SECRET.PRIVATE_KEY"
            confidence = "HIGH" if high_ent else "MEDIUM"
        elif ctx.matched_category == "password":
            chosen_rule_id = "SECRET.HARDCODED.PASSWORD"
            confidence = "HIGH" if (ctx.context_strength == "HIGH" or high_ent) else "MEDIUM"
        elif ctx.matched_category == "api_key":
            chosen_rule_id = "SECRET.HARDCODED.API_KEY"
            confidence = "HIGH" if (ctx.context_strength == "HIGH" or high_ent) else "MEDIUM"
        elif ctx.matched_category == "token":
            chosen_rule_id = "SECRET.HARDCODED.TOKEN"
            confidence = "HIGH" if (ctx.context_strength == "HIGH" or high_ent) else "MEDIUM"
        elif ctx.matched_category == "db_url" and ("://" in lit.value and "@" in lit.value):
            chosen_rule_id = "SECRET.DATABASE.CONNECTION_URL"
            confidence = "HIGH"
        elif high_ent and ent_score >= 4.5 and len(lit.value.strip()) >= 28:
            chosen_rule_id = "SECRET.HIGH_ENTROPY.LITERAL"
            confidence = "LOW"
            severity = "LOW"

        if not chosen_rule_id:
            continue

        dedup_key = (lit.language, lit.line, chosen_rule_id, mask_secret(chosen_secret))
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)

        findings.append(
            _build_finding(
                rule_id=chosen_rule_id,
                language=lit.language,
                line=lit.line,
                column=lit.column,
                raw_secret=chosen_secret,
                context_name=lit.context_name,
                confidence_override=confidence,
                severity_override=severity,
            )
        )

    return findings
