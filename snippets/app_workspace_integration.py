# Add this helper and route integration into your existing app.py

SUPPORTED_LANGUAGES = {"C", "C++", "Python", "Java"}

LANGUAGE_ALIASES = {
    "c": "C",
    "cpp": "C++",
    "c++": "C++",
    "python": "Python",
    "py": "Python",
    "java": "Java",
}


def validate_workspace_request(payload: dict):
    """Validate selected language and ensure only active-language source is analyzed."""
    raw_lang = str(payload.get("language", "")).strip()
    normalized_lang = LANGUAGE_ALIASES.get(raw_lang.lower(), raw_lang)

    if normalized_lang not in SUPPORTED_LANGUAGES:
        return None, None, f"Unsupported language: '{raw_lang}'. Allowed: C, C++, Python, Java."

    source_code = payload.get("source_code")
    if not isinstance(source_code, str) or not source_code.strip():
        return normalized_lang, "", "Source code cannot be empty."

    return normalized_lang, source_code, None


# Inside your /analyze route:
# lang, source_code, err = validate_workspace_request(data)
# if err:
#     return jsonify({"error": err}), 400
# analysis_result = run_existing_analysis(lang, source_code)
# analysis_result["workspace_meta"] = {
#     "analyzed_language": lang,
#     "line_count": len(source_code.splitlines()),
#     "snapshot_id": data.get("snapshot_id", "")
# }
# return jsonify(analysis_result)
