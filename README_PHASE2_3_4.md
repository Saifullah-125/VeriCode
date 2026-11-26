# VeriCode 2.0 – Phases 2, 3 & 4 Integration Guide

## Included Files
- `security/secrets/__init__.py`
- `security/secrets/secret_rules.py` – Rule registry, severity/confidence defaults, and secret masking (`mask_secret`).
- `security/secrets/literal_extractor.py` – Phase 2 syntax-aware literal extraction for C, C++, Python, and Java.
- `security/secrets/context_analyzer.py` – Phase 3 assignment/key/argument context inspection and placeholder allowlists.
- `security/secrets/pattern_detector.py` – Phase 3 credential signatures, PEM private-key blocks, DB URIs, and sensitive URL params.
- `security/secrets/entropy_analyzer.py` – Phase 3 Shannon entropy heuristics.
- `security/secrets/secret_scanner.py` – Phase 3 detector coordinator and normalized masked finding builder.
- `security/risk_evaluator.py` – Phase 4 deduplicated merger and deterministic 0–100 risk evaluator.
- `snippets/app_phase4_integration.py` – Minimal hook (`attach_secret_findings`) for `app.py` (zero GUI or workflow changes).
- `tests/test_literal_extraction.py` & `tests/test_secret_scanner.py` – Pytest test suites.

## Setup Steps
1. Extract and copy `security/` and `tests/` into your VeriCode project root.
2. In `app.py`, import `attach_secret_findings` (from `snippets/app_phase4_integration.py`) and wrap `result = run_pipeline(code, language=normalized_lang)` with `result = attach_secret_findings(result, code)`.
3. Run tests:
   ```bash
   python -m pytest tests/test_literal_extraction.py tests/test_secret_scanner.py
   ```
