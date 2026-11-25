# VeriCode 2.0 – Phase 0 & Phase 1 Integration Guide

## Included Files
- `.gitignore`: Excludes `__pycache__`, `.env`, `.secret_key`, and `users.db`.
- `.env.example`: Environment variable template for Flask and future AI integration.
- `static/js/editor_state.js`: Independent per-language workspace state manager (`C`, `C++`, `Python`, `Java`), language-specific placeholders, sample loader, and stale-result tracking.
- `tests/test_language_workspaces.py`: Pytest suite verifying language validation and empty-source rejection.
- `snippets/app_workspace_integration.py`: Backend validation helper and `/analyze` response metadata snippet for `app.py`.
- `snippets/template_integration.html`: Frontend HTML/JS hookup snippet for your dashboard template.

## Quick Setup
1. Copy `.gitignore`, `.env.example`, `static/js/editor_state.js`, and `tests/test_language_workspaces.py` into your VeriCode repository root.
2. Add `validate_workspace_request` and `workspace_meta` from `snippets/app_workspace_integration.py` into `app.py`.
3. Include `static/js/editor_state.js` in your HTML template using `snippets/template_integration.html`.
4. Run tests:
   ```bash
   python -m pytest tests/test_compiler.py tests/test_language_workspaces.py
   ```
