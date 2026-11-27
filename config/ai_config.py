"""Configuration for the VeriCode Hybrid AI Security & Hardening Agent."""

import os


class AIConfig:
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "").strip()
    GEMINI_MODEL: str = os.getenv("VERICODE_GEMINI_MODEL", "gemini-2.5-flash").strip()
    ENABLE_EXTERNAL_LLM: bool = bool(GEMINI_API_KEY) and os.getenv("VERICODE_AI_OFFLINE", "0") != "1"
    REQUEST_TIMEOUT_SEC: float = float(os.getenv("VERICODE_AI_TIMEOUT", "6.0"))
    ENABLE_LOCAL_COMPILER_CHECK: bool = os.getenv("VERICODE_LOCAL_COMPILER_CHECK", "1") == "1"
