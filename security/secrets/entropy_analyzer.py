"""Phase 3: Shannon entropy heuristics for random-looking string literals."""

import math
import re
from typing import Tuple

_BASE64_LIKE_RE = re.compile(r"^[A-Za-z0-9+/=_-]+$")
_HEX_LIKE_RE = re.compile(r"^[0-9a-fA-F]+$")
_URL_OR_PATH_RE = re.compile(r"^(?:https?://|/|\\\\|[A-Za-z]:\\\\)")


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def is_high_entropy_candidate(value: str, min_length: int = 20, threshold: float = 4.2) -> Tuple[bool, float]:
    """Return (is_high_entropy, score). Used as supporting evidence rather than standalone proof."""
    if not value:
        return False, 0.0
    s = value.strip()
    if len(s) < min_length or len(s) > 256:
        return False, 0.0
    if " " in s or "\n" in s:
        return False, 0.0
    if _URL_OR_PATH_RE.match(s):
        return False, 0.0

    ent = shannon_entropy(s)
    if _HEX_LIKE_RE.match(s):
        return (ent >= 3.3 and len(s) >= 24), round(ent, 3)

    if _BASE64_LIKE_RE.match(s):
        return (ent >= threshold), round(ent, 3)

    return (ent >= (threshold + 0.2)), round(ent, 3)
