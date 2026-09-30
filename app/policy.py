"""Policy engine: turns detection results into an action.

Kept deliberately separate from the detection layers so the response
behavior (block vs. sanitize vs. flag) can be tuned per deployment
without touching any detection code.
"""
import re

from app import config
from app.schemas import Action, Verdict


def sanitize(content: str, attack_type: str) -> str:
    """Best-effort stripping of the malicious segment for sanitize-and-pass.

    This is intentionally simple: it removes HTML/markdown comments (the
    main indirect-injection vector) and leaves the rest of the content
    untouched. A production system would do more targeted span removal
    based on where Layer 1/2/3 located the offending text.
    """
    if attack_type == "Indirect Prompt Injection":
        return re.sub(r"<!--.*?-->", "[removed: hidden instruction]", content, flags=re.S)
    return content


def decide(layer: str, attack_type: str, confidence: float) -> tuple[Action, Verdict]:
    """Map a single layer's finding to (action, verdict)."""
    if attack_type == "None":
        return "allow", "allowed"

    if layer == "heuristic":
        # Layer 1 only fires on high-precision patterns. Still respect
        # SANITIZABLE_TYPES here — an indirect injection caught by a fast
        # regex deserves the same sanitize-and-pass treatment as one
        # caught by Layer 2, not an automatic hard block.
        if attack_type in config.SANITIZABLE_TYPES:
            return "sanitize", "sanitized"
        return "block", "blocked"

    if layer == "similarity":
        if confidence >= config.SIMILARITY_BLOCK_THRESHOLD:
            if attack_type in config.SANITIZABLE_TYPES:
                return "sanitize", "sanitized"
            return "block", "blocked"
        # otherwise: ambiguous band, handled by caller escalating to Layer 3
        return "flag_for_review", "flagged"

    if layer == "llm_judge":
        if confidence >= config.JUDGE_BLOCK_CONFIDENCE:
            if attack_type in config.SANITIZABLE_TYPES:
                return "sanitize", "sanitized"
            return "block", "blocked"
        if confidence >= config.JUDGE_LOW_CONFIDENCE_FLOOR:
            return "flag_for_review", "flagged"
        return "allow", "allowed"

    return "allow", "allowed"
