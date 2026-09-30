"""Layer 1: cheap, fast, regex-based heuristics.

This layer runs on every request and costs essentially nothing. It's
deliberately conservative — patterns are written to have very few false
positives, since anything it flags is blocked immediately without
going through Layers 2 or 3.
"""
import re
import time
from dataclasses import dataclass

from app.schemas import LayerResult


@dataclass
class Rule:
    attack_type: str
    pattern: re.Pattern
    description: str


RULES: list[Rule] = [
    Rule(
        "Instruction Override",
        re.compile(r"ignore (all |any )?(previous|prior|above) instructions?", re.I),
        "Direct instruction-override phrasing",
    ),
    Rule(
        "Instruction Override",
        re.compile(r"disregard (everything|all) (you were|previously) told", re.I),
        "Disregard-prior-context phrasing",
    ),
    Rule(
        "Role Change",
        re.compile(r"you are (now|no longer)\b.{0,40}\b(ai|assistant|dan|entity)", re.I),
        "Explicit role-reassignment phrasing",
    ),
    Rule(
        "Role Change",
        re.compile(r"act as (an? )?(unrestricted|unfiltered|jailbreak|dan)\b", re.I),
        "Unrestricted-persona request",
    ),
    Rule(
        "Secret Extraction",
        re.compile(r"(repeat|reveal|show|print).{0,25}(system prompt|hidden instructions?|your instructions?)", re.I),
        "System prompt exfiltration attempt",
    ),
    Rule(
        "Encoded Instructions",
        # long base64-looking run — heuristic, Layer 2/3 disambiguate content vs. noise
        re.compile(r"(?:[A-Za-z0-9+/]{4}){10,}={0,2}"),
        "Long base64-like payload",
    ),
    Rule(
        "Indirect Prompt Injection",
        re.compile(r"<!--.*?(ignore|instead|agent reading|assistant).*?-->", re.I | re.S),
        "Instruction hidden in an HTML/markdown comment",
    ),
]


def check_heuristics(content: str) -> LayerResult:
    start = time.perf_counter()
    for rule in RULES:
        if rule.pattern.search(content):
            return LayerResult(
                layer="heuristic",
                ran=True,
                attack_type=rule.attack_type,
                confidence=0.95,
                detail=rule.description,
                latency_ms=round((time.perf_counter() - start) * 1000, 2),
            )
    return LayerResult(
        layer="heuristic",
        ran=True,
        attack_type="None",
        confidence=0.0,
        detail="No known pattern matched",
        latency_ms=round((time.perf_counter() - start) * 1000, 2),
    )
