"""Request/response models for the firewall API."""
from __future__ import annotations

from typing import Literal, Optional
from pydantic import BaseModel, Field

AttackType = Literal[
    "Instruction Override",
    "Role Change",
    "Secret Extraction",
    "Encoded Instructions",
    "Indirect Prompt Injection",
    "None",
]

Action = Literal["block", "sanitize", "flag_for_review", "allow"]
Verdict = Literal["blocked", "sanitized", "flagged", "allowed"]


class CheckRequest(BaseModel):
    content: str = Field(..., min_length=1, description="Raw text to inspect.")
    source_type: str = Field(
        default="user_message",
        description="Where this content came from, e.g. user_message, web_page, pdf, email, api_response.",
    )


class LayerResult(BaseModel):
    layer: str
    ran: bool
    attack_type: AttackType = "None"
    confidence: float = 0.0
    detail: str = ""
    latency_ms: float = 0.0


class CheckResponse(BaseModel):
    trace_id: str
    verdict: Verdict
    action: Action
    attack_type: AttackType
    confidence: float
    reasoning: str
    layers: list[LayerResult]
    sanitized_content: Optional[str] = None
    total_latency_ms: float
