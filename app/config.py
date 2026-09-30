"""Central configuration and tunable thresholds.

Everything here is meant to be adjusted per deployment without touching
detection logic. Values are read from environment variables where it
makes sense (secrets, model names); thresholds are plain constants you
can tune after looking at your own precision/recall numbers.
"""
import os
from pathlib import Path

# --- paths ---
BASE_DIR = Path(__file__).resolve().parent
CORPUS_PATH = BASE_DIR / "data" / "attack_corpus.json"

# --- Anthropic (Layer 3 judge) ---
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
JUDGE_MODEL = os.environ.get("FIREWALL_JUDGE_MODEL", "claude-sonnet-4-6")

# --- Layer 2 embedding model ---
# all-MiniLM-L6-v2 is small (~90MB), fast on CPU, and good enough for a
# hackathon demo. Swap for a larger model if you need higher accuracy.
EMBEDDING_MODEL_NAME = os.environ.get("FIREWALL_EMBEDDING_MODEL", "all-MiniLM-L6-v2")

# --- thresholds ---
# Layer 2: cosine similarity against the nearest labeled attack example.
SIMILARITY_BLOCK_THRESHOLD = 0.72   # above this: block without asking the LLM
SIMILARITY_ESCALATE_THRESHOLD = 0.45  # between escalate and block: send to Layer 3
# below SIMILARITY_ESCALATE_THRESHOLD: allow, don't bother the LLM

# Layer 3: LLM judge confidence thresholds
JUDGE_BLOCK_CONFIDENCE = 0.6        # judge says "block" and is at least this confident -> block
JUDGE_LOW_CONFIDENCE_FLOOR = 0.35   # judge says "block" but below this -> flag for review instead

# Policy: which attack types get sanitize-and-pass instead of a hard block,
# when the match came from Layer 2 (paraphrase) rather than Layer 1 (exact).
SANITIZABLE_TYPES = {"Indirect Prompt Injection"}
