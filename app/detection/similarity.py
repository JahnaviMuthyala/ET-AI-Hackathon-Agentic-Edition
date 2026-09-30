"""Layer 2: semantic similarity against a labeled attack corpus.

Unlike Layer 1's exact patterns, this layer catches paraphrased or
reworded attacks by comparing sentence embeddings. It loads the model
and embeds the corpus once at startup, then every request is just one
embedding + a matrix multiply — cheap enough to run on every request
that Layer 1 didn't already resolve.
"""
import json
import time

import numpy as np
from sentence_transformers import SentenceTransformer

from app import config
from app.schemas import LayerResult


class SimilarityDetector:
    def __init__(self, model_name: str = config.EMBEDDING_MODEL_NAME):
        self.model = SentenceTransformer(model_name)
        self.corpus: list[dict] = json.loads(config.CORPUS_PATH.read_text())
        texts = [item["text"] for item in self.corpus]
        # normalize so dot product == cosine similarity
        embeddings = self.model.encode(texts, convert_to_numpy=True, normalize_embeddings=True)
        self.corpus_embeddings = embeddings

    def check(self, content: str) -> LayerResult:
        start = time.perf_counter()
        query_embedding = self.model.encode(
            [content], convert_to_numpy=True, normalize_embeddings=True
        )[0]
        # cosine similarity against every corpus entry at once
        scores = self.corpus_embeddings @ query_embedding
        best_idx = int(np.argmax(scores))
        best_score = float(scores[best_idx])
        best_type = self.corpus[best_idx]["type"]
        matched_text = self.corpus[best_idx]["text"]

        return LayerResult(
            layer="similarity",
            ran=True,
            attack_type=best_type if best_score >= config.SIMILARITY_ESCALATE_THRESHOLD else "None",
            confidence=round(best_score, 4),
            detail=f"Nearest corpus match ({best_score:.2f}): \"{matched_text[:80]}\"",
            latency_ms=round((time.perf_counter() - start) * 1000, 2),
        )


# Singleton — the model and corpus embeddings are loaded once per process,
# not per request. Importing this module triggers the (one-time) load.
_detector: SimilarityDetector | None = None


def get_detector() -> SimilarityDetector:
    global _detector
    if _detector is None:
        _detector = SimilarityDetector()
    return _detector
