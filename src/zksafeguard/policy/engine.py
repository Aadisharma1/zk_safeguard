"""Deterministic prompt-safety policy engine (config-driven)."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class PolicyVerdict:
    verdict: str
    risk_score: float
    matched_rules: list[str] = field(default_factory=list)

    @property
    def accepted(self) -> bool:
        return self.verdict == "ALLOW"


class PolicyEngine:
    """Rule-based safety evaluation. Deterministic for a given config+prompt."""

    def __init__(self, config: dict):
        self.cfg = config
        self.denylist = [re.compile(p, re.IGNORECASE) for p in config.get("denylist_patterns", [])]
        self.injection = [re.compile(p, re.IGNORECASE) for p in config.get("injection_patterns", [])]
        self.weights = config.get("weights", {})
        self.threshold = float(config.get("risk_threshold", 0.5))

    @classmethod
    def from_file(cls, path: str | Path) -> "PolicyEngine":
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def digest(self) -> str:
        """SHA-256 digest of the exact policy configuration."""
        return hashlib.sha256(
            json.dumps(self.cfg, sort_keys=True).encode()
        ).hexdigest()

    def evaluate(self, prompt: str, fhe_model_score: float | None = None) -> PolicyVerdict:
        """Evaluate a prompt. fhe_model_score in [0,1] from the encrypted
        scorer (optional in rule-only mode)."""
        matched: list[str] = []
        score = 0.0
        for i, rx in enumerate(self.denylist):
            if rx.search(prompt):
                matched.append(f"denylist[{i}]")
                score += float(self.weights.get("denylist_hit", 1.0))
        for i, rx in enumerate(self.injection):
            if rx.search(prompt):
                matched.append(f"injection[{i}]")
                score += float(self.weights.get("injection_hit", 0.7))
        if fhe_model_score is not None:
            if not 0.0 <= fhe_model_score <= 1.0:
                raise ValueError("fhe_model_score must be in [0, 1]")
            score += float(self.weights.get("fhe_model_weight", 0.3)) * fhe_model_score
        score = min(score, 1.0)
        verdict = "ALLOW" if score < self.threshold else "REJECT"
        return PolicyVerdict(verdict=verdict, risk_score=round(score, 6), matched_rules=matched)
