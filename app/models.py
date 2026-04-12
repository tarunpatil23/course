from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class CatalogMetadata:
    name: str
    version: str
    date: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CWEEntry:
    cwe_id: int
    name: str
    abstraction: str
    status: str
    description: str
    extended_description: str
    likelihood_of_exploit: str
    scopes: list[str] = field(default_factory=list)
    impacts: list[str] = field(default_factory=list)
    consequence_likelihoods: list[str] = field(default_factory=list)
    detection_effectiveness: list[str] = field(default_factory=list)
    mitigation_effectiveness: list[str] = field(default_factory=list)
    platform_prevalence: list[str] = field(default_factory=list)
    related_weakness_count: int = 0
    related_attack_pattern_count: int = 0
    observed_example_count: int = 0
    modes_of_introduction: list[str] = field(default_factory=list)
    mapping_usage: str = "Unknown"
    top25_member: bool = False
    security_relevant: bool = True
    exclusions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScoreBreakdown:
    exploitability: float
    consequence: float
    platform_scope: float
    detection_gap: float
    mitigation_gap: float
    relationship_density: float
    evidence_signal: float
    introduction_breadth: float
    top25_bonus: float
    total: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScoredEntry:
    entry: CWEEntry
    score: ScoreBreakdown
    derived_rationale: str

    def to_dict(self) -> dict[str, Any]:
        payload = self.entry.to_dict()
        payload["score"] = self.score.to_dict()
        payload["derived_rationale"] = self.derived_rationale
        return payload
