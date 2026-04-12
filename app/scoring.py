from __future__ import annotations

from statistics import mean

from .models import CWEEntry, ScoreBreakdown, ScoredEntry

LIKELIHOOD_MAP = {
    "high": 1.0,
    "medium": 0.66,
    "low": 0.33,
    "unknown": 0.45,
}
CONSEQUENCE_LIKELIHOOD_MAP = {
    "high": 1.0,
    "medium": 0.66,
    "low": 0.33,
    "unknown": 0.45,
}
EFFECTIVENESS_MAP = {
    "high": 1.0,
    "moderate": 0.65,
    "opportunistic": 0.25,
    "limited": 0.30,
    "none": 0.05,
    "unknown": 0.45,
}
PREVALENCE_MAP = {
    "widespread": 1.0,
    "often": 0.82,
    "common": 0.78,
    "sometimes": 0.6,
    "rarely": 0.25,
    "undetermined": 0.45,
}
HIGH_VALUE_SCOPES = {
    "confidentiality",
    "integrity",
    "availability",
    "access control",
    "authentication",
    "authorization",
    "accountability",
    "non-repudiation",
}
HIGH_VALUE_IMPACTS = {
    "read application data",
    "modify application data",
    "gain privileges or assume identity",
    "bypass protection mechanism",
    "execute unauthorized code or commands",
    "hide activities",
    "dos: resource consumption (cpu)",
    "dos: resource consumption (memory)",
    "dos: resource consumption (other)",
}
INTRO_PHASE_WEIGHTS = {
    "architecture and design": 1.0,
    "implementation": 0.9,
    "operation": 0.7,
    "testing": 0.6,
    "documentation": 0.3,
    "build and compilation": 0.6,
}


def score_entries(entries: list[CWEEntry]) -> list[ScoredEntry]:
    scored = [ScoredEntry(entry=entry, score=score_entry(entry), derived_rationale=build_rationale(entry, score_entry(entry))) for entry in entries]
    return sorted(scored, key=lambda item: item.score.total, reverse=True)


def score_entry(entry: CWEEntry) -> ScoreBreakdown:
    exploitability = 22.0 * _map_single(entry.likelihood_of_exploit, LIKELIHOOD_MAP, 0.45)
    consequence = 26.0 * _consequence_signal(entry)
    platform_scope = 8.0 * _average_map(entry.platform_prevalence, PREVALENCE_MAP, 0.45)
    detection_gap = 10.0 * (1.0 - _average_map(entry.detection_effectiveness, EFFECTIVENESS_MAP, 0.40))
    mitigation_gap = 10.0 * _mitigation_gap(entry)
    relationship_density = 8.0 * _relationship_signal(entry)
    evidence_signal = 8.0 * _evidence_signal(entry)
    introduction_breadth = 5.0 * _introduction_signal(entry)
    top25_bonus = 3.0 if entry.top25_member else 0.0

    total = round(
        min(
            exploitability
            + consequence
            + platform_scope
            + detection_gap
            + mitigation_gap
            + relationship_density
            + evidence_signal
            + introduction_breadth
            + top25_bonus,
            100.0,
        ),
        2,
    )

    return ScoreBreakdown(
        exploitability=round(exploitability, 2),
        consequence=round(consequence, 2),
        platform_scope=round(platform_scope, 2),
        detection_gap=round(detection_gap, 2),
        mitigation_gap=round(mitigation_gap, 2),
        relationship_density=round(relationship_density, 2),
        evidence_signal=round(evidence_signal, 2),
        introduction_breadth=round(introduction_breadth, 2),
        top25_bonus=round(top25_bonus, 2),
        total=total,
    )


def _map_single(value: str, mapping: dict[str, float], default: float) -> float:
    return mapping.get(value.strip().lower(), default)


def _average_map(values: list[str], mapping: dict[str, float], default: float) -> float:
    if not values:
        return default
    mapped = [mapping.get(value.strip().lower(), default) for value in values]
    return mean(mapped)


def _consequence_signal(entry: CWEEntry) -> float:
    scopes = {value.strip().lower() for value in entry.scopes}
    impacts = {value.strip().lower() for value in entry.impacts}
    critical_scope_score = min(len(scopes & HIGH_VALUE_SCOPES) / 4.0, 1.0) * 0.45
    breadth_score = min(len(scopes) / 5.0, 1.0) * 0.2
    impact_score = min(len(impacts & HIGH_VALUE_IMPACTS) / 4.0, 1.0) * 0.2
    likelihood_score = _average_map(entry.consequence_likelihoods, CONSEQUENCE_LIKELIHOOD_MAP, 0.45) * 0.15
    return min(critical_scope_score + breadth_score + impact_score + likelihood_score, 1.0)


def _mitigation_gap(entry: CWEEntry) -> float:
    if not entry.mitigation_effectiveness:
        return 0.85
    return 1.0 - _average_map(entry.mitigation_effectiveness, EFFECTIVENESS_MAP, 0.45)


def _relationship_signal(entry: CWEEntry) -> float:
    weakness_ratio = min(entry.related_weakness_count / 10.0, 1.0)
    capec_ratio = min(entry.related_attack_pattern_count / 5.0, 1.0)
    return min((weakness_ratio * 0.7) + (capec_ratio * 0.3), 1.0)


def _evidence_signal(entry: CWEEntry) -> float:
    observed_ratio = min(entry.observed_example_count / 6.0, 1.0)
    top25_ratio = 0.4 if entry.top25_member else 0.0
    return min(observed_ratio * 0.8 + top25_ratio, 1.0)


def _introduction_signal(entry: CWEEntry) -> float:
    if not entry.modes_of_introduction:
        return 0.3
    weights = [INTRO_PHASE_WEIGHTS.get(value.strip().lower(), 0.35) for value in entry.modes_of_introduction]
    breadth_bonus = min(len(set(v.strip().lower() for v in entry.modes_of_introduction)) / 3.0, 1.0) * 0.25
    return min(mean(weights) * 0.75 + breadth_bonus, 1.0)


def build_rationale(entry: CWEEntry, score: ScoreBreakdown) -> str:
    reasons: list[str] = []
    if entry.top25_member:
        reasons.append("listed in the official Top 25 overlay")
    if entry.likelihood_of_exploit.strip().lower() in {"high", "medium"}:
        reasons.append(f"likelihood of exploit is {entry.likelihood_of_exploit.lower()}")
    if entry.observed_example_count:
        reasons.append(f"{entry.observed_example_count} observed example(s) link the weakness to real CVEs")
    if entry.related_attack_pattern_count:
        reasons.append(f"{entry.related_attack_pattern_count} CAPEC relationship(s) strengthen attack relevance")
    if entry.related_weakness_count >= 3:
        reasons.append(f"{entry.related_weakness_count} related weaknesses suggest broad structural influence")
    if entry.scopes:
        reasons.append(f"security scope spans {', '.join(entry.scopes[:3])}")
    if not reasons:
        reasons.append("score is driven by the available structured security attributes in the CWE record")
    return "This entry ranks highly because " + "; ".join(reasons) + "."
