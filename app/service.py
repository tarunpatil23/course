from __future__ import annotations

from collections import Counter
from pathlib import Path
import json
from statistics import mean

from .models import ScoredEntry
from .parser import parse_catalog, parse_top25_members
from .scoring import score_entries


ALLOWED_SORTS = {"score_desc", "score_asc", "id_asc", "id_desc", "name_asc"}
ALLOWED_ABSTRACTIONS = {"base", "variant", "class", "compound", "pillar", "category", "unknown"}


class IndexService:
    def __init__(self, index_path: Path):
        self.index_path = index_path

    def build_index(self, primary_dataset: Path, top25_dataset: Path) -> dict:
        metadata, entries = parse_catalog(primary_dataset)
        top25 = parse_top25_members(top25_dataset)
        for entry in entries:
            entry.top25_member = entry.cwe_id in top25
        scored_security_entries = score_entries([entry for entry in entries if entry.security_relevant])
        excluded_entries = [entry.to_dict() for entry in entries if not entry.security_relevant]
        index = {
            "metadata": metadata.to_dict(),
            "summary": self._build_summary(scored_security_entries, len(excluded_entries)),
            "entries": [item.to_dict() for item in scored_security_entries],
            "excluded_entries": excluded_entries,
        }
        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        self.index_path.write_text(json.dumps(index, indent=2), encoding="utf-8")
        return index

    def load_index(self) -> dict:
        return json.loads(self.index_path.read_text(encoding="utf-8"))

    def ensure_index(self, primary_dataset: Path, top25_dataset: Path) -> dict:
        if self.index_path.exists():
            return self.load_index()
        return self.build_index(primary_dataset, top25_dataset)

    def query_entries(
        self,
        index: dict,
        q: str = "",
        min_score: float = 0.0,
        top25_only: bool = False,
        abstraction: str = "",
        sort: str = "score_desc",
        limit: int = 50,
    ) -> list[dict]:
        if sort not in ALLOWED_SORTS:
            raise ValueError("Invalid sort option")
        if abstraction and abstraction.lower() not in ALLOWED_ABSTRACTIONS:
            raise ValueError("Invalid abstraction filter")
        if limit < 1 or limit > 200:
            raise ValueError("Limit must be between 1 and 200")
        if min_score < 0 or min_score > 100:
            raise ValueError("min_score must be between 0 and 100")

        needle = q.strip().lower()
        results: list[dict] = []
        for entry in index["entries"]:
            if entry["score"]["total"] < min_score:
                continue
            if top25_only and not entry.get("top25_member", False):
                continue
            if abstraction and entry["abstraction"].lower() != abstraction.lower():
                continue
            haystack = " ".join([
                str(entry["cwe_id"]),
                entry["name"],
                entry["description"],
                entry["extended_description"],
            ]).lower()
            if needle and needle not in haystack:
                continue
            results.append(entry)

        if sort == "score_desc":
            results.sort(key=lambda item: item["score"]["total"], reverse=True)
        elif sort == "score_asc":
            results.sort(key=lambda item: item["score"]["total"])
        elif sort == "id_asc":
            results.sort(key=lambda item: item["cwe_id"])
        elif sort == "id_desc":
            results.sort(key=lambda item: item["cwe_id"], reverse=True)
        elif sort == "name_asc":
            results.sort(key=lambda item: item["name"].lower())

        return results[:limit]

    def _build_summary(self, entries: list[ScoredEntry], excluded_count: int) -> dict:
        scope_counter: Counter[str] = Counter()
        intro_counter: Counter[str] = Counter()
        top25_count = 0
        for item in entries:
            scope_counter.update(item.entry.scopes)
            intro_counter.update(item.entry.modes_of_introduction)
            if item.entry.top25_member:
                top25_count += 1
        top10 = entries[:10]
        return {
            "entry_count": len(entries),
            "excluded_count": excluded_count,
            "average_score": round(mean([item.score.total for item in entries]) if entries else 0.0, 2),
            "top25_entries_in_index": top25_count,
            "top25_overlap_top10": sum(1 for item in top10 if item.entry.top25_member),
            "top_scopes": scope_counter.most_common(8),
            "top_modes_of_introduction": intro_counter.most_common(8),
        }
