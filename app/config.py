from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os


@dataclass(frozen=True)
class AppConfig:
    base_dir: Path
    primary_dataset: Path
    top25_dataset: Path
    index_path: Path



def load_config() -> AppConfig:
    base_dir = Path(__file__).resolve().parent.parent
    return AppConfig(
        base_dir=base_dir,
        primary_dataset=Path(os.getenv("CWE_PRIMARY_DATASET", base_dir / "data" / "677.xml")),
        top25_dataset=Path(os.getenv("CWE_TOP25_DATASET", base_dir / "data" / "1435.xml")),
        index_path=Path(os.getenv("CWE_INDEX_PATH", base_dir / "output" / "cwe_index.json")),
    )
