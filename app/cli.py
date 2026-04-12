from __future__ import annotations

import argparse
from pathlib import Path

from .service import IndexService


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build the secure CWE insight index")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build-index", help="Parse datasets and build the analysis index")
    build.add_argument("--input", required=True, help="Path to the primary CWE XML dataset")
    build.add_argument("--top25", required=True, help="Path to the Top 25 CWE XML dataset")
    build.add_argument("--output", required=True, help="Path for the generated JSON index")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "build-index":
        service = IndexService(Path(args.output))
        index = service.build_index(Path(args.input), Path(args.top25))
        print(f"Built index with {index['summary']['entry_count']} security-relevant entries")
        print(f"Excluded {index['summary']['excluded_count']} quality-only or prohibited entries")
        print(f"Saved index to {args.output}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
