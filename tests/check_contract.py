#!/usr/bin/env python3
"""Static check that the flow extractor emits the AI engine's feature contract.

No third-party dependencies are required, so this runs on the host even when
Docker is unavailable.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read_list(path: Path, name: str) -> list[str]:
    module = ast.parse(path.read_text())
    for node in module.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    return list(ast.literal_eval(node.value))
    raise SystemExit(f"{name} not found in {path}")


def main() -> int:
    features_path = ROOT / "ai-engine" / "app" / "features.py"
    extract_path = ROOT / "flow-extractor" / "app" / "extract.py"

    features = read_list(features_path, "FEATURES")
    identity = read_list(extract_path, "IDENTITY_COLUMNS")
    emitted = read_list(extract_path, "FEATURE_COLUMNS")

    problems: list[str] = []
    missing = [feature for feature in features if feature not in emitted + identity]
    if missing:
        problems.append(f"flow-extractor does not emit AI features: {missing}")

    duplicated = sorted(set(identity) & set(emitted))
    if duplicated:
        problems.append(f"columns listed as both identity and feature: {duplicated}")

    if problems:
        print("FAILED feature contract check:")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    print(
        f"OK: {len(features)} AI features are all emitted by flow-extractor "
        f"({len(identity)} identity + {len(emitted)} feature columns)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
