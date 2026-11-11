"""Shared helpers for the detection-as-code pipeline."""
from __future__ import annotations

from pathlib import Path

import yaml
from sigma.collection import SigmaCollection
from sigma.rule import SigmaDetection, SigmaRule

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"
CASES_DIR = ROOT / "tests" / "cases"
PIPELINES_DIR = ROOT / "pipelines"
BUILD_DIR = ROOT / "build"
DOCS_DIR = ROOT / "docs"


def rule_files() -> list[Path]:
    return sorted(RULES_DIR.rglob("*.yml"))


def load_collection(path: Path) -> SigmaCollection:
    """Parse a rule file into a *fresh* collection.

    pySigma pipelines mutate rule objects in place during conversion, so a collection must
    never be reused across backends/targets. Always re-parse.
    """
    return SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))


def load_raw(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def rule_fields(rule: SigmaRule) -> set[str]:
    """All field names referenced by a rule's detection section."""

    def walk(det: SigmaDetection):
        for item in det.detection_items:
            if isinstance(item, SigmaDetection):
                yield from walk(item)
            elif item.field:
                yield item.field

    fields: set[str] = set()
    for det in rule.detection.detections.values():
        fields.update(walk(det))
    return fields


def attack_tags(raw: dict) -> tuple[list[str], list[str]]:
    """Return (tactics, techniques) from a rule's `tags`. Techniques are upper-cased IDs."""
    tactics, techniques = [], []
    for tag in raw.get("tags", []):
        name = str(tag).lower()
        if not name.startswith("attack."):
            continue
        body = name[len("attack."):]
        if body.startswith("t") and body[1:2].isdigit():
            techniques.append(body.upper())
        else:
            tactics.append(body)
    return tactics, techniques
