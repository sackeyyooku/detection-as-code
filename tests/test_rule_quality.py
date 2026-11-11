"""Static quality gates: every rule must be well-formed, documented and tested."""
from __future__ import annotations

import re
import uuid

import pytest
import yaml
from sigma.collection import SigmaCollection

from tools.common import CASES_DIR, attack_tags, load_raw, rule_files

REQUIRED = [
    "title", "id", "status", "description", "references", "author", "date",
    "tags", "logsource", "detection", "falsepositives", "level",
]
LEVELS = {"informational", "low", "medium", "high", "critical"}
STATUSES = {"experimental", "test", "stable"}
TECHNIQUE_TAG = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")


def _expected_prefix(logsource: dict) -> str:
    if logsource.get("category") == "process_creation":
        return "proc_creation_win_"
    if logsource.get("category") == "process_access":
        return "proc_access_win_"
    if logsource.get("service") == "security":
        return "win_security_"
    pytest.fail(f"no naming convention defined for logsource {logsource}")


@pytest.fixture(params=rule_files(), ids=lambda p: p.stem)
def rule_path(request):
    return request.param


def test_parses_without_errors(rule_path):
    coll = SigmaCollection.from_yaml(rule_path.read_text(encoding="utf-8"), collect_errors=True)
    assert len(coll.rules) == 1, "one rule per file"
    assert not coll.errors, coll.errors
    assert not coll.rules[0].errors, coll.rules[0].errors


def test_required_metadata(rule_path):
    raw = load_raw(rule_path)
    missing = [k for k in REQUIRED if not raw.get(k)]
    assert not missing, f"missing fields: {missing}"
    assert raw["level"] in LEVELS
    assert raw["status"] in STATUSES
    uuid.UUID(str(raw["id"]))  # raises if not a valid UUID


def test_attack_tagging(rule_path):
    raw = load_raw(rule_path)
    tags = [str(t).lower() for t in raw["tags"]]
    assert any(TECHNIQUE_TAG.match(t) for t in tags), "needs at least one ATT&CK technique tag"
    tactics, _ = attack_tags(raw)
    assert tactics, "needs at least one ATT&CK tactic tag"


def test_filename_convention(rule_path):
    raw = load_raw(rule_path)
    assert rule_path.name.startswith(_expected_prefix(raw["logsource"]))


def test_has_positive_and_negative_cases(rule_path):
    case_file = CASES_DIR / f"{rule_path.stem}.yml"
    assert case_file.exists(), f"missing test cases: {case_file.name}"
    cases = yaml.safe_load(case_file.read_text(encoding="utf-8"))
    assert cases.get("positive"), "needs >= 1 positive case (must fire)"
    assert cases.get("negative"), "needs >= 1 negative case (must NOT fire)"


def test_rule_ids_unique():
    ids = [str(load_raw(p)["id"]) for p in rule_files()]
    assert len(ids) == len(set(ids))


def test_no_orphan_case_files():
    stems = {p.stem for p in rule_files()}
    orphans = [c.name for c in CASES_DIR.glob("*.yml") if c.stem not in stems]
    assert not orphans, f"test cases with no rule: {orphans}"
