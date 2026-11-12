"""Replay real attack telemetry (public EVTX captures) through every rule.

Each manifest sample declares the rules that MUST fire. Any alert outside must_fire / also_fires
fails the test, so a rule change that starts firing on known-bad captures is surfaced for review.
"""
from __future__ import annotations

import os

import pytest

from tools.common import SAMPLES_CACHE, load_manifest, rule_files
from tools.telemetry import load_events, matching_events

MANIFEST = load_manifest()
RULES = {p.stem: p for p in rule_files()}
ALWAYS_TOLERATED = {"win_security_event_log_cleared"}  # lab operators cleared logs before capture


def test_manifest_references_real_rules():
    named = {r for s in MANIFEST["samples"] for r in s["must_fire"] + s.get("also_fires", [])}
    assert named <= set(RULES), f"unknown rules in manifest: {sorted(named - set(RULES))}"


@pytest.mark.parametrize("sample", MANIFEST["samples"], ids=lambda s: s["path"].split("/")[-1])
def test_rules_on_real_telemetry(sample):
    path = SAMPLES_CACHE / sample["path"]
    if not path.exists():
        if os.environ.get("REQUIRE_TELEMETRY") == "1":
            pytest.fail("sample not fetched; run `python -m tools.fetch_samples`")
        pytest.skip("sample not fetched; run `python -m tools.fetch_samples`")

    events = load_events(path)
    fired = {stem for stem, rule_path in RULES.items() if matching_events(rule_path, events)}
    must = set(sample["must_fire"])
    allowed = must | set(sample.get("also_fires", [])) | ALWAYS_TOLERATED

    assert must <= fired, f"missed detections: {sorted(must - fired)}"
    assert fired <= allowed, f"unreviewed alerts: {sorted(fired - allowed)}"
