"""Offline tests for the Splunk end-to-end harness (no Splunk required).

They verify event construction and the runner's pass/fail logic using a fake client, so mistakes in
the harness itself are caught before anyone starts a container.
"""
from __future__ import annotations

import pytest

from tools.common import rule_files
from tools.e2e_splunk import build_probes, build_rule_events, render, run

RUN_ID = "unit0001"


def test_every_rule_has_events_with_source_and_code():
    events, spl_by_rule = build_rule_events(RUN_ID)
    assert set(spl_by_rule) == {p.stem for p in rule_files()}
    for stem in spl_by_rule:
        mine = [e for e in events if e.group == stem]
        assert {e.kind for e in mine} == {"positive", "negative"}
        for e in mine:
            assert e.source in ("XmlWinEventLog:Microsoft-Windows-Sysmon/Operational", "WinEventLog:Security")
            assert "EventID" not in e.fields and e.fields["EventCode"].isdigit()
            assert e.fields["TestId"] == e.test_id and e.test_id.startswith(RUN_ID)


def test_test_ids_are_unique():
    events, _ = build_rule_events(RUN_ID)
    ids = [e.test_id for e in events]
    assert len(ids) == len(set(ids))


def test_probes_have_both_outcomes():
    for probe in build_probes(RUN_ID):
        outcomes = {expected for *_rest, expected in probe.events}
        assert outcomes == {True, False}


class FakeSplunk:
    """Answers searches the way a correct Splunk would; `sabotage` simulates a broken rule."""

    def __init__(self, run_id, sabotage_missed=None, sabotage_false_alert=None):
        self.run_id = run_id
        self.events, self.spl = build_rule_events(run_id)
        self.probes = build_probes(run_id)
        self.ingested = 0
        self.sabotage_missed = sabotage_missed
        self.sabotage_false_alert = sabotage_false_alert

    def ingest(self, payload, source, sourcetype, host):
        self.ingested += 1

    def wait_for_count(self, host, expected, timeout=0):
        assert self.ingested == expected

    def version(self):
        return "0.0.0 (fake)"

    def search(self, spl):
        for stem, query in self.spl.items():
            if query == spl:
                rows = [e for e in self.events if e.group == stem and e.kind == "positive"]
                if self.sabotage_missed == stem:
                    rows = rows[1:]
                ids = [e.test_id for e in rows]
                if self.sabotage_false_alert == stem:
                    ids.append(next(e.test_id for e in self.events if e.group == stem and e.kind == "negative"))
                return [{"TestId": i} for i in ids]
        for probe in self.probes:
            if probe.query == spl:
                return [{"TestId": f"{self.run_id}.probe-{probe.name}.{label}"}
                        for label, _s, _f, expected in probe.events if expected]
        raise AssertionError(f"unexpected query: {spl}")


def test_runner_passes_with_a_correct_splunk():
    report = run(FakeSplunk(RUN_ID), RUN_ID)
    assert report.ok
    assert "❌" not in render(report)


@pytest.mark.parametrize("mode", ["sabotage_missed", "sabotage_false_alert"])
def test_runner_detects_broken_rules(mode):
    stem = rule_files()[0].stem
    report = run(FakeSplunk(RUN_ID, **{mode: stem}), RUN_ID)
    assert not report.ok
    failed = [r for r in report.rules if not r.ok]
    assert [r.rule for r in failed] == [stem]
    assert "❌" in render(report)


def test_security_events_are_rendered_as_classic_wineventlog():
    events, _ = build_rule_events(RUN_ID)
    security = [e for e in events if e.source == "WinEventLog:Security"]
    assert security and all(e.sourcetype == "WinEventLog" for e in security)
    for e in security:
        lines = e.payload.split("\n")
        assert "LogName=Security" in lines and f"ComputerName={e.test_id}" in lines
        assert any(line.startswith("EventCode=") for line in lines)
        assert "Message=Test event." in lines
    sysmon = [e for e in events if e.source != "WinEventLog:Security"]
    assert sysmon and all(e.sourcetype == "e2e_json" and e.payload.startswith("{") for e in sysmon)
