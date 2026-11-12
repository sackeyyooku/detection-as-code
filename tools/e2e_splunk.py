"""End-to-end test: execute the *compiled SPL* inside a real Splunk instance.

For every rule, the positive and negative events from tests/cases are ingested into Splunk and the
compiled query is run exactly as it would be deployed. Positives must be returned, negatives must not.
Two probe queries also assert Splunk's operator precedence (OR binds tighter than implicit AND), which
the generated SPL relies on.

What this proves: the generated SPL parses, quotes/escapes correctly and has the intended boolean logic
in Splunk. What it does NOT prove: that a Splunk Windows/Sysmon add-on extracts the same field names in
production. Events here are JSON, so field names are taken exactly as the rules use them.

Event formats: Sysmon-style events are JSON (field names exactly as the rules use them). Windows Security
events use the classic WinEventLog text format and are field-extracted by Splunk's own built-in rules,
as in production, which is what exposed the Sigma-vs-Splunk field-name differences handled in
pipelines/splunk_env.yml.

Usage:  docker compose -f e2e/docker-compose.yml up -d   then   python -m tools.e2e_splunk
"""
from __future__ import annotations

import base64
import http.client
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

import yaml

from tools.common import CASES_DIR, DOCS_DIR, load_collection, rule_files
from tools.convert import _splunk_backend

DEFAULT_URL = "https://127.0.0.1:8089"
DEFAULT_PASSWORD = "DetectE2E-2026"
SOURCETYPE = "e2e_json"
INDEX = "main"


# --------------------------------------------------------------------------- Splunk REST client
class SplunkClient:
    """Minimal Splunk management-API client (stdlib only)."""

    def __init__(self, base_url: str, user: str, password: str):
        self.base_url = base_url.rstrip("/")
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.headers = {"Authorization": f"Basic {token}"}
        # The container presents a self-signed certificate; this client only talks to localhost.
        self.ssl = ssl.create_default_context()
        self.ssl.check_hostname = False
        self.ssl.verify_mode = ssl.CERT_NONE

    def _request(self, method: str, path: str, params: dict | None = None, data: bytes | None = None,
                 content_type: str | None = None, timeout: int = 120) -> str:
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        headers = dict(self.headers)
        if content_type:
            headers["Content-Type"] = content_type
        request = urllib.request.Request(url, data=data, method=method, headers=headers)
        with urllib.request.urlopen(request, timeout=timeout, context=self.ssl) as response:
            return response.read().decode("utf-8")

    def _search(self, query: str) -> list[dict]:
        if not query.lstrip().startswith("|"):
            query = "search " + query
        body = urllib.parse.urlencode({
            "search": query, "exec_mode": "oneshot", "output_mode": "json",
            "earliest_time": "-60m", "latest_time": "+10m", "count": "0",
        }).encode()
        text = self._request("POST", "/services/search/jobs", data=body,
                             content_type="application/x-www-form-urlencoded")
        return json.loads(text).get("results", [])

    # ---- public API used by run()
    def wait_until_ready(self, timeout: int = 1200) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                self._request("GET", "/services/server/info", {"output_mode": "json"}, timeout=15)
                self._search("| makeresults count=1")
                return
            except (urllib.error.URLError, OSError, http.client.HTTPException, json.JSONDecodeError):
                print(".", end="", flush=True)
                time.sleep(10)
        raise TimeoutError("Splunk did not become ready; check `docker logs detection-e2e-splunk`")

    def version(self) -> str:
        info = json.loads(self._request("GET", "/services/server/info", {"output_mode": "json"}))
        content = info["entry"][0]["content"]
        return f"{content.get('version', '?')} (build {content.get('build', '?')})"

    def ingest(self, payload: str, source: str, sourcetype: str, host: str) -> None:
        params = {"index": INDEX, "source": source, "sourcetype": sourcetype, "host": host}
        body = payload.encode("utf-8")
        for attempt in range(5):
            try:
                self._request("POST", "/services/receivers/simple", params, body, "text/plain")
                return
            except (urllib.error.URLError, OSError, http.client.HTTPException):
                if attempt == 4:
                    raise
                time.sleep(3)

    def wait_for_count(self, host: str, expected: int, timeout: int = 180) -> None:
        deadline = time.time() + timeout
        seen = 0
        while time.time() < deadline:
            rows = self._search(f'index={INDEX} host="{host}" | stats count')
            seen = int(rows[0]["count"]) if rows else 0
            if seen >= expected:
                return
            time.sleep(3)
        raise TimeoutError(f"only {seen}/{expected} events became searchable")

    def search(self, spl: str) -> list[dict]:
        return self._search(f"{spl} | eval TestId=coalesce(TestId, ComputerName) | table TestId")


# --------------------------------------------------------------------------- test data
@dataclass(frozen=True)
class E2EEvent:
    test_id: str
    group: str  # rule stem
    kind: str   # positive | negative
    name: str
    source: str
    sourcetype: str
    payload: str
    fields: dict


@dataclass(frozen=True)
class Probe:
    name: str
    description: str
    query: str
    events: tuple  # (label, source, fields, expected_to_match)


CLASSIC_SOURCES = {"WinEventLog:Security"}
# Sigma (Event Viewer XML) field -> where it lives in a classic WinEventLog text event
CLASSIC_HEADER_FIELDS = {"EventID": "EventCode", "Provider_Name": "SourceName"}
CLASSIC_MESSAGE_FIELDS = {
    "ServiceName": "Service Name",
    "TicketEncryptionType": "Ticket Encryption Type",
    "Status": "Failure Code",
    "SubjectUserName": "Account Name",
}


def render_classic(case_fields: dict, test_id: str, record_number: int) -> str:
    """Render a Sigma-named event as classic WinEventLog text (what Splunk's Windows inputs produce).

    The test id travels in ComputerName, a field Splunk's built-in extraction is known to populate.
    """
    header = {
        "LogName": "Security", "EventType": "0", "ComputerName": test_id, "Type": "Information",
        "RecordNumber": str(record_number), "Keywords": "Audit Success", "OpCode": "Info",
    }
    message = []
    for key, value in case_fields.items():
        if key in CLASSIC_HEADER_FIELDS:
            header[CLASSIC_HEADER_FIELDS[key]] = value
        elif key in CLASSIC_MESSAGE_FIELDS:
            message.append(f"\t{CLASSIC_MESSAGE_FIELDS[key]}:\t\t{value}")
        else:
            raise ValueError(f"no classic WinEventLog mapping for field {key!r}; add it to CLASSIC_* in e2e_splunk.py")
    header.setdefault("SourceName", "Microsoft Windows security auditing.")
    stamp = datetime.now(timezone.utc).strftime("%m/%d/%Y %I:%M:%S %p")
    lines = [stamp] + [f"{k}={v}" for k, v in header.items()]
    lines += ["Message=Test event.", "Details:"] + message
    return "\n".join(lines)


def compile_spl(rule_path) -> str:
    return _splunk_backend().convert(load_collection(rule_path))[0].strip()


def build_rule_events(run_id: str) -> tuple[list[E2EEvent], dict[str, str]]:
    """Turn tests/cases into Splunk-shaped events, plus the compiled SPL for each rule."""
    events: list[E2EEvent] = []
    spl_by_rule: dict[str, str] = {}
    for rule_path in rule_files():
        stem = rule_path.stem
        spl = compile_spl(rule_path)
        spl_by_rule[stem] = spl
        source = re.match(r'source="([^"]+)"', spl).group(1)
        event_code = re.search(r"EventCode=(\d+)", spl)
        cases = yaml.safe_load((CASES_DIR / f"{stem}.yml").read_text(encoding="utf-8"))
        for kind in ("positive", "negative"):
            for index, case in enumerate(cases[kind]):
                case_fields = {str(k): str(v) for k, v in case["event"].items()}
                fields = dict(case_fields)
                if "EventID" in fields:                 # Sigma's EventID is Splunk's EventCode
                    fields["EventCode"] = fields.pop("EventID")
                elif event_code:                        # process rules: logsource implies the code
                    fields["EventCode"] = event_code.group(1)
                test_id = f"{run_id}.{stem}.{kind}.{index}"   # no pipes or spaces: it travels in a text header
                fields["TestId"] = test_id
                if source in CLASSIC_SOURCES:
                    payload = render_classic(case_fields, test_id, 1000 + len(events))
                    sourcetype = "WinEventLog"
                else:
                    payload = json.dumps(fields)
                    sourcetype = SOURCETYPE
                events.append(E2EEvent(test_id, stem, kind, case["name"], source, sourcetype, payload, fields))
    return events, spl_by_rule


def build_probes(run_id: str) -> list[Probe]:
    s, other = f"e2e-probe-{run_id}", f"e2e-probe-other-{run_id}"
    return [
        Probe(
            "or-binds-before-and",
            "`A OR B C` must mean `(A OR B) AND C`",
            f'source="{s}" PX=1 OR PY=2 PZ=3',
            (("a", s, {"PX": "1", "PZ": "3"}, True),
             ("b", s, {"PY": "2", "PZ": "3"}, True),
             ("c", s, {"PX": "1", "PZ": "9"}, False),
             ("d", s, {"PY": "2", "PZ": "9"}, False)),
        ),
        Probe(
            "leading-terms-bind-to-or-groups",
            "`S (G1) OR (G2)` must mean `S AND (G1 OR G2)`",
            f'source="{s}" (PX=1 OR PY=2 PZ=3) OR (PW=1 PV=2)',
            (("a", s, {"PX": "1", "PZ": "3"}, True),
             ("b", s, {"PW": "1", "PV": "2"}, True),
             ("c", s, {"PX": "1", "PZ": "9"}, False),
             ("d", other, {"PW": "1", "PV": "2"}, False)),
        ),
    ]


# --------------------------------------------------------------------------- runner
@dataclass
class RuleResult:
    rule: str
    positives: int
    negatives: int
    missed: list
    false_alerts: list

    @property
    def ok(self) -> bool:
        return not self.missed and not self.false_alerts


@dataclass
class ProbeResult:
    name: str
    description: str
    expected: list
    observed: list

    @property
    def ok(self) -> bool:
        return self.expected == self.observed


@dataclass
class Report:
    version: str
    rules: list
    probes: list

    @property
    def ok(self) -> bool:
        return all(r.ok for r in self.rules) and all(p.ok for p in self.probes)


def run(client, run_id: str | None = None) -> Report:
    run_id = run_id or uuid.uuid4().hex[:8]
    host = f"e2e-{run_id}"
    events, spl_by_rule = build_rule_events(run_id)
    probes = build_probes(run_id)

    for event in events:
        client.ingest(event.payload, event.source, event.sourcetype, host)
    probe_ids = {}
    for probe in probes:
        for label, source, fields, _expected in probe.events:
            test_id = f"{run_id}.probe-{probe.name}.{label}"
            probe_ids[(probe.name, label)] = test_id
            client.ingest(json.dumps({**fields, "TestId": test_id}), source, SOURCETYPE, host)
    total = len(events) + len(probe_ids)
    client.wait_for_count(host, total)

    rule_results = []
    for stem, spl in spl_by_rule.items():
        found = {row.get("TestId") for row in client.search(spl)}
        mine = [e for e in events if e.group == stem]
        rule_results.append(RuleResult(
            rule=stem,
            positives=sum(e.kind == "positive" for e in mine),
            negatives=sum(e.kind == "negative" for e in mine),
            missed=[e.name for e in mine if e.kind == "positive" and e.test_id not in found],
            false_alerts=[e.name for e in mine if e.kind == "negative" and e.test_id in found],
        ))

    probe_results = []
    for probe in probes:
        found = {row.get("TestId") for row in client.search(probe.query)}
        observed = sorted(label for label, *_ in probe.events if probe_ids[(probe.name, label)] in found)
        expected = sorted(label for label, _s, _f, ok in probe.events if ok)
        probe_results.append(ProbeResult(probe.name, probe.description, expected, observed))

    return Report(client.version(), rule_results, probe_results)


def render(report: Report) -> str:
    lines = [
        "# End-to-end results (Splunk)",
        "",
        f"_Run on {datetime.now(timezone.utc):%Y-%m-%d} against Splunk Enterprise {report.version}. "
        "Generated by `python -m tools.e2e_splunk`._",
        "",
        "Compiled SPL was executed in a real Splunk instance against each rule's positive and negative events. "
        "Sysmon-style events were ingested as JSON; Windows Security events as classic WinEventLog text, "
        "field-extracted by Splunk's built-in rules.",
        "",
        "| Rule | Positives caught | Negatives silent | Result |",
        "|---|---|---|---|",
    ]
    for r in report.rules:
        caught, silent = r.positives - len(r.missed), r.negatives - len(r.false_alerts)
        lines.append(f"| `{r.rule}` | {caught}/{r.positives} | {silent}/{r.negatives} | {'✅' if r.ok else '❌'} |")
    lines += ["", "## Operator-precedence probes", "", "| Probe | Expected matches | Observed | Result |", "|---|---|---|---|"]
    for p in report.probes:
        lines.append(f"| {p.description} | {', '.join(p.expected)} | {', '.join(p.observed) or 'none'} | "
                     f"{'✅' if p.ok else '❌'} |")
    failures = [r for r in report.rules if not r.ok]
    if failures:
        lines += ["", "## Failures", ""]
        for r in failures:
            lines.append(f"- `{r.rule}`: missed {r.missed or 'none'}; false alerts {r.false_alerts or 'none'}")
    return "\n".join(lines) + "\n"


def main() -> int:
    client = SplunkClient(os.environ.get("SPLUNK_URL", DEFAULT_URL), "admin",
                          os.environ.get("SPLUNK_PASSWORD", DEFAULT_PASSWORD))
    print("Waiting for Splunk to be ready (first start can take several minutes)", end="", flush=True)
    client.wait_until_ready()
    print("\nRunning end-to-end checks...")
    report = run(client)
    text = render(report)
    DOCS_DIR.mkdir(exist_ok=True)
    (DOCS_DIR / "e2e-results.md").write_text(text, encoding="utf-8")
    print(text)
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
