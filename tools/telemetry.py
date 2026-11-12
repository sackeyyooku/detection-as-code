"""Replay real Windows event logs (.evtx) through the compiled Sigma rules.

Events are flattened (System + EventData fields) and loaded into an in-memory SQLite table;
each rule's SQL, produced by the pySigma SQLite backend, runs over the events that match the
rule's logsource.
"""
from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path

from sigma.backends.sqlite import sqliteBackend

from tools.common import load_collection, load_raw, rule_fields

SYSMON = "Microsoft-Windows-Sysmon/Operational"


def load_events(evtx_path: Path) -> list[dict]:
    """Parse an .evtx file into flat dicts keyed by Sigma-style field names."""
    from evtx import PyEvtxParser  # imported lazily: only needed for telemetry tests

    events = []
    for record in PyEvtxParser(str(evtx_path)).records_json():
        event = json.loads(record["data"])["Event"]
        system = event.get("System", {})
        event_id = system.get("EventID")
        if isinstance(event_id, dict):
            event_id = event_id.get("#text")
        flat = {
            "EventID": event_id,
            "Channel": system.get("Channel"),
            "Provider_Name": (system.get("Provider") or {}).get("#attributes", {}).get("Name"),
            "Computer": system.get("Computer"),
        }
        data = event.get("EventData")
        if isinstance(data, dict):
            for key, value in data.items():
                if not key.startswith("#") and not isinstance(value, (dict, list)):
                    flat[key] = value
        events.append({k: (None if v is None else str(v)) for k, v in flat.items()})
    return events


def _in_logsource(logsource: dict, event: dict) -> bool:
    """Which events a rule applies to (the SQLite backend adds no logsource condition)."""
    if logsource.get("category") == "process_creation":
        return event.get("Channel") == SYSMON and event.get("EventID") == "1"
    if logsource.get("category") == "process_access":
        return event.get("Channel") == SYSMON and event.get("EventID") == "10"
    if logsource.get("service") == "security":
        return event.get("Channel") == "Security"
    raise ValueError(f"unsupported logsource: {logsource}")


def _regexp(pattern, value):
    return value is not None and re.search(pattern, value, re.IGNORECASE) is not None


def matching_events(rule_path: Path, events: list[dict]) -> list[dict]:
    """Return the events (from those in the rule's logsource) that the rule fires on."""
    logsource = load_raw(rule_path)["logsource"]
    scoped = [e for e in events if _in_logsource(logsource, e)]
    if not scoped:
        return []
    columns = sorted(rule_fields(load_collection(rule_path).rules[0]))
    sql = sqliteBackend().convert(load_collection(rule_path))[0]  # fresh parse per conversion

    con = sqlite3.connect(":memory:")
    con.create_function("regexp", 2, _regexp, deterministic=True)
    cols = ["_rowid"] + columns
    con.execute("CREATE TABLE logs (" + ", ".join(f'"{c}" TEXT COLLATE NOCASE' for c in cols) + ")")
    con.executemany(
        f"INSERT INTO logs VALUES ({', '.join('?' for _ in cols)})",
        [[str(i)] + [e.get(c) for c in columns] for i, e in enumerate(scoped)],
    )
    hit_ids = {int(r[0]) for r in con.execute(sql.replace("SELECT *", "SELECT _rowid", 1))}
    return [scoped[i] for i in sorted(hit_ids)]
