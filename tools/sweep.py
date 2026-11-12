"""Run every rule over a directory of .evtx files and write a point-in-time report.

usage: python -m tools.sweep PATH_TO_EVTX_ATTACK_SAMPLES COMMIT_SHA
"""
from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

from tools.common import DOCS_DIR, rule_files
from tools.telemetry import load_events, matching_events


def _describe(event: dict) -> str:
    if event.get("CommandLine"):
        return event["CommandLine"][:110]
    if event.get("SourceImage"):
        return f"{event['SourceImage']} -> {event.get('TargetImage')} ({event.get('GrantedAccess')})"
    return f"EventID {event.get('EventID')} on {event.get('Computer')}"


def main(root: Path, commit: str) -> int:
    samples = sorted(root.rglob("*.evtx"))
    hits: dict[str, list[tuple[str, int, str]]] = defaultdict(list)
    lsass_events = lsass_matched = 0
    lsass_rule = next(p for p in rule_files() if "lsass" in p.stem)
    for sample in samples:
        events = load_events(sample)
        lsass = [e for e in events if (e.get("Channel") or "").endswith("Sysmon/Operational")
                 and e.get("EventID") == "10" and (e.get("TargetImage") or "").lower().endswith("\\lsass.exe")]
        if lsass:
            lsass_events += len(lsass)
        for rule_path in rule_files():
            matched = matching_events(rule_path, events)
            if matched:
                hits[rule_path.stem].append((str(sample.relative_to(root)), len(matched), _describe(matched[0])))
                if rule_path == lsass_rule:
                    lsass_matched += len(matched)

    lines = [
        "# Real-telemetry sweep",
        "",
        f"_Point-in-time report. Dataset: sbousseaden/EVTX-ATTACK-SAMPLES @ `{commit[:10]}` "
        f"({len(samples)} captures). Regenerate with `python -m tools.sweep <path> <commit>`._",
        "",
        f"LSASS handle-access events in the dataset: **{lsass_events}**; "
        f"flagged by the LSASS rule: **{lsass_matched}**.",
        "",
        "| Rule | Captures with alerts |",
        "|---|---|",
    ]
    for rule_path in rule_files():
        lines.append(f"| `{rule_path.stem}` | {len(hits[rule_path.stem])} |")
    for rule_path in rule_files():
        if rule_path.stem == "win_security_event_log_cleared":
            continue  # alerts on genuine log clears the lab operators performed before capture
        lines += ["", f"## `{rule_path.stem}`", ""]
        rows = hits[rule_path.stem]
        if not rows:
            lines.append("_No capture in this dataset exercises this rule (validated with synthetic events only)._")
        for sample, n, example in rows[:10]:
            lines.append(f"- `{sample}` ({n}): `{example}`")
    DOCS_DIR.mkdir(exist_ok=True)
    (DOCS_DIR / "telemetry-sweep.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"LSASS events {lsass_events}, flagged {lsass_matched}; rules with hits: "
          f"{sum(1 for v in hits.values() if v)}/{len(rule_files())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(Path(sys.argv[1]), sys.argv[2]))
