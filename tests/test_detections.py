"""Behavioural tests: replay known-good and known-benign events against each rule.

Each Sigma rule is compiled to SQL with the pySigma SQLite backend and executed against an
in-memory table holding a single event. No SIEM is needed, so this runs in milliseconds in CI.

Semantics notes
  * Columns use COLLATE NOCASE because Sigma string matching is case-insensitive.
  * Fields missing from an event are NULL (like an absent field in a SIEM).
  * REGEXP is registered so rules using the `re` modifier work.
"""
from __future__ import annotations

import re
import sqlite3

import pytest
import yaml
from sigma.backends.sqlite import sqliteBackend

from tools.common import CASES_DIR, load_collection, rule_fields, rule_files

RULES = {p.stem: p for p in rule_files()}


def _regexp(pattern, value):
    return value is not None and re.search(pattern, value, re.IGNORECASE) is not None


def fires(rule_stem: str, event: dict) -> bool:
    path = RULES[rule_stem]
    coll = load_collection(path)
    columns = sorted(rule_fields(coll.rules[0]) | set(event))
    sql = sqliteBackend().convert(load_collection(path))[0]  # fresh parse: conversion mutates rules

    con = sqlite3.connect(":memory:")
    con.create_function("regexp", 2, _regexp, deterministic=True)
    con.execute("CREATE TABLE logs (" + ", ".join(f'"{c}" TEXT COLLATE NOCASE' for c in columns) + ")")
    con.execute(
        f"INSERT INTO logs VALUES ({', '.join('?' for _ in columns)})",
        [None if event.get(c) is None else str(event[c]) for c in columns],
    )
    return len(con.execute(sql).fetchall()) == 1


def _collect():
    params = []
    for case_file in sorted(CASES_DIR.glob("*.yml")):
        data = yaml.safe_load(case_file.read_text(encoding="utf-8"))
        for kind, expected in (("positive", True), ("negative", False)):
            for case in data.get(kind, []):
                params.append(
                    pytest.param(
                        case_file.stem, case["event"], expected,
                        id=f"{case_file.stem}::{kind}::{case['name']}",
                    )
                )
    return params


@pytest.mark.parametrize("rule_stem,event,expected", _collect())
def test_rule_behaviour(rule_stem, event, expected):
    assert fires(rule_stem, event) is expected
