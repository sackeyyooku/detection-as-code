# Design decisions and known gaps

## Decisions

**Sigma + pySigma, not hand-written SIEM queries.** Rules are vendor-neutral YAML; one rule compiles to
every backend. Switching SIEMs becomes a pipeline change, not a rewrite.

**Behavioural unit tests via the SQLite backend.** Each rule is compiled to SQL and run against an
in-memory table containing one event. Positive cases must fire, negative cases must not. It needs no
SIEM, runs in under a second, and gives rule authors a tight feedback loop. Mutation checks confirm the
harness works: removing a filter or a match value from a rule makes specific tests fail.

**Every rule needs at least one positive and one negative case.** Enforced in CI. Negatives are where
false-positive tuning knowledge lives (for example, the LSASS rule's system-path filter).

**Environment mapping lives in config.** `pipelines/splunk_env.yml` is the only place that knows where
Sysmon data lives in Splunk. Rules stay portable.

**Generated docs are committed and drift-checked.** CI fails if `docs/` is stale, so coverage numbers
in the repo can't silently diverge from the rules.

**Unsupported targets are recorded, not hidden.** A rule that a backend can't express shows up as a
cross mark in `docs/conversion-matrix.md` rather than failing the whole build.

## Gotchas found while building

- **pySigma conversion mutates rule objects.** Reusing a parsed collection across backends leaks one
  backend's field renames into the next. `tools.common.load_collection` always re-parses.
- **pySigma is pinned to 1.x.** `pysigma-backend-kusto` 1.0.1 requires pySigma < 2, while newer Splunk and
  SQLite backends target pySigma 2.x. The pins in `requirements.txt` are the newest mutually compatible set.
- **SPL operator precedence.** In Splunk, `OR` binds tighter than implicit `AND`, so generated queries such
  as `Image=a OR OriginalFileName=b CommandLine=c` are correct, but easy to misread.

## Known gaps (unverified assumptions)

- The behavioural tests validate **rule logic**, not **backend translation**. A bug in query generation, or
  a difference between real Splunk field extraction and the Sigma field names, would not be caught yet.
- Security-log rules assume the pySigma default source (`WinEventLog:Security`) and the field names
  used by the rule (`ServiceName`, `TicketEncryptionType`, `Status`). Real field names depend on how your
  Splunk Windows TA renders events (classic vs XML). **Verify against your own data** (roadmap phase 3).
- Three rules do not compile to KQL (Defender XDR has no Security-log or Sysmon process-access table).
- Thresholds are untuned and rules are marked `experimental`. They are portfolio-grade starting points,
  not a drop-in production rule set.
