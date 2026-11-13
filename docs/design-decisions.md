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

## Technical lessons learned

- **pySigma conversion mutates rule objects.** Reusing a parsed collection across backends leaks one
  backend's field renames into the next. `tools.common.load_collection` always re-parses.
- **pySigma is pinned to 1.x.** `pysigma-backend-kusto` 1.0.1 requires pySigma < 2, while newer Splunk and
  SQLite backends target pySigma 2.x. The pins in `requirements.txt` are the newest mutually compatible set.
- **SPL operator precedence.** In Splunk, `OR` binds tighter than implicit `AND`, so generated queries such
  as `Image=a OR OriginalFileName=b CommandLine=c` are correct, but easy to misread.

## Findings from real telemetry

Rules were replayed against 278 public attack captures
([sweep report](telemetry-sweep.md)). What it exposed:

- **A real blind spot in my own LSASS rule.** The first version excluded every source under
  `C:\Windows\System32\`. PowerShell (Invoke-Mimikatz) and rundll32 memory dumpers live there, so they were
  silently allow-listed. Only 13 of the 28 LSASS handle-access events in the dataset were flagged. The
  rule now excludes exact paths only (and a regression case proves a fake `C:\Temp\svchost.exe` still
  alerts), lifting it to 23 of 28. The five unflagged events are: two PPLdump events with a low access
  mask (`0x1000`), two `services.exe` events excluded by design, and one unrelated `0x101ffb` handle.
- **Genuine Event 1102 in 24 captures.** The dataset's authors cleared the Security log before many
  captures, so the log-cleared rule correctly fires on them. The telemetry tests tolerate this rule
  everywhere instead of pretending those are false positives.
- **Unreviewed alerts fail the build.** Each sample lists the rules that must fire; any other alert fails
  until someone reviews it. That is how the regsvr32 rule's alerts on two Atomic Red Team captures were
  confirmed as true positives (and promoted to required detections) rather than waved through.
- **Honest coverage limits.** No public capture exercises the Kerberoasting rule, so it is validated with
  synthetic events only. The Office rule has a single real example (a side-loaded `WINWORD.exe` copy
  running from `AppData`).

## End-to-end harness (Splunk in Docker)

`make e2e` ingests every rule's positive and negative events into a disposable Splunk container and runs
the *compiled SPL* exactly as it would be deployed. Positives must be returned and negatives must not.
Two probe queries also assert the operator-precedence rule the generated SPL silently depends on
(`A OR B C` means `(A OR B) AND C` in Splunk).

- **Proves:** the generated SPL parses, escapes backslashes and wildcards correctly, and has the intended
  boolean logic inside a real Splunk.
- **Does not prove:** that a production Sysmon add-on extracts the field names the rules use. Sysmon-style
  test events are JSON, so those names are taken as given. Windows Security events are different: they are
  sent as classic WinEventLog text and extracted by Splunk's own built-in rules, as in production.
- The runner's pass/fail logic is unit-tested offline with a fake client, so harness bugs are caught
  before a container is started.

### Findings from the first real Splunk run (Splunk Enterprise 10.6.1.1)

- All nine Sysmon-based rules passed first time, and both operator-precedence probes passed, so the
  parenthesis-free SPL that pySigma generates really does mean what the rules intend in Splunk.
- **Both Windows Security rules failed, and the cause was not the test.** Splunk's built-in handling of
  `WinEventLog*` sources ignores JSON and extracts the classic text format. Replaying realistic classic events
  showed that Splunk names the fields `Service_Name`, `Ticket_Encryption_Type`, `Failure_Code` and
  `SourceName`, not the Event Viewer XML names the Sigma rules use (`ServiceName`, `TicketEncryptionType`,
  `Status`, `Provider_Name`). The queries as first compiled would never have fired on real classic-format
  Security logs.
- **Fix:** a field mapping for the Windows Security logsource in `pipelines/splunk_env.yml`, keeping the Sigma
  rules portable, a regression test on the compiled SPL, and a harness that now sends classic-format events.
  Sigma-to-SIEM translation depends on how events are rendered, which is why this check needs a real SIEM.

## Licensing

The samples are GPL-3.0. They are never copied into this repository; `tools/fetch_samples.py` downloads
them from upstream at a pinned commit and verifies each file's SHA-256.

## Known gaps (unverified assumptions)

- **Splunk is verified; other targets are not.** The end-to-end run executed the compiled SPL in Splunk
  Enterprise 10.6.1.1 (see `docs/e2e-results.md`). The KQL output is only checked for compilation, not run in
  Sentinel or Defender.
- **Sysmon field names are assumed.** Sysmon-style test events are JSON using the field names the rules use. A
  production Sysmon add-on should expose the same names, but that is not verified here.
- **Security events assume the classic text format.** If your Splunk renders Windows Security events as XML
  (`XmlWinEventLog:Security`) the field names and source differ, and `pipelines/splunk_env.yml` needs a matching
  mapping.
- Three rules do not compile to KQL (Defender XDR has no Security-log or Sysmon process-access table).
- Thresholds are untuned and rules are marked `experimental`. They are portfolio-grade starting points,
  not a drop-in production rule set.

## ATT&CK version note

ATT&CK v19 (April 2026) retired the Defense Evasion tactic and split it into Stealth and Defense Impairment;
v20 (October 2026) is current. Rules whose behaviour is about blending in (obfuscation, signed-binary proxy
execution) are tagged `attack.stealth`, and the Navigator layer targets v20. Technique IDs
used here are unchanged apart from one that MITRE renumbered (below). Re-check mappings when a new ATT&CK release lands.

The log-cleared rule moved with ATT&CK: from v19, Clear Windows Event Logs is T1685.005 (Disable or Modify
Tools, under Defense Impairment), no longer T1070.001. The stale ID was found because the technique silently
failed to highlight in the Navigator layer, which is a good reason to keep that visual check.
