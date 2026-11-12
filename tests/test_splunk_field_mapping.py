"""The Splunk target must use field names that Splunk's built-in extraction produces for classic
WinEventLog Security events (verified against a real Splunk), not the Sigma / Event Viewer XML names."""
from __future__ import annotations

from tools.common import RULES_DIR
from tools.e2e_splunk import compile_spl

KERBEROAST = RULES_DIR / "windows" / "security" / "win_security_kerberoasting_rc4_tgs.yml"
LOG_CLEARED = RULES_DIR / "windows" / "security" / "win_security_event_log_cleared.yml"


def test_kerberoasting_uses_classic_splunk_field_names():
    spl = compile_spl(KERBEROAST)
    for name in ("Ticket_Encryption_Type", "Failure_Code", "Service_Name"):
        assert name in spl
    for name in ("TicketEncryptionType", "ServiceName", "Status="):
        assert name not in spl


def test_log_cleared_uses_sourcename():
    spl = compile_spl(LOG_CLEARED)
    assert "SourceName=" in spl and "Provider_Name" not in spl
