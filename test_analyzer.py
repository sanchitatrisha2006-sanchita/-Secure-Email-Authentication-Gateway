"""Header parsing, the analyzer, the gateway and the DNS audit."""
from emailauth import dkim
from emailauth.analyzer import analyze
from emailauth.dns_resolver import FakeResolver
from emailauth.gateway import authenticate_inbound
from emailauth.headers import (parse_authentication_results, parse_received_chain,
                               parse_received_spf, unfolded_headers)
from emailauth.records import audit_domain, build_dmarc, build_spf, zone_line
from tests.conftest import MESSAGE, OWN_IP

RECEIVED = f"Received: from mail.example.com (mail.example.com [{OWN_IP}]) by mx.receiver.test; Sat, 21 Nov 2026\r\n".encode()
SPOOF = (b"Return-Path: <bounce@evil.test>\nFrom: CEO <ceo@example.com>\nTo: bob@dest.test\n"
         b"Subject: Wire money\nDate: Sat, 21 Nov 2026 10:00:00 +0000\n\nPay now.\n")


def levels(report, level):
    return [f.message for f in report.findings if f.level == level]


# ---------------------------------------------------------------- header parsing
def test_authentication_results_parsing():
    raw = (b"Authentication-Results: mx.google.com;\r\n"
           b"  dkim=pass header.i=@example.com header.s=s1 header.b=abc;\r\n"
           b"  spf=pass (google.com: domain of a@example.com designates 192.0.2.1 as permitted sender)"
           b" smtp.mailfrom=a@example.com;\r\n  dmarc=fail (p=REJECT) header.from=example.com\r\n"
           b"From: a@example.com\r\n\r\nx")
    claims = parse_authentication_results(unfolded_headers(raw), {"mx.google.com"})
    got = {c.method: c for c in claims}
    assert [c.method for c in claims] == ["dkim", "spf", "dmarc"]
    assert got["dkim"].properties["header.s"] == "s1"
    assert got["spf"].properties["smtp.mailfrom"] == "a@example.com"
    assert got["dmarc"].result == "fail" and got["dmarc"].trusted is True


def test_received_chain_and_received_spf():
    raw = (b"Received: from a.test (a.test [203.0.113.7]) by b.test; x\r\n"
           b"Received: from c.test ([IPv6:2001:db8::1]) by a.test; y\r\n"
           b"Received-SPF: pass (b.test: ok) client-ip=203.0.113.7; envelope-from=u@x.test; helo=a.test;\r\n"
           b"From: u@x.test\r\n\r\n")
    headers = unfolded_headers(raw)
    hops = parse_received_chain(headers)
    assert hops[0].ips == ["203.0.113.7"] and hops[1].ips == ["2001:db8::1"]
    spf = parse_received_spf(headers)
    assert spf["result"] == "pass" and spf["client-ip"] == "203.0.113.7"


# -------------------------------------------------------------------- analyzer
def test_legitimate_message_passes(signed, resolver):
    report = analyze(RECEIVED + signed, resolver)
    assert report.client_ip == OWN_IP and "inferred" in report.client_ip_source
    assert report.dmarc.result == "pass" and report.verdict.startswith("PASS")


def test_spoofed_message_fails_and_is_explained(resolver):
    resolver.zone["evil.test"] = {"TXT": ["v=spf1 ip4:203.0.113.66 -all"]}
    report = analyze(SPOOF, resolver, client_ip="203.0.113.66")
    assert report.spf.result == "pass" and report.dmarc.result == "fail"
    assert report.dmarc.disposition == "reject"
    assert any("not aligned" in m for m in levels(report, "info"))
    assert "no DKIM signature" in " ".join(levels(report, "warn"))


def test_forged_authentication_results_flagged(resolver):
    forged = b"Authentication-Results: mx.receiver.test; dmarc=pass header.from=example.com\n" + SPOOF
    report = analyze(forged, resolver, client_ip="203.0.113.66", trusted_authserv={"other.test"})
    assert any("injected" in m for m in levels(report, "warn"))
    report = analyze(forged, resolver, client_ip="203.0.113.66")
    assert any("claims dmarc=pass" in m for m in levels(report, "warn"))


def test_display_name_spoofing_and_reply_to(resolver):
    raw = (b'From: "paypal@paypal.com" <help@example.com>\nReply-To: attacker@evil.test\n'
           b"Subject: s\n\nbody\n")
    report = analyze(raw, resolver, client_ip=OWN_IP)
    warnings = " ".join(levels(report, "warn"))
    assert "display-name spoofing" in warnings and "Reply-To" in warnings


def test_multiple_from_addresses(resolver):
    report = analyze(b"From: a@example.com\nFrom: b@evil.test\n\nx\n", resolver, client_ip=OWN_IP)
    assert any("Multiple From" in m for m in levels(report, "fail"))


def test_headers_only_input(signed, resolver):
    headers_only = RECEIVED + signed.split(b"\r\n\r\n")[0] + b"\r\n"
    report = analyze(headers_only, resolver)
    assert report.dkim[0].result == "pass" and report.dkim[0].body_checked is False
    assert any("Only headers" in m for m in levels(report, "info"))


def test_missing_ip_is_reported_not_guessed(resolver):
    report = analyze(SPOOF.replace(b"Return-Path: <bounce@evil.test>\n", b""), resolver)
    assert report.spf is None and any("SPF not re-checked" in m for m in levels(report, "warn"))


def test_dns_outage_does_not_crash(signed):
    broken = FakeResolver({}, broken={"_dmarc.example.com", "example.com", "s1._domainkey.example.com"})
    assert analyze(RECEIVED + signed, broken).verdict


# ---------------------------------------------------------------------- gateway
def test_gateway_accepts_and_stamps_legit(signed, resolver):
    d = authenticate_inbound(signed, OWN_IP, "alice@example.com", resolver, authserv_id="mx.receiver.test")
    assert d.action == "accept"
    assert d.message.startswith(b"Authentication-Results: mx.receiver.test; spf=pass")
    assert "dmarc=pass" in d.auth_results and "dkim=pass header.d=example.com header.s=s1" in d.auth_results


def test_gateway_rejects_spoof_but_monitors_when_not_enforcing(resolver):
    resolver.zone["evil.test"] = {"TXT": ["v=spf1 ip4:203.0.113.66 -all"]}
    args = (SPOOF, "203.0.113.66", "bounce@evil.test", resolver)
    assert authenticate_inbound(*args).action == "reject"
    monitored = authenticate_inbound(*args, enforce=False)
    assert monitored.action == "accept" and "dmarc=fail" in monitored.auth_results


def test_gateway_strips_prestamped_results(resolver):
    prestamped = b"Authentication-Results: mx.receiver.test; dmarc=pass header.from=example.com\n" + SPOOF
    d = authenticate_inbound(prestamped, "203.0.113.66", "bounce@evil.test", resolver,
                             authserv_id="mx.receiver.test")
    stamps = [l for l in d.message.split(b"\r\n") if l.lower().startswith(b"authentication-results")]
    assert len(stamps) == 1 and b"dmarc=fail" in stamps[0]


def test_gateway_blocks_header_injection_via_domain(resolver):
    d = authenticate_inbound(SPOOF, "203.0.113.66", "x@evil.test\r\nBcc: spy@evil.test", resolver)
    assert b"\r\nBcc:" not in d.auth_results.encode()


# ---------------------------------------------------------------- records / audit
def test_record_builders():
    assert build_spf(ip4=["192.0.2.1"], include=["_spf.esp.test"], use_mx=True, all_policy="~all") \
        == "v=spf1 mx ip4:192.0.2.1 include:_spf.esp.test ~all"
    assert build_dmarc("quarantine", rua="mailto:d@example.com", pct=10) \
        == "v=DMARC1; p=quarantine; pct=10; adkim=r; aspf=r; rua=mailto:d@example.com"
    long_value = "v=DKIM1; k=rsa; p=" + "A" * 400
    assert zone_line("s._domainkey.example.com.", long_value).count('"') == 4      # split in 2 strings


def test_audit_clean_domain(resolver):
    findings = audit_domain("example.com", "s1", resolver)
    assert not [f for f in findings if f.level == "fail"]
    assert any("2048-bit" in f.message for f in findings)


def test_audit_finds_problems():
    bad = FakeResolver({"example.com": {"TXT": ["v=spf1 +all"]},
                        "_dmarc.example.com": {"TXT": ["v=DMARC1; p=none"]}})
    messages = [f.message for f in audit_domain("example.com", "s1", bad)]
    assert any("+all" in m for m in messages)
    assert any("no key" in m for m in messages)
    assert any("monitoring mode" in m for m in messages)
    assert any("no rua" in m for m in messages)
