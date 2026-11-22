from emailauth.dkim import DkimResult
from emailauth.dmarc import evaluate, is_aligned, organizational_domain
from emailauth.dns_resolver import FakeResolver
from emailauth.spf import SpfResult


def r(record, domain="example.com"):
    return FakeResolver({f"_dmarc.{domain}": {"TXT": [record]}})


SPF_OK = SpfResult("pass", "example.com")
DKIM_OK = [DkimResult("pass", "example.com", "s1")]
NONE = [DkimResult("none")]


def test_organizational_domain():
    assert organizational_domain("a.b.example.com") == "example.com"
    assert organizational_domain("mail.example.co.uk") == "example.co.uk"
    assert organizational_domain("shop.example.co.in") == "example.co.in"


def test_alignment_modes():
    assert is_aligned("mail.example.com", "example.com", "r")
    assert not is_aligned("mail.example.com", "example.com", "s")
    assert not is_aligned("example.com.evil.test", "example.com", "r")


def test_pass_via_spf_only_or_dkim_only():
    res = r("v=DMARC1; p=reject")
    assert evaluate("example.com", SPF_OK, NONE, res).result == "pass"
    assert evaluate("example.com", SpfResult("fail", "example.com"), DKIM_OK, res).result == "pass"


def test_fail_applies_policy():
    out = evaluate("example.com", SpfResult("fail", "example.com"), NONE, r("v=DMARC1; p=reject"))
    assert (out.result, out.disposition) == ("fail", "reject")


def test_unaligned_pass_does_not_count():
    out = evaluate("example.com", SpfResult("pass", "evil.test"),
                   [DkimResult("pass", "esp.test", "x")], r("v=DMARC1; p=quarantine"))
    assert out.result == "fail" and out.disposition == "quarantine"
    assert len(out.reasons) == 2


def test_monitoring_mode_never_blocks():
    out = evaluate("example.com", None, NONE, r("v=DMARC1; p=none; rua=mailto:d@example.com"))
    assert out.result == "fail" and out.disposition == "none"


def test_strict_alignment_rejects_subdomain():
    out = evaluate("example.com", SpfResult("pass", "mail.example.com"), NONE,
                   r("v=DMARC1; p=reject; aspf=s"))
    assert out.result == "fail"


def test_subdomain_policy_from_org_domain():
    res = r("v=DMARC1; p=reject; sp=none")
    out = evaluate("news.example.com", None, NONE, res)
    assert out.found_at == "example.com" and out.policy == "none" and out.disposition == "none"


def test_pct_downgrades_unsampled_messages():
    res = r("v=DMARC1; p=reject; pct=10")
    assert evaluate("example.com", None, NONE, res, random_fn=lambda: 0.05).disposition == "reject"
    assert evaluate("example.com", None, NONE, res, random_fn=lambda: 0.50).disposition == "quarantine"


def test_no_record_invalid_or_duplicate():
    assert evaluate("example.com", SPF_OK, NONE, FakeResolver({})).result == "none"
    assert evaluate("example.com", SPF_OK, NONE, r("v=DMARC1; p=bogus")).result == "none"
    dup = FakeResolver({"_dmarc.example.com": {"TXT": ["v=DMARC1; p=none", "v=DMARC1; p=reject"]}})
    assert evaluate("example.com", SPF_OK, NONE, dup).result == "none"


def test_dns_failure_is_temperror():
    res = FakeResolver({}, broken={"_dmarc.example.com"})
    assert evaluate("example.com", SPF_OK, NONE, res).result == "temperror"
