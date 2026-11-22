from emailauth.dns_resolver import FakeResolver
from emailauth.spf import check_spf


def spf(ip, zone, sender="u@example.com"):
    return check_spf(ip, sender, FakeResolver(zone))


def rec(*terms):
    return {"example.com": {"TXT": ["v=spf1 " + " ".join(terms)]}}


def test_ip4_cidr_match_and_fail():
    assert spf("192.0.2.77", rec("ip4:192.0.2.0/24", "-all")).result == "pass"
    assert spf("198.51.100.1", rec("ip4:192.0.2.0/24", "-all")).result == "fail"


def test_ip6():
    assert spf("2001:db8::5", rec("ip6:2001:db8::/32", "-all")).result == "pass"
    assert spf("192.0.2.1", rec("ip6:2001:db8::/32", "-all")).result == "fail"


def test_qualifiers():
    assert spf("1.2.3.4", rec("~all")).result == "softfail"
    assert spf("1.2.3.4", rec("?all")).result == "neutral"
    assert spf("1.2.3.4", rec("+all")).result == "pass"


def test_no_match_without_all_is_neutral():
    assert spf("1.2.3.4", rec("ip4:10.0.0.1")).result == "neutral"


def test_a_and_mx_mechanisms():
    zone = {**rec("a", "mx:mail.example.com/30", "-all"),
            "example.com": {"TXT": ["v=spf1 a mx:mail.example.com/30 -all"], "A": ["192.0.2.1"]},
            "mail.example.com": {"MX": ["mx1.example.com"]}, "mx1.example.com": {"A": ["198.51.100.4"]}}
    assert spf("192.0.2.1", zone).result == "pass"
    assert spf("198.51.100.5", zone).result == "pass"        # inside mx host's /30
    assert spf("198.51.100.9", zone).result == "fail"


def test_include_pass_and_non_match():
    zone = {**rec("include:_spf.esp.test", "-all"),
            "_spf.esp.test": {"TXT": ["v=spf1 ip4:198.51.100.0/24 -all"]}}
    assert spf("198.51.100.3", zone).result == "pass"
    # the included record's own -all must NOT fail the message; evaluation continues
    assert spf("203.0.113.3", zone).result == "fail"
    zone["example.com"]["TXT"] = ["v=spf1 include:_spf.esp.test ~all"]
    assert spf("203.0.113.3", zone).result == "softfail"


def test_include_of_missing_record_is_permerror():
    assert spf("1.2.3.4", rec("include:gone.test", "-all")).result == "permerror"


def test_redirect():
    zone = {**rec("redirect=_spf.corp.test"), "_spf.corp.test": {"TXT": ["v=spf1 ip4:192.0.2.1 -all"]}}
    assert spf("192.0.2.1", zone).result == "pass"
    assert spf("192.0.2.2", zone).result == "fail"


def test_lookup_limit_enforced():
    zone = {f"i{n}.test": {"TXT": ["v=spf1 -all"]} for n in range(11)}
    zone["example.com"] = {"TXT": ["v=spf1 " + " ".join(f"include:i{n}.test" for n in range(11)) + " -all"]}
    r = spf("1.2.3.4", zone)
    assert r.result == "permerror" and "10" in r.reason


def test_include_loop_hits_limit():
    zone = {"example.com": {"TXT": ["v=spf1 include:loop.test -all"]},
            "loop.test": {"TXT": ["v=spf1 include:example.com -all"]}}
    assert spf("1.2.3.4", zone).result == "permerror"


def test_none_and_multiple_records():
    assert spf("1.2.3.4", {}).result == "none"
    assert spf("1.2.3.4", {"example.com": {"TXT": ["v=spf1 -all", "v=spf1 +all"]}}).result == "permerror"


def test_dns_failure_is_temperror():
    r = check_spf("1.2.3.4", "u@example.com", FakeResolver({}, broken={"example.com"}))
    assert r.result == "temperror"


def test_empty_sender_uses_helo():
    r = check_spf("192.0.2.1", "", FakeResolver(rec("ip4:192.0.2.1", "-all")), helo="example.com")
    assert r.result == "pass" and r.domain == "example.com"


def test_unsupported_features_are_permerror():
    assert spf("1.2.3.4", rec("ptr", "-all")).result == "permerror"
    assert spf("1.2.3.4", rec("exists:%{i}.bl.test", "-all")).result == "permerror"


def test_invalid_ip_and_bad_cidr():
    assert check_spf("not-an-ip", "u@example.com", FakeResolver({})).result == "permerror"
    assert spf("1.2.3.4", rec("a/99", "-all")).result == "permerror"
