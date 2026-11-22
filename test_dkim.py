import pytest

from emailauth import dkim
from emailauth.dns_resolver import FakeResolver
from tests.conftest import MESSAGE


def result(raw, resolver, **kw):
    return dkim.verify_all(raw, resolver, **kw)[0]


def test_sign_then_verify(signed, resolver):
    r = result(signed, resolver)
    assert (r.result, r.domain, r.selector) == ("pass", "example.com", "s1")


def test_body_tampering_fails(signed, resolver):
    r = result(signed.replace(b"this is", b"this was"), resolver)
    assert r.result == "fail" and "body hash" in r.reason


def test_header_tampering_fails(signed, resolver):
    assert result(signed.replace(b"Subject: Hello", b"Subject: Hullo"), resolver).result == "fail"


def test_added_from_header_breaks_signature(signed, resolver):
    """Oversigning: prepending a second From must invalidate the signature."""
    forged = b"From: ceo@example.com\r\n" + signed
    assert result(forged, resolver).result == "fail"


def test_relaxed_canonicalization_survives_rewrapping(signed, resolver):
    rewrapped = signed.replace(b"Subject: Hello   world", b"Subject: Hello\r\n world")
    assert result(rewrapped, resolver).result == "pass"


def test_trailing_blank_lines_and_whitespace_ignored(signed, resolver):
    assert result(signed + b"\r\n\r\n", resolver).result == "pass"


def test_unix_line_endings_normalised(signed, resolver):
    assert result(signed.replace(b"\r\n", b"\n"), resolver).result == "pass"


def test_no_signature(resolver):
    assert result(MESSAGE, resolver).result == "none"


def test_missing_key_is_permerror(signed):
    assert result(signed, FakeResolver({})).result == "permerror"


def test_dns_failure_is_temperror(signed):
    r = result(signed, FakeResolver({}, broken={"s1._domainkey.example.com"}))
    assert r.result == "temperror"


def test_revoked_key_fails(signed, zone):
    zone["s1._domainkey.example.com"]["TXT"] = ["v=DKIM1; k=rsa; p="]
    assert result(signed, FakeResolver(zone)).result == "fail"


def test_wrong_key_fails(signed, zone):
    _, other_pub = dkim.generate_keypair(2048)
    zone["s1._domainkey.example.com"]["TXT"] = [dkim.dkim_txt_record(other_pub)]
    assert result(signed, FakeResolver(zone)).result == "fail"


def test_1024_bit_key_is_the_accepted_minimum(zone):
    priv, pub = dkim.generate_keypair(1024)
    zone["s1._domainkey.example.com"]["TXT"] = [dkim.dkim_txt_record(pub)]
    signed = dkim.sign(MESSAGE, "example.com", "s1", priv)
    assert result(signed, FakeResolver(zone)).result == "pass"


def test_expired_signature(keypair, resolver):
    signed = dkim.sign(MESSAGE, "example.com", "s1", keypair[0], now=1_000, expire_seconds=60)
    assert result(signed, resolver, now=2_000).result == "fail"
    assert result(signed, resolver, now=1_030).result == "pass"


def test_body_length_tag_rejected(signed, resolver):
    forged = signed.replace(b"; bh=", b"; l=5; bh=", 1)
    assert result(forged, resolver).result == "fail"


def test_signature_must_cover_from(signed, resolver):
    forged = signed.replace(b"h=from:from:", b"h=", 1)
    assert result(forged, resolver).result == "fail"


def test_headers_only_input_skips_body_check(signed, resolver):
    headers_only = signed.split(b"\r\n\r\n")[0] + b"\r\n"
    r = result(headers_only, resolver)
    assert r.result == "pass" and r.body_checked is False


def test_signing_requires_from(keypair):
    with pytest.raises(ValueError):
        dkim.sign(b"Subject: x\n\nbody\n", "example.com", "s1", keypair[0])


def test_body_canonicalization_rules():
    assert dkim.canonicalize_body(b"a  b \r\n\r\n\r\n", "relaxed") == b"a b\r\n"
    assert dkim.canonicalize_body(b"", "relaxed") == b""
    assert dkim.canonicalize_body(b"", "simple") == b"\r\n"
    assert dkim.canonicalize_body(b"a  b \r\n\r\n", "simple") == b"a  b \r\n"


def test_header_canonicalization_relaxed():
    out = dkim.canonicalize_header("Subject", b"SubJect:  A \t B\r\n  C ", "relaxed")
    assert out == b"subject:A B C"
