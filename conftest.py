"""Shared fixtures: one RSA key pair and a fake DNS zone for a domain with all three protocols."""
import pytest

from emailauth import dkim
from emailauth.dns_resolver import FakeResolver

OWN_IP = "192.0.2.10"
MESSAGE = (b"From: Alice <alice@example.com>\nTo: bob@dest.test\nSubject: Hello   world\n"
           b"Date: Sat, 21 Nov 2026 10:00:00 +0000\nMessage-ID: <1@example.com>\n\n"
           b"Hi Bob,\n  this is a test.  \n\n\n")


@pytest.fixture(scope="session")
def keypair():
    return dkim.generate_keypair(2048)


@pytest.fixture()
def zone(keypair):
    return {
        "example.com": {"TXT": [f"v=spf1 ip4:{OWN_IP} include:_spf.esp.test -all"]},
        "_spf.esp.test": {"TXT": ["v=spf1 ip4:198.51.100.0/24 ~all"]},
        "s1._domainkey.example.com": {"TXT": [dkim.dkim_txt_record(keypair[1])]},
        "_dmarc.example.com": {"TXT": ["v=DMARC1; p=reject; rua=mailto:d@example.com"]},
    }


@pytest.fixture()
def resolver(zone):
    return FakeResolver(zone)


@pytest.fixture()
def signed(keypair):
    return dkim.sign(MESSAGE, "example.com", "s1", keypair[0])
