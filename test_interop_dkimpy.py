"""Cross-check our DKIM against the reference library `dkimpy` (skipped if not installed).

Run this on your own machine: `pip install dkimpy && pytest tests/test_interop_dkimpy.py`.
"""
import pytest

dkimpy = pytest.importorskip("dkim")

from emailauth import dkim as ours          # noqa: E402
from tests.conftest import MESSAGE          # noqa: E402


def _dns_for(keypair):
    record = ours.dkim_txt_record(keypair[1]).encode()
    return lambda name, timeout=5: record


def test_dkimpy_verifies_our_signature(keypair):
    signed = ours.sign(MESSAGE, "example.com", "s1", keypair[0])
    assert dkimpy.verify(signed, dnsfunc=_dns_for(keypair))


def test_we_verify_dkimpy_signature(keypair, resolver):
    signature = dkimpy.sign(MESSAGE.replace(b"\n", b"\r\n"), b"s1", b"example.com", keypair[0],
                            include_headers=[b"from", b"to", b"subject", b"date"])
    assert ours.verify_all(signature + MESSAGE.replace(b"\n", b"\r\n"), resolver)[0].result == "pass"
