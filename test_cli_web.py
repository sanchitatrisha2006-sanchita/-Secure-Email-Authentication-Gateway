import json

import pytest

from emailauth.cli import main
from emailauth.web import create_app
from tests.conftest import OWN_IP


def test_cli_genkey_and_records(tmp_path, capsys):
    assert main(["genkey", "--domain", "example.com", "--selector", "s1", "--out-dir", str(tmp_path)]) == 0
    key = tmp_path / "s1.example.com.private.pem"
    assert key.exists() and (key.stat().st_mode & 0o777) == 0o600
    out = capsys.readouterr().out
    assert "s1._domainkey.example.com." in out and "v=DKIM1; k=rsa; p=" in out
    with pytest.raises(FileExistsError):                  # an existing key is never overwritten
        main(["genkey", "--domain", "example.com", "--selector", "s1", "--out-dir", str(tmp_path)])
    main(["records", "--domain", "example.com", "--selector", "s1", "--key", str(key),
          "--ip4", OWN_IP, "--rua", "mailto:d@example.com"])
    out = capsys.readouterr().out
    assert f"v=spf1 ip4:{OWN_IP} ~all" in out and "p=none" in out and "p=reject" in out


def test_cli_sign_and_check_roundtrip(tmp_path, capsys, keypair, zone):
    from tests.conftest import MESSAGE
    key, msg, signed, zone_file = (tmp_path / n for n in ("k.pem", "m.eml", "s.eml", "zone.json"))
    key.write_bytes(keypair[0])
    msg.write_bytes(b"Received: from m.example.com (m.example.com [%s]) by x; y\n" % OWN_IP.encode() + MESSAGE)
    zone_file.write_text(json.dumps(zone))
    assert main(["sign", str(msg), "--domain", "example.com", "--selector", "s1",
                 "--key", str(key), "--out", str(signed)]) == 0
    assert main(["check", str(signed), "--zone", str(zone_file)]) == 0          # exit 0 = DMARC pass
    assert "VERDICT: PASS" in capsys.readouterr().out
    assert main(["check", str(msg), "--zone", str(zone_file), "--ip", "203.0.113.9", "--json"]) in (0, 1)


def test_web_form_and_api(resolver, signed):
    client = create_app(resolver).test_client()
    signed = b"Return-Path: <alice@example.com>\r\n" + signed      # envelope sender, added on delivery
    assert client.get("/").status_code == 200
    page = client.post("/", data={"raw": signed.decode(), "ip": OWN_IP})
    html = page.get_data(as_text=True)
    assert "PASS: authenticated" in html
    assert "default-src 'none'" in page.headers["Content-Security-Policy"]
    api = client.post("/api/analyze", json={"raw": signed.decode(), "ip": OWN_IP}).get_json()
    assert api["dmarc"]["result"] == "pass" and api["spf"]["result"] == "pass"


def test_web_escapes_hostile_input(resolver):
    raw = 'From: "<script>alert(1)</script>" <a@example.com>\nSubject: x\n\nbody\n'
    html = create_app(resolver).test_client().post("/", data={"raw": raw}).get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html


def test_web_input_validation_and_size_limit(resolver):
    client = create_app(resolver).test_client()
    assert client.post("/api/analyze", json={"raw": ""}).status_code == 400
    assert client.post("/api/analyze", json={"nope": 1}).status_code == 400
    assert client.post("/", data={"raw": "x" * 1_100_000}).status_code == 413
