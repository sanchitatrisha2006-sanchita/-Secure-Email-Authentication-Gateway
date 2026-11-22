"""Offline end-to-end demo: a fake DNS zone + six delivery scenarios.

    python scripts/demo.py

Writes examples/zone.json and examples/*.eml so you can also try the CLI:
    python -m emailauth check examples/spoofed.eml --zone examples/zone.json --ip 203.0.113.66
"""
import json
import zlib
from pathlib import Path

from emailauth import dkim
from emailauth.dns_resolver import FakeResolver
from emailauth.gateway import authenticate_inbound

OUT = Path(__file__).resolve().parent.parent / "examples"
DOMAIN, SELECTOR = "example.com", "s2026"
OWN_IP, SPOOFER_IP, FORWARDER_IP, ESP_IP = "192.0.2.10", "203.0.113.66", "203.0.113.99", "198.51.100.20"

own_key, own_pub = dkim.generate_keypair(2048)
esp_key, esp_pub = dkim.generate_keypair(2048)

ZONE = {
    DOMAIN: {"TXT": [f"v=spf1 ip4:{OWN_IP} -all"]},
    f"{SELECTOR}._domainkey.{DOMAIN}": {"TXT": [dkim.dkim_txt_record(own_pub)]},
    f"_dmarc.{DOMAIN}": {"TXT": ["v=DMARC1; p=reject; adkim=r; aspf=r; rua=mailto:dmarc@example.com"]},
    "evil.test": {"TXT": [f"v=spf1 ip4:{SPOOFER_IP} -all"]},             # attackers publish valid SPF too
    "esp.test": {"TXT": [f"v=spf1 ip4:{ESP_IP} -all"]},
    "esp1._domainkey.esp.test": {"TXT": [dkim.dkim_txt_record(esp_pub)]},
}


def message(frm: str, subject: str, body: str, return_path: str, ip: str, host: str) -> bytes:
    return (f"Return-Path: <{return_path}>\nFrom: {frm}\nTo: bob@receiver.test\nSubject: {subject}\n"
            f"Date: Sat, 21 Nov 2026 09:30:00 +0000\nMessage-ID: <{zlib.crc32(subject.encode())}@{host}>\n"
            f"\n{body}\n").encode()


def received(ip: str, host: str) -> bytes:
    return (f"Received: from {host} ({host} [{ip}]) by mx.receiver.test with ESMTPS; "
            f"Sat, 21 Nov 2026 09:30:05 +0000\r\n").encode()


def main() -> None:
    OUT.mkdir(exist_ok=True)
    resolver = FakeResolver(ZONE)
    legit = message("Alice <alice@example.com>", "Quarterly report", "Report attached.",
                    "alice@example.com", OWN_IP, "mail.example.com")
    signed_legit = dkim.sign(legit, DOMAIN, SELECTOR, own_key)

    scenarios = [
        ("1. Legitimate mail", signed_legit, OWN_IP, "alice@example.com", True),
        ("2. Spoofed From, attacker's own SPF",
         message("CEO <ceo@example.com>", "Urgent wire transfer", "Pay now.",
                 "bounce@evil.test", SPOOFER_IP, "evil.test"), SPOOFER_IP, "bounce@evil.test", True),
        ("3. Same spoof, DMARC in monitoring mode (enforce off)",
         message("CEO <ceo@example.com>", "Urgent wire transfer", "Pay now.",
                 "bounce@evil.test", SPOOFER_IP, "evil.test"), SPOOFER_IP, "bounce@evil.test", False),
        ("4. Body altered in transit",
         signed_legit.replace(b"Report attached.", b"Please log in at evil.test"),
         OWN_IP, "alice@example.com", True),
        ("5. Forwarded: SPF breaks, DKIM survives", signed_legit, FORWARDER_IP, "alice@example.com", True),
        ("6. Third-party sender signing with its own domain",
         dkim.sign(message("Alice <alice@example.com>", "Newsletter", "News!", "b@esp.test", ESP_IP, "esp.test"),
                   "esp.test", "esp1", esp_key), ESP_IP, "b@esp.test", True),
    ]

    print(f"{'scenario':<56}{'SPF':<10}{'DKIM':<10}{'DMARC':<7}{'action':<11}aligned (spf/dkim)")
    print("-" * 110)
    for index, (title, raw, ip, mail_from, enforce) in enumerate(scenarios, 1):
        arrived = received(ip, "sender.test") + raw          # the receiving MTA adds its Received line
        decision = authenticate_inbound(arrived, ip, mail_from, resolver,
                                        authserv_id="mx.receiver.test", enforce=enforce)
        r = decision.report
        print(f"{title:<56}{r.spf.result:<10}{r.dkim[0].result:<10}{r.dmarc.result:<7}"
              f"{decision.action:<11}{r.dmarc.spf_aligned}/{r.dmarc.dkim_aligned}")
        (OUT / f"scenario{index}.eml").write_bytes(decision.message)
    (OUT / "zone.json").write_text(json.dumps(ZONE, indent=2))
    print(f"\nWrote {OUT}/zone.json and scenario1..6.eml")


if __name__ == "__main__":
    main()
