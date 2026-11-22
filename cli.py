"""Command line interface:  python -m emailauth <command> ..."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from emailauth import dkim
from emailauth.analyzer import analyze
from emailauth.dns_resolver import DnsPythonResolver, FakeResolver
from emailauth.records import (audit_domain, build_dmarc, build_spf, dmarc_rollout,
                               public_b64_from_pem, zone_line)

ICONS = {"info": "[i]", "warn": "[!]", "fail": "[x]"}


def _resolver(args):
    return FakeResolver.from_json(args.zone) if getattr(args, "zone", None) else DnsPythonResolver()


def cmd_genkey(args) -> int:
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    private_pem, public_b64 = dkim.generate_keypair(args.bits)
    key_path = out / f"{args.selector}.{args.domain}.private.pem"
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)   # never overwrite a key
    with os.fdopen(fd, "wb") as fh:
        fh.write(private_pem)
    print(f"Private key written to {key_path} (mode 600). Keep it secret; never publish or commit it.\n")
    print("Publish this DNS TXT record:\n")
    print(zone_line(f"{args.selector}._domainkey.{args.domain}.", dkim.dkim_txt_record(public_b64)))
    return 0


def cmd_records(args) -> int:
    spf = build_spf(ip4=args.ip4, ip6=args.ip6, include=args.include, use_mx=args.mx,
                    use_a=args.a, all_policy=args.spf_all)
    print(f"; --- SPF\n{zone_line(args.domain + '.', spf)}\n")
    if args.key:
        pub = public_b64_from_pem(Path(args.key).read_bytes())
        print(f"; --- DKIM\n{zone_line(f'{args.selector}._domainkey.{args.domain}.', dkim.dkim_txt_record(pub))}\n")
    dmarc = build_dmarc(args.dmarc_policy, rua=args.rua, pct=args.pct)
    print(f"; --- DMARC (current stage)\n{zone_line('_dmarc.' + args.domain + '.', dmarc)}\n")
    print("; --- DMARC rollout plan")
    for stage, record in dmarc_rollout(args.rua):
        print(f"; {stage}\n;   {record}")
    return 0


def cmd_sign(args) -> int:
    signed = dkim.sign(Path(args.message).read_bytes(), args.domain, args.selector,
                       Path(args.key).read_bytes())
    sys.stdout.buffer.write(signed) if not args.out else Path(args.out).write_bytes(signed)
    return 0


def cmd_check(args) -> int:
    raw = sys.stdin.buffer.read() if args.message == "-" else Path(args.message).read_bytes()
    report = analyze(raw, _resolver(args), client_ip=args.ip, mail_from=args.mail_from, helo=args.helo,
                     trusted_authserv=set(args.trusted_authserv) or None)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, default=str))
        return 0 if report.dmarc and report.dmarc.result == "pass" else 1
    print(f"VERDICT: {report.verdict}\n")
    print(f"From:       {report.from_address}  (domain {report.from_domain})")
    print(f"MAIL FROM:  {report.mail_from_domain or '-'}")
    print(f"Client IP:  {report.client_ip or '-'}  {('(' + report.client_ip_source + ')') if report.client_ip else ''}\n")
    if report.spf:
        print(f"SPF    {report.spf.result:<10} {report.spf.domain}  {report.spf.reason}")
    for r in report.dkim:
        print(f"DKIM   {r.result:<10} d={r.domain or '-'} s={r.selector or '-'}  {r.reason}")
    if report.dmarc:
        d = report.dmarc
        print(f"DMARC  {d.result:<10} policy={d.policy} disposition={d.disposition} "
              f"spf_aligned={d.spf_aligned} dkim_aligned={d.dkim_aligned}")
    if report.claims:
        print("\nClaims in headers (Authentication-Results):")
        for c in report.claims:
            print(f"  {c.method}={c.result}  by {c.authserv_id}  {c.properties}")
    if report.findings:
        print("\nFindings:")
        for f in report.findings:
            print(f"  {ICONS[f.level]} {f.message}")
    return 0 if report.dmarc and report.dmarc.result == "pass" else 1


def cmd_audit(args) -> int:
    findings = audit_domain(args.domain, args.selector, _resolver(args))
    for f in findings:
        print(f"{ICONS[f.level]} {f.message}")
    return 1 if any(f.level == "fail" for f in findings) else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="emailauth", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("genkey", help="generate a DKIM key pair and print the DNS record")
    p.add_argument("--domain", required=True)
    p.add_argument("--selector", required=True)
    p.add_argument("--out-dir", default="keys")
    p.add_argument("--bits", type=int, default=2048, choices=[1024, 2048, 4096])
    p.set_defaults(func=cmd_genkey)

    p = sub.add_parser("records", help="print SPF/DKIM/DMARC records and the DMARC rollout plan")
    p.add_argument("--domain", required=True)
    p.add_argument("--selector", default="mail")
    p.add_argument("--key", help="DKIM private key PEM (used to derive the public record)")
    p.add_argument("--ip4", nargs="*", default=[])
    p.add_argument("--ip6", nargs="*", default=[])
    p.add_argument("--include", nargs="*", default=[])
    p.add_argument("--mx", action="store_true")
    p.add_argument("--a", action="store_true")
    p.add_argument("--spf-all", default="~all", choices=["-all", "~all", "?all"])
    p.add_argument("--dmarc-policy", default="none", choices=["none", "quarantine", "reject"])
    p.add_argument("--rua")
    p.add_argument("--pct", type=int, default=100)
    p.set_defaults(func=cmd_records)

    p = sub.add_parser("sign", help="DKIM-sign a message")
    p.add_argument("message")
    p.add_argument("--domain", required=True)
    p.add_argument("--selector", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--out")
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("check", help="parse a raw email/header and verify SPF, DKIM and DMARC")
    p.add_argument("message", help="path to a .eml file, or - for stdin")
    p.add_argument("--ip", help="connecting IP (default: inferred from topmost Received header)")
    p.add_argument("--mail-from", help="envelope sender (default: Return-Path header)")
    p.add_argument("--helo")
    p.add_argument("--trusted-authserv", nargs="*", default=[])
    p.add_argument("--zone", help="JSON file with a fake DNS zone, for offline labs")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("audit", help="check a domain's published SPF/DKIM/DMARC records")
    p.add_argument("domain")
    p.add_argument("--selector")
    p.add_argument("--zone")
    p.set_defaults(func=cmd_audit)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
