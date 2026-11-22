"""Build SPF / DKIM / DMARC DNS records and audit what a domain actually publishes."""
from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from emailauth.analyzer import Finding
from emailauth.dkim import dkim_txt_record, parse_tags
from emailauth.dmarc import fetch_policy
from emailauth.dns_resolver import DnsTempError, Resolver
from emailauth.spf import check_spf


def build_spf(*, ip4: list[str] = (), ip6: list[str] = (), include: list[str] = (),
              use_mx: bool = False, use_a: bool = False, all_policy: str = "-all") -> str:
    """Compose an SPF record. Use '~all' (softfail) while testing, '-all' once confident."""
    if all_policy not in ("-all", "~all", "?all"):
        raise ValueError("all_policy must be -all, ~all or ?all (never +all)")
    terms = ["v=spf1"]
    terms += ["mx"] * use_mx + ["a"] * use_a
    terms += [f"ip4:{x}" for x in ip4] + [f"ip6:{x}" for x in ip6] + [f"include:{x}" for x in include]
    return " ".join(terms + [all_policy])


def build_dmarc(policy: str = "none", *, rua: str | None = None, ruf: str | None = None,
                pct: int = 100, subdomain_policy: str | None = None,
                adkim: str = "r", aspf: str = "r") -> str:
    if policy not in ("none", "quarantine", "reject"):
        raise ValueError("policy must be none, quarantine or reject")
    if not 0 <= pct <= 100:
        raise ValueError("pct must be between 0 and 100")
    parts = ["v=DMARC1", f"p={policy}"]
    if subdomain_policy:
        parts.append(f"sp={subdomain_policy}")
    if pct != 100:
        parts.append(f"pct={pct}")
    parts += [f"adkim={adkim}", f"aspf={aspf}"]
    parts += [f"rua={rua}"] * bool(rua) + [f"ruf={ruf}"] * bool(ruf)
    return "; ".join(parts)


def dmarc_rollout(rua: str | None = None) -> list[tuple[str, str]]:
    """The staged path from monitoring to enforcement."""
    return [
        ("1. Monitor (weeks 0-4): collect reports, change nothing", build_dmarc("none", rua=rua)),
        ("2. Quarantine a sample (week 4+)", build_dmarc("quarantine", rua=rua, pct=10)),
        ("3. Quarantine everything", build_dmarc("quarantine", rua=rua)),
        ("4. Reject a sample", build_dmarc("reject", rua=rua, pct=25)),
        ("5. Full enforcement", build_dmarc("reject", rua=rua)),
    ]


def zone_line(name: str, value: str, ttl: int = 3600) -> str:
    """Format a TXT record for a BIND zone file; strings over 255 bytes must be split."""
    chunks = " ".join(f'"{value[i:i + 255]}"' for i in range(0, len(value), 255))
    return f"{name}\t{ttl}\tIN\tTXT\t{chunks}"


def public_b64_from_pem(private_key_pem: bytes) -> str:
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("only RSA keys are supported")
    der = key.public_key().public_bytes(serialization.Encoding.DER,
                                        serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode()


# --------------------------------------------------------------------------- audit
def audit_domain(domain: str, selector: str | None, resolver: Resolver) -> list[Finding]:
    """Check the published records for common mistakes (functional verification of the DNS setup)."""
    out: list[Finding] = []
    add = lambda level, msg: out.append(Finding(level, msg))        # noqa: E731
    try:
        spf_records = [t for t in resolver.txt(domain) if t.lower().startswith("v=spf1")]
        if not spf_records:
            add("fail", f"SPF: no record at {domain}")
        elif len(spf_records) > 1:
            add("fail", "SPF: several SPF records published (must be exactly one)")
        else:
            record = spf_records[0]
            add("info", f"SPF: {record}")
            if "+all" in record.split() or record.split()[-1] == "?all":
                add("fail", "SPF: ends in +all/?all, which authorises (or ignores) everyone")
            elif not record.split()[-1].endswith("all") and "redirect=" not in record:
                add("warn", "SPF: no terminating 'all' mechanism")
            elif record.split()[-1] == "~all":
                add("info", "SPF: softfail (~all): fine while testing; move to -all when confident")
            if " ptr" in record:
                add("warn", "SPF: ptr is deprecated and slow")
            probe = check_spf("203.0.113.250", f"probe@{domain}", resolver)
            if probe.result in ("permerror", "temperror"):
                add("fail", f"SPF: evaluation gives {probe.result}: {probe.reason}")
            elif probe.lookups >= 8:
                add("warn", f"SPF: {probe.lookups} of 10 allowed DNS lookups used; little headroom")
            else:
                add("info", f"SPF: evaluates cleanly ({probe.lookups}/10 lookups)")

        if selector:
            key_records = [parse_tags(t) for t in resolver.txt(f"{selector}._domainkey.{domain}")]
            key = next((t for t in key_records if "p" in t), None)
            if key is None:
                add("fail", f"DKIM: no key at {selector}._domainkey.{domain}")
            elif not key["p"]:
                add("fail", "DKIM: key is revoked (empty p=)")
            else:
                try:
                    pub = serialization.load_der_public_key(base64.b64decode(key["p"]))
                    bits = pub.key_size
                    add("info" if bits >= 2048 else "warn",
                        f"DKIM: {bits}-bit RSA key published" + ("" if bits >= 2048 else " (2048 recommended)"))
                except Exception:
                    add("fail", "DKIM: p= is not a valid public key (check for stray spaces or quotes)")
                if "y" in key.get("t", "").split(":"):
                    add("warn", "DKIM: key is flagged t=y (testing mode); remove before enforcement")

        policy = fetch_policy(domain, resolver)
        if policy is None:
            add("fail", f"DMARC: no valid record at _dmarc.{domain}")
        else:
            add("info", f"DMARC: p={policy.p}, pct={policy.pct}, published at {policy.found_at}")
            if policy.p == "none":
                add("info", "DMARC: monitoring mode: nothing is blocked yet")
            if "rua" not in policy.tags:
                add("warn", "DMARC: no rua= address, so you will receive no aggregate reports")
    except DnsTempError as exc:
        add("warn", f"DNS lookup failed during audit: {exc}")
    return out
