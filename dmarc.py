"""DMARC policy discovery, identifier alignment and disposition (RFC 7489)."""
from __future__ import annotations

import random
import re
from dataclasses import dataclass, field
from typing import Callable

from emailauth.dkim import DkimResult, parse_tags
from emailauth.dns_resolver import DnsTempError, Resolver, normalize
from emailauth.spf import SpfResult

# Small built-in list of multi-label public suffixes. Production code should use the full
# Public Suffix List (e.g. the `tldextract` package) for correct organizational domains.
MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.za",
    "co.in", "net.in", "org.in", "ac.in", "gov.in", "edu.in", "co.jp", "ne.jp", "or.jp",
    "com.br", "com.cn", "com.mx", "com.sg", "com.tr", "co.kr",
}
POLICIES = ("none", "quarantine", "reject")


def organizational_domain(domain: str) -> str:
    labels = normalize(domain).split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    keep = 3 if ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES else 2
    return ".".join(labels[-keep:])


def is_aligned(auth_domain: str, from_domain: str, mode: str) -> bool:
    auth_domain, from_domain = normalize(auth_domain), normalize(from_domain)
    if mode == "s":
        return auth_domain == from_domain
    return organizational_domain(auth_domain) == organizational_domain(from_domain)


@dataclass
class DmarcPolicy:
    tags: dict[str, str]
    found_at: str                         # domain where the record was published

    @property
    def p(self) -> str:
        return self.tags["p"].lower()

    @property
    def pct(self) -> int:
        value = self.tags.get("pct", "100")
        return min(max(int(value), 0), 100) if value.isdigit() else 100

    def mode(self, tag: str) -> str:      # adkim / aspf
        return "s" if self.tags.get(tag, "r").lower() == "s" else "r"


@dataclass
class DmarcResult:
    result: str                           # pass | fail | none | temperror
    from_domain: str = ""
    policy: str | None = None             # policy that applies to this domain (none/quarantine/reject)
    disposition: str = "none"             # what a receiver should do with this message
    spf_aligned: bool = False
    dkim_aligned: bool = False
    record: str = ""
    found_at: str = ""
    pct: int = 100
    reasons: list[str] = field(default_factory=list)


def fetch_policy(from_domain: str, resolver: Resolver) -> DmarcPolicy | None:
    """Look up _dmarc.<from-domain>, then fall back to the organizational domain."""
    from_domain = normalize(from_domain)
    candidates = [from_domain]
    if organizational_domain(from_domain) != from_domain:
        candidates.append(organizational_domain(from_domain))
    for domain in candidates:
        records = [t for t in resolver.txt(f"_dmarc.{domain}") if re.match(r"(?i)\s*v=DMARC1\s*;", t + ";")]
        if len(records) != 1:         # none -> keep looking; several -> invalid, treated as none
            continue
        tags = parse_tags(records[0])
        if tags.get("p", "").lower() in POLICIES:
            return DmarcPolicy(tags, domain)
    return None


def evaluate(from_domain: str, spf: SpfResult | None, dkim: list[DkimResult],
             resolver: Resolver, random_fn: Callable[[], float] = random.random) -> DmarcResult:
    """Combine SPF and DKIM results with the From domain's published DMARC policy."""
    from_domain = normalize(from_domain)
    try:
        policy = fetch_policy(from_domain, resolver)
    except DnsTempError as exc:
        return DmarcResult("temperror", from_domain, reasons=[str(exc)])
    if policy is None:
        return DmarcResult("none", from_domain, reasons=["no valid DMARC record published"])

    spf_aligned = bool(spf and spf.result == "pass"
                       and is_aligned(spf.domain, from_domain, policy.mode("aspf")))
    dkim_aligned = any(r.result == "pass" and is_aligned(r.domain, from_domain, policy.mode("adkim"))
                       for r in dkim)
    result = DmarcResult("pass" if spf_aligned or dkim_aligned else "fail", from_domain,
                         spf_aligned=spf_aligned, dkim_aligned=dkim_aligned,
                         record=";".join(f"{k}={v}" for k, v in policy.tags.items()),
                         found_at=policy.found_at, pct=policy.pct)

    applies_sp = policy.found_at != from_domain and "sp" in policy.tags
    effective = policy.tags["sp"].lower() if applies_sp else policy.p
    result.policy = effective if effective in POLICIES else policy.p

    if result.result == "fail":
        disposition = result.policy
        if policy.pct < 100 and random_fn() * 100 >= policy.pct:      # outside the sampled slice
            disposition = {"reject": "quarantine", "quarantine": "none"}.get(disposition, "none")
            result.reasons.append(f"pct={policy.pct}: this message fell outside the enforced sample")
        result.disposition = disposition
        if not spf_aligned and spf and spf.result == "pass":
            result.reasons.append(f"SPF passed for {spf.domain} but it is not aligned with {from_domain}")
        if not dkim_aligned and any(r.result == "pass" for r in dkim):
            result.reasons.append("a DKIM signature verified but its d= domain is not aligned with From")
    return result
