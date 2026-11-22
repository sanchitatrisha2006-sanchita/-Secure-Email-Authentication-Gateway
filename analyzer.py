"""Combine header parsing with independent SPF / DKIM / DMARC verification."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from email.utils import parseaddr

from emailauth import dmarc as dmarc_mod
from emailauth.dkim import DkimResult, parse_tags, split_message, verify_all
from emailauth.dmarc import DmarcResult, is_aligned, organizational_domain
from emailauth.dns_resolver import DnsTempError, Resolver
from emailauth.headers import (AuthClaim, Hop, address_domain, from_addresses, get_all,
                               infer_client_ip, parse_authentication_results, parse_received_chain,
                               parse_received_spf, unfolded_headers)
from emailauth.spf import SpfResult, check_spf


@dataclass
class Finding:
    level: str          # info | warn | fail
    message: str


@dataclass
class AnalysisReport:
    verdict: str = ""
    from_address: str = ""
    from_domain: str = ""
    mail_from_domain: str = ""
    client_ip: str | None = None
    client_ip_source: str = ""
    claims: list[AuthClaim] = field(default_factory=list)
    received_spf: dict | None = None
    dkim_signatures: list[dict] = field(default_factory=list)
    hops: list[Hop] = field(default_factory=list)
    spf: SpfResult | None = None
    dkim: list[DkimResult] = field(default_factory=list)
    dmarc: DmarcResult | None = None
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _signature_summary(headers) -> list[dict]:
    out = []
    for value in get_all(headers, "DKIM-Signature"):
        tags = parse_tags(value)
        out.append({k: tags.get(k, "") for k in ("d", "s", "a", "c", "h", "t", "x", "l")})
    return out


def analyze(raw: bytes, resolver: Resolver, *, client_ip: str | None = None,
            mail_from: str | None = None, helo: str | None = None,
            trusted_authserv: set[str] | None = None, now: float | None = None) -> AnalysisReport:
    """Parse a raw message (or just its headers) and verify it independently via DNS."""
    headers = unfolded_headers(raw)
    _, _, has_body = split_message(raw)
    report = AnalysisReport()
    add = lambda level, msg: report.findings.append(Finding(level, msg))   # noqa: E731

    # ---- identities
    froms = from_addresses(headers)
    if not froms:
        add("fail", "No usable From header: DMARC cannot be evaluated.")
    else:
        name, address = froms[0]
        report.from_address, report.from_domain = address, address_domain(address)
        if len(froms) > 1:
            add("fail", "Multiple From addresses: a classic trick to confuse authentication checks.")
        shown = re.search(r"[\w.+-]+@([\w.-]+\.\w+)", name or "")
        if shown and shown.group(1).lower() != report.from_domain:
            add("warn", f"Display name shows {shown.group(0)!r} but the real address is "
                        f"{address!r}: possible display-name spoofing.")
    return_path = get_all(headers, "Return-Path")
    if mail_from is None:                               # envelope sender, as recorded by the receiver
        mail_from = parseaddr(return_path[0])[1] if return_path else ""
    report.mail_from_domain = mail_from.rpartition("@")[2].lower() if mail_from else ""
    reply_to = get_all(headers, "Reply-To")
    if reply_to and report.from_domain:
        rt_domain = address_domain(reply_to[0])
        if rt_domain and organizational_domain(rt_domain) != organizational_domain(report.from_domain):
            add("warn", f"Reply-To domain ({rt_domain}) differs from the From domain: "
                        "replies would go somewhere else.")

    # ---- claims already present in the headers
    report.claims = parse_authentication_results(headers, trusted_authserv)
    report.received_spf = parse_received_spf(headers)
    report.hops = parse_received_chain(headers)
    report.dkim_signatures = _signature_summary(headers)
    if report.claims and not trusted_authserv:
        add("info", "Authentication-Results headers are claims written by whoever handled the message; "
                    "only the one added by your own receiving server (matching authserv-id) can be trusted.")
    elif trusted_authserv and report.claims and not any(c.trusted for c in report.claims):
        add("warn", "None of the Authentication-Results headers come from a trusted authserv-id: "
                    "they could have been injected by the sender.")

    # ---- independent verification
    if client_ip:
        report.client_ip, report.client_ip_source = client_ip, "provided"
    elif (inferred := infer_client_ip(report.hops)):
        report.client_ip, report.client_ip_source = inferred, "inferred from the topmost Received header"
        add("info", f"SPF was checked against {inferred}, inferred from the topmost Received header; "
                    "confirm it was added by your own mail server.")
    try:
        if report.client_ip and (report.mail_from_domain or helo):
            report.spf = check_spf(report.client_ip, mail_from or "", resolver, helo)
        else:
            add("warn", "SPF not re-checked: connecting IP or envelope sender unknown "
                        "(supply the IP, or paste the full header including Received lines).")
        report.dkim = verify_all(raw, resolver, now)
        if report.from_domain:
            report.dmarc = dmarc_mod.evaluate(report.from_domain, report.spf, report.dkim, resolver)
    except DnsTempError as exc:
        add("warn", f"DNS problem during verification: {exc}")

    _add_findings(report, add, has_body)
    return report


def _add_findings(report: AnalysisReport, add, has_body: bool) -> None:
    if not has_body and any(s["d"] for s in report.dkim_signatures):
        add("info", "Only headers were supplied: DKIM header signatures were verified but the "
                    "body hash could not be checked. Paste the full message for a complete result.")
    for r in report.dkim:
        if r.result in ("fail", "permerror"):
            add("fail", f"DKIM ({r.domain or '?'}): {r.reason}")
        elif r.result == "temperror":
            add("warn", f"DKIM ({r.domain}): {r.reason}")
        elif r.result == "pass" and report.from_domain and not is_aligned(r.domain, report.from_domain, "r"):
            add("info", f"DKIM passed for {r.domain}, which is not aligned with {report.from_domain}: "
                        "it does not count for DMARC.")
    if report.dkim and report.dkim[0].result == "none":
        add("warn", "Message carries no DKIM signature.")
    if report.spf and report.spf.result in ("fail", "softfail", "permerror", "temperror"):
        add("warn", f"SPF {report.spf.result} for {report.spf.domain}: {report.spf.reason}")
    if (report.spf and report.spf.result == "pass" and report.from_domain
            and not is_aligned(report.spf.domain, report.from_domain, "r")):
        add("info", f"SPF passed for {report.spf.domain}, which is not aligned with "
                    f"{report.from_domain}: it does not count for DMARC.")

    # Do the headers' claims agree with what we computed ourselves?
    computed = {"spf": report.spf.result if report.spf else None,
                "dmarc": report.dmarc.result if report.dmarc else None,
                "dkim": "pass" if any(r.result == "pass" for r in report.dkim) else
                        (report.dkim[0].result if report.dkim else None)}
    for claim in report.claims:
        mine = computed.get(claim.method)
        if mine and claim.result == "pass" and mine not in ("pass",) and claim.trusted is not False:
            add("warn", f"Header claims {claim.method}=pass (by {claim.authserv_id}) but our own check "
                        f"says {mine}: forged header, or DNS changed since delivery.")

    d = report.dmarc
    if d is None:
        report.verdict = "UNKNOWN: could not evaluate DMARC (no From domain)."
    elif d.result == "pass":
        how = " and ".join(x for x, ok in (("SPF", d.spf_aligned), ("DKIM", d.dkim_aligned)) if ok)
        report.verdict = f"PASS: authenticated and aligned with {d.from_domain} via {how}."
    elif d.result == "fail":
        report.verdict = (f"FAIL: DMARC fails for {d.from_domain}. Published policy p={d.policy}, "
                          f"so a receiver should apply: {d.disposition}.")
    elif d.result == "none":
        report.verdict = (f"NO POLICY: {d.from_domain} publishes no DMARC record, so spoofing of this "
                          "domain cannot be rejected by receivers.")
    else:
        report.verdict = "TEMPERROR: DNS failure while looking up the DMARC policy."
