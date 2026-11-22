"""Inbound gateway logic: authenticate a message and decide what to do with it."""
from __future__ import annotations

import re
from dataclasses import dataclass

from emailauth.analyzer import AnalysisReport, analyze
from emailauth.dkim import split_message
from emailauth.dns_resolver import Resolver


@dataclass
class GatewayDecision:
    action: str                 # accept | quarantine | reject
    auth_results: str           # the Authentication-Results header we added
    message: bytes              # message with that header prepended (CRLF line endings)
    report: AnalysisReport


def _token(value: str) -> str:
    """Strip anything that could break out of a header value (header injection)."""
    return re.sub(r"[^A-Za-z0-9._@-]", "", value or "")


def build_authentication_results(authserv_id: str, report: AnalysisReport) -> str:
    parts = [_token(authserv_id)]
    if report.spf:
        parts.append(f"spf={report.spf.result} smtp.mailfrom={_token(report.mail_from_domain) or 'none'}")
    for r in report.dkim:
        extra = f" header.d={_token(r.domain)} header.s={_token(r.selector)}" if r.domain else ""
        parts.append(f"dkim={r.result}{extra}")
    if report.dmarc:
        d = report.dmarc
        policy = f" (p={d.policy} dis={d.disposition})" if d.policy else ""
        parts.append(f"dmarc={d.result}{policy} header.from={_token(d.from_domain)}")
    return "Authentication-Results: " + "; ".join(parts)


def authenticate_inbound(raw: bytes, client_ip: str, mail_from: str, resolver: Resolver, *,
                         helo: str | None = None, authserv_id: str = "mx.localhost",
                         enforce: bool = True) -> GatewayDecision:
    """Verify SPF/DKIM/DMARC for an incoming message.

    * Any pre-existing Authentication-Results header claiming *our* authserv-id is removed
      first, so a sender cannot pre-stamp their own 'pass'.
    * With enforce=False (DMARC monitoring mode) the action is always 'accept'; the
      would-be disposition is still visible in the header and report.
    """
    headers, _, _ = split_message(raw)
    own = authserv_id.lower()
    cleaned = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n").replace(b"\n", b"\r\n")
    for name, line in headers:
        if name.lower() == "authentication-results" and \
                line.split(b":", 1)[1].decode("utf-8", "replace").strip().lower().startswith(own):
            cleaned = cleaned.replace(line + b"\r\n", b"", 1)

    report = analyze(cleaned, resolver, client_ip=client_ip, mail_from=mail_from, helo=helo,
                     trusted_authserv={own})
    header = build_authentication_results(authserv_id, report)
    action = "accept"
    if enforce and report.dmarc and report.dmarc.result == "fail" \
            and report.dmarc.disposition in ("quarantine", "reject"):
        action = report.dmarc.disposition
    return GatewayDecision(action, header, header.encode() + b"\r\n" + cleaned, report)
