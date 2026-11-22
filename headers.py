"""Parsing of the authentication-related parts of a raw email (RFC 5322 / RFC 8601)."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from email.utils import getaddresses, parseaddr

from emailauth.dkim import split_message


@dataclass
class AuthClaim:
    """One method result from an Authentication-Results header, e.g. spf=pass smtp.mailfrom=x."""
    authserv_id: str
    method: str
    result: str
    properties: dict[str, str] = field(default_factory=dict)
    trusted: bool | None = None          # None = no trusted authserv-id configured


@dataclass
class Hop:
    from_host: str
    by_host: str
    ips: list[str]
    raw: str


def unfolded_headers(raw: bytes) -> list[tuple[str, str]]:
    """(name, value) pairs in message order, unfolded and decoded for display."""
    headers, _, _ = split_message(raw)
    out = []
    for name, line in headers:
        value = line.split(b":", 1)[1].decode("utf-8", "replace")
        out.append((name, re.sub(r"\r\n(?=[ \t])", "", value).strip()))
    return out


def get_all(headers: list[tuple[str, str]], name: str) -> list[str]:
    return [v for n, v in headers if n.lower() == name.lower()]


def _strip_comments(text: str) -> str:
    """Remove RFC 5322 (nested) parenthesised comments."""
    previous = None
    while previous != text:
        previous, text = text, re.sub(r"\([^()]*\)", " ", text)
    return text


def parse_authentication_results(headers: list[tuple[str, str]],
                                 trusted_authserv: set[str] | None = None) -> list[AuthClaim]:
    """Parse every Authentication-Results header into per-method claims.

    These are *claims made by whoever wrote the header*. A sender can forge them, so only
    headers carrying the authserv-id of your own receiving server deserve trust.
    """
    claims: list[AuthClaim] = []
    for value in get_all(headers, "Authentication-Results"):
        parts = [p.strip() for p in _strip_comments(value).split(";") if p.strip()]
        if not parts:
            continue
        authserv = parts[0].split()[0].lower()
        trusted = None if not trusted_authserv else authserv in trusted_authserv
        for part in parts[1:]:
            m = re.match(r"([A-Za-z0-9_-]+)\s*=\s*([A-Za-z0-9_-]+)(.*)", part)
            if not m:
                continue
            props = {k.lower(): v.strip('"') for k, v in
                     re.findall(r'([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\s*=\s*("[^"]*"|\S+)', m.group(3))}
            claims.append(AuthClaim(authserv, m.group(1).lower(), m.group(2).lower(), props, trusted))
    return claims


def parse_received_spf(headers: list[tuple[str, str]]) -> dict[str, str] | None:
    values = get_all(headers, "Received-SPF")
    if not values:
        return None
    first = _strip_comments(values[0])
    info = {"result": first.split()[0].lower() if first.split() else ""}
    for key, val in re.findall(r'([A-Za-z-]+)\s*=\s*("[^"]*"|[^;\s]+)', first):
        info[key.lower()] = val.strip('"')
    return info


_IPV4 = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])")
_IPV6 = re.compile(r"(?:IPv6:)?((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})")


def parse_received_chain(headers: list[tuple[str, str]]) -> list[Hop]:
    """Received headers, topmost (most recent hop, added by the final receiver) first."""
    hops = []
    for value in get_all(headers, "Received"):
        ips = []
        for candidate in _IPV4.findall(value) + _IPV6.findall(value):
            try:
                ips.append(str(ipaddress.ip_address(candidate)))
            except ValueError:
                continue
        frm = re.search(r"\bfrom\s+(\S+)", value, re.I)
        by = re.search(r"\bby\s+(\S+)", value, re.I)
        hops.append(Hop(frm.group(1) if frm else "", by.group(1) if by else "", ips, value))
    return hops


def infer_client_ip(hops: list[Hop]) -> str | None:
    """First usable IP in the topmost Received header = the host that connected to the receiver.

    Loopback and link-local addresses are skipped (private ranges are kept so labs work).
    Only trustworthy when that header was added by *your* mail server; older hops can be forged.
    """
    if not hops:
        return None
    for ip in hops[0].ips:
        addr = ipaddress.ip_address(ip)
        if not (addr.is_loopback or addr.is_link_local or addr.is_unspecified):
            return ip
    return None


def address_domain(value: str) -> str:
    addr = parseaddr(value)[1]
    return addr.rpartition("@")[2].lower().strip(">") if "@" in addr else ""


def from_addresses(headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """All (display name, address) pairs across From headers."""
    return [(n, a) for n, a in getaddresses(get_all(headers, "From")) if a]
