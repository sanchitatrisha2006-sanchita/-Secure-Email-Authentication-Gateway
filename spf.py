"""SPF evaluation (RFC 7208).

Supported: all, ip4, ip6, a, mx, include, exists, redirect (qualifiers + - ~ ?),
the 10-lookup and 2-void-lookup limits, and 10 MX names per mx mechanism.
Not supported (reported as permerror): macros (%{...}) and the deprecated ptr mechanism.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from emailauth.dns_resolver import DnsTempError, Resolver, normalize

MAX_DNS_LOOKUPS = 10
MAX_VOID_LOOKUPS = 2
MAX_MX_NAMES = 10
QUALIFIER_RESULT = {"": "pass", "+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}


@dataclass
class SpfResult:
    result: str            # pass | fail | softfail | neutral | none | temperror | permerror
    domain: str = ""       # the domain whose policy was evaluated (aligned against From for DMARC)
    reason: str = ""
    mechanism: str | None = None
    lookups: int = 0


class _SpfError(Exception):
    def __init__(self, result: str, reason: str):
        super().__init__(reason)
        self.result, self.reason = result, reason


class _Context:
    def __init__(self, ip, resolver: Resolver):
        self.ip, self.resolver = ip, resolver
        self.lookups = 0
        self.voids = 0

    def count_lookup(self) -> None:
        self.lookups += 1
        if self.lookups > MAX_DNS_LOOKUPS:
            raise _SpfError("permerror", f"more than {MAX_DNS_LOOKUPS} DNS-querying mechanisms")

    def note_void(self, answers: list) -> list:
        if not answers:
            self.voids += 1
            if self.voids > MAX_VOID_LOOKUPS:
                raise _SpfError("permerror", f"more than {MAX_VOID_LOOKUPS} void DNS lookups")
        return answers

    def addresses(self, name: str) -> list[str]:
        return self.note_void(self.resolver.addresses(name, ipv6=self.ip.version == 6))


def _parse_ip(value: str):
    ip = ipaddress.ip_address(value.strip())
    if ip.version == 6 and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def _in_network(ip, address: str, v4_len: int, v6_len: int) -> bool:
    try:
        net = ipaddress.ip_network(f"{address}/{v4_len if ip.version == 4 else v6_len}", strict=False)
    except ValueError:
        return False
    return ip.version == net.version and ip in net


def _parse_cidr(text: str) -> tuple[int, int]:
    m = re.fullmatch(r"(?:/(\d+))?(?://(\d+))?", text)
    if not m:
        raise _SpfError("permerror", f"bad CIDR length {text!r}")
    v4, v6 = int(m.group(1) or 32), int(m.group(2) or 128)
    if v4 > 32 or v6 > 128:
        raise _SpfError("permerror", f"CIDR length out of range {text!r}")
    return v4, v6


def _domain_spec(spec: str | None, default: str) -> str:
    if spec is None:
        return default
    if "%" in spec:
        raise _SpfError("permerror", "SPF macros are not supported by this implementation")
    return normalize(spec)


def _matches(name: str, rest: str, domain: str, ctx: _Context) -> bool:
    """Does the mechanism match the client IP? May raise _SpfError."""
    if name == "all":
        return True
    if name in ("ip4", "ip6"):
        if not rest.startswith(":"):
            raise _SpfError("permerror", f"{name} requires an address")
        try:
            net = ipaddress.ip_network(rest[1:], strict=False)
        except ValueError as exc:
            raise _SpfError("permerror", f"invalid {name} network {rest[1:]!r}") from exc
        if (name == "ip4") != (net.version == 4):
            raise _SpfError("permerror", f"{name} given a v{net.version} address")
        return ctx.ip.version == net.version and ctx.ip in net
    if name == "ptr":
        raise _SpfError("permerror", "the deprecated ptr mechanism is not supported")
    if name in ("include", "exists"):
        if not rest.startswith(":"):
            raise _SpfError("permerror", f"{name} requires a domain")
        target = _domain_spec(rest[1:], domain)
        ctx.count_lookup()
        if name == "exists":
            return bool(ctx.note_void(ctx.resolver.addresses(target)))
        sub = _evaluate(target, ctx)
        if sub.result == "pass":
            return True
        if sub.result in ("fail", "softfail", "neutral"):
            return False
        if sub.result == "temperror":
            raise _SpfError("temperror", f"include:{target} -> {sub.reason}")
        raise _SpfError("permerror", f"include:{target} -> {sub.result} ({sub.reason})")
    if name in ("a", "mx"):
        target, cidr = domain, rest
        if rest.startswith(":"):
            body = rest[1:]
            cut = body.find("/")
            target = _domain_spec(body[:cut] if cut >= 0 else body, domain)
            cidr = body[cut:] if cut >= 0 else ""
        v4_len, v6_len = _parse_cidr(cidr)
        ctx.count_lookup()
        if name == "a":
            return any(_in_network(ctx.ip, a, v4_len, v6_len) for a in ctx.addresses(target))
        hosts = ctx.note_void(ctx.resolver.mx(target))
        if len(hosts) > MAX_MX_NAMES:
            raise _SpfError("permerror", f"mx lists more than {MAX_MX_NAMES} hosts")
        return any(_in_network(ctx.ip, a, v4_len, v6_len)
                   for host in hosts for a in ctx.addresses(host))
    raise _SpfError("permerror", f"unknown mechanism {name!r}")


def _evaluate(domain: str, ctx: _Context) -> SpfResult:
    records = [t for t in ctx.resolver.txt(domain) if re.match(r"(?i)v=spf1(\s|$)", t)]
    if not records:
        return SpfResult("none", domain, "no SPF record published")
    if len(records) > 1:
        return SpfResult("permerror", domain, "multiple SPF records published")

    redirect = None
    try:
        for term in records[0].split()[1:]:
            modifier = re.fullmatch(r"([A-Za-z][\w.-]*)=(.*)", term)
            if modifier:
                if modifier.group(1).lower() == "redirect":
                    redirect = _domain_spec(modifier.group(2), domain)
                continue                                      # exp= and unknown modifiers ignored
            m = re.fullmatch(r"([+\-~?]?)([A-Za-z0-9]+)(.*)", term)
            if not m:
                raise _SpfError("permerror", f"cannot parse term {term!r}")
            qualifier, name, rest = m.group(1), m.group(2).lower(), m.group(3)
            if _matches(name, rest, domain, ctx):
                return SpfResult(QUALIFIER_RESULT[qualifier], domain,
                                 f"matched {term!r}", term, ctx.lookups)
        if redirect:
            ctx.count_lookup()
            sub = _evaluate(redirect, ctx)
            if sub.result == "none":
                raise _SpfError("permerror", f"redirect target {redirect} has no SPF record")
            return sub
    except _SpfError as err:
        return SpfResult(err.result, domain, err.reason, None, ctx.lookups)
    return SpfResult("neutral", domain, "no mechanism matched", None, ctx.lookups)


def check_spf(client_ip: str, sender: str, resolver: Resolver, helo: str | None = None) -> SpfResult:
    """Evaluate SPF for `client_ip` sending as `sender` (the MAIL FROM address).

    An empty sender (bounce) falls back to postmaster@<helo>, as the RFC requires.
    """
    try:
        ip = _parse_ip(client_ip)
    except ValueError:
        return SpfResult("permerror", "", f"invalid client IP {client_ip!r}")
    domain = sender.rpartition("@")[2] if sender else (helo or "")
    domain = normalize(domain)
    if not re.fullmatch(r"[a-z0-9]([a-z0-9._-]*[a-z0-9])?\.[a-z0-9-]{2,}", domain):
        return SpfResult("none", domain, "no valid domain to check")
    ctx = _Context(ip, resolver)
    try:
        result = _evaluate(domain, ctx)
    except DnsTempError as exc:
        return SpfResult("temperror", domain, str(exc), None, ctx.lookups)
    except _SpfError as err:
        return SpfResult(err.result, domain, err.reason, None, ctx.lookups)
    result.domain = domain          # DMARC aligns against the original domain, not an include target
    result.lookups = ctx.lookups
    return result
