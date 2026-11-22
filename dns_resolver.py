"""DNS access behind a small interface so every protocol module can be tested offline."""
from __future__ import annotations

import json
from typing import Protocol


class DnsTempError(Exception):
    """Timeout / SERVFAIL: the answer is unknown (maps to SPF/DKIM/DMARC 'temperror')."""


def normalize(name: str) -> str:
    return name.strip().rstrip(".").lower()


class Resolver(Protocol):
    def txt(self, name: str) -> list[str]: ...
    def addresses(self, name: str, ipv6: bool = False) -> list[str]: ...
    def mx(self, name: str) -> list[str]: ...


class FakeResolver:
    """In-memory zone for tests and offline labs.

    zone = {"example.com": {"TXT": ["v=spf1 -all"], "A": ["192.0.2.1"], "MX": ["mail.example.com"]}}
    Names listed in `broken` raise DnsTempError, like a SERVFAIL.
    """

    def __init__(self, zone: dict[str, dict[str, list[str]]] | None = None,
                 broken: set[str] | None = None):
        self.zone = {normalize(k): v for k, v in (zone or {}).items()}
        self.broken = {normalize(b) for b in (broken or set())}
        self.queries: list[tuple[str, str]] = []

    @classmethod
    def from_json(cls, path: str) -> "FakeResolver":
        with open(path, encoding="utf-8") as fh:
            return cls(json.load(fh))

    def _get(self, name: str, rtype: str) -> list[str]:
        name = normalize(name)
        self.queries.append((name, rtype))
        if name in self.broken:
            raise DnsTempError(f"simulated SERVFAIL for {name}")
        return list(self.zone.get(name, {}).get(rtype, []))

    def txt(self, name):
        return self._get(name, "TXT")

    def addresses(self, name, ipv6=False):
        return self._get(name, "AAAA" if ipv6 else "A")

    def mx(self, name):
        return self._get(name, "MX")


class DnsPythonResolver:
    """Live DNS via dnspython (imported lazily so the rest works without it)."""

    def __init__(self, timeout: float = 3.0):
        import dns.exception
        import dns.resolver
        self._dns = dns
        self._resolver = dns.resolver.Resolver()
        self._resolver.lifetime = timeout

    def _query(self, name: str, rtype: str):
        dns = self._dns
        try:
            return list(self._resolver.resolve(normalize(name), rtype))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
            raise DnsTempError(f"{rtype} lookup for {name} failed: {exc.__class__.__name__}") from exc
        except dns.name.LabelTooLong as exc:     # malformed names from untrusted input
            raise DnsTempError(f"invalid DNS name {name!r}") from exc

    def txt(self, name):
        return [b"".join(r.strings).decode("utf-8", "replace") for r in self._query(name, "TXT")]

    def addresses(self, name, ipv6=False):
        return [r.address for r in self._query(name, "AAAA" if ipv6 else "A")]

    def mx(self, name):
        records = sorted(self._query(name, "MX"), key=lambda r: r.preference)
        return [str(r.exchange).rstrip(".") for r in records]
