"""DKIM (RFC 6376): key generation, signing (rsa-sha256) and verification.

Canonicalisation supported: simple and relaxed, for headers and body.
Policy choices: SHA-1 and Ed25519 signatures are reported as unsupported, keys under
1024 bits fail, and signatures using the body-length tag l= are rejected.
"""
from __future__ import annotations

import base64
import hashlib
import re
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from emailauth.dns_resolver import DnsTempError, Resolver

DEFAULT_SIGNED_HEADERS = ["from", "to", "cc", "subject", "date", "message-id", "reply-to",
                          "mime-version", "content-type", "content-transfer-encoding",
                          "in-reply-to", "references"]
# Listed one extra time so an attacker cannot append a second From/To/Subject/Date after signing
OVERSIGNED_HEADERS = {"from", "to", "subject", "date"}
MIN_KEY_BITS = 1024

Header = tuple[str, bytes]          # (name, raw "Name: value" incl. folding, no trailing CRLF)


# --------------------------------------------------------------------------- keys
def generate_keypair(bits: int = 2048) -> tuple[bytes, str]:
    """Return (private key PEM, base64 public key as published in the DNS p= tag)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    private_pem = key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
    public_der = key.public_key().public_bytes(serialization.Encoding.DER,
                                               serialization.PublicFormat.SubjectPublicKeyInfo)
    return private_pem, base64.b64encode(public_der).decode()


def dkim_txt_record(public_b64: str) -> str:
    return f"v=DKIM1; k=rsa; p={public_b64}"


# ------------------------------------------------------------------ message parsing
def split_message(raw: bytes) -> tuple[list[Header], bytes, bool]:
    """Split into (headers, body, has_body). Line endings are normalised to CRLF.

    A whitespace-only body counts as "no body supplied": people pasting only headers
    usually leave a trailing blank line, and we must not then check an empty body hash.
    """
    data = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n").replace(b"\n", b"\r\n")
    head, sep, body = data.partition(b"\r\n\r\n")
    headers: list[Header] = []
    for line in head.split(b"\r\n"):
        if line[:1] in (b" ", b"\t") and headers:
            name, raw_line = headers[-1]
            headers[-1] = (name, raw_line + b"\r\n" + line)        # folded continuation
        elif b":" in line:
            headers.append((line.split(b":", 1)[0].decode("ascii", "replace").strip(), line))
    return headers, body, bool(sep) and bool(body.strip())


# ---------------------------------------------------------------- canonicalisation
def canonicalize_body(body: bytes, mode: str) -> bytes:
    lines = body.split(b"\r\n")
    if mode == "relaxed":
        lines = [re.sub(rb"[ \t]+", b" ", line).rstrip(b" ") for line in lines]
    while lines and lines[-1] == b"":
        lines.pop()
    if not lines:
        return b"" if mode == "relaxed" else b"\r\n"
    return b"\r\n".join(lines) + b"\r\n"


def canonicalize_header(name: str, raw: bytes, mode: str) -> bytes:
    if mode == "simple":
        return raw
    value = raw.split(b":", 1)[1]
    value = re.sub(rb"\r\n(?=[ \t])", b"", value)          # unfold
    value = re.sub(rb"[ \t]+", b" ", value).strip(b" ")
    return name.strip().lower().encode() + b":" + value


def select_headers(headers: list[Header], names: list[str]) -> list[Header]:
    """RFC 6376 5.4.2: each name in h= consumes the last not-yet-used instance (bottom-up)."""
    used: dict[str, int] = {}
    selected: list[Header] = []
    for name in names:
        lname = name.strip().lower()
        candidates = [h for h in headers if h[0].lower() == lname]
        index = used.get(lname, 0)
        used[lname] = index + 1
        if index < len(candidates):
            selected.append(candidates[-1 - index])
    return selected


def parse_tags(value: str) -> dict[str, str]:
    """Parse 'tag=value; tag=value' (first occurrence of a tag wins)."""
    tags: dict[str, str] = {}
    for part in value.split(";"):
        key, eq, val = part.partition("=")
        if eq and key.strip().lower() not in tags:
            tags[key.strip().lower()] = val.strip()
    return tags


def _b64_clean(value: str) -> bytes:
    return base64.b64decode(re.sub(r"\s+", "", value), validate=True)


# ------------------------------------------------------------------------ signing
def _load_private_key(pem: bytes) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("only RSA keys are supported")
    return key


def sign(raw: bytes, domain: str, selector: str, private_key_pem: bytes, *,
         canonicalization: str = "relaxed/relaxed", now: int | None = None,
         expire_seconds: int | None = None) -> bytes:
    """Return the message with a DKIM-Signature header prepended (CRLF line endings)."""
    header_mode, body_mode = canonicalization.split("/")
    headers, body, _ = split_message(raw)
    if not any(h[0].lower() == "from" for h in headers):
        raise ValueError("message has no From header; DKIM requires it to be signed")

    names: list[str] = []
    for name in DEFAULT_SIGNED_HEADERS:
        count = sum(h[0].lower() == name for h in headers)
        if count:
            names += [name] * (count + (name in OVERSIGNED_HEADERS))
    body_hash = base64.b64encode(
        hashlib.sha256(canonicalize_body(body, body_mode)).digest()).decode()

    timestamp = int(now if now is not None else time.time())
    template = (f"v=1; a=rsa-sha256; c={canonicalization}; d={domain}; s={selector}; "
                f"t={timestamp}; ")
    if expire_seconds:
        template += f"x={timestamp + expire_seconds}; "
    template += f"h={':'.join(names)}; bh={body_hash}; b="
    sig_header = b"DKIM-Signature: " + template.encode()

    signed_data = b"".join(canonicalize_header(n, r, header_mode) + b"\r\n"
                           for n, r in select_headers(headers, names))
    signed_data += canonicalize_header("DKIM-Signature", sig_header, header_mode)
    signature = base64.b64encode(
        _load_private_key(private_key_pem).sign(signed_data, padding.PKCS1v15(), hashes.SHA256())
    ).decode()
    folded = "\r\n\t".join(signature[i:i + 72] for i in range(0, len(signature), 72))

    original = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n").replace(b"\n", b"\r\n")
    return sig_header + folded.encode() + b"\r\n" + original


# ---------------------------------------------------------------------- verifying
@dataclass
class DkimResult:
    result: str                 # pass | fail | permerror | temperror | none
    domain: str = ""
    selector: str = ""
    reason: str = ""
    body_checked: bool = True


def _verify_one(headers: list[Header], body: bytes, has_body: bool, sig_raw: bytes,
                resolver: Resolver, now: float) -> DkimResult:
    value = sig_raw.split(b":", 1)[1].decode("ascii", "replace")
    tags = parse_tags(re.sub(r"\r\n(?=[ \t])", "", value))
    domain, selector = tags.get("d", "").lower(), tags.get("s", "")

    def res(result: str, reason: str) -> DkimResult:
        return DkimResult(result, domain, selector, reason, has_body)

    missing = [t for t in ("v", "a", "b", "bh", "d", "h", "s") if t not in tags]
    if missing:
        return res("permerror", f"signature missing required tag(s): {', '.join(missing)}")
    if tags["v"] != "1":
        return res("permerror", f"unsupported DKIM version {tags['v']!r}")
    if tags["a"].lower() != "rsa-sha256":
        return res("permerror", f"unsupported or deprecated algorithm {tags['a']!r}")
    if "l" in tags:
        return res("fail", "body length limit (l=) is not accepted: it allows content to be appended")
    if "from" not in [h.strip().lower() for h in tags["h"].split(":")]:
        return res("fail", "From header is not covered by the signature (h=)")
    if "i" in tags and not tags["i"].lower().rpartition("@")[2].endswith(domain):
        return res("permerror", "i= identity is not within the d= domain")
    if "x" in tags and tags["x"].isdigit() and int(tags["x"]) < now:
        return res("fail", "signature has expired (x=)")

    canon = tags.get("c", "simple/simple").lower()
    header_mode, _, body_mode = canon.partition("/")
    body_mode = body_mode or "simple"
    if header_mode not in ("simple", "relaxed") or body_mode not in ("simple", "relaxed"):
        return res("permerror", f"unknown canonicalization {canon!r}")

    # --- public key from DNS
    try:
        records = resolver.txt(f"{selector}._domainkey.{domain}")
    except DnsTempError as exc:
        return res("temperror", str(exc))
    key_tags = next((t for t in map(parse_tags, records) if "p" in t), None)
    if key_tags is None:
        return res("permerror", f"no DKIM key published at {selector}._domainkey.{domain}")
    if not key_tags["p"]:
        return res("fail", "key has been revoked (empty p=)")
    if key_tags.get("k", "rsa").lower() != "rsa":
        return res("permerror", "unsupported key type")
    try:
        public_key = serialization.load_der_public_key(_b64_clean(key_tags["p"]))
        assert isinstance(public_key, rsa.RSAPublicKey)
    except Exception:
        return res("permerror", "published key is not a valid RSA public key")
    if public_key.key_size < MIN_KEY_BITS:
        return res("fail", f"{public_key.key_size}-bit key is too weak (minimum {MIN_KEY_BITS})")

    # --- body hash
    if has_body:
        computed = hashlib.sha256(canonicalize_body(body, body_mode)).digest()
        try:
            if computed != _b64_clean(tags["bh"]):
                return res("fail", "body hash did not verify (body modified after signing)")
        except ValueError:
            return res("permerror", "bh= is not valid base64")

    # --- header signature (b= value is blanked, per RFC 6376 3.7)
    blanked = re.sub(rb"((?:^|;)\s*b\s*=)[^;]*", rb"\1", sig_raw.split(b":", 1)[1])
    sig_canon = canonicalize_header("DKIM-Signature", b"DKIM-Signature:" + blanked, header_mode)
    names = tags["h"].split(":")
    data = b"".join(canonicalize_header(n, r, header_mode) + b"\r\n"
                    for n, r in select_headers(headers, names)) + sig_canon
    try:
        public_key.verify(_b64_clean(tags["b"]), data, padding.PKCS1v15(), hashes.SHA256())
    except (InvalidSignature, ValueError):
        return res("fail", "signature did not verify (headers modified or wrong key)")
    note = "" if has_body else "headers only: body hash not checked"
    return res("pass", note or "signature verified")


def verify_all(raw: bytes, resolver: Resolver, now: float | None = None) -> list[DkimResult]:
    """Verify every DKIM-Signature header. Returns [DkimResult('none')] if there are none."""
    headers, body, has_body = split_message(raw)
    signatures = [r for n, r in headers if n.lower() == "dkim-signature"]
    if not signatures:
        return [DkimResult("none", reason="no DKIM-Signature header")]
    now = time.time() if now is None else now
    return [_verify_one(headers, body, has_body, sig, resolver, now) for sig in signatures]
