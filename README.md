# Secure Email Authentication Gateway (SPF + DKIM + DMARC)

A learning-grade but complete toolkit: **generate and publish** the DNS records, **sign** outgoing mail,
**verify** incoming mail, and **analyze raw headers** in a CLI or web tool. SPF, DKIM and DMARC are
implemented from the RFCs on top of a pluggable DNS resolver, so everything can be tested offline.

## Quick start
```bash
pip install -r requirements.txt
python scripts/demo.py                  # 6 delivery scenarios against a fake DNS zone (no domain needed)
pytest -q                               # 68 tests
flask --app emailauth.web run           # web analyzer on http://127.0.0.1:5000
```

## Commands
```bash
python -m emailauth genkey  --domain example.com --selector s2026          # RSA-2048 key + DNS TXT record
python -m emailauth records --domain example.com --selector s2026 \
        --key keys/s2026.example.com.private.pem --ip4 203.0.113.10 --rua mailto:dmarc@example.com
python -m emailauth sign    message.eml --domain example.com --selector s2026 \
        --key keys/s2026.example.com.private.pem --out signed.eml
python -m emailauth check   signed.eml [--ip 203.0.113.10] [--json]        # exit 0 only if DMARC passes
python -m emailauth audit   example.com --selector s2026                   # lint what is published in DNS
# offline lab: add  --zone examples/zone.json  to check/audit to use the fake zone instead of live DNS
python -m emailauth check examples/scenario2.eml --zone examples/zone.json --ip 203.0.113.66
```

## Layout
| File | Role |
|---|---|
| `emailauth/dkim.py` | key generation, `sign()`, `verify_all()` (rsa-sha256, simple/relaxed, From oversigning) |
| `emailauth/spf.py` | RFC 7208 evaluator: ip4/ip6/a/mx/include/exists/redirect, 10-lookup + void-lookup limits |
| `emailauth/dmarc.py` | policy discovery (+ org-domain fallback), relaxed/strict alignment, `p`/`sp`/`pct` |
| `emailauth/headers.py` | parses Authentication-Results, Received-SPF, Received chain, From/Reply-To |
| `emailauth/analyzer.py` | independent re-verification + findings (display-name spoofing, forged results...) |
| `emailauth/gateway.py` | inbound decision (accept/quarantine/reject), stamps Authentication-Results |
| `emailauth/records.py` | SPF/DMARC builders, DMARC rollout plan, DNS audit |
| `emailauth/cli.py`, `web.py` | command line and Flask web tool |
| `docs/DEPLOYMENT.md` | step-by-step guide for a real domain, incl. SPF/DKIM/DMARC rollout |

## How the three protocols fit together (what the demo shows)
| Scenario | SPF | DKIM | DMARC | Lesson |
|---|---|---|---|---|
| Legitimate mail | pass | pass | pass | both aligned |
| Spoofed From, attacker's own SPF | pass (evil.test) | none | **fail -> reject** | SPF alone is not enough: it authenticates the *envelope* domain, not the From the user sees; DMARC adds **alignment** |
| Same, DMARC `p=none` | pass | none | fail -> accept | monitoring mode logs but never blocks |
| Body altered in transit | pass | **fail** | pass | DKIM detects tampering; DMARC passes through aligned SPF |
| Forwarded message | **fail** | pass | pass | forwarding breaks SPF; DKIM survives |
| Third-party sender signing as esp.test | pass | pass | **fail** | authenticated is not the same as *aligned* |

## Security choices
- Authentication-Results headers in a message are only *claims*; the analyzer labels them untrusted unless
  they carry your own `authserv-id`, and the gateway strips any pre-stamped header carrying your id.
- Header values written by the gateway are sanitised (no header injection); the web tool escapes all output,
  sends a strict CSP, and limits input to 1 MB; the private key file is created with mode 600 and never overwritten.
- DKIM policy: SHA-1/Ed25519 reported unsupported, keys under 1024 bits rejected, `l=` rejected,
  `From` must be signed (and is oversigned when signing).

## Known limitations (be upfront about these in your write-up)
- Implemented from the RFCs and tested here against itself and a fake DNS; **it has not been run against the
  live internet or the reference `dkimpy` library**. `tests/test_interop_dkimpy.py` cross-checks both ways -
  run it (`pip install dkimpy`) before relying on interoperability.
- `DnsPythonResolver` (live DNS) is the only module not exercised by the automated tests.
- SPF macros (`%{i}` etc.) and `ptr` are not supported (reported as `permerror`); no ARC, no BIMI, no DMARC report parsing.
- Organizational domain uses a small built-in suffix list; use the Public Suffix List (`tldextract`) in production.
- For production, prefer battle-tested components (Postfix + OpenDKIM/Rspamd, or a hosted provider) and use this
  toolkit for learning, auditing and header forensics.
