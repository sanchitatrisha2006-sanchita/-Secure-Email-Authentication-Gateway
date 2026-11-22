# Deploying SPF, DKIM and DMARC for a real domain

Replace `example.com`, IPs and addresses with your own. Do the steps **in this order**; wait for DNS TTLs
(use 300 s while testing) and check each step before the next.

## 0. Inventory every system that sends mail as your domain
Office 365 / Google Workspace, your own server, newsletter tool, CRM, ticketing, invoicing app...
Anything missed here will fail DMARC later. Ask each vendor for its SPF `include:` and its DKIM setup.

## 1. SPF - who may send
```bash
python -m emailauth records --domain example.com --ip4 203.0.113.10 --include _spf.google.com --spf-all '~all'
```
Publish as ONE TXT record at the domain root, e.g. `v=spf1 ip4:203.0.113.10 include:_spf.google.com ~all`.
- Start with `~all` (softfail); move to `-all` once DMARC reports show no legitimate source failing.
- Stay under 10 DNS lookups (each `include`, `a`, `mx` counts); never publish two SPF records.

## 2. DKIM - sign outgoing mail
```bash
python -m emailauth genkey --domain example.com --selector s2026
```
1. Publish the printed TXT record at `s2026._domainkey.example.com`. The private key stays on the signing host.
2. Sign a test mail: `python -m emailauth sign test.eml --domain example.com --selector s2026 --key keys/s2026.example.com.private.pem`.
   For a real mail server use OpenDKIM/Rspamd with the same key; for SaaS senders use the CNAME/TXT they give you.
3. Rotate keys every 6-12 months: publish a new selector, switch signing, remove the old selector after ~7 days.

## 3. Verify the DNS before sending anything
```bash
python -m emailauth audit example.com --selector s2026
dig +short TXT example.com
dig +short TXT s2026._domainkey.example.com
dig +short TXT _dmarc.example.com
```

## 4. DMARC - monitor first, then enforce
Stage 1 (weeks 0-4), **monitoring only**: `_dmarc.example.com TXT "v=DMARC1; p=none; rua=mailto:dmarc@example.com; adkim=r; aspf=r"`
Read the aggregate (rua) reports; every legitimate source must show SPF **or** DKIM *aligned* pass.
Fix senders that fail (custom DKIM domain, custom return-path domain at the vendor).

Then tighten gradually (`python -m emailauth records ... --dmarc-policy quarantine --pct 10` prints each record):

| Stage | Record | Move on when |
|---|---|---|
| 1 | `p=none` | 100% of legitimate mail aligned |
| 2 | `p=quarantine; pct=10` -> `50` -> `100` | no legitimate mail in spam folders |
| 3 | `p=reject; pct=25` -> `100` | stable for a few weeks |

Add `sp=reject` once you are sure no subdomain sends unauthenticated mail, and `p=reject` on domains that never send mail
(together with `v=spf1 -all`).

## 5. End-to-end test with real mailboxes
Send a signed message from your server to a Gmail/Outlook address, open "Show original" (Gmail) and paste the **whole**
message into the web tool (`flask --app emailauth.web run`) or save it and run `python -m emailauth check original.eml`.
You want `spf=pass`, `dkim=pass`, `dmarc=pass` and aligned domains. Then send from a forged `From:` to confirm it fails.

## 6. Reading results - common failure causes
| Symptom | Likely cause |
|---|---|
| `spf=pass` but `dmarc=fail` | SPF passed for the vendor's bounce domain, not yours (not aligned): set a custom return-path |
| `dkim=fail: body hash did not verify` | a gateway/footer/list modified the body after signing |
| `dkim=permerror: no key` | selector or DNS record name wrong, or DNS not propagated |
| SPF `permerror` | more than 10 lookups, two SPF records, or a syntax typo |
| Fails only for forwarded mail | expected for SPF; DKIM should still pass (ARC helps mailing lists) |
