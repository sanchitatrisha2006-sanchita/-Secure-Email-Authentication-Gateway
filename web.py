"""Web tool: paste a raw email (or just its headers) and get an authentication summary.

    flask --app emailauth.web run          # http://127.0.0.1:5000
"""
from __future__ import annotations

from flask import Flask, jsonify, render_template_string, request

from emailauth.analyzer import analyze
from emailauth.dns_resolver import DnsPythonResolver, Resolver

MAX_BYTES = 1_000_000

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Email authentication analyzer</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#1b1f23}
 textarea{width:100%;height:14rem;font-family:ui-monospace,monospace;font-size:.85rem}
 input[type=text]{width:16rem} table{border-collapse:collapse;width:100%;margin:.5rem 0}
 td,th{border:1px solid #d0d7de;padding:.35rem .6rem;text-align:left;font-size:.9rem}
 .pass{color:#1a7f37;font-weight:600}.fail,.permerror{color:#cf222e;font-weight:600}
 .softfail,.temperror,.neutral,.none{color:#9a6700;font-weight:600}
 .verdict{padding:.8rem 1rem;border-radius:6px;font-weight:600;margin:1rem 0}
 .v-PASS{background:#dafbe1}.v-FAIL{background:#ffebe9}.v-OTHER{background:#fff8c5}
 .warn{color:#9a6700}.fail-f{color:#cf222e}.info{color:#57606a}
</style></head><body>
<h1>Email authentication analyzer</h1>
<p>Paste a full raw message (best) or only its headers. SPF, DKIM and DMARC are re-verified via live DNS.</p>
<form method="post" action="/">
 <textarea name="raw" required placeholder="Received: from ...&#10;Authentication-Results: ...&#10;From: ...">{{ raw }}</textarea>
 <p><label>Connecting IP (optional) <input type="text" name="ip" value="{{ ip }}"></label>
    <label>Trusted authserv-id (optional) <input type="text" name="trusted" value="{{ trusted }}"></label>
    <button type="submit">Analyze</button></p>
</form>
{% if error %}<p class="fail-f">{{ error }}</p>{% endif %}
{% if r %}
 <div class="verdict v-{{ 'PASS' if r.verdict.startswith('PASS') else 'FAIL' if r.verdict.startswith('FAIL') else 'OTHER' }}">{{ r.verdict }}</div>
 <table><tr><th>Check</th><th>Result</th><th>Domain</th><th>Details</th></tr>
 {% if r.spf %}<tr><td>SPF</td><td class="{{ r.spf.result }}">{{ r.spf.result }}</td><td>{{ r.spf.domain }}</td><td>{{ r.spf.reason }}</td></tr>{% endif %}
 {% for d in r.dkim %}<tr><td>DKIM</td><td class="{{ d.result }}">{{ d.result }}</td><td>{{ d.domain }}{% if d.selector %} (s={{ d.selector }}){% endif %}</td><td>{{ d.reason }}</td></tr>{% endfor %}
 {% if r.dmarc %}<tr><td>DMARC</td><td class="{{ r.dmarc.result }}">{{ r.dmarc.result }}</td><td>{{ r.dmarc.from_domain }}</td>
  <td>policy={{ r.dmarc.policy }}, disposition={{ r.dmarc.disposition }}, SPF aligned={{ r.dmarc.spf_aligned }}, DKIM aligned={{ r.dmarc.dkim_aligned }}</td></tr>{% endif %}
 </table>
 <p>From: <b>{{ r.from_address }}</b> &middot; envelope sender domain: <b>{{ r.mail_from_domain or '-' }}</b>
 &middot; client IP: <b>{{ r.client_ip or '-' }}</b> <small>{{ r.client_ip_source }}</small></p>
 {% if r.claims %}<h3>Claims found in the headers (Authentication-Results)</h3>
 <table><tr><th>Method</th><th>Result</th><th>Claimed by</th><th>Trusted?</th><th>Properties</th></tr>
 {% for c in r.claims %}<tr><td>{{ c.method }}</td><td class="{{ c.result }}">{{ c.result }}</td><td>{{ c.authserv_id }}</td>
  <td>{{ 'yes' if c.trusted else 'NO' if c.trusted is false else 'not configured' }}</td><td>{{ c.properties }}</td></tr>{% endfor %}</table>{% endif %}
 {% if r.hops %}<h3>Delivery path (newest first)</h3><table><tr><th>from</th><th>by</th><th>IPs</th></tr>
 {% for h in r.hops %}<tr><td>{{ h.from_host }}</td><td>{{ h.by_host }}</td><td>{{ h.ips|join(', ') }}</td></tr>{% endfor %}</table>{% endif %}
 {% if r.findings %}<h3>Findings</h3><ul>
 {% for f in r.findings %}<li class="{{ 'fail-f' if f.level == 'fail' else f.level }}"><b>{{ f.level }}</b>: {{ f.message }}</li>{% endfor %}</ul>{% endif %}
{% endif %}
</body></html>"""


def _run(raw: str, ip: str, trusted: str, resolver: Resolver):
    return analyze(raw.encode("utf-8", "replace"), resolver, client_ip=ip.strip() or None,
                   trusted_authserv={t.strip().lower() for t in trusted.split(",") if t.strip()} or None)


def create_app(resolver: Resolver | None = None) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_BYTES
    state = {"resolver": resolver}

    def get_resolver() -> Resolver:
        if state["resolver"] is None:                       # created on first use
            state["resolver"] = DnsPythonResolver()
        return state["resolver"]

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = \
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.route("/", methods=["GET", "POST"])
    def index():
        ctx = {"raw": "", "ip": "", "trusted": "", "r": None, "error": None}
        if request.method == "POST":
            ctx.update(raw=request.form.get("raw", ""), ip=request.form.get("ip", ""),
                       trusted=request.form.get("trusted", ""))
            try:
                ctx["r"] = _run(ctx["raw"], ctx["ip"], ctx["trusted"], get_resolver())
            except Exception as exc:                        # never leak a stack trace to the page
                app.logger.exception("analysis failed")
                ctx["error"] = f"Analysis failed: {exc.__class__.__name__}"
        return render_template_string(PAGE, **ctx)

    @app.post("/api/analyze")
    def api_analyze():
        body = request.get_json(silent=True) or {}
        if not isinstance(body.get("raw"), str) or not body["raw"].strip():
            return jsonify(error="JSON body must contain a non-empty string field 'raw'"), 400
        report = _run(body["raw"], str(body.get("ip", "")), str(body.get("trusted", "")), get_resolver())
        return jsonify(report.to_dict())

    return app


app = create_app()
