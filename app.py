import os
import uuid
import logging
import functools
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from markupsafe import escape
from flask import Flask, render_template, request, redirect, url_for, jsonify, abort, Response

import database as db
from email_parser import parse_eml
from header_analyzer import analyze_headers
from url_analyzer import analyze_all_urls
from attachment_analyzer import analyze_all_attachments
from ioc_extractor import extract_iocs
from threat_scorer import calculate_score
from mitre_mapper import map_findings_to_mitre, get_attack_summary
from stix_exporter import generate_stix_bundle, stix_to_json
from whois_lookup import enrich_url_findings
from report_generator import generate_pdf
from models import AnalysisReport
from config import SECRET_KEY, MAX_FILE_SIZE, UPLOAD_DIR, VT_ENABLED, API_KEY

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE

# --- Rate Limiting ---
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    limiter = Limiter(get_remote_address, app=app, default_limits=["200 per hour"])
except ImportError:
    limiter = None
    logging.info("flask-limiter not installed — rate limiting disabled")


def sanitize(val):
    if val is None:
        return ""
    return str(escape(str(val)))


def require_api_key(f):
    """Decorator: require X-API-Key header when API_KEY is configured."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if API_KEY:
            provided = request.headers.get("X-API-Key", "")
            if provided != API_KEY:
                return jsonify({"error": "Invalid or missing API key"}), 401
        return f(*args, **kwargs)
    return decorated


# =========================================================================
# WEB ROUTES
# =========================================================================

@app.route("/")
def index():
    return render_template("index.html", stats=db.get_stats(), recent=db.get_history(10), vt=VT_ENABLED)


@app.route("/analyze", methods=["POST"])
def analyze():
    files = request.files.getlist("eml_file")
    if not files or (len(files) == 1 and not files[0].filename):
        return redirect(url_for("index"))

    report_ids = []
    errors = []

    for f in files:
        if not f.filename or not f.filename.lower().endswith(".eml"):
            errors.append(f"{f.filename or 'unknown'}: not a .eml file")
            continue
        raw_bytes = f.read()
        if not raw_bytes:
            errors.append(f"{f.filename}: empty file")
            continue
        try:
            report = _run_analysis(raw_bytes, f.filename)
            db.save_report(report.to_dict())
            report_ids.append(report.report_id)
        except Exception:
            logging.exception("Analysis failed for %s", f.filename)
            errors.append(f"{f.filename}: analysis failed")

    if not report_ids:
        error_msg = "; ".join(errors) if errors else "Upload a .eml file"
        return render_template("index.html", error=error_msg,
                             stats=db.get_stats(), recent=db.get_history(10), vt=VT_ENABLED)

    if len(report_ids) == 1:
        return redirect(url_for("view_report", report_id=report_ids[0]))

    # Multiple files: redirect to history with a success message
    return redirect(url_for("history"))


@app.route("/report/<report_id>")
def view_report(report_id):
    report_data = db.get_report(sanitize(report_id))
    if not report_data:
        abort(404)
    return render_template("report.html", report=report_data, vt=VT_ENABLED)


@app.route("/report/<report_id>/pdf")
def download_pdf(report_id):
    report_data = db.get_report(sanitize(report_id))
    if not report_data:
        abort(404)
    pdf_buf = generate_pdf(report_data)
    if pdf_buf is None:
        return jsonify({"error": "PDF generation unavailable — install fpdf2"}), 500
    filename = f"phishguard_{report_id}.pdf"
    return Response(
        pdf_buf.getvalue(),
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/history")
def history():
    query = request.args.get("q", "").strip()
    if query:
        analyses = db.search_history(query)
    else:
        analyses = db.get_history(100)
    return render_template("history.html", analyses=analyses, stats=db.get_stats(), query=query)


@app.route("/dashboard")
def dashboard():
    stats = db.get_stats()
    trend = db.get_trend_data(30)
    recent = db.get_history(20)
    return render_template("dashboard.html", stats=stats, trend=trend, recent=recent, vt=VT_ENABLED)


# =========================================================================
# API ROUTES
# =========================================================================

@app.route("/api/analyze", methods=["POST"])
@require_api_key
def api_analyze():
    if limiter:
        # Apply stricter limit for analysis endpoint
        pass
    if "eml_file" not in request.files:
        return jsonify({"error": "No eml_file in request"}), 400
    f = request.files["eml_file"]
    if not f.filename or not f.filename.lower().endswith(".eml"):
        return jsonify({"error": ".eml files only"}), 400
    raw_bytes = f.read()
    if not raw_bytes:
        return jsonify({"error": "Empty file"}), 400
    try:
        report = _run_analysis(raw_bytes, f.filename)
    except Exception:
        logging.exception("API analysis failed for %s", f.filename)
        return jsonify({"error": "Analysis failed — file may be malformed"}), 500
    report_dict = report.to_dict()
    db.save_report(report_dict)
    return jsonify(report_dict)


@app.route("/api/report/<report_id>")
@require_api_key
def api_report(report_id):
    data = db.get_report(sanitize(report_id))
    if not data:
        return jsonify({"error": "Not found"}), 404
    return jsonify(data)


@app.route("/api/history")
@require_api_key
def api_history():
    return jsonify(db.get_history(100))


@app.route("/api/iocs/<report_id>")
@require_api_key
def api_iocs(report_id):
    data = db.get_report(sanitize(report_id))
    if not data:
        return jsonify({"error": "Not found"}), 404
    return jsonify(data.get("iocs", {}))


@app.route("/api/stix/<report_id>")
@require_api_key
def api_stix(report_id):
    data = db.get_report(sanitize(report_id))
    if not data:
        return jsonify({"error": "Not found"}), 404
    bundle = generate_stix_bundle(data)
    return Response(
        stix_to_json(bundle),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=stix_{report_id}.json"},
    )


@app.route("/api/mitre/<report_id>")
@require_api_key
def api_mitre(report_id):
    data = db.get_report(sanitize(report_id))
    if not data:
        return jsonify({"error": "Not found"}), 404
    return jsonify({
        "mappings": data.get("mitre_mappings", []),
        "attack_summary": data.get("attack_summary", {}),
    })


@app.route("/api/report/<report_id>", methods=["DELETE"])
@require_api_key
def api_delete_report(report_id):
    deleted = db.delete_report(sanitize(report_id))
    if not deleted:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"status": "deleted", "id": report_id})


@app.route("/api/stats")
@require_api_key
def api_stats():
    return jsonify(db.get_stats())


@app.route("/api/trend")
@require_api_key
def api_trend():
    days = request.args.get("days", 30, type=int)
    return jsonify(db.get_trend_data(min(days, 365)))


@app.route("/delete/<report_id>", methods=["POST"])
def delete_report_web(report_id):
    db.delete_report(sanitize(report_id))
    return redirect(url_for("history"))


@app.route("/api/export/csv")
@require_api_key
def export_csv():
    rows = db.get_history(1000)
    lines = ["id,filename,from_address,subject,threat_level,threat_score,analyzed_at"]
    for r in rows:
        subj = r.get("subject", "").replace('"', '""')
        lines.append(
            f'"{r["id"]}","{r["filename"]}","{r["from_address"]}","{subj}",'
            f'"{r["threat_level"]}",{r["threat_score"]},"{r.get("analyzed_at_display", "")}"'
        )
    csv_data = "\n".join(lines)
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=phishguard_export.csv"},
    )


# =========================================================================
# ANALYSIS PIPELINE
# =========================================================================

def _run_analysis(raw_bytes, filename):
    report = AnalysisReport()
    report.report_id = uuid.uuid4().hex[:12]
    report.filename = filename
    report.analyzed_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    msg, headers, body, attachments_raw = parse_eml(raw_bytes)
    headers = analyze_headers(headers)
    report.headers = headers
    report.body = body

    # Run URL analysis and attachment analysis concurrently
    url_findings = []
    att_findings = []

    with ThreadPoolExecutor(max_workers=2) as executor:
        url_future = executor.submit(analyze_all_urls, body.text_content, body.html_content)
        att_future = executor.submit(analyze_all_attachments, attachments_raw)

        url_findings = url_future.result()
        att_findings = att_future.result()

    report.urls = [uf.to_dict() for uf in url_findings]
    report.attachments = [af.to_dict() for af in att_findings]

    iocs = extract_iocs(headers, body, url_findings, att_findings)
    report.iocs = iocs

    score = calculate_score(headers, url_findings, att_findings, body)
    report.score = score

    # MITRE ATT&CK mapping
    mitre_mappings = map_findings_to_mitre(score.breakdown)
    attack_summary = get_attack_summary(mitre_mappings)

    # WHOIS enrichment (best-effort, non-blocking for report generation)
    whois_data = {}
    try:
        whois_data = enrich_url_findings(url_findings)
    except Exception:
        logging.debug("WHOIS enrichment failed — continuing without it")

    # Store enrichment data in the report dict (we'll add to to_dict output)
    report_dict = report.to_dict()
    report_dict["mitre_mappings"] = mitre_mappings
    report_dict["attack_summary"] = attack_summary
    report_dict["whois"] = whois_data

    # We need to return something that has to_dict(), so we'll patch it
    report._enriched_dict = report_dict
    report.to_dict = lambda: report._enriched_dict

    return report


# =========================================================================
# ERROR HANDLERS
# =========================================================================

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Not found"}), 404
    return render_template("index.html", error="Page not found",
                         stats=db.get_stats(), recent=db.get_history(10), vt=VT_ENABLED), 404


@app.errorhandler(413)
def too_large(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "File too large (25MB max)"}), 413
    return render_template("index.html", error="File too large (25MB max)",
                         stats=db.get_stats(), recent=db.get_history(10), vt=VT_ENABLED), 413


@app.errorhandler(429)
def rate_limited(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Rate limit exceeded — try again later"}), 429
    return render_template("index.html", error="Too many requests — please slow down",
                         stats=db.get_stats(), recent=db.get_history(10), vt=VT_ENABLED), 429


@app.errorhandler(500)
def server_error(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Internal server error"}), 500
    return render_template("index.html", error="Internal server error — please try again",
                         stats=db.get_stats(), recent=db.get_history(10), vt=VT_ENABLED), 500


if __name__ == "__main__":
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    db.init_db()
    logging.info("PhishGuard running on http://127.0.0.1:5000")
    if VT_ENABLED:
        logging.info("VirusTotal integration active")
    else:
        logging.info("VirusTotal disabled (set VT_API_KEY to enable)")
    if API_KEY:
        logging.info("API key authentication enabled")
    else:
        logging.info("API key auth disabled (set PHISH_API_KEY to enable)")
    app.run(host="0.0.0.0", port=5000, debug=False)
