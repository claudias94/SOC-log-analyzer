"""
app.py

Claus SOC Toolkit
SOC Log Analyzer Web Interface

Version 3.0
"""

from flask import Flask, render_template, send_from_directory, abort
from pathlib import Path
from analyzer import analyze
from logger import logger

app = Flask(__name__)
REPORT_DIR = Path(__file__).resolve().parent / "reports"
app.config["SECRET_KEY"] = "claus-soc-toolkit-v3"


@app.route("/")
def dashboard():
    """
    Main SOC dashboard.
    """

    logger.info("Loading SOC dashboard...")

    results = analyze()

    return render_template(
        "dashboard.html",
        results=results,
    )


@app.route("/health")
def health():
    """
    Health endpoint.
    """

    return {
        "status": "ok",
        "application": "SOC Log Analyzer",
        "version": "3.0",
    }

@app.route("/reports/<path:filename>")
def download_report(filename):
    """
    Serve generated reports from the reports directory.
    """

    file_path = REPORT_DIR / filename

    if not file_path.exists():
        abort(404)

    return send_from_directory(
        REPORT_DIR,
        filename,
        as_attachment=True
    )
REPORTS_DIR = Path("reports")
if __name__ == "__main__":
    app.run(
        debug=True,
        host="0.0.0.0",
        port=5000,
    )
