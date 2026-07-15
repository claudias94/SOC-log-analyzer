"""
report.py

Generate HTML security reports using Jinja2.
"""

from pathlib import Path
from datetime import datetime

from jinja2 import Environment, FileSystemLoader

from logger import logger
from config import APP_NAME, APP_VERSION


class ReportGenerator:
    """
    Generates HTML reports from detection results.
    """

    def __init__(self):
        self.template_dir = Path("templates")
        self.output_dir = Path("reports")

        self.output_dir.mkdir(exist_ok=True)

        self.env = Environment(
            loader=FileSystemLoader(self.template_dir)
        )

    def generate_html(self, results):
        """
        Generate an HTML report.
        """

        logger.info("Generating HTML report...")

        template = self.env.get_template("report.html")

        html = template.render(
            results=results,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            app_name=APP_NAME,
            app_version=APP_VERSION,
        )

        output_file = self.output_dir / "report.html"

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html)

        logger.info(f"Report saved to {output_file}")

        return output_file
