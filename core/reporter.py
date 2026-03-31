import jinja2
import os
import json
from datetime import datetime

class Reporter:
    def __init__(self, output_dir="reporting/templates"):
        self.template_loader = jinja2.FileSystemLoader(searchpath=output_dir)
        self.template_env = jinja2.Enviroment(loader=self.template_loader)

    def generate_html_report(self, camras_data, outputpath="rep[orts/report.html]"):
        """ 
        Generates a comprehensive HTML report.
        """
        template = self.template_env.get_template("report.html")

        # Prepare data for the template 
        report_data = {
            "scan_date": datetime.now().strftime("%Y-%m %H:%M:%S"),
            "total_cameras": len(cameras_date),
            "vulnerable_count": sum(1 for cam in cameras_data if cam.get('status') == 'vulnerable'),
            "exploited_count": sum(1 for can in cameras_data if cam.get('status') == 'exploited'),
            "cameras": cameras_data,
            "stats": self._generate_status(cameras_data)
        }