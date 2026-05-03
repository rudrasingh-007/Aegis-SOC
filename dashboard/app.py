"""Flask dashboard server for Aegis-SOC."""

from itertools import count

import os

from flask import (
	Flask,
	render_template,
	jsonify,
	request,
	session,
	redirect,
	url_for,
	render_template_string,
)

from simulator.alert_simulator import generate_alerts
from log_parser.auth_log_parser import parse_auth_log_content
from engine.rule_engine import process_alerts
from enrichment.threat_intel import enrich_alerts
from correlator.alert_correlator import correlate_alerts
from anomaly.anomaly_detector import run_anomaly_detection
from l2_investigator.l2_engine import run_l2_investigation
from playbooks.response_playbooks import run_playbooks
from logger.false_positive_logger import log_false_positives
from integrations.wazuh_ingestor import (
	generate_sample_wazuh_alerts,
	load_wazuh_alerts_from_file,
)


app = Flask(__name__)
app.config['TIMEOUT'] = 120

# Simple session-based auth configuration
DASHBOARD_USERNAME = os.environ.get("DASHBOARD_USERNAME", "admin")
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "aegis123")
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24).hex())


@app.before_request
def require_login():
	"""Require login for all routes except the login page and static files."""
	# Allow login page and static files without authentication
	if request.path in ("/login", "/health") or request.path.startswith("/static"):
		return

	if not session.get("logged_in"):
		return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
	"""Simple session-based login using inline template."""
	error = None
	if request.method == "POST":
		username = request.form.get("username", "")
		password = request.form.get("password", "")
		if (
			username == DASHBOARD_USERNAME
			and password == DASHBOARD_PASSWORD
		):
			session["logged_in"] = True
			return redirect(url_for("index"))
		else:
			error = "Invalid username or password"

	login_form = """
	<!doctype html>
	<html>
	  <head>
		<title>AEGIS-SOC Login</title>
		<meta name="viewport" content="width=device-width, initial-scale=1" />
		<style>
		  * {
			box-sizing: border-box;
		  }

		  body {
			margin: 0;
			min-height: 100vh;
			display: flex;
			align-items: center;
			justify-content: center;
			background: #0a0e1a;
			background-image: radial-gradient(circle at center, rgba(59,130,246,0.08) 0%, rgba(59,130,246,0.08) 0%, transparent 60%),
				linear-gradient(to right, #1f2937 1px, transparent 1px),
				linear-gradient(to bottom, #1f2937 1px, transparent 1px);
			background-size: 100% 100%, 40px 40px, 40px 40px;
			color: #ffffff;
			font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
			padding: 16px;
		  }

		  .login-card {
			width: 100%;
			max-width: 520px;
			background: #111827;
			border: 1px solid rgba(59,130,246,0.4);
			border-radius: 14px;
			padding: 48px;
			box-shadow: 0 20px 40px rgba(0, 0, 0, 0.45), 0 0 40px rgba(59,130,246,0.15);
		  }

		  .brand {
			margin: 0;
			color: #3b82f6;
			font-family: "Courier New", Courier, monospace;
			font-size: 36px;
			font-weight: 800;
			line-height: 1;
			letter-spacing: 1px;
		  }

		  .tagline {
			margin-top: 10px;
			margin-bottom: 20px;
			font-size: 11px;
			color: #6b7280;
			text-transform: uppercase;
			letter-spacing: 0.2em;
		  }

		  .divider {
			height: 1px;
			background: #1f2937;
			margin: 10px 0 18px;
		  }

		  .subtitle {
			margin: 0 0 14px;
			font-size: 12px;
			color: #9ca3af;
			text-transform: uppercase;
			letter-spacing: 0.12em;
		  }

		  label {
			display: block;
			font-size: 12px;
			color: #9ca3af;
			margin-bottom: 8px;
			text-transform: uppercase;
			letter-spacing: 0.08em;
		  }

		  input {
			width: 100%;
			height: 44px;
			padding: 0 12px;
			margin-bottom: 14px;
			border-radius: 8px;
			border: 1px solid #1f2937;
			background: #0a0e1a;
			color: #ffffff;
			outline: none;
			transition: border-color 0.2s ease;
		  }

		  input:focus {
			border-color: #3b82f6;
		  }

		  .error {
			margin: 2px 0 14px;
			color: #ef4444;
			font-size: 13px;
		  }

		  button {
			width: 100%;
			height: 44px;
			border: none;
			border-radius: 8px;
			background: #3b82f6;
			color: #ffffff;
			font-weight: 700;
			font-size: 14px;
			cursor: pointer;
			transition: background-color 0.2s ease;
		  }

		  button:hover {
			background: #2563eb;
		  }
		</style>
	  </head>
	  <body>
		<div class="login-card">
		  <h1 class="brand">AEGIS-SOC</h1>
		  <p class="tagline">AUTOMATED THREAT TRIAGE SYSTEM</p>
		  <div class="divider"></div>
		  <p class="subtitle">CLEARANCE REQUIRED</p>
		  <form method="post">
			<label for="username">Username</label>
			<input id="username" name="username" autocomplete="username" />
			<label for="password">Password</label>
			<input id="password" name="password" type="password" autocomplete="current-password" />
			{% if error %}<p class="error">{{ error }}</p>{% endif %}
			<button type="submit">Login</button>
		  </form>
		</div>
	  </body>
	</html>
	"""

	return render_template_string(login_form, error=error)


@app.route("/logout")
def logout():
	"""Log the user out and redirect to login page."""
	session.clear()
	return redirect(url_for("login"))


@app.route("/")
def index():
	"""Render dashboard home page."""
	return render_template("index.html")


@app.route("/run-pipeline", methods=["POST"])
def run_pipeline():
	"""Run the end-to-end Aegis-SOC pipeline and return JSON results."""
	# Check if a file was uploaded
	if 'log_file' in request.files:
		# Parse the uploaded log file
		file = request.files['log_file']
		if file and file.filename.endswith('.log'):
			try:
				content = file.read().decode('utf-8')
				alerts = parse_auth_log_content(content)
			except Exception as e:
				return jsonify({"error": f"Failed to parse log file: {str(e)}"}), 400
		else:
			return jsonify({"error": "Invalid file format. Please upload a .log file."}), 400
	else:
		# Use existing JSON-based alert generation
		data = request.get_json(silent=True) or {}
		count = int(data.get("count", 5))
		alerts = generate_alerts(count)
	
	alerts = process_alerts(alerts)
	alerts = enrich_alerts(alerts)
	alerts = run_anomaly_detection(alerts)

	correlation_results = correlate_alerts(alerts)

	run_l2_investigation(alerts)
	run_playbooks(alerts)
	log_false_positives(alerts)

	# Keep Wazuh integration utilities imported and available for dashboard workflows.
	_ = generate_sample_wazuh_alerts, load_wazuh_alerts_from_file

	critical_count = sum(1 for alert in alerts if alert.get("severity") == "CRITICAL")
	high_count = sum(1 for alert in alerts if alert.get("severity") == "HIGH")
	medium_count = sum(1 for alert in alerts if alert.get("severity") == "MEDIUM")
	low_count = sum(1 for alert in alerts if alert.get("severity") == "LOW")
	threat_confirmed_count = sum(
		1 for alert in alerts if alert.get("threat_confirmed") is True
	)
	anomaly_count = sum(
		1
		for alert in alerts
		if (
			alert.get("attempt_count_anomaly")
			or alert.get("ip_frequency_anomaly")
			or alert.get("alert_type_anomaly")
		)
	)

	summary = {
		"total_alerts": len(alerts),
		"critical_count": critical_count,
		"high_count": high_count,
		"medium_count": medium_count,
		"low_count": low_count,
		"threat_confirmed_count": threat_confirmed_count,
		"anomaly_count": anomaly_count,
	}

	return jsonify(
		{
			"alerts": alerts,
			"correlation_results": correlation_results,
			"summary": summary,
		}
	)


@app.route("/health")
def health():
	"""Return simple health status."""
	return jsonify({"status": "ok"})


if __name__ == "__main__":
	app.run(debug=True, port=5000, threaded=True)
