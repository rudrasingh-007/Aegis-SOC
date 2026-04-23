"""Flask dashboard server for Aegis-SOC."""

from flask import Flask, render_template, jsonify

from simulator.alert_simulator import generate_alerts
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


@app.route("/")
def index():
	"""Render dashboard home page."""
	return render_template("index.html")


@app.route("/run-pipeline", methods=["POST"])
def run_pipeline():
	"""Run the end-to-end Aegis-SOC pipeline and return JSON results."""
	alerts = generate_alerts(5)
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
