"""Anomaly detection module for Aegis-SOC."""

import os
import json
import datetime
import statistics
from collections import Counter

from sklearn.ensemble import IsolationForest
from storage.history_store import save_alerts, get_historical_data

def _safe_mean(values):
	if not values:
		return 0.0
	return statistics.mean(values)


def _build_frequency_maps(historical_alerts):
	"""Build source_ip and alert_type frequency maps from historical alerts."""
	ip_frequency = Counter()
	alert_type_frequency = Counter()

	for alert in historical_alerts:
		ip_frequency[alert.get("source_ip", "unknown")] += 1
		alert_type_frequency[alert.get("alert_type", "unknown")] += 1

	return ip_frequency, alert_type_frequency


def run_anomaly_detection(alerts):
	"""Run all anomaly detectors, print a summary, and save a JSON report."""
	# Persist current alerts to database
	save_alerts(alerts)
	
	# Retrieve all historical alerts as baseline
	historical_alerts = get_historical_data()

	# Build historical frequency maps for feature extraction
	ip_frequency_map, alert_type_frequency_map = _build_frequency_maps(historical_alerts)

	feature_matrix = []
	for alert in alerts:
		attempt_count = int(alert.get("attempt_count", 0) or 0)
		source_ip = alert.get("source_ip", "unknown")
		alert_type = alert.get("alert_type", "unknown")
		ip_frequency = int(ip_frequency_map.get(source_ip, 0))
		alert_type_frequency = int(alert_type_frequency_map.get(alert_type, 0))
		feature_matrix.append([attempt_count, ip_frequency, alert_type_frequency])

	if len(alerts) < 2:
		for alert in alerts:
			alert["is_anomaly"] = False
			alert["anomaly_score"] = 0.0
			alert["anomaly_details"] = {
				"attempt_count_anomaly": False,
				"ip_frequency_anomaly": False,
				"alert_type_anomaly": False,
			}
	else:
		model = IsolationForest(contamination=0.1, random_state=42)
		predictions = model.fit_predict(feature_matrix)
		scores = model.decision_function(feature_matrix)

		attempt_count_mean = _safe_mean([row[0] for row in feature_matrix])
		ip_frequency_mean = _safe_mean([row[1] for row in feature_matrix])
		alert_type_frequency_mean = _safe_mean([row[2] for row in feature_matrix])

		for alert, prediction, score, row in zip(alerts, predictions, scores, feature_matrix):
			alert["is_anomaly"] = bool(prediction == -1)
			alert["anomaly_score"] = round(float(score), 4)
			alert["anomaly_details"] = {
				"attempt_count_anomaly": bool(row[0] > attempt_count_mean),
				"ip_frequency_anomaly": bool(row[1] > ip_frequency_mean),
				"alert_type_anomaly": bool(row[2] > alert_type_frequency_mean),
			}

	anomaly_count = sum(1 for alert in alerts if alert.get("is_anomaly"))

	report = {
		"generated_at": datetime.datetime.utcnow().isoformat() + "Z",
		"total_alerts": len(alerts),
		"summary": {
			"anomalous_alerts": anomaly_count,
		},
		"alerts": alerts,
	}

	output_folder = "anomaly_reports"
	os.makedirs(output_folder, exist_ok=True)
	report_path = os.path.join(
		output_folder,
		f"anomaly_report_{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json",
	)
	with open(report_path, "w", encoding="utf-8") as report_file:
		json.dump(report, report_file, indent=2)

	print("=" * 60)
	print("Aegis-SOC Anomaly Detection Summary")
	print("=" * 60)
	print(f"Anomalous Alerts: {anomaly_count}")
	print(f"Report Saved To: {report_path}")
	print("=" * 60)

	return alerts
