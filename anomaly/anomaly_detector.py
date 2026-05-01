"""Anomaly detection module for Aegis-SOC."""

import os
import json
import datetime
import statistics
from storage.history_store import save_alerts, get_historical_data


def calculate_zscore(value, mean, standard_deviation):
	"""Calculate and return a z-score as a float."""
	if standard_deviation == 0:
		return 0.0
	return float((value - mean) / standard_deviation)


def _safe_mean(values):
	if not values:
		return 0.0
	return statistics.mean(values)


def _safe_stdev(values):
	if len(values) < 2:
		return 0.0
	return statistics.stdev(values)


def detect_attempt_count_anomalies(alerts, baseline_alerts=None):
	"""Flag alerts with anomalous attempt_count values using baseline data."""
	if baseline_alerts is None:
		baseline_alerts = alerts
	
	baseline_attempt_counts = [
		alert.get("attempt_count", 0) for alert in baseline_alerts
	]
	mean_value = _safe_mean(baseline_attempt_counts)
	standard_deviation = _safe_stdev(baseline_attempt_counts)

	for alert in alerts:
		attempt_count = alert.get("attempt_count", 0)
		zscore = calculate_zscore(attempt_count, mean_value, standard_deviation)
		alert["attempt_count_zscore"] = zscore
		alert["attempt_count_anomaly"] = zscore > 2.0

	return alerts


def detect_ip_frequency_anomalies(alerts, baseline_alerts=None):
	"""Flag alerts from IPs that appear with anomalous frequency using baseline data."""
	if baseline_alerts is None:
		baseline_alerts = alerts
	
	baseline_ip_counts = {}
	for alert in baseline_alerts:
		source_ip = alert.get("source_ip", "unknown")
		baseline_ip_counts[source_ip] = baseline_ip_counts.get(source_ip, 0) + 1

	counts = list(baseline_ip_counts.values())
	mean_value = _safe_mean(counts)
	standard_deviation = _safe_stdev(counts)

	ip_scores = {
		source_ip: calculate_zscore(count, mean_value, standard_deviation)
		for source_ip, count in baseline_ip_counts.items()
	}

	for alert in alerts:
		source_ip = alert.get("source_ip", "unknown")
		zscore = ip_scores.get(source_ip, 0.0)
		alert["ip_frequency_zscore"] = zscore
		alert["ip_frequency_anomaly"] = zscore > 2.0

	return alerts


def detect_alert_type_anomalies(alerts, baseline_alerts=None):
	"""Flag alerts whose type appears with anomalous frequency using baseline data."""
	if baseline_alerts is None:
		baseline_alerts = alerts
	
	baseline_alert_type_counts = {}
	for alert in baseline_alerts:
		alert_type = alert.get("alert_type", "unknown")
		baseline_alert_type_counts[alert_type] = (
			baseline_alert_type_counts.get(alert_type, 0) + 1
		)

	counts = list(baseline_alert_type_counts.values())
	mean_value = _safe_mean(counts)
	standard_deviation = _safe_stdev(counts)

	alert_type_scores = {
		alert_type: calculate_zscore(count, mean_value, standard_deviation)
		for alert_type, count in baseline_alert_type_counts.items()
	}

	for alert in alerts:
		alert_type = alert.get("alert_type", "unknown")
		zscore = alert_type_scores.get(alert_type, 0.0)
		alert["alert_type_zscore"] = zscore
		alert["alert_type_anomaly"] = zscore > 2.0

	return alerts


def run_anomaly_detection(alerts):
	"""Run all anomaly detectors, print a summary, and save a JSON report."""
	# Persist current alerts to database
	save_alerts(alerts)
	
	# Retrieve all historical alerts as baseline
	historical_alerts = get_historical_data()
	
	# Run detectors using historical data as baseline
	detect_attempt_count_anomalies(alerts, baseline_alerts=historical_alerts)
	detect_ip_frequency_anomalies(alerts, baseline_alerts=historical_alerts)
	detect_alert_type_anomalies(alerts, baseline_alerts=historical_alerts)

	attempt_count_anomalies = sum(
		1 for alert in alerts if alert.get("attempt_count_anomaly")
	)
	ip_frequency_anomalies = sum(
		1 for alert in alerts if alert.get("ip_frequency_anomaly")
	)
	alert_type_anomalies = sum(
		1 for alert in alerts if alert.get("alert_type_anomaly")
	)

	report = {
		"generated_at": datetime.datetime.utcnow().isoformat() + "Z",
		"total_alerts": len(alerts),
		"summary": {
			"attempt_count_anomalies": attempt_count_anomalies,
			"ip_frequency_anomalies": ip_frequency_anomalies,
			"alert_type_anomalies": alert_type_anomalies,
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
	print(f"Attempt Count Anomalies: {attempt_count_anomalies}")
	print(f"IP Frequency Anomalies: {ip_frequency_anomalies}")
	print(f"Alert Type Anomalies: {alert_type_anomalies}")
	print(f"Report Saved To: {report_path}")
	print("=" * 60)

	return alerts
