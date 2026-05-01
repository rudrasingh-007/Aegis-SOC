"""Rule engine module for classifying and processing security alerts."""

from config.config import (
	CRITICAL,
	HIGH,
	LOW,
	MEDIUM,
	FAILED_LOGIN_HIGH_SEVERITY_THRESHOLD,
)


SEVERITY_ORDER = [LOW, MEDIUM, HIGH, CRITICAL]


def classify_alert(alert):
	"""Classify a single alert dictionary and return a severity level."""
	alert_type = alert.get("alert_type")
	attempt_count = alert.get("attempt_count", 0)

	if alert_type == "malware_detected":
		return CRITICAL

	if alert_type == "brute_force":
		return CRITICAL

	if (
		alert_type == "failed_login"
		and attempt_count >= FAILED_LOGIN_HIGH_SEVERITY_THRESHOLD
	):
		return HIGH

	if alert_type == "port_scan":
		return MEDIUM

	if alert_type == "suspicious_connection":
		return MEDIUM

	if alert_type == "ransomware_detected":
		return CRITICAL

	if alert_type == "ddos_attack":
		return HIGH

	if alert_type == "privilege_escalation":
		return HIGH

	if alert_type == "unauthorized_wifi_access":
		return MEDIUM

	if alert_type == "dns_tunneling":
		return MEDIUM

	if attempt_count < 3:
		return LOW

	return MEDIUM


def process_alerts(alerts):
	"""Add severity to each alert and return the same list."""
	for alert in alerts:
		alert["severity"] = classify_alert(alert)
	return alerts


def _bump_severity(severity, levels):
	"""Raise severity by the requested number of levels without exceeding CRITICAL."""
	try:
		current_index = SEVERITY_ORDER.index(severity)
	except ValueError:
		return severity

	new_index = min(current_index + levels, len(SEVERITY_ORDER) - 1)
	return SEVERITY_ORDER[new_index]


def reclassify_with_threat_intel(alert):
	"""Reclassify severity upward using threat intel scores."""
	severity = alert.get("severity", LOW)
	abuse_score = alert.get("abuse_score", 0)
	virustotal_score = alert.get("virustotal_score", 0)

	if abuse_score > 90 or virustotal_score >= 10:
		alert["severity"] = _bump_severity(severity, 2)
	elif abuse_score > 75 or virustotal_score >= 5:
		alert["severity"] = _bump_severity(severity, 1)

	return alert


def reclassify_alerts(alerts):
	"""Reclassify a list of alerts using threat intel scores."""
	for alert in alerts:
		reclassify_with_threat_intel(alert)
	return alerts
