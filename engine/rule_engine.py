"""Rule engine module for classifying and processing security alerts."""

from config.config import (
	CRITICAL,
	HIGH,
	LOW,
	MEDIUM,
	FAILED_LOGIN_HIGH_SEVERITY_THRESHOLD,
)


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
