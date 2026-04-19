"""Threat intelligence enrichment using AbuseIPDB."""

import requests

from config.config import (
	ABUSEIPDB_API_KEY,
	ABUSEIPDB_URL,
	ABUSEIPDB_MIN_CONFIDENCE_SCORE,
	MEDIUM,
	HIGH,
	CRITICAL,
)


def check_ip(ip_address):
	"""Return AbuseIPDB abuseConfidenceScore for an IP, or 0 on failure."""
	headers = {
		"Key": ABUSEIPDB_API_KEY,
		"Accept": "application/json",
	}
	params = {"ipAddress": ip_address}

	try:
		response = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
		response.raise_for_status()
		payload = response.json()
		return int(payload.get("data", {}).get("abuseConfidenceScore", 0))
	except (requests.RequestException, ValueError, TypeError):
		return 0


def enrich_alerts(alerts):
	"""Enrich eligible alerts with AbuseIPDB score and threat confirmation."""
	severities_to_check = {MEDIUM, HIGH, CRITICAL}

	for alert in alerts:
		if alert.get("severity") in severities_to_check:
			score = check_ip(alert.get("source_ip", ""))
			alert["abuse_score"] = score
			alert["threat_confirmed"] = score > ABUSEIPDB_MIN_CONFIDENCE_SCORE

	return alerts
