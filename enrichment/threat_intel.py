"""Threat intelligence enrichment using AbuseIPDB."""

import requests

from config.config import (
	ABUSEIPDB_API_KEY,
	ABUSEIPDB_URL,
	ABUSEIPDB_MIN_CONFIDENCE_SCORE,
	VIRUSTOTAL_API_KEY,
	VIRUSTOTAL_URL,
	MEDIUM,
	HIGH,
	CRITICAL,
)


ABUSEIPDB_CATEGORY_MAP = {
	3: 'Fraud Orders',
	4: 'DDoS Attack',
	5: 'FTP Brute-Force',
	6: 'Ping of Death',
	7: 'Phishing',
	8: 'Fraud VoIP',
	9: 'Open Proxy',
	10: 'Web Spam',
	11: 'Email Spam',
	12: 'Blog Spam',
	13: 'VPN IP',
	14: 'Port Scan',
	15: 'Hacking',
	16: 'SQL Injection',
	17: 'Spoofing',
	18: 'Brute Force',
	19: 'Bad Web Bot',
	20: 'Exploited Host',
	21: 'Web App Attack',
	22: 'SSH',
	23: 'IoT Targeted',
}


def check_ip(ip_address):
	"""Return (abuseConfidenceScore, categories_list) from AbuseIPDB for an IP.

	On success returns a tuple: (int_abuse_score, list_of_category_codes).
	On any failure returns (0, []).
	"""
	headers = {
		"Key": ABUSEIPDB_API_KEY,
		"Accept": "application/json",
	}
	params = {"ipAddress": ip_address}

	try:
		response = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
		response.raise_for_status()
		payload = response.json()
		data = payload.get("data", {}) or {}
		abuse_score = int(data.get("abuseConfidenceScore", 0))
		raw_categories = data.get("categories", []) or []
		# Normalize category codes to integers where possible
		categories = []
		if isinstance(raw_categories, list):
			for c in raw_categories:
				try:
					categories.append(int(c))
				except Exception:
					continue
		return abuse_score, categories
	except (requests.RequestException, ValueError, TypeError):
		return 0, []


def check_ip_virustotal(ip_address):
	"""Return VirusTotal malicious vote count for an IP, or 0 on failure."""
	headers = {
		"x-apikey": VIRUSTOTAL_API_KEY,
		"Accept": "application/json",
	}

	try:
		response = requests.get(f"{VIRUSTOTAL_URL}{ip_address}", headers=headers, timeout=10)
		response.raise_for_status()
		payload = response.json()
		return int(
			payload.get("data", {})
			.get("attributes", {})
			.get("last_analysis_stats", {})
			.get("malicious", 0)
		)
	except (requests.RequestException, ValueError, TypeError):
		return 0


def enrich_alerts(alerts):
	"""Enrich eligible alerts with AbuseIPDB score and threat confirmation."""
	severities_to_check = {MEDIUM, HIGH, CRITICAL}

	for alert in alerts:
		if alert.get("severity") in severities_to_check:
			abuse_score, raw_categories = check_ip(alert.get("source_ip", ""))
			virustotal_score = check_ip_virustotal(alert.get("source_ip", ""))
			alert["abuse_score"] = abuse_score
			alert["virustotal_score"] = virustotal_score
			alert["threat_confirmed"] = (
				abuse_score > ABUSEIPDB_MIN_CONFIDENCE_SCORE
				or virustotal_score > 0
			)
			# Map raw category codes to human-readable names
			mapped = []
			if isinstance(raw_categories, list):
				for c in raw_categories:
					try:
						mapped.append(ABUSEIPDB_CATEGORY_MAP.get(int(c), f"Unknown({c})"))
					except Exception:
						mapped.append(f"Unknown({c})")

			alert["abuse_categories"] = mapped

	return alerts
