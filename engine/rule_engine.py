"""Rule engine module for classifying and processing security alerts."""

from config.config import (
	CRITICAL,
	HIGH,
	LOW,
	MEDIUM,
	FAILED_LOGIN_HIGH_SEVERITY_THRESHOLD,
)


SEVERITY_ORDER = [LOW, MEDIUM, HIGH, CRITICAL]


MITRE_ATTACK_MAP = {
    'port_scan': {'tactic': 'Reconnaissance', 'technique_id': 'T1046', 'technique_name': 'Network Service Scanning'},
    'brute_force': {'tactic': 'Credential Access', 'technique_id': 'T1110', 'technique_name': 'Brute Force'},
    'failed_login': {'tactic': 'Credential Access', 'technique_id': 'T1110.001', 'technique_name': 'Password Guessing'},
    'malware_detected': {'tactic': 'Execution', 'technique_id': 'T1204', 'technique_name': 'User Execution'},
    'ransomware_detected': {'tactic': 'Impact', 'technique_id': 'T1486', 'technique_name': 'Data Encrypted for Impact'},
    'privilege_escalation': {'tactic': 'Privilege Escalation', 'technique_id': 'T1068', 'technique_name': 'Exploitation for Privilege Escalation'},
    'suspicious_connection': {'tactic': 'Command and Control', 'technique_id': 'T1071', 'technique_name': 'Application Layer Protocol'},
    'ddos_attack': {'tactic': 'Impact', 'technique_id': 'T1498', 'technique_name': 'Network Denial of Service'},
    'dns_tunneling': {'tactic': 'Exfiltration', 'technique_id': 'T1048', 'technique_name': 'Exfiltration Over Alternative Protocol'},
    'unauthorized_wifi_access': {'tactic': 'Initial Access', 'technique_id': 'T1465', 'technique_name': 'Rogue Wi-Fi Access Points'},
}


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


def tag_mitre(alert):
	"""Add MITRE ATT&CK tactic and technique info to an alert.
	
	Looks up the alert's alert_type in MITRE_ATTACK_MAP and adds:
	- mitre_tactic
	- mitre_technique_id
	- mitre_technique_name
	
	If alert_type is not in the map, all three fields are set to 'Unknown'.
	Returns the modified alert.
	"""
	alert_type = alert.get("alert_type")
	mitre_info = MITRE_ATTACK_MAP.get(alert_type)
	
	if mitre_info:
		alert["mitre_tactic"] = mitre_info["tactic"]
		alert["mitre_technique_id"] = mitre_info["technique_id"]
		alert["mitre_technique_name"] = mitre_info["technique_name"]
	else:
		alert["mitre_tactic"] = "Unknown"
		alert["mitre_technique_id"] = "Unknown"
		alert["mitre_technique_name"] = "Unknown"
	
	return alert


def tag_mitre_alerts(alerts):
	"""Add MITRE ATT&CK info to every alert in a list and return the list."""
	for alert in alerts:
		tag_mitre(alert)
	return alerts
