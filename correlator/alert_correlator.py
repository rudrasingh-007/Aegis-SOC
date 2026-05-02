"""Alert correlation module for Aegis-SOC."""

import os
import json
import datetime


KNOWN_ATTACK_CHAINS = [
	["port_scan", "brute_force", "privilege_escalation"],
	["port_scan", "brute_force", "malware_detected", "ransomware_detected"],
	[
		"unauthorized_wifi_access",
		"suspicious_connection",
		"failed_login",
		"privilege_escalation",
	],
	["brute_force", "dns_tunneling", "suspicious_connection"],
]


def _parse_timestamp(timestamp_value):
	"""Parse supported alert timestamp formats."""
	try:
		return datetime.datetime.strptime(timestamp_value, "%Y-%m-%d %H:%M:%S")
	except ValueError:
		if timestamp_value.endswith("Z"):
			timestamp_value = timestamp_value[:-1]
		return datetime.datetime.fromisoformat(timestamp_value)


def _sort_alerts_by_timestamp(alerts):
	"""Return alerts ordered by timestamp."""
	return sorted(
		alerts,
		key=lambda alert: _parse_timestamp(alert["timestamp"]),
	)


def detect_time_window(alerts):
	"""Detect whether any two alerts occur within 60 seconds of each other."""
	if len(alerts) < 2:
		return False

	ordered_alerts = _sort_alerts_by_timestamp(alerts)
	parsed_timestamps = [
		_parse_timestamp(alert["timestamp"])
		for alert in ordered_alerts
	]

	for first_timestamp, second_timestamp in zip(
		parsed_timestamps, parsed_timestamps[1:]
	):
		if (second_timestamp - first_timestamp).total_seconds() <= 60:
			return True

	return False


def _contains_subsequence(sequence, chain):
	"""Check whether chain appears as an ordered subsequence in sequence."""
	chain_index = 0
	for item in sequence:
		if item == chain[chain_index]:
			chain_index += 1
			if chain_index == len(chain):
				return True
	return False


def detect_attack_sequence(alerts):
	"""Detect whether any known attack chain appears in timestamp order."""
	if not alerts:
		return {"sequence_detected": False, "matched_chain": None}

	ordered_alerts = _sort_alerts_by_timestamp(alerts)
	alert_types = [alert.get("alert_type", "unknown") for alert in ordered_alerts]

	for chain in KNOWN_ATTACK_CHAINS:
		if _contains_subsequence(alert_types, chain):
			return {"sequence_detected": True, "matched_chain": chain}

	return {"sequence_detected": False, "matched_chain": None}


def group_by_ip(alerts):
	"""Group alerts by source IP address."""
	grouped = {}
	for alert in alerts:
		source_ip = alert.get("source_ip", "unknown")
		grouped.setdefault(source_ip, []).append(alert)
	return grouped


def assess_correlation(alert_group):
	"""Assess correlation details for alerts sharing the same source IP."""
	if not alert_group:
		return {
			"source_ip": "unknown",
			"total_alerts": 0,
			"alert_types": [],
			"target_systems": [],
			"highest_severity": "LOW",
			"threat_confirmed": False,
			"correlated": False,
			"rapid_attack": False,
			"sequence_detected": False,
			"matched_chain": None,
			"summary": "No alerts available for correlation.",
		}

	source_ip = alert_group[0].get("source_ip", "unknown")
	total_alerts = len(alert_group)
	alert_types = sorted({alert.get("alert_type", "unknown") for alert in alert_group})
	target_systems = sorted(
		{alert.get("target_system", "unknown") for alert in alert_group}
	)

	severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
	highest_severity = "LOW"
	highest_rank = 0
	for alert in alert_group:
		severity = alert.get("severity", "LOW")
		rank = severity_rank.get(severity, 0)
		if rank > highest_rank:
			highest_rank = rank
			highest_severity = severity

	threat_confirmed = any(alert.get("threat_confirmed") is True for alert in alert_group)
	correlated = total_alerts >= 2
	rapid_attack = detect_time_window(alert_group)
	sequence_result = detect_attack_sequence(alert_group)

	if correlated:
		summary = (
			f"Correlated incident from {source_ip}: {total_alerts} alerts across "
			f"{len(target_systems)} target systems with highest severity {highest_severity}."
		)
	else:
		summary = (
			f"Single alert from {source_ip} with severity {highest_severity}; "
			"insufficient events for correlation."
		)

	return {
		"source_ip": source_ip,
		"total_alerts": total_alerts,
		"alert_types": alert_types,
		"target_systems": target_systems,
		"highest_severity": highest_severity,
		"threat_confirmed": threat_confirmed,
		"correlated": correlated,
		"rapid_attack": rapid_attack,
		"sequence_detected": sequence_result["sequence_detected"],
		"matched_chain": sequence_result["matched_chain"],
		"summary": summary,
	}


def correlate_alerts(alerts):
	"""Correlate alerts by source IP, save report, print correlated summaries."""
	grouped_alerts = group_by_ip(alerts)
	correlation_results = [
		assess_correlation(alert_group) for alert_group in grouped_alerts.values()
	]

	report = {
		"generated_at": datetime.datetime.utcnow().isoformat() + "Z",
		"total_input_alerts": len(alerts),
		"total_ip_groups": len(grouped_alerts),
		"results": correlation_results,
	}

	output_folder = "correlation_reports"
	os.makedirs(output_folder, exist_ok=True)
	report_name = (
		f"correlation_report_{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json"
	)
	report_path = os.path.join(output_folder, report_name)
	with open(report_path, "w", encoding="utf-8") as report_file:
		json.dump(report, report_file, indent=2)

	correlated_incidents = [r for r in correlation_results if r.get("correlated")]
	if correlated_incidents:
		print("=" * 60)
		print("Aegis-SOC Correlated Incidents")
		print("=" * 60)
		for incident in correlated_incidents:
			print(f"Source IP: {incident['source_ip']}")
			print(f"Total Alerts: {incident['total_alerts']}")
			print(f"Highest Severity: {incident['highest_severity']}")
			print(f"Threat Confirmed: {incident['threat_confirmed']}")
			print(f"Summary: {incident['summary']}")
			print(f"Rapid Attack: {incident['rapid_attack']}")
			print(f"Sequence Detected: {incident['sequence_detected']}")
			if incident.get("matched_chain") is not None:
				print(f"Matched Chain: {' → '.join(incident['matched_chain'])}")
			else:
				print("Matched Chain: None")
			print("-" * 60)

	return correlation_results
