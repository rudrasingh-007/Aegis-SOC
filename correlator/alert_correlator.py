"""Alert correlation module for Aegis-SOC."""

import os
import json
import datetime


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
			print("-" * 60)

	return correlation_results
