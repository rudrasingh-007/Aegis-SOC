"""L2 investigation engine for deep analysis of critical security alerts."""

import os
import json
import datetime


SYSTEM_CRITICALITY = {
	"domain_controller": 5,
	"database": 4,
	"firewall": 3,
	"web_server": 2,
	"employee_workstation": 1,
}

ISOLATION_RECOMMENDATIONS = {
	"domain_controller": "ISOLATE IMMEDIATELY - Domain controller compromise affects entire network",
	"database": "ISOLATE AND PRESERVE EVIDENCE - Potential data breach or ransomware payload",
	"firewall": "ISOLATE AND REPLACE - Perimeter defense compromised",
	"web_server": "ISOLATE AND PATCH - Public facing service compromised",
	"employee_workstation": "INVESTIGATE BEFORE ISOLATING - Potential lateral movement entry point",
}


def build_timeline(alert):
	"""Build a simple attack timeline narrative from alert fields."""
	timestamp = alert.get("timestamp", "N/A")
	alert_type = alert.get("alert_type", "unknown")
	source_ip = alert.get("source_ip", "unknown")
	target_system = alert.get("target_system", "unknown")
	attempt_count = alert.get("attempt_count", "N/A")

	timeline = [
		f"{timestamp} - Initial alert detected: {alert_type}",
		f"{timestamp} - Suspicious activity originated from source IP {source_ip}",
		f"{timestamp} - Targeted system identified as {target_system}",
		f"{timestamp} - Observed attempt count: {attempt_count}",
		f"{datetime.datetime.utcnow().isoformat()}Z - L2 investigation initiated",
	]

	return timeline


def assess_impact(alert):
	"""Assess target criticality and recommend isolation response."""
	target_system = alert.get("target_system", "employee_workstation")
	criticality_score = SYSTEM_CRITICALITY.get(target_system, 1)

	if criticality_score >= 4:
		impact_level = "SEVERE"
	elif criticality_score == 3:
		impact_level = "HIGH"
	else:
		impact_level = "MODERATE"

	return {
		"criticality_score": criticality_score,
		"impact_level": impact_level,
		"isolation_recommendation": ISOLATION_RECOMMENDATIONS.get(
			target_system,
			"INVESTIGATE BEFORE ISOLATING - Unknown system profile",
		),
	}


def investigate(alert):
	"""Create and save an L2 investigation report for one critical alert."""
	timeline = build_timeline(alert)
	impact_assessment = assess_impact(alert)

	threat_intel_scores = {
		key: value
		for key, value in alert.items()
		if key.endswith("_score") or key in {"threat_confirmed"}
	}

	report = {
		"report_generated_at": datetime.datetime.utcnow().isoformat() + "Z",
		"original_alert": alert,
		"timeline": timeline,
		"impact_assessment": impact_assessment,
		"threat_intel": threat_intel_scores,
	}

	output_folder = "l2_reports"
	os.makedirs(output_folder, exist_ok=True)

	alert_id = alert.get(
		"alert_id", f"l2-{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
	)
	output_path = os.path.join(output_folder, f"{alert_id}_l2_report.json")
	with open(output_path, "w", encoding="utf-8") as output_file:
		json.dump(report, output_file, indent=2)

	print("=" * 60)
	print("Aegis-SOC L2 Investigation Summary")
	print("=" * 60)
	print(f"Alert ID: {alert.get('alert_id', 'N/A')}")
	print(f"Severity: {alert.get('severity', 'N/A')}")
	print(f"Alert Type: {alert.get('alert_type', 'N/A')}")
	print(f"Target System: {alert.get('target_system', 'N/A')}")
	print(f"Criticality Score: {impact_assessment['criticality_score']}")
	print(f"Impact Level: {impact_assessment['impact_level']}")
	print(f"Isolation Recommendation: {impact_assessment['isolation_recommendation']}")
	if threat_intel_scores:
		print("Threat Intel Scores:")
		for key, value in threat_intel_scores.items():
			print(f"  - {key}: {value}")
	print(f"Report Saved To: {output_path}")
	print("=" * 60)


def run_l2_investigation(alerts):
	"""Run L2 investigation only for alerts marked as CRITICAL."""
	for alert in alerts:
		if alert.get("severity") == "CRITICAL":
			investigate(alert)
