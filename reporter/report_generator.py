"""Report generation module for Aegis-SOC alerts."""

import os
import json
import datetime

from config.config import REPORTS_OUTPUT_FOLDER


def get_recommended_action(severity):
	"""Return recommended SOC action for a given severity level."""
	actions = {
		"CRITICAL": "Immediate escalation to L2. Isolate affected system.",
		"HIGH": "Investigate immediately. Check related logs.",
		"MEDIUM": "Monitor closely. Verify with threat intel.",
		"LOW": "Log and ignore. Likely false positive.",
	}
	return actions.get(severity, "No action defined.")


def generate_report(alert):
	"""Print a readable alert report and save it as a JSON file."""
	os.makedirs(REPORTS_OUTPUT_FOLDER, exist_ok=True)

	report = {
		"generated_at": datetime.datetime.utcnow().isoformat() + "Z",
		"alert": alert,
		"recommended_action": get_recommended_action(alert.get("severity", "")),
	}

	print("=" * 50)
	print("Aegis-SOC Alert Report")
	print("=" * 50)
	print(f"Alert ID: {alert.get('alert_id', 'N/A')}")
	print(f"Timestamp: {alert.get('timestamp', 'N/A')}")
	print(f"Source IP: {alert.get('source_ip', 'N/A')}")
	print(f"Alert Type: {alert.get('alert_type', 'N/A')}")
	print(f"Target System: {alert.get('target_system', 'N/A')}")
	print(f"Attempt Count: {alert.get('attempt_count', 'N/A')}")
	print(f"Severity: {alert.get('severity', 'N/A')}")
	if "abuse_score" in alert:
		print(f"Abuse Score: {alert.get('abuse_score')}")

	if "virustotal_score" in alert:
		print(f"VirusTotal Score: {alert.get('virustotal_score')}")	

	if "threat_confirmed" in alert:
		print(f"Threat Confirmed: {alert.get('threat_confirmed')}")
	print(f"Recommended Action: {report['recommended_action']}")
	print("=" * 50)

	alert_id = alert.get("alert_id", f"alert-{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}")
	report_path = os.path.join(REPORTS_OUTPUT_FOLDER, f"{alert_id}.json")
	with open(report_path, "w", encoding="utf-8") as report_file:
		json.dump(report, report_file, indent=2)


def generate_reports(alerts):
	"""Generate reports for each alert in the input list."""
	for alert in alerts:
		generate_report(alert)
