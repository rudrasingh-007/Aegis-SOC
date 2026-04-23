"""Wazuh SIEM integration module for Aegis-SOC."""

import json
import datetime
import os


WAZUH_RULE_SEVERITY_MAP = {
	1: "LOW",
	2: "LOW",
	3: "LOW",
	4: "MEDIUM",
	5: "MEDIUM",
	6: "MEDIUM",
	7: "MEDIUM",
	8: "HIGH",
	9: "HIGH",
	10: "HIGH",
	11: "HIGH",
	12: "CRITICAL",
	13: "CRITICAL",
	14: "CRITICAL",
	15: "CRITICAL",
}


def parse_wazuh_alert(wazuh_alert):
	"""Convert a Wazuh alert to an Aegis-SOC compatible alert dictionary."""
	rule = wazuh_alert.get("rule", {})
	agent = wazuh_alert.get("agent", {})

	rule_level = int(rule.get("level", 1))
	severity = WAZUH_RULE_SEVERITY_MAP.get(rule_level, "LOW")

	alert_id = wazuh_alert.get(
		"id", f"WAZUH-{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}"
	)
	timestamp = wazuh_alert.get("timestamp") or wazuh_alert.get("@timestamp")
	if not timestamp:
		timestamp = datetime.datetime.utcnow().isoformat() + "Z"

	alert_type = str(rule.get("description", "wazuh_event")).strip().lower()
	alert_type = "_".join(alert_type.split())

	return {
		"alert_id": alert_id,
		"timestamp": timestamp,
		"source_ip": agent.get("ip", "unknown"),
		"alert_type": alert_type,
		"target_system": agent.get("name", "unknown"),
		"attempt_count": 1,
		"severity": severity,
	}


def load_wazuh_alerts_from_file(filepath):
	"""Load Wazuh alerts from a JSON file and parse to Aegis-SOC format."""
	with open(filepath, "r", encoding="utf-8") as file:
		wazuh_alerts = json.load(file)

	return [parse_wazuh_alert(alert) for alert in wazuh_alerts]


def generate_sample_wazuh_alerts():
	"""Generate sample Wazuh alerts in real format and save to integrations folder."""
	sample_alerts = [
		{
			"id": "1741012345.1001",
			"timestamp": "2026-04-23T08:12:31Z",
			"rule": {
				"level": 6,
				"description": "Multiple failed logins detected",
			},
			"agent": {
				"id": "001",
				"name": "web-server-01",
				"ip": "203.0.113.24",
			},
			"manager": {"name": "wazuh-manager-1"},
		},
		{
			"id": "1741012388.1002",
			"timestamp": "2026-04-23T08:13:14Z",
			"rule": {
				"level": 10,
				"description": "Port scan activity from external source",
			},
			"agent": {
				"id": "002",
				"name": "firewall-gateway",
				"ip": "198.51.100.77",
			},
			"manager": {"name": "wazuh-manager-1"},
		},
		{
			"id": "1741012459.1003",
			"timestamp": "2026-04-23T08:14:29Z",
			"rule": {
				"level": 14,
				"description": "Ransomware behavior detected on endpoint",
			},
			"agent": {
				"id": "003",
				"name": "finance-workstation-07",
				"ip": "192.0.2.56",
			},
			"manager": {"name": "wazuh-manager-1"},
		},
	]

	output_folder = "integrations"
	os.makedirs(output_folder, exist_ok=True)
	output_path = os.path.join(output_folder, "sample_wazuh_alerts.json")

	with open(output_path, "w", encoding="utf-8") as file:
		json.dump(sample_alerts, file, indent=2)
