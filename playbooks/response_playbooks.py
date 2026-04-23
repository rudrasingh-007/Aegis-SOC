"""Response playbooks module for Aegis-SOC."""

import os
import json
import datetime


PLAYBOOKS = {
	"malware_detected": {
		"name": "Malware Containment and Recovery",
		"description": "Contain malware, preserve evidence, identify the threat, and restore operations.",
		"steps": [
			"1. Isolate the affected system from the network.",
			"2. Preserve forensic evidence before making changes.",
			"3. Identify the malware family and infection vector.",
			"4. Run a full system scan across affected endpoints.",
			"5. Recover systems from known clean backups and monitor for reinfection.",
		],
	},
	"ransomware_detected": {
		"name": "Ransomware Response and Restoration",
		"description": "Stop ransomware spread, confirm backups, and restore from clean sources.",
		"steps": [
			"1. Immediately isolate the affected host and any connected systems.",
			"2. Verify backup integrity and availability for impacted assets.",
			"3. Identify the ransomware variant and scope of encryption.",
			"4. Capture forensic images before remediation begins.",
			"5. Restore from a known clean backup after validation.",
			"6. Conduct a post-incident review and harden controls.",
		],
	},
	"ddos_attack": {
		"name": "DDoS Mitigation and Service Recovery",
		"description": "Analyze traffic, contain the flood, and restore service availability.",
		"steps": [
			"1. Analyze inbound traffic patterns and identify attack vectors.",
			"2. Apply upstream filtering and scrubbing where available.",
			"3. Enable rate limiting and protective controls on exposed services.",
			"4. Notify the ISP or upstream provider for assistance.",
			"5. Scale infrastructure or fail over to absorb the load.",
			"6. Restore service stability and validate normal traffic levels.",
		],
	},
	"privilege_escalation": {
		"name": "Privilege Escalation Containment",
		"description": "Lock down accounts, review access paths, and verify credential compromise.",
		"steps": [
			"1. Lock down suspicious accounts and privileged identities.",
			"2. Terminate active sessions associated with the incident.",
			"3. Review access logs for abnormal elevation paths.",
			"4. Identify compromised credentials or tokens.",
			"5. Perform a privilege audit across impacted systems.",
			"6. Increase monitoring for repeated escalation attempts.",
		],
	},
	"dns_tunneling": {
		"name": "DNS Tunneling Detection and Response",
		"description": "Block malicious DNS activity, isolate affected hosts, and hunt for persistence.",
		"steps": [
			"1. Block suspicious DNS traffic and domains at the resolver or firewall.",
			"2. Isolate the affected system from the network.",
			"3. Identify the command-and-control channel using DNS indicators.",
			"4. Run a full network scan for related activity.",
			"5. Harden DNS policies and monitoring controls.",
			"6. Conduct a threat hunt for additional tunnel activity.",
		],
	},
}


def get_playbook(alert_type):
	"""Return a matching playbook or a generic default playbook."""
	return PLAYBOOKS.get(
		alert_type,
		{
			"name": "Generic Incident Response",
			"description": "General response actions for unmapped alert types.",
			"steps": [
				"1. Review the alert and validate the signal.",
				"2. Determine scope and potential impact.",
				"3. Preserve evidence and document findings.",
				"4. Escalate to the appropriate response team.",
				"5. Monitor for related activity and close the incident when safe.",
			],
		},
	)


def execute_playbook(alert):
	"""Print and save a playbook execution for a single alert."""
	alert_type = alert.get("alert_type", "unknown")
	playbook = get_playbook(alert_type)

	execution = {
		"executed_at": datetime.datetime.utcnow().isoformat() + "Z",
		"alert": alert,
		"playbook": playbook,
	}

	output_folder = "playbook_executions"
	os.makedirs(output_folder, exist_ok=True)

	alert_id = alert.get(
		"alert_id", f"playbook-{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
	)
	output_path = os.path.join(output_folder, f"{alert_id}.json")
	with open(output_path, "w", encoding="utf-8") as output_file:
		json.dump(execution, output_file, indent=2)

	print("=" * 60)
	print("Aegis-SOC Response Playbook")
	print("=" * 60)
	print(f"Alert ID: {alert.get('alert_id', 'N/A')}")
	print(f"Severity: {alert.get('severity', 'N/A')}")
	print(f"Alert Type: {alert_type}")
	print(f"Playbook: {playbook['name']}")
	print(f"Description: {playbook['description']}")
	print("Steps:")
	for step in playbook["steps"]:
		print(f"  - {step}")
	print(f"Execution Saved To: {output_path}")
	print("=" * 60)

	return playbook


def run_playbooks(alerts):
	"""Execute playbooks only for HIGH and CRITICAL alerts."""
	for alert in alerts:
		if alert.get("severity") in {"HIGH", "CRITICAL"}:
			execute_playbook(alert)
