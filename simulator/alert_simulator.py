"""Alert simulator module for generating synthetic SOC alerts."""

import random
import datetime


SOURCE_IPS = [
	"185.220.101.14",
	"45.95.147.30",
	"103.27.124.98",
	"91.240.118.171",
	"198.54.117.212",
	"176.65.134.77",
]

ALERT_TYPES = [
	"failed_login",
	"port_scan",
	"malware_detected",
	"suspicious_connection",
	"brute_force",
	"unauthorized_wifi_access",
	"ransomware_detected",
	"privilege_escalation",
	"ddos_attack",
	"dns_tunneling",
]

TARGET_SYSTEMS = [
	"web_server",
	"database",
	"firewall",
	"domain_controller",
	"employee_workstation",
]


KNOWN_MALWARE_HASHES = [
    '24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c',
    '027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745',
    '60ac1b794c461943a3be1e57f1de5861d00a0bff0a7636dbf8b5634db623c20f',
    'aee20ee245900ba0b74a849bc6ebe742f5b0755e869f9bb7bf7a9d9e7d3e1e5f',
    '0f2d6a4a7a4b9c3e5d1f8b2c7e9a6d3f1c5e8b4a2d7f9c1e3b6a8d2f4c7e9b1',
]


def generate_alert():
	"""Generate and return a single simulated alert dictionary."""
	alert_type = random.choice(ALERT_TYPES)
	# Assign file_hash only for malware/ransomware detections
	if alert_type in ("malware_detected", "ransomware_detected"):
		file_hash = random.choice(KNOWN_MALWARE_HASHES)
	else:
		file_hash = None

	return {
		"alert_id": f"ALERT-{random.randint(100000, 999999)}",
		"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
		"source_ip": random.choice(SOURCE_IPS),
		"alert_type": alert_type,
		"target_system": random.choice(TARGET_SYSTEMS),
		"attempt_count": random.randint(1, 25),
		"file_hash": file_hash,
	}


def generate_alerts(count):
	"""Generate and return a list containing `count` simulated alerts.
	
	Enforces: privilege_escalation alerts only occur if a prior alert
	from the same source_ip has alert_type of brute_force or failed_login.
	If not, replaces privilege_escalation with brute_force.
	"""
	alerts = []
	for _ in range(count):
		alert = generate_alert()
		
		# Check privilege_escalation prerequisite rule
		if alert["alert_type"] == "privilege_escalation":
			source_ip = alert["source_ip"]
			# Look for a prior alert from same source_ip with brute_force or failed_login
			has_prerequisite = any(
				a["source_ip"] == source_ip and a["alert_type"] in ("brute_force", "failed_login")
				for a in alerts
			)
			# If no prerequisite exists, replace with brute_force
			if not has_prerequisite:
				alert["alert_type"] = "brute_force"
		
		alerts.append(alert)
	
	return alerts
