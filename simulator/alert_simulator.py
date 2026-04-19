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
]

TARGET_SYSTEMS = [
	"web_server",
	"database",
	"firewall",
	"domain_controller",
	"employee_workstation",
]


def generate_alert():
	"""Generate and return a single simulated alert dictionary."""
	return {
		"alert_id": f"ALERT-{random.randint(100000, 999999)}",
		"timestamp": datetime.datetime.utcnow().isoformat() + "Z",
		"source_ip": random.choice(SOURCE_IPS),
		"alert_type": random.choice(ALERT_TYPES),
		"target_system": random.choice(TARGET_SYSTEMS),
		"attempt_count": random.randint(1, 25),
	}


def generate_alerts(count):
	"""Generate and return a list containing `count` simulated alerts."""
	return [generate_alert() for _ in range(count)]
