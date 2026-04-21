"""False positive logging module for Aegis-SOC."""

import os
import json
import datetime


LOG_FOLDER = "logs"
LOG_FILE = os.path.join(LOG_FOLDER, "false_positives.json")


def is_false_positive(alert):
	"""Return True when an alert is considered a false positive."""
	return alert.get("severity") == "LOW" or alert.get("threat_confirmed") is False


def log_false_positive(alert):
	"""Append a false positive alert to the JSON log file."""
	os.makedirs(LOG_FOLDER, exist_ok=True)

	alert_to_log = dict(alert)
	alert_to_log["logged_at"] = datetime.datetime.utcnow().isoformat() + "Z"

	existing_alerts = []
	if os.path.exists(LOG_FILE):
		try:
			with open(LOG_FILE, "r", encoding="utf-8") as log_file:
				existing_alerts = json.load(log_file)
				if not isinstance(existing_alerts, list):
					existing_alerts = []
		except (json.JSONDecodeError, OSError):
			existing_alerts = []

	existing_alerts.append(alert_to_log)

	with open(LOG_FILE, "w", encoding="utf-8") as log_file:
		json.dump(existing_alerts, log_file, indent=2)


def log_false_positives(alerts):
	"""Log all false positives from a list of alerts."""
	logged_count = 0

	for alert in alerts:
		if is_false_positive(alert):
			log_false_positive(alert)
			logged_count += 1

	print(f"Logged {logged_count} false positives.")
