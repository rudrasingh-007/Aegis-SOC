"""Suricata EVE JSON log parser."""

import json
from datetime import datetime

SURICATA_CATEGORY_MAP = {
	'Network Scan': 'port_scan',
	'Brute Force': 'brute_force',
	'Malware': 'malware_detected',
	'Attempted Administrator Privilege Gain': 'privilege_escalation',
	'Potentially Bad Traffic': 'dns_tunneling',
	'Denial of Service': 'ddos_attack',
	'Exploit Kit': 'malware_detected',
}


def _parse_suricata_timestamp(timestamp_str):
	"""Convert Suricata timestamp format '2026-05-12T10:15:22.000000+0000' to 'YYYY-MM-DD HH:MM:SS'."""
	# Parse the timestamp up to the microseconds, ignore timezone offset
	try:
		dt = datetime.strptime(timestamp_str.split('+')[0].split('.')[0], '%Y-%m-%dT%H:%M:%S')
		return dt.strftime('%Y-%m-%d %H:%M:%S')
	except Exception:
		return datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')


def parse_suricata_log_content(content):
	"""Parse Suricata EVE JSON log content and return alerts list."""
	lines = content.strip().split('\n')
	alerts = []
	alert_id_counter = 1
	
	for line in lines:
		if not line.strip():
			continue
		
		try:
			entry = json.loads(line)
		except json.JSONDecodeError:
			# Skip malformed JSON lines silently
			continue
		
		# Only process alert events
		if entry.get('event_type') != 'alert':
			continue
		
		# Extract fields
		src_ip = entry.get('src_ip')
		timestamp_str = entry.get('timestamp')
		alert_obj = entry.get('alert', {})
		category = alert_obj.get('category')
		severity = alert_obj.get('severity')
		signature = alert_obj.get('signature', '')
		
		if not src_ip or not timestamp_str:
			continue
		
		# Map category to alert type
		alert_type = SURICATA_CATEGORY_MAP.get(category, 'suspicious_connection')
		
		# Parse timestamp
		timestamp = _parse_suricata_timestamp(timestamp_str)
		
		# Build alert
		alert = {
			"alert_id": f"SURICATA-{alert_id_counter}",
			"timestamp": timestamp,
			"source_ip": src_ip,
			"alert_type": alert_type,
			"target_system": "firewall",
			"attempt_count": 1,
			"suricata_signature": signature,
		}
		
		alerts.append(alert)
		alert_id_counter += 1
	
	return alerts


def parse_suricata_log(filepath):
	"""Parse a Suricata EVE JSON log file and return alerts list."""
	try:
		with open(filepath, 'r', encoding='utf-8') as f:
			content = f.read()
		return parse_suricata_log_content(content)
	except Exception as e:
		print(f"Error reading {filepath}: {e}")
		return []
