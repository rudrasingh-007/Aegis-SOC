"""Tests for Suricata EVE JSON parser module."""

import json

from log_parser.suricata_parser import parse_suricata_log_content


def make_suricata_line(src_ip, category, signature, severity=2, timestamp='2026-05-12T10:15:22.000000+0000'):
	"""Create a properly formatted Suricata EVE alert JSON line."""
	return json.dumps({
		"timestamp": timestamp,
		"event_type": "alert",
		"src_ip": src_ip,
		"alert": {
			"category": category,
			"signature": signature,
			"severity": severity,
		},
	})


def test_network_scan_category_produces_port_scan_alert():
	"""Test that a Network Scan category produces a port_scan alert."""
	log_content = make_suricata_line("192.168.1.10", "Network Scan", "ET SCAN Nmap Scripting Engine User-Agent Detected")

	alerts = parse_suricata_log_content(log_content)

	assert len(alerts) == 1
	assert alerts[0]["alert_type"] == "port_scan"


def test_brute_force_category_produces_brute_force_alert():
	"""Test that a Brute Force category produces a brute_force alert."""
	log_content = make_suricata_line("10.0.0.5", "Brute Force", "SURICATA SSH Brute Force Attempt")

	alerts = parse_suricata_log_content(log_content)

	assert len(alerts) == 1
	assert alerts[0]["alert_type"] == "brute_force"


def test_malware_category_produces_malware_detected_alert():
	"""Test that a Malware category produces a malware_detected alert."""
	log_content = make_suricata_line("185.220.101.45", "Malware", "ET MALWARE Possible Malicious File Download")

	alerts = parse_suricata_log_content(log_content)

	assert len(alerts) == 1
	assert alerts[0]["alert_type"] == "malware_detected"


def test_unknown_category_produces_suspicious_connection_alert():
	"""Test that an unknown category produces a suspicious_connection alert."""
	log_content = make_suricata_line("203.0.113.25", "Unknown Category", "Some Unknown Signature")

	alerts = parse_suricata_log_content(log_content)

	assert len(alerts) == 1
	assert alerts[0]["alert_type"] == "suspicious_connection"


def test_malformed_json_line_is_skipped_and_no_alert_is_produced():
	"""Test that a malformed JSON line is skipped and no alert is produced."""
	log_content = '{"timestamp": "2026-05-12T10:15:22.000000+0000", "event_type": "alert"\n'

	alerts = parse_suricata_log_content(log_content)

	assert len(alerts) == 0