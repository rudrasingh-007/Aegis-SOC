"""Tests for web log parser module."""

import pytest

from log_parser.web_log_parser import parse_web_log_content


def make_log_line(ip, path, status_code, timestamp='12/May/2026:10:15:22 +0000'):
	"""Create a properly formatted Apache/Nginx log line."""
	method = "GET"
	bytes_count = 1024
	return f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" {status_code} {bytes_count}'


def test_three_or_more_401_responses_produces_brute_force_alert():
	"""Test that 3+ 401 responses from same IP produces a brute_force alert."""
	log_content = '\n'.join([
		make_log_line("192.168.1.105", "/admin/login", 401),
		make_log_line("192.168.1.105", "/admin/login", 401),
		make_log_line("192.168.1.105", "/admin/login", 401),
	])
	
	alerts = parse_web_log_content(log_content)
	
	# Should have one brute_force alert
	brute_force_alerts = [a for a in alerts if a.get("alert_type") == "brute_force"]
	assert len(brute_force_alerts) == 1
	assert brute_force_alerts[0]["attempt_count"] == 3


def test_fewer_than_three_401_responses_produces_failed_login_alert():
	"""Test that 1-2 401 responses from same IP produces a failed_login alert."""
	log_content = '\n'.join([
		make_log_line("10.0.0.1", "/admin/login", 401),
		make_log_line("10.0.0.1", "/admin/login", 401),
	])
	
	alerts = parse_web_log_content(log_content)
	
	# Should have one failed_login alert
	failed_login_alerts = [a for a in alerts if a.get("alert_type") == "failed_login"]
	assert len(failed_login_alerts) == 1
	assert failed_login_alerts[0]["attempt_count"] == 1


def test_sensitive_path_access_produces_suspicious_connection_alert():
	"""Test that a request to a sensitive path produces a suspicious_connection alert."""
	log_content = '\n'.join([
		make_log_line("203.45.67.89", "/admin", 404),
		make_log_line("203.45.67.89", "/", 200),
	])
	
	alerts = parse_web_log_content(log_content)
	
	# Should have one suspicious_connection alert
	suspicious_alerts = [a for a in alerts if a.get("alert_type") == "suspicious_connection"]
	assert len(suspicious_alerts) == 1
	assert suspicious_alerts[0]["source_ip"] == "203.45.67.89"


def test_sql_injection_in_url_produces_malware_detected_alert():
	"""Test that a request with SQL injection in URL produces a malware_detected alert."""
	log_content = '\n'.join([
		make_log_line("185.220.101.45", "/search?q=SELECT+*+FROM+users", 200),
		make_log_line("185.220.101.45", "/", 200),
	])
	
	alerts = parse_web_log_content(log_content)
	
	# Should have one malware_detected alert
	malware_alerts = [a for a in alerts if a.get("alert_type") == "malware_detected"]
	assert len(malware_alerts) == 1
	assert malware_alerts[0]["source_ip"] == "185.220.101.45"


def test_normal_200_responses_produce_no_alerts():
	"""Test that normal 200 responses to normal paths produce no alerts."""
	log_content = '\n'.join([
		make_log_line("72.14.207.99", "/index.html", 200),
		make_log_line("72.14.207.99", "/about.html", 200),
		make_log_line("203.45.67.89", "/css/style.css", 200),
		make_log_line("203.45.67.89", "/js/script.js", 200),
	])
	
	alerts = parse_web_log_content(log_content)
	
	# Should have no alerts
	assert len(alerts) == 0
