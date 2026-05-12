"""Web log parser for Apache/Nginx access logs."""

import re
from datetime import datetime

SENSITIVE_PATHS = ['/admin', '/wp-admin', '/.env', '/phpmyadmin', '/.git', '/config', '/backup']
SQL_PATTERNS = ['SELECT', 'UNION', 'DROP', 'INSERT', 'OR 1=1', 'OR+1=1', 'UNION+SELECT']

# Regex for Apache/Nginx log format: ip - - [timestamp] "method path HTTP/1.1" status_code bytes
LOG_PATTERN = r'(\S+) - - \[([^\]]+)\] "(\S+) ([^\s]+) HTTP/[\d.]+\" (\d+) (\d+)'


def _convert_apache_timestamp(timestamp_str):
	"""Convert Apache timestamp format '12/May/2026:10:15:22 +0000' to 'YYYY-MM-DD HH:MM:SS'."""
	# timestamp_str format: "12/May/2026:10:15:22 +0000"
	timestamp_part = timestamp_str.split(' ')[0]
	dt = datetime.strptime(timestamp_part, '%d/%b/%Y:%H:%M:%S')
	return dt.strftime('%Y-%m-%d %H:%M:%S')


def parse_web_log_content(content):
	"""Parse Apache/Nginx access log content and return alerts list."""
	lines = content.strip().split('\n')
	
	# Track unique IPs and their characteristics
	ip_401_count = {}  # IP -> count of 401s
	ip_timestamps = {}  # IP -> first timestamp
	ip_has_sensitive = set()  # IPs that accessed sensitive paths
	ip_has_sql = set()  # IPs with SQL injection attempts
	
	for line in lines:
		if not line.strip():
			continue
		
		match = re.match(LOG_PATTERN, line)
		if not match:
			continue
		
		ip, timestamp_str, method, path, status_code_str, bytes_str = match.groups()
		status_code = int(status_code_str)
		
		# Store first timestamp for this IP
		if ip not in ip_timestamps:
			ip_timestamps[ip] = _convert_apache_timestamp(timestamp_str)
		
		# Check for 401 responses
		if status_code == 401:
			ip_401_count[ip] = ip_401_count.get(ip, 0) + 1
		
		# Check for sensitive paths
		for sensitive_path in SENSITIVE_PATHS:
			if sensitive_path in path:
				ip_has_sensitive.add(ip)
				break
		
		# Check for SQL injection patterns in path
		for sql_pattern in SQL_PATTERNS:
			if sql_pattern.upper() in path.upper():
				ip_has_sql.add(ip)
				break
	
	alerts = []
	alert_id_counter = 1
	
	# Generate alerts for 401 responses
	for ip, count in ip_401_count.items():
		if count >= 3:
			alert_type = "brute_force"
			attempt_count = count
		else:
			alert_type = "failed_login"
			attempt_count = 1
		
		alert = {
			"alert_id": f"WEBLOG-{alert_id_counter}",
			"timestamp": ip_timestamps[ip],
			"source_ip": ip,
			"alert_type": alert_type,
			"target_system": "web_server",
			"attempt_count": attempt_count,
		}
		alerts.append(alert)
		alert_id_counter += 1
	
	# Generate alerts for sensitive path access
	for ip in ip_has_sensitive:
		alert = {
			"alert_id": f"WEBLOG-{alert_id_counter}",
			"timestamp": ip_timestamps.get(ip, datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')),
			"source_ip": ip,
			"alert_type": "suspicious_connection",
			"target_system": "web_server",
			"attempt_count": 1,
		}
		alerts.append(alert)
		alert_id_counter += 1
	
	# Generate alerts for SQL injection
	for ip in ip_has_sql:
		alert = {
			"alert_id": f"WEBLOG-{alert_id_counter}",
			"timestamp": ip_timestamps.get(ip, datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')),
			"source_ip": ip,
			"alert_type": "malware_detected",
			"target_system": "web_server",
			"attempt_count": 1,
		}
		alerts.append(alert)
		alert_id_counter += 1
	
	return alerts


def parse_web_log(filepath):
	"""Parse an Apache/Nginx access log file and return alerts list."""
	try:
		with open(filepath, 'r', encoding='utf-8') as f:
			content = f.read()
		return parse_web_log_content(content)
	except Exception as e:
		print(f"Error reading {filepath}: {e}")
		return []
