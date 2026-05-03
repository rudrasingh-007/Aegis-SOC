"""
Aegis-SOC auth.log parser module.

Parses Linux auth.log files and converts entries into Aegis-SOC alert dicts.
Detects brute force attempts, failed logins, and privilege escalation attempts.
"""

import re
import random
from datetime import datetime


def generate_alert_id():
    """
    Generate a unique alert ID.
    
    Returns:
        String in format "AUTHLOG-XXXXXX" where X is a random digit
    """
    random_number = random.randint(100000, 999999)
    return f"AUTHLOG-{random_number}"


def parse_timestamp(timestamp_str):
    """
    Parse Linux log timestamp format "May  2 04:17:32" to "YYYY-MM-DD HH:MM:SS".
    
    Uses the current year to fill in the year field.
    
    Args:
        timestamp_str: String in format "May  2 04:17:32"
    
    Returns:
        String in format "YYYY-MM-DD HH:MM:SS" or None if parsing fails
    """
    try:
        current_year = datetime.now().year
        # Normalize multiple spaces to single space for consistent parsing
        normalized = ' '.join(timestamp_str.split())
        dt = datetime.strptime(f"{current_year} {normalized}", "%Y %b %d %H:%M:%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def extract_source_ip(log_line):
    """
    Extract source IP address from auth.log line.
    
    Looks for pattern: "from XXX.XXX.XXX.XXX port"
    
    Args:
        log_line: A line from auth.log
    
    Returns:
        IP address string or None if not found
    """
    match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)\s+port', log_line)
    if match:
        return match.group(1)
    return None


def extract_username_from_sudo(log_line):
    """
    Extract username from sudo line.
    
    Looks for pattern: "sudo: username :"
    
    Args:
        log_line: A line from auth.log containing sudo
    
    Returns:
        Username string or None if not found
    """
    match = re.search(r'sudo:\s+(\w+)\s+:', log_line)
    if match:
        return match.group(1)
    return None


def parse_auth_log_content(content):
    """
    Parse raw auth.log content (string) and return list of alert dicts.
    
    Parsing rules:
    1. Lines with "Failed password" or "Invalid user" are grouped by source IP.
       If attempt_count >= 3, alert_type is "brute_force", else "failed_login".
    2. Lines with "sudo", "COMMAND", and ("not allowed" or "incorrect password")
       are flagged as "privilege_escalation" attempts.
    3. Normal activity (Accepted password, session opened/closed, disconnect)
       is skipped.
    
    Args:
        content: Raw auth.log file content as a string
    
    Returns:
        List of alert dictionaries with fields:
        alert_id, timestamp, source_ip, alert_type, target_system, attempt_count
    """
    lines = content.strip().split('\n')
    
    # Track failed login attempts by source IP
    failed_attempts = {}
    alerts = []
    
    for line in lines:
        if not line.strip():
            continue
        
        # Skip normal activity lines
        if any(skip in line for skip in ['Accepted password', 'session opened', 
                                          'session closed', 'Received disconnect']):
            continue
        
        # Extract timestamp from line
        timestamp_match = re.search(r'(\w+\s+\d+\s+\d{2}:\d{2}:\d{2})', line)
        timestamp_str = timestamp_match.group(1) if timestamp_match else None
        timestamp = parse_timestamp(timestamp_str) if timestamp_str else None
        
        # Pattern 1: Failed login attempts (Failed password, Invalid user)
        if 'Failed password' in line or 'Invalid user' in line:
            source_ip = extract_source_ip(line)
            
            if source_ip:
                # Track attempts by source IP
                if source_ip not in failed_attempts:
                    failed_attempts[source_ip] = {
                        'count': 0,
                        'first_timestamp': timestamp,
                        'last_timestamp': timestamp
                    }
                failed_attempts[source_ip]['count'] += 1
                failed_attempts[source_ip]['last_timestamp'] = timestamp
        
        # Pattern 2: Privilege escalation (sudo with COMMAND and denial/failure)
        elif 'sudo' in line and 'COMMAND' in line and ('not allowed' in line or 'incorrect password' in line):
            username = extract_username_from_sudo(line)
            
            alert = {
                'alert_id': generate_alert_id(),
                'timestamp': timestamp,
                'source_ip': 'internal',
                'alert_type': 'privilege_escalation',
                'target_system': 'domain_controller',
                'attempt_count': 1
            }
            if username:
                alert['username'] = username
            alerts.append(alert)
    
    # Convert failed login attempts to alerts
    for source_ip, data in failed_attempts.items():
        attempt_count = data['count']
        alert_type = 'brute_force' if attempt_count >= 3 else 'failed_login'
        
        alert = {
            'alert_id': generate_alert_id(),
            'timestamp': data['first_timestamp'],
            'source_ip': source_ip,
            'alert_type': alert_type,
            'target_system': 'ssh_server',
            'attempt_count': attempt_count
        }
        alerts.append(alert)
    
    return alerts


def parse_auth_log(filepath):
    """
    Parse a Linux auth.log file and return list of alert dicts.
    
    Args:
        filepath: Path to the auth.log file
    
    Returns:
        List of alert dictionaries, or empty list if file not found or error occurs
    """
    try:
        with open(filepath, 'r') as f:
            content = f.read()
        return parse_auth_log_content(content)
    except FileNotFoundError:
        print(f"Error: File {filepath} not found.")
        return []
    except Exception as e:
        print(f"Error reading file {filepath}: {e}")
        return []
