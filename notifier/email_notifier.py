"""Email notification module for Aegis-SOC critical alerts."""

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from config.config import EMAIL_SENDER, EMAIL_PASSWORD, EMAIL_RECEIVER, CRITICAL


def send_critical_alert(alert):
	"""Send a critical alert email using Gmail SMTP over SSL."""
	message = MIMEMultipart()
	message["From"] = EMAIL_SENDER
	message["To"] = EMAIL_RECEIVER
	message["Subject"] = f"[Aegis-SOC] CRITICAL ALERT - {alert.get('alert_type', 'unknown')} from {alert.get('source_ip', 'unknown')}"

	body_lines = [
		f"Alert ID: {alert.get('alert_id', 'N/A')}",
		f"Timestamp: {alert.get('timestamp', 'N/A')}",
		f"Source IP: {alert.get('source_ip', 'N/A')}",
		f"Alert Type: {alert.get('alert_type', 'N/A')}",
		f"Target System: {alert.get('target_system', 'N/A')}",
		f"Attempt Count: {alert.get('attempt_count', 'N/A')}",
	]

	if "abuse_score" in alert:
		body_lines.append(f"Abuse Score: {alert.get('abuse_score')}")

	body_lines.append(f"Recommended Action: {alert.get('recommended_action', 'No action defined.')}")

	message.attach(MIMEText("\n".join(body_lines), "plain"))

	try:
		with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
			server.login(EMAIL_SENDER, EMAIL_PASSWORD)
			server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, message.as_string())
		print(f"Critical alert email sent successfully for alert {alert.get('alert_id', 'N/A')}.")
	except Exception as error:
		print(f"Failed to send critical alert email for alert {alert.get('alert_id', 'N/A')}: {error}")


def notify_critical_alerts(alerts):
	"""Send critical alert notifications for alerts with CRITICAL severity only."""
	for alert in alerts:
		if alert.get("severity") == CRITICAL:
			send_critical_alert(alert)
