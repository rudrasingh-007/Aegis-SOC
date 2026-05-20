def explain_alert(alert):
	"""Add a plain-English explanation list to a single alert dict."""
	explanations = []

	alert_type = alert.get("alert_type")
	if alert_type is not None:
		explanations.append(f"Alert type: {alert_type}")

	mitre_tactic = alert.get("mitre_tactic")
	mitre_technique_id = alert.get("mitre_technique_id")
	if mitre_tactic is not None or mitre_technique_id is not None:
		parts = ["MITRE:"]
		if mitre_tactic is not None:
			parts.append(str(mitre_tactic))
		if mitre_technique_id is not None:
			if mitre_tactic is not None:
				parts.append(f"— {mitre_technique_id}")
			else:
				parts.append(str(mitre_technique_id))
		explanations.append(" ".join(parts).replace("  ", " ").strip())

	abuse_score = alert.get("abuse_score")
	virustotal_score = alert.get("virustotal_score")
	if abuse_score is not None or virustotal_score is not None:
		threat_confirmed = alert.get("threat_confirmed")
		status_text = "threat confirmed" if threat_confirmed else "threat not confirmed"
		explanations.append(
			f"AbuseIPDB score: {abuse_score}, VirusTotal score: {virustotal_score} — {status_text}"
		)

	file_hash_score = alert.get("file_hash_score")
	if file_hash_score is not None and file_hash_score > 0:
		explanations.append(f"File hash flagged by VirusTotal: score {file_hash_score}")

	if alert.get("correlated") is True:
		explanations.append("Correlated with other alerts from same source IP")

	original_severity = alert.get("original_severity")
	current_severity = alert.get("severity")
	if original_severity is not None and current_severity is not None and original_severity != current_severity:
		explanations.append(
			f"Severity reclassified from {original_severity} to {current_severity}"
		)

	if alert.get("is_anomaly") is True:
		explanations.append(
			f"Flagged as anomaly by ML detector (score: {alert.get('anomaly_score')})"
		)

	alert["explanation"] = explanations
	return alert


def explain_alerts(alerts):
	"""Add explanations to a list of alert dicts and return the updated list."""
	return [explain_alert(alert) for alert in alerts]
