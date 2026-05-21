def score_alert(alert):
	"""Add a confidence score to a single alert dict."""
	score = 0

	if alert.get("threat_confirmed") is True:
		score += 25

	if alert.get("sequence_detected") is True:
		score += 20

	if alert.get("abuse_score", 0) > 75:
		score += 15

	if alert.get("correlated") is True:
		score += 15

	if alert.get("is_anomaly") is True:
		score += 10

	if alert.get("file_hash_score", 0) > 0:
		score += 10

	if alert.get("virustotal_score", 0) > 0:
		score += 5

	alert["confidence_score"] = int(min(score, 100))
	return alert


def score_alerts(alerts):
	"""Add confidence scores to a list of alerts and return the updated list."""
	return [score_alert(alert) for alert in alerts]
