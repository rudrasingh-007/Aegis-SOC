"""Tests for the confidence scoring module."""

from confidence.confidence_scorer import score_alert


def test_empty_alert_scores_zero():
	alert = {}

	scored = score_alert(alert)

	assert scored["confidence_score"] == 0


def test_threat_confirmed_adds_25():
	alert = {"threat_confirmed": True}

	scored = score_alert(alert)

	assert scored["confidence_score"] == 25


def test_multiple_signals_add_up():
	alert = {
		"threat_confirmed": True,
		"correlated": True,
		"is_anomaly": True,
	}

	scored = score_alert(alert)

	assert scored["confidence_score"] == 50


def test_score_capped_at_100():
	alert = {
		"threat_confirmed": True,
		"sequence_detected": True,
		"abuse_score": 100,
		"correlated": True,
		"is_anomaly": True,
		"file_hash_score": 10,
		"virustotal_score": 10,
	}

	scored = score_alert(alert)

	assert scored["confidence_score"] == 100


def test_confidence_score_is_integer():
	alert = {"virustotal_score": 1}

	scored = score_alert(alert)

	assert isinstance(scored["confidence_score"], int) is True
