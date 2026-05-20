"""Tests for the explainability explainer module."""

from explainability.explainer import explain_alert


def test_basic_alert():
	alert = {"alert_type": "brute_force"}

	explained = explain_alert(alert)

	assert isinstance(explained["explanation"], list)
	assert "brute_force" in explained["explanation"][0]


def test_reclassification():
	alert = {"original_severity": "HIGH", "severity": "CRITICAL"}

	explained = explain_alert(alert)

	assert any("reclassified" in item for item in explained["explanation"])


def test_threat_confirmed():
	alert = {
		"abuse_score": 85,
		"virustotal_score": 3,
		"threat_confirmed": True,
	}

	explained = explain_alert(alert)

	assert any("threat confirmed" in item for item in explained["explanation"])


def test_anomaly_flagged():
	alert = {"is_anomaly": True, "anomaly_score": -0.15}

	explained = explain_alert(alert)

	assert any("anomaly" in item for item in explained["explanation"])


def test_correlated():
	alert = {"correlated": True}

	explained = explain_alert(alert)

	assert any("Correlated" in item for item in explained["explanation"])
