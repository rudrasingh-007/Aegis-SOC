import pytest

from anomaly import anomaly_detector


def _make_alert(source_ip="10.0.0.1", alert_type="failed_login", attempt_count=3):
	"""Build a minimal alert payload for anomaly detector tests."""
	return {
		"alert_id": "ALERT-100001",
		"source_ip": source_ip,
		"alert_type": alert_type,
		"attempt_count": attempt_count,
	}


@pytest.fixture
def stub_history_store(monkeypatch):
	"""Stub out save/get history store calls so tests never touch real DB."""
	state = {"last_saved_alerts": []}

	def fake_save_alerts(alerts):
		state["last_saved_alerts"] = alerts

	def fake_get_historical_data():
		return state["last_saved_alerts"]

	monkeypatch.setattr(anomaly_detector, "save_alerts", fake_save_alerts)
	monkeypatch.setattr(anomaly_detector, "get_historical_data", fake_get_historical_data)
	return state


def test_every_alert_gets_is_anomaly_field(stub_history_store):
	alerts = [
		_make_alert(source_ip="10.0.0.1", alert_type="failed_login", attempt_count=2),
		_make_alert(source_ip="10.0.0.2", alert_type="failed_login", attempt_count=3),
	]

	result = anomaly_detector.run_anomaly_detection(alerts)

	assert all("is_anomaly" in alert for alert in result)


def test_every_alert_gets_anomaly_score_float(stub_history_store):
	alerts = [
		_make_alert(source_ip="10.0.0.1", alert_type="failed_login", attempt_count=2),
		_make_alert(source_ip="10.0.0.2", alert_type="port_scan", attempt_count=4),
	]

	result = anomaly_detector.run_anomaly_detection(alerts)

	assert all("anomaly_score" in alert and isinstance(alert["anomaly_score"], float) for alert in result)


def test_every_alert_gets_expected_anomaly_details_keys(stub_history_store):
	alerts = [
		_make_alert(source_ip="10.0.0.1", alert_type="failed_login", attempt_count=2),
		_make_alert(source_ip="10.0.0.2", alert_type="port_scan", attempt_count=4),
	]

	result = anomaly_detector.run_anomaly_detection(alerts)

	for alert in result:
		assert "anomaly_details" in alert
		assert isinstance(alert["anomaly_details"], dict)
		assert set(alert["anomaly_details"].keys()) == {
			"attempt_count_anomaly",
			"ip_frequency_anomaly",
			"alert_type_anomaly",
		}


def test_fewer_than_two_alerts_sets_is_anomaly_false(stub_history_store):
	alerts = [_make_alert(source_ip="10.0.0.1", alert_type="failed_login", attempt_count=7)]

	result = anomaly_detector.run_anomaly_detection(alerts)

	assert all(alert["is_anomaly"] is False for alert in result)


def test_fewer_than_two_alerts_sets_anomaly_score_zero(stub_history_store):
	alerts = [_make_alert(source_ip="10.0.0.1", alert_type="failed_login", attempt_count=7)]

	result = anomaly_detector.run_anomaly_detection(alerts)

	assert all(alert["anomaly_score"] == 0.0 for alert in result)


def test_uniform_batch_with_one_high_attempt_count_flags_anomaly(stub_history_store):
	alerts = [
		_make_alert(source_ip="10.0.0.1", alert_type="failed_login", attempt_count=5),
		_make_alert(source_ip="10.0.0.2", alert_type="failed_login", attempt_count=5),
		_make_alert(source_ip="10.0.0.3", alert_type="failed_login", attempt_count=5),
		_make_alert(source_ip="10.0.0.4", alert_type="failed_login", attempt_count=120),
	]

	result = anomaly_detector.run_anomaly_detection(alerts)

	assert any(alert["is_anomaly"] for alert in result)
