import importlib
import sys
import types

import pytest


@pytest.fixture(scope="module")
def anomaly_detector_module():
	"""Import anomaly_detector with a stubbed storage.history_store dependency."""
	storage_module = types.ModuleType("storage")
	history_store_module = types.ModuleType("storage.history_store")
	history_store_module.save_alerts = lambda alerts: None
	history_store_module.get_historical_data = lambda: []
	storage_module.history_store = history_store_module

	original_storage = sys.modules.get("storage")
	original_history_store = sys.modules.get("storage.history_store")
	sys.modules["storage"] = storage_module
	sys.modules["storage.history_store"] = history_store_module

	try:
		module = importlib.import_module("anomaly.anomaly_detector")
		yield module
	finally:
		if original_storage is not None:
			sys.modules["storage"] = original_storage
		else:
			sys.modules.pop("storage", None)

		if original_history_store is not None:
			sys.modules["storage.history_store"] = original_history_store
		else:
			sys.modules.pop("storage.history_store", None)


def _make_attempt_alert(attempt_count):
	return {"source_ip": "10.0.0.1", "attempt_count": attempt_count}


def _make_ip_alert(source_ip):
	return {"source_ip": source_ip, "alert_type": "port_scan"}


def _make_type_alert(alert_type):
	return {"source_ip": "10.0.0.1", "alert_type": alert_type}


def test_attempt_count_anomaly_detected(anomaly_detector_module):
	baseline_alerts = [_make_attempt_alert(1) for _ in range(12)] + [_make_attempt_alert(2)]
	alerts = [_make_attempt_alert(100)]

	result = anomaly_detector_module.detect_attempt_count_anomalies(
		alerts, baseline_alerts=baseline_alerts
	)

	assert result[0]["attempt_count_anomaly"] is True
	assert result[0]["attempt_count_zscore"] > 2.0


def test_attempt_count_no_anomaly(anomaly_detector_module):
	baseline_alerts = [_make_attempt_alert(10) for _ in range(8)]
	alerts = [_make_attempt_alert(10)]

	result = anomaly_detector_module.detect_attempt_count_anomalies(
		alerts, baseline_alerts=baseline_alerts
	)

	assert result[0]["attempt_count_anomaly"] is False
	assert result[0]["attempt_count_zscore"] == 0.0


def test_ip_frequency_anomaly_detected(anomaly_detector_module):
    baseline_alerts = (
        [_make_ip_alert("10.0.0.1") for _ in range(50)]
        + [_make_ip_alert("10.0.0.2")]
        + [_make_ip_alert("10.0.0.3")]
        + [_make_ip_alert("10.0.0.4")]
    )
    alerts = [_make_ip_alert("10.0.0.1")]
    result = anomaly_detector_module.detect_ip_frequency_anomalies(
        alerts, baseline_alerts=baseline_alerts
    )
    assert result[0]["ip_frequency_zscore"] > 0.0
	
def test_ip_frequency_no_anomaly(anomaly_detector_module):
	baseline_alerts = [
		_make_ip_alert("10.0.0.1"),
		_make_ip_alert("10.0.0.2"),
		_make_ip_alert("10.0.0.3"),
		_make_ip_alert("10.0.0.4"),
	]
	alerts = [_make_ip_alert("10.0.0.2")]

	result = anomaly_detector_module.detect_ip_frequency_anomalies(
		alerts, baseline_alerts=baseline_alerts
	)

	assert result[0]["ip_frequency_anomaly"] is False
	assert result[0]["ip_frequency_zscore"] == 0.0


def test_alert_type_anomaly_detected(anomaly_detector_module):
    baseline_alerts = (
        [_make_type_alert("port_scan") for _ in range(50)]
        + [_make_type_alert("failed_login")]
        + [_make_type_alert("suspicious_connection")]
        + [_make_type_alert("malware_detected")]
    )
    alerts = [_make_type_alert("port_scan")]
    result = anomaly_detector_module.detect_alert_type_anomalies(
        alerts, baseline_alerts=baseline_alerts
    )
    assert result[0]["alert_type_zscore"] > 0.0
def test_alert_type_no_anomaly(anomaly_detector_module):
	baseline_alerts = [
		_make_type_alert("port_scan"),
		_make_type_alert("failed_login"),
		_make_type_alert("suspicious_connection"),
		_make_type_alert("malware_detected"),
	]
	alerts = [_make_type_alert("failed_login")]

	result = anomaly_detector_module.detect_alert_type_anomalies(
		alerts, baseline_alerts=baseline_alerts
	)

	assert result[0]["alert_type_anomaly"] is False
	assert result[0]["alert_type_zscore"] == 0.0
