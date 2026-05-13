"""Tests for lateral movement detector module."""

from unittest.mock import mock_open

import lateral_movement.lateral_detector as lateral_detector
from lateral_movement.lateral_detector import detect_lateral_movement


def make_alert(source_ip, target_system):
	"""Create a minimal alert payload for lateral movement tests."""
	return {
		"alert_id": f"ALERT-{source_ip}-{target_system}",
		"source_ip": source_ip,
		"target_system": target_system,
	}


def _disable_file_io(monkeypatch):
	"""Disable filesystem side effects from report writing."""
	monkeypatch.setattr(lateral_detector.os, "makedirs", lambda *args, **kwargs: None)
	monkeypatch.setattr(lateral_detector, "open", mock_open(), raising=False)


def test_escalating_criticality_across_three_targets_gets_flagged(monkeypatch):
	"""An IP touching 3 targets with increasing criticality should be flagged."""
	_disable_file_io(monkeypatch)
	alerts = [
		make_alert("10.0.0.1", "employee_workstation"),
		make_alert("10.0.0.1", "web_server"),
		make_alert("10.0.0.1", "domain_controller"),
	]

	result = detect_lateral_movement(alerts)

	assert all(alert["lateral_movement_detected"] is True for alert in result)


def test_two_different_targets_does_not_get_flagged(monkeypatch):
	"""An IP touching only 2 different targets should not be flagged."""
	_disable_file_io(monkeypatch)
	alerts = [
		make_alert("10.0.0.2", "employee_workstation"),
		make_alert("10.0.0.2", "web_server"),
	]

	result = detect_lateral_movement(alerts)

	assert all(alert["lateral_movement_detected"] is False for alert in result)


def test_decreasing_criticality_across_three_targets_does_not_get_flagged(monkeypatch):
	"""An IP touching 3 targets with decreasing criticality should not be flagged."""
	_disable_file_io(monkeypatch)
	alerts = [
		make_alert("10.0.0.3", "domain_controller"),
		make_alert("10.0.0.3", "database"),
		make_alert("10.0.0.3", "web_server"),
	]

	result = detect_lateral_movement(alerts)

	assert all(alert["lateral_movement_detected"] is False for alert in result)


def test_flagged_ip_has_ordered_lateral_movement_path(monkeypatch):
	"""Flagged IP should carry ordered unique target path on all alerts."""
	_disable_file_io(monkeypatch)
	alerts = [
		make_alert("10.0.0.4", "employee_workstation"),
		make_alert("10.0.0.4", "web_server"),
		make_alert("10.0.0.4", "employee_workstation"),
		make_alert("10.0.0.4", "firewall"),
	]

	result = detect_lateral_movement(alerts)
	expected_path = ["employee_workstation", "web_server", "firewall"]

	assert all(alert["lateral_movement_detected"] is True for alert in result)
	assert all(alert["lateral_movement_path"] == expected_path for alert in result)


def test_non_flagged_alerts_have_false_and_empty_path(monkeypatch):
	"""Non-flagged alerts should have False flag and empty path list."""
	_disable_file_io(monkeypatch)
	alerts = [
		make_alert("10.0.0.5", "database"),
		make_alert("10.0.0.5", "firewall"),
	]

	result = detect_lateral_movement(alerts)

	assert all(alert["lateral_movement_detected"] is False for alert in result)
	assert all(alert["lateral_movement_path"] == [] for alert in result)