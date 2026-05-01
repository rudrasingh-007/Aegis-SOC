import builtins
from unittest.mock import mock_open

import pytest

from l2_investigator import l2_engine


@pytest.fixture
def no_file_io(monkeypatch):
	"""Disable report file writing while testing L2 investigation logic."""
	monkeypatch.setattr(l2_engine.os, "makedirs", lambda *args, **kwargs: None)
	monkeypatch.setattr(builtins, "open", mock_open())
	monkeypatch.setattr(l2_engine.json, "dump", lambda *args, **kwargs: None)


def make_critical_alert(target_system):
	"""Create a minimal critical alert for L2 investigation tests."""
	return {
		"alert_id": "ALERT-100001",
		"severity": "CRITICAL",
		"source_ip": "10.0.0.1",
		"alert_type": "malware_detected",
		"target_system": target_system,
		"attempt_count": 5,
		"abuse_score": 95,
		"virustotal_score": 12,
		"threat_confirmed": True,
	}


def test_domain_controller_is_severe(no_file_io):
	alert = make_critical_alert("domain_controller")
	impact_assessment = l2_engine.assess_impact(alert)

	assert impact_assessment["impact_level"] == "SEVERE"


def test_employee_workstation_is_moderate(no_file_io):
	alert = make_critical_alert("employee_workstation")
	impact_assessment = l2_engine.assess_impact(alert)

	assert impact_assessment["impact_level"] == "MODERATE"


def test_firewall_is_high_impact(no_file_io):
	alert = make_critical_alert("firewall")
	impact_assessment = l2_engine.assess_impact(alert)

	assert impact_assessment["impact_level"] == "HIGH"


def test_isolation_recommendation_exists(no_file_io):
	alert = make_critical_alert("domain_controller")
	report = l2_engine.investigate(alert)

	assert report["isolation_recommendation"]


def test_l2_report_has_required_fields(no_file_io):
	alert = make_critical_alert("firewall")
	report = l2_engine.investigate(alert)

	required_fields = {
		"alert_id",
		"severity",
		"alert_type",
		"target_system",
		"impact_level",
		"isolation_recommendation",
	}

	assert required_fields.issubset(report.keys())
