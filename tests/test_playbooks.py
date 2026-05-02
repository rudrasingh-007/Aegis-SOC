import pytest

from playbooks.response_playbooks import get_playbook



def make_alert(alert_type):
	"""Create a minimal alert for playbook selection tests."""
	return {
		"alert_id": "ALERT-200001",
		"severity": "CRITICAL",
		"alert_type": alert_type,
	}



def test_malware_playbook_returned():
	alert = make_alert("malware_detected")
	playbook = get_playbook(alert["alert_type"])

	assert "malware" in playbook["name"].lower()



def test_playbook_has_steps():
	alert = make_alert("privilege_escalation")
	playbook = get_playbook(alert["alert_type"])

	assert isinstance(playbook["steps"], list)
	assert len(playbook["steps"]) > 0



def test_unknown_alert_type_returns_fallback():
	alert = make_alert("unknown_attack")
	playbook = get_playbook(alert["alert_type"])

	assert playbook is not None
	assert isinstance(playbook["steps"], list)
	assert len(playbook["steps"]) > 0



def test_all_known_attack_types_have_playbooks():
	for alert_type in [
		"malware_detected",
		"ransomware_detected",
		"ddos_attack",
		"privilege_escalation",
		"dns_tunneling",
		"brute_force",
	]:
		alert = make_alert(alert_type)
		playbook = get_playbook(alert["alert_type"])

		assert playbook is not None
		assert isinstance(playbook["steps"], list)
		assert len(playbook["steps"]) > 0
