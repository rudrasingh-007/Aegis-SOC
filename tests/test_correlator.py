import unittest

from correlator.alert_correlator import group_by_ip, assess_correlation, correlate_alerts


class TestAlertCorrelator(unittest.TestCase):
	def test_group_by_ip_groups_correctly(self):
		alerts = [
			{
				"alert_id": "A1",
				"source_ip": "10.0.0.1",
				"alert_type": "port_scan",
				"target_system": "web_server",
				"severity": "MEDIUM",
			},
			{
				"alert_id": "A2",
				"source_ip": "10.0.0.1",
				"alert_type": "failed_login",
				"target_system": "database",
				"severity": "HIGH",
			},
			{
				"alert_id": "A3",
				"source_ip": "10.0.0.2",
				"alert_type": "malware_detected",
				"target_system": "employee_workstation",
				"severity": "CRITICAL",
			},
		]
		grouped = group_by_ip(alerts)
		self.assertEqual(len(grouped), 2)
		self.assertEqual(len(grouped["10.0.0.1"]), 2)

	def test_assess_correlation_single_alert_not_correlated(self):
		alert_group = [
			{
				"alert_id": "A1",
				"source_ip": "10.0.0.1",
				"alert_type": "port_scan",
				"target_system": "web_server",
				"severity": "MEDIUM",
				"threat_confirmed": False,
			}
		]
		result = assess_correlation(alert_group)
		self.assertFalse(result["correlated"])

	def test_assess_correlation_two_alerts_is_correlated(self):
		alert_group = [
			{
				"alert_id": "A1",
				"source_ip": "10.0.0.1",
				"alert_type": "port_scan",
				"target_system": "web_server",
				"severity": "MEDIUM",
				"threat_confirmed": False,
			},
			{
				"alert_id": "A2",
				"source_ip": "10.0.0.1",
				"alert_type": "failed_login",
				"target_system": "database",
				"severity": "HIGH",
				"threat_confirmed": False,
			},
		]
		result = assess_correlation(alert_group)
		self.assertTrue(result["correlated"])

	def test_assess_correlation_highest_severity(self):
		alert_group = [
			{
				"alert_id": "A1",
				"source_ip": "10.0.0.3",
				"alert_type": "suspicious_connection",
				"target_system": "web_server",
				"severity": "MEDIUM",
				"threat_confirmed": False,
			},
			{
				"alert_id": "A2",
				"source_ip": "10.0.0.3",
				"alert_type": "ransomware_detected",
				"target_system": "database",
				"severity": "CRITICAL",
				"threat_confirmed": True,
			},
		]
		result = assess_correlation(alert_group)
		self.assertEqual(result["highest_severity"], "CRITICAL")

	def test_assess_correlation_threat_confirmed_true_if_any(self):
		alert_group = [
			{
				"alert_id": "A1",
				"source_ip": "10.0.0.4",
				"alert_type": "failed_login",
				"target_system": "domain_controller",
				"severity": "HIGH",
				"threat_confirmed": False,
			},
			{
				"alert_id": "A2",
				"source_ip": "10.0.0.4",
				"alert_type": "malware_detected",
				"target_system": "domain_controller",
				"severity": "CRITICAL",
				"threat_confirmed": True,
			},
		]
		result = assess_correlation(alert_group)
		self.assertTrue(result["threat_confirmed"])


if __name__ == "__main__":
	unittest.main()
