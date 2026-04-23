import unittest

from engine.rule_engine import classify_alert, process_alerts


class TestRuleEngine(unittest.TestCase):
	def test_malware_detected_is_critical(self):
		alert = {"alert_type": "malware_detected", "attempt_count": 5}
		self.assertEqual(classify_alert(alert), "CRITICAL")

	def test_brute_force_is_critical(self):
		alert = {"alert_type": "brute_force", "attempt_count": 5}
		self.assertEqual(classify_alert(alert), "CRITICAL")

	def test_failed_login_high_attempt_is_high(self):
		alert = {"alert_type": "failed_login", "attempt_count": 15}
		self.assertEqual(classify_alert(alert), "HIGH")

	def test_failed_login_low_attempt_is_medium(self):
		alert = {"alert_type": "failed_login", "attempt_count": 3}
		self.assertEqual(classify_alert(alert), "MEDIUM")

	def test_port_scan_is_medium(self):
		alert = {"alert_type": "port_scan", "attempt_count": 5}
		self.assertEqual(classify_alert(alert), "MEDIUM")

	def test_low_attempt_count_is_low(self):
		alert = {"alert_type": "unknown_type", "attempt_count": 1}
		self.assertEqual(classify_alert(alert), "LOW")

	def test_process_alerts_adds_severity(self):
		alerts = [
			{"alert_type": "malware_detected", "attempt_count": 2},
			{"alert_type": "failed_login", "attempt_count": 12},
			{"alert_type": "unknown_type", "attempt_count": 1},
		]
		processed = process_alerts(alerts)
		self.assertEqual(len(processed), 3)
		self.assertTrue(all("severity" in alert for alert in processed))


if __name__ == "__main__":
	unittest.main()
