import unittest

from engine.rule_engine import (
	classify_alert,
	process_alerts,
	reclassify_alerts,
	reclassify_with_threat_intel,
)


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

	def test_reclassify_with_threat_intel_bumps_two_levels(self):
		alert = {"severity": "LOW", "abuse_score": 91, "virustotal_score": 0}
		updated = reclassify_with_threat_intel(alert)
		self.assertEqual(updated["severity"], "HIGH")

	def test_reclassify_with_threat_intel_bumps_one_level(self):
		alert = {"severity": "MEDIUM", "abuse_score": 76, "virustotal_score": 0}
		updated = reclassify_with_threat_intel(alert)
		self.assertEqual(updated["severity"], "HIGH")

	def test_reclassify_with_threat_intel_caps_at_critical(self):
		alert = {"severity": "HIGH", "abuse_score": 95, "virustotal_score": 12}
		updated = reclassify_with_threat_intel(alert)
		self.assertEqual(updated["severity"], "CRITICAL")

	def test_reclassify_alerts_updates_all_alerts(self):
		alerts = [
			{"severity": "LOW", "abuse_score": 0, "virustotal_score": 0},
			{"severity": "LOW", "abuse_score": 80, "virustotal_score": 0},
		]
		updated = reclassify_alerts(alerts)
		self.assertEqual(updated[0]["severity"], "LOW")
		self.assertEqual(updated[1]["severity"], "MEDIUM")


if __name__ == "__main__":
	unittest.main()
