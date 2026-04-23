import unittest

from simulator.alert_simulator import generate_alert, generate_alerts


class TestAlertSimulator(unittest.TestCase):
	def test_generate_alert_has_required_fields(self):
		alert = generate_alert()
		required_fields = {
			"alert_id",
			"timestamp",
			"source_ip",
			"alert_type",
			"target_system",
			"attempt_count",
		}
		self.assertTrue(required_fields.issubset(alert.keys()))

	def test_generate_alert_id_format(self):
		alert = generate_alert()
		self.assertTrue(alert["alert_id"].startswith("ALERT-"))

	def test_generate_alerts_returns_correct_count(self):
		alerts = generate_alerts(5)
		self.assertEqual(len(alerts), 5)

	def test_generate_alerts_all_have_severity_none(self):
		alerts = generate_alerts(5)
		self.assertTrue(all("severity" not in alert for alert in alerts))

	def test_attempt_count_in_valid_range(self):
		alerts = generate_alerts(20)
		self.assertTrue(all(1 <= alert["attempt_count"] <= 25 for alert in alerts))


if __name__ == "__main__":
	unittest.main()
