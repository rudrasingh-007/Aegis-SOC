"""Main entry point for the Aegis-SOC cybersecurity pipeline."""
from anomaly.anomaly_detector import run_anomaly_detection
from playbooks.response_playbooks import run_playbooks
from integrations.wazuh_ingestor import generate_sample_wazuh_alerts, load_wazuh_alerts_from_file
from correlator.alert_correlator import correlate_alerts
from l2_investigator.l2_engine import run_l2_investigation
from logger.false_positive_logger import log_false_positives
from notifier.email_notifier import notify_critical_alerts
from simulator.alert_simulator import generate_alerts
from engine.rule_engine import process_alerts, reclassify_alerts
from enrichment.threat_intel import enrich_alerts
from reporter.report_generator import generate_reports


def main():
	"""Run the end-to-end Aegis-SOC alert processing pipeline."""
	alerts = []
	wazuh_alerts = []
	current_step = "pipeline initialization"

	try:
		print("=" * 55)
		print("Aegis-SOC Cybersecurity Alert Processing Pipeline")
		print("=" * 55)

		current_step = "generate sample Wazuh alerts"
		try:
			print("[Aegis-SOC] Generating sample Wazuh alerts for integration demo...")
			generate_sample_wazuh_alerts()
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		current_step = "load Wazuh alerts from file"
		try:
			wazuh_alerts = load_wazuh_alerts_from_file("integrations/sample_wazuh_alerts.json")
			print(f"[Aegis-SOC] Loaded {len(wazuh_alerts)} Wazuh alerts into pipeline.")
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		current_step = "generate alerts"
		try:
			alerts = generate_alerts(5)
			alerts = alerts + wazuh_alerts
			print("[Aegis-SOC] Alerts have been generated.")
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		current_step = "rule engine classification"
		try:
			alerts = process_alerts(alerts)
			print("[Aegis-SOC] Rule engine classification is done.")
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		current_step = "threat intel enrichment"
		try:
			alerts = enrich_alerts(alerts)
			print("[Aegis-SOC] Threat intel enrichment is done.")
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		current_step = "threat intel reclassification"
		try:
			alerts = reclassify_alerts(alerts)
			print("[Aegis-SOC] Threat intel reclassification is done.")
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		current_step = "anomaly detection"
		try:
			alerts = run_anomaly_detection(alerts)
			print("[Aegis-SOC] Anomaly detection complete.")
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		current_step = "alert correlation"
		try:
			correlate_alerts(alerts)
			print("[Aegis-SOC] Alert correlation complete.")
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		current_step = "critical alert notification"
		try:
			notify_critical_alerts(alerts)
			print("[Aegis-SOC] Critical alert notifications sent.")
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		current_step = "report generation"
		try:
			generate_reports(alerts)
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		current_step = "l2 investigation"
		try:
			run_l2_investigation(alerts)
			print("[Aegis-SOC] L2 investigations complete.")
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		current_step = "response playbook execution"
		try:
			run_playbooks(alerts)
			print("[Aegis-SOC] Response playbooks executed.")
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		current_step = "false positive logging"
		try:
			log_false_positives(alerts)
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		print("[Aegis-SOC] Pipeline complete.")
	except Exception as error:
		print(f"[Aegis-SOC][ERROR] Pipeline failed at step '{current_step}'. Details: {error}")


if __name__ == "__main__":
	main()
