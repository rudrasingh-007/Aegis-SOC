"""Main entry point for the Aegis-SOC cybersecurity pipeline."""
from integrations.wazuh_ingestor import generate_sample_wazuh_alerts, load_wazuh_alerts_from_file
from correlator.alert_correlator import correlate_alerts
from l2_investigator.l2_engine import run_l2_investigation
from logger.false_positive_logger import log_false_positives
from notifier.email_notifier import notify_critical_alerts
from simulator.alert_simulator import generate_alerts
from engine.rule_engine import process_alerts
from enrichment.threat_intel import enrich_alerts
from reporter.report_generator import generate_reports


def main():
	"""Run the end-to-end Aegis-SOC alert processing pipeline."""
	print("=" * 55)
	print("Aegis-SOC Cybersecurity Alert Processing Pipeline")
	print("=" * 55)

	print("[Aegis-SOC] Generating sample Wazuh alerts for integration demo...")
	generate_sample_wazuh_alerts()
	wazuh_alerts = load_wazuh_alerts_from_file("integrations/sample_wazuh_alerts.json")
	print(f"[Aegis-SOC] Loaded {len(wazuh_alerts)} Wazuh alerts into pipeline.")
	alerts = generate_alerts(5)
	alerts = alerts + wazuh_alerts

	alerts = generate_alerts(5)
	print("[Aegis-SOC] Alerts have been generated.")

	alerts = process_alerts(alerts)
	print("[Aegis-SOC] Rule engine classification is done.")

	alerts = enrich_alerts(alerts)
	print("[Aegis-SOC] Threat intel enrichment is done.")

	correlate_alerts(alerts)
	print("[Aegis-SOC] Alert correlation complete.")

	notify_critical_alerts(alerts)
	print("[Aegis-SOC] Critical alert notifications sent.")
	
	generate_reports(alerts)

	run_l2_investigation(alerts)
	print("[Aegis-SOC] L2 investigations complete.")

	log_false_positives(alerts)
	print("[Aegis-SOC] Pipeline complete.")


if __name__ == "__main__":
	main()
