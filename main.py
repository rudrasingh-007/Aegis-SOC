"""Main entry point for the Aegis-SOC cybersecurity pipeline."""
from confidence.confidence_scorer import score_alerts
from explainability.explainer import explain_alerts
from anomaly.anomaly_detector import run_anomaly_detection
from playbooks.response_playbooks import run_playbooks
from integrations.wazuh_ingestor import generate_sample_wazuh_alerts, load_wazuh_alerts_from_file
from correlator.alert_correlator import correlate_alerts
from lateral_movement.lateral_detector import detect_lateral_movement
from l2_investigator.l2_engine import run_l2_investigation
from logger.false_positive_logger import log_false_positives
from notifier.email_notifier import notify_critical_alerts
from simulator.alert_simulator import generate_alerts
from log_parser.auth_log_parser import parse_auth_log
from log_parser.web_log_parser import parse_web_log
from log_parser.suricata_parser import parse_suricata_log
from engine.rule_engine import process_alerts, reclassify_alerts, tag_mitre_alerts
from enrichment.threat_intel import enrich_alerts
from reporter.report_generator import generate_reports


def _default_pipeline_selection():
	return {
		"use_simulator": True,
		"simulator_count": 5,
		"selected_log_sources": set(),
	}


def _prompt_pipeline_selection():
	print("=== AEGIS-SOC ===")
	try:
		input_source = input(
			"Select input source:\n"
			"  [1] Simulator only\n"
			"  [2] Log sources only\n"
			"  [3] Both\n"
			"Choice: "
		).strip()

		if input_source not in {"1", "2", "3"}:
			return _default_pipeline_selection()

		use_simulator = input_source in {"1", "3"}
		simulator_count = 5
		selected_log_sources = set()

		if use_simulator:
			raw_count = input("Number of simulated alerts? (5-20, default 5): ").strip()
			if raw_count:
				try:
					requested_count = int(raw_count)
					if 5 <= requested_count <= 20:
						simulator_count = requested_count
				except ValueError:
					simulator_count = 5

		if input_source in {"2", "3"}:
			log_source_choice = input(
				"Select log sources:\n"
				"  [1] All\n"
				"  [2] Auth log only\n"
				"  [3] Web log only\n"
				"  [4] Suricata only\n"
				"  [5] Wazuh only\n"
				"Choice: "
			).strip()

			log_source_map = {
				"1": {"auth", "web", "suricata", "wazuh"},
				"2": {"auth"},
				"3": {"web"},
				"4": {"suricata"},
				"5": {"wazuh"},
			}
			if log_source_choice not in log_source_map:
				return _default_pipeline_selection()
			selected_log_sources = log_source_map[log_source_choice]

		return {
			"use_simulator": use_simulator,
			"simulator_count": simulator_count,
			"selected_log_sources": selected_log_sources,
		}
	except EOFError:
		return _default_pipeline_selection()
	except Exception:
		return _default_pipeline_selection()


def main():
	"""Run the end-to-end Aegis-SOC alert processing pipeline."""
	alerts = []
	simulator_alerts = []
	wazuh_alerts = []
	auth_alerts = []
	web_log_alerts = []
	suricata_alerts = []
	current_step = "pipeline initialization"
	pipeline_selection = _prompt_pipeline_selection()
	use_simulator = pipeline_selection["use_simulator"]
	simulator_count = pipeline_selection["simulator_count"]
	selected_log_sources = pipeline_selection["selected_log_sources"]

	try:
		print("=" * 60)
		print("Aegis-SOC Cybersecurity Alert Processing Pipeline")
		print("=" * 60)

		current_step = "generate sample Wazuh alerts"
		try:
			if "wazuh" in selected_log_sources:
				print("[Aegis-SOC] Generating sample Wazuh alerts for integration demo...")
				generate_sample_wazuh_alerts()
				print()
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		current_step = "load Wazuh alerts from file"
		try:
			if "wazuh" in selected_log_sources:
				wazuh_alerts = load_wazuh_alerts_from_file("integrations/sample_wazuh_alerts.json")
				print(f"[Aegis-SOC] Loaded {len(wazuh_alerts)} Wazuh alerts into pipeline.")
				print()
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		current_step = "load web log alerts"
		try:
			if "web" in selected_log_sources:
				web_log_alerts = parse_web_log("sample_logs/access.log")
				print(f"[Aegis-SOC] Loaded {len(web_log_alerts)} web log alerts into pipeline.")
				print()
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		current_step = "load auth log alerts"
		try:
			if "auth" in selected_log_sources:
				auth_alerts = parse_auth_log("sample_logs/auth.log")
				print(f"[Aegis-SOC] Loaded {len(auth_alerts)} auth log alerts into pipeline.")
				print()
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		current_step = "load suricata alerts"
		try:
			if "suricata" in selected_log_sources:
				suricata_alerts = parse_suricata_log("sample_logs/suricata.json")
				print(f"[Aegis-SOC] Loaded {len(suricata_alerts)} Suricata alerts into pipeline.")
				print()
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		current_step = "generate alerts"
		try:
			if use_simulator:
				simulator_alerts = generate_alerts(simulator_count)
			alerts = []
			if use_simulator:
				alerts = alerts + simulator_alerts
			if "wazuh" in selected_log_sources:
				alerts = alerts + wazuh_alerts
			if "web" in selected_log_sources:
				alerts = alerts + web_log_alerts
			if "suricata" in selected_log_sources:
				alerts = alerts + suricata_alerts
			if "auth" in selected_log_sources:
				alerts = alerts + auth_alerts
			print("[Aegis-SOC] Alerts have been generated.")
			print()
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		current_step = "rule engine classification"
		try:
			alerts = process_alerts(alerts)
			print("[Aegis-SOC] Rule engine classification is done.")
			print()
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		current_step = "threat intel enrichment"
		try:
			alerts = enrich_alerts(alerts)
			print("[Aegis-SOC] Threat intel enrichment is done.")
			print()
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		current_step = "threat intel reclassification"
		try:
			alerts = reclassify_alerts(alerts)
			print("[Aegis-SOC] Threat intel reclassification is done.")
			print()
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		current_step = "mitre att&ck tagging"
		try:
			alerts = tag_mitre_alerts(alerts)
			print("[Aegis-SOC] MITRE ATT&CK tagging complete.")
			print()
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		current_step = "anomaly detection"
		try:
			alerts = run_anomaly_detection(alerts)
			print("[Aegis-SOC] Anomaly detection complete.")
			print()
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		current_step = "alert correlation"
		try:
			correlate_alerts(alerts)
			print("[Aegis-SOC] Alert correlation complete.")
			print()
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		current_step = "lateral movement detection"
		try:
			alerts = detect_lateral_movement(alerts)
			print("[Aegis-SOC] Lateral movement detection complete.")
			print()
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		current_step = "alert explainability"
		try:
			alerts = explain_alerts(alerts)
			print("[Aegis-SOC] Alert explainability complete.")
			print()
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		current_step = "confidence scoring"
		try:
			alerts = score_alerts(alerts)
			print("[Aegis-SOC] Confidence scoring complete.")
			print()
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		current_step = "critical alert notification"
		try:
			notify_critical_alerts(alerts)
			print("[Aegis-SOC] Critical alert notifications sent.")
			print()
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		current_step = "report generation"
		try:
			generate_reports(alerts)
			print()
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		current_step = "l2 investigation"
		try:
			run_l2_investigation(alerts)
			print("[Aegis-SOC] L2 investigations complete.")
			print()
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		current_step = "response playbook execution"
		try:
			run_playbooks(alerts)
			print("[Aegis-SOC] Response playbooks executed.")
			print()
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		current_step = "false positive logging"
		try:
			log_false_positives(alerts)
			print()
		except Exception as error:
			print(f"[Aegis-SOC][WARNING] Step failed: {current_step} | Error: {error}")

		critical_count = sum(1 for alert in alerts if alert.get("severity") == "CRITICAL")
		high_count = sum(1 for alert in alerts if alert.get("severity") == "HIGH")
		medium_count = sum(1 for alert in alerts if alert.get("severity") == "MEDIUM")
		low_count = sum(1 for alert in alerts if alert.get("severity") == "LOW")
		threat_confirmed_count = sum(
			1 for alert in alerts if alert.get("threat_confirmed") is True
		)
		anomaly_count = sum(1 for alert in alerts if alert.get("is_anomaly") is True)

		print()
		print("=" * 60)
		print("  PIPELINE SUMMARY")
		print("=" * 60)
		print(f"Total Alerts     : {len(alerts)}")
		print(f"Critical         : {critical_count}")
		print(f"High             : {high_count}")
		print(f"Medium           : {medium_count}")
		print(f"Low              : {low_count}")
		print(f"Threat Confirmed : {threat_confirmed_count}")
		print(f"Anomalies        : {anomaly_count}")
		print()

		print("[Aegis-SOC] Pipeline complete.")
	except Exception as error:
		print(f"[Aegis-SOC][ERROR] Pipeline failed at step '{current_step}'. Details: {error}")


if __name__ == "__main__":
	main()
