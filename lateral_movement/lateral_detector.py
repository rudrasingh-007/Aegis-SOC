"""Lateral movement detection for Aegis-SOC alerts."""

import os
import json
import datetime


SYSTEM_CRITICALITY = {
	"employee_workstation": 1,
	"web_server": 2,
	"firewall": 3,
	"database": 4,
	"domain_controller": 5,
}


def detect_lateral_movement(alerts):
	"""Detect simple lateral movement patterns and annotate alerts in place."""
	alerts_by_ip = {}
	for alert in alerts:
		source_ip = alert.get("source_ip")
		alerts_by_ip.setdefault(source_ip, []).append(alert)

	flagged_ips = []

	for source_ip, ip_alerts in alerts_by_ip.items():
		unique_targets_in_order = []
		seen_targets = set()
		for alert in ip_alerts:
			target_system = alert.get("target_system")
			if target_system not in seen_targets:
				seen_targets.add(target_system)
				unique_targets_in_order.append(target_system)

		is_flagged = False
		if len(unique_targets_in_order) >= 3:
			first_target = unique_targets_in_order[0]
			last_target = unique_targets_in_order[-1]
			first_score = SYSTEM_CRITICALITY.get(first_target, 1)
			last_score = SYSTEM_CRITICALITY.get(last_target, 1)
			if last_score > first_score:
				is_flagged = True

		for alert in ip_alerts:
			alert["lateral_movement_detected"] = is_flagged
			if is_flagged:
				alert["lateral_movement_path"] = unique_targets_in_order
			else:
				alert["lateral_movement_path"] = []

		if is_flagged:
			flagged_ips.append(
				{
					"source_ip": source_ip,
					"path": unique_targets_in_order,
					"alert_count": len(ip_alerts),
				}
			)

	os.makedirs("lateral_movement_reports", exist_ok=True)
	timestamp = datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")
	report = {
		"generated_at": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
		"total_alerts": len(alerts),
		"lateral_movement_cases": len(flagged_ips),
		"flagged_ips": flagged_ips,
	}

	report_path = os.path.join(
		"lateral_movement_reports",
		f"lateral_movement_report_{timestamp}.json",
	)
	with open(report_path, "w", encoding="utf-8") as report_file:
		json.dump(report, report_file, indent=2)

	print(f"[Aegis-SOC] Lateral movement cases detected: {len(flagged_ips)}")

	return alerts