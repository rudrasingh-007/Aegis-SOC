# Changelog
## [V9.0]
- Added alert explainability module — every alert now carries a plain English explanation of why it was flagged and escalated
- Added confidence scoring — each alert receives a weighted signal score (0-100) reflecting detection certainty
- Added port_scan dedicated playbook — replaces generic fallback for port scan alerts
- Redesigned dashboard charts — severity donut and alert type bar chart now stacked vertically with color-coded severity stat panel
- Expanded unit tests from 68 to 78 across all core modules

## [V8.0]
- Added false positive ticketing system — auto-creates SQLite tickets for every false positive with OPEN/IN_PROGRESS/CLOSED workflow
- Added multi-user dashboard with role-based access — admin and analyst roles, SHA-256 password hashing, user management UI
- Added executable playbook logging — every playbook step now records SIMULATED status with timestamp and execution summary
- Expanded unit tests from 58 to 68 across all core modules

## [V7.0]
- Added Apache/Nginx web log parser - detects brute force, SQL injection, and sensitive path reconnaissance
- Added Suricata EVE JSON log parser - converts NIDS alerts directly into pipeline alerts
- Added lateral movement detection module - flags attackers escalating across multiple target systems
- Added dashboard support for web log and Suricata file uploads
- Expanded unit tests from 43 to 58 across all core modules

## [V6.0]
- Added AbuseIPDB attack category extraction - maps numeric category codes to human-readable abuse types
- Added file hash analysis via VirusTotal - malware and ransomware alerts now carry real SHA256 hashes checked against VirusTotal
- Added MITRE ATT&CK tagging - every alert is tagged with tactic, technique ID, and technique name
- Added privilege escalation prerequisite logic to alert simulator - escalation only follows brute force or failed login
- Replaced Z-score anomaly detection with Isolation Forest ML model for improved accuracy
- Added scikit-learn to dependencies

## [V5.0]
- Added kill-chain attack sequence detection across correlated alerts
- Added time-window correlation for rapid multi-alert detection
- Added threat intel reclassification — severity upgrades based on AbuseIPDB and VirusTotal scores
- Added SQLite historical baseline for statistically meaningful anomaly detection
- Added session-based dashboard authentication with styled login page
- Added Linux auth.log parser for real log file ingestion
- Added dashboard file upload — process real logs through the browser UI
- Expanded unit tests from 17 to 43 across all core modules

## [V4.0]
- Added Flask live SOC dashboard with charts and pipeline control
- Added Z-score based anomaly detection engine
- Added automated incident response playbooks for 6 attack types

## [V3.0]
- Added L2 automated investigation engine with impact assessment
- Added alert correlation engine for multi-vector attack detection
- Added Wazuh SIEM compatible ingestion layer

## [V2.0]
- Added email notifications for CRITICAL alerts via Gmail SMTP
- Added VirusTotal dual source threat intel enrichment
- Expanded alert simulation to 10 attack vectors
- Added false positive tracking and logging

## [V1.0]
- Core alert triage pipeline
- Rule based severity classification
- AbuseIPDB threat intel enrichment
- Structured JSON report generation