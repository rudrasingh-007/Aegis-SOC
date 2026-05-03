# Changelog
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