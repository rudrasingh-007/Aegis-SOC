  ```
  █████╗ ███████╗ ██████╗ ██╗███████╗      ███████╗ ██████╗  ██████╗
  ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝      ██╔════╝██╔═══██╗██╔════╝
  ███████║█████╗  ██║  ███╗██║███████╗      ███████╗██║   ██║██║
  ██╔══██║██╔══╝  ██║   ██║██║╚════██║      ╚════██║██║   ██║██║
  ██║  ██║███████╗╚██████╔╝██║███████║      ███████║╚██████╔╝╚██████╗
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝      ╚══════╝ ╚═════╝  ╚═════╝
  ```

  ```
  SYSTEM     : Automated L1 SOC Triage System
  VERSION    : 5.0
  STATUS     : ACTIVE
  CLEARANCE  : OPEN SOURCE
  ```
Aegis-SOC queries real threat intelligence APIs and flags confirmed malicious IPs automatically.
It detects kill-chain attack sequences across correlated alerts.
It simulates and automates core aspects of L1 and L2 SOC triage — from alert ingestion to investigation and response — in a single pipeline.
  ---

  ## OVERVIEW

  Aegis-SOC is a modular, open source SOC automation tool designed to automate L1 SOC triage end-to-end. The system generates or ingests alerts, applies a rule-based classification engine, and performs dual-source enrichment against AbuseIPDB and VirusTotal. Alerts receive dynamic threat-intel reclassification (severity upgrades driven by AbuseIPDB and VirusTotal scores), then flow into a statistical anomaly detector that leverages a persistent SQLite historical baseline for Z-score calculations. Correlated alerts are analyzed for rapid time-window attacks and known kill-chain sequences to reveal multi-vector campaigns. The platform supports automated email notifications for critical incidents, structured JSON and console report generation, an L2 automated investigation engine with impact assessment and isolation recommendations, and a library of response playbooks. False positives are logged for tuning, and a secured Flask dashboard with session-based authentication provides operators with controlled access and visualization.

  ---
  ## DASHBOARD PREVIEW

  ![Aegis-SOC Dashboard](assets/dashboard_preview.png)
  ---

  ## FEATURES

  ```
  [+]  Realistic Alert Simulation       10 attack vectors across 5 target systems
  [+]  Rule Based Classification        LOW / MEDIUM / HIGH / CRITICAL severity engine
  [+]  Dual Source Threat Intel         AbuseIPDB + VirusTotal cross-validation
  [+]  Email Notifications              Real-time CRITICAL alert dispatch via Gmail SMTP
  [+]  Structured Report Generation     Console + JSON incident reports per alert
  [+]  False Positive Tracking          Persistent FP registry for rule tuning
  [+]  L2 Investigation Engine          Automated deep analysis with isolation recommendations
  [+]  Alert Correlation                Multi-vector attack detection by source IP grouping
  [+]  Wazuh SIEM Integration           Wazuh compatible ingestion layer for live connectivity
  [+]  Automated Response Playbooks     Step-by-step incident response for 6 attack types
  [+]  Anomaly Detection Engine         Z-score based statistical anomaly detection
  [+]  Live SOC Dashboard               Flask web dashboard with charts, alerts table, and pipeline control
  [+]  Auth Log Ingestion              Parse real Linux auth.log files into alerts
  [+]  Dashboard File Upload           Upload real log files through the browser UI
  [+]  Threat Intel Reclassification    Severity upgraded dynamically based on AbuseIPDB and VirusTotal scores
  [+]  Kill-Chain Sequence Detection    Identifies known attack chains across correlated alerts
  [+]  Time-Window Correlation          Flags rapid multi-alert attacks within 60 second windows
  [+]  SQLite Historical Baseline       Persistent alert history for statistically meaningful anomaly detection
  [+]  Dashboard Authentication         Session-based login with environment configured credentials
  [+]  43 Automated Unit Tests          43 automated unit tests across core modules
  ```

  ## THREAT PIPELINE

  ```
  [SIMULATOR/WAZUH] → [RULE ENGINE] → [THREAT INTEL] → [RECLASSIFIER] → [ANOMALY DETECTOR] → [CORRELATOR] → [NOTIFIER] → [REPORTER] → [L2 ENGINE] → [PLAYBOOKS] → [FP LOGGER]

  ```

  ## PIPELINE ARCHITECTURE
  ```
  INPUT LAYER
    ├── Alert Simulator      →  10 attack vectors, synthetic alerts
    ├── Wazuh Ingestor       →  SIEM compatible ingestion
    └── Auth Log Parser      →  Real Linux auth.log ingestion

  PROCESSING LAYER
    ├── Rule Engine          →  Severity classification (LOW/MED/HIGH/CRIT)
    ├── Threat Intel         →  AbuseIPDB + VirusTotal enrichment
    ├── Anomaly Detector     →  Z-score statistical analysis
    └── Alert Correlator     →  Multi-vector attack grouping

  OUTPUT LAYER
    ├── Email Notifier       →  CRITICAL alert dispatch
    ├── Report Generator     →  JSON + Console incident reports
    ├── L2 Investigator      →  Impact assessment + isolation rec.
    ├── Response Playbooks   →  Step-by-step incident response
    └── FP Logger            →  False positive registry

  ```
  | Stage | Module | Function |
  |---|---|---|
  | 01 | Alert Simulator / Wazuh Ingestor | Generates or ingests security alerts |
  | 02 | Rule Engine | Classifies severity — LOW / MEDIUM / HIGH / CRITICAL |
  | 03 | Threat Intel | Dual source enrichment via AbuseIPDB + VirusTotal |
  | 03b | Threat Intel Reclassification | Upgrades severity based on abuse and VirusTotal scores |
  | 04 | Alert Correlator | Groups related alerts by source IP |
  | 05 | Email Notifier | Dispatches analyst notifications for CRITICAL incidents |
  | 06 | Report Generator | Outputs structured console + JSON incident reports |
  | 07 | L2 Investigation Engine | Deep automated analysis for CRITICAL alerts |
  | 08 | FP Logger | Maintains persistent false positive registry |

  ---

  ## SEVERITY MATRIX

  ```
  CRITICAL  [████████████]  Immediate escalation. Isolate affected system.
  HIGH      [████████░░░░]  Investigate immediately. Review related logs.
  MEDIUM    [████░░░░░░░░]  Monitor closely. Cross-reference threat intel.
  LOW       [██░░░░░░░░░░]  Likely false positive. Log and discard.
  ```

  ---

  ## ATTACK VECTORS COVERED

  ```
  failed_login          brute_force           malware_detected
  port_scan             suspicious_connection ransomware_detected
  privilege_escalation  ddos_attack           unauthorized_wifi_access
  dns_tunneling
  ```

  ---

  ## SYSTEM STRUCTURE

  ```
  Aegis-SOC/
  │
  ├── main.py                        # Pipeline entry point
  ├── config/
  │   └── config.py                  # Central configuration
  ├── simulator/
  │   └── alert_simulator.py         # Alert simulation module
  ├── engine/
  │   └── rule_engine.py             # Rule based classification engine
  ├── storage/
  │   └── history_store.py              # SQLite historical alert persistence
  ├── log_parser/
  │   └── auth_log_parser.py            # Linux auth.log parser
  ├── sample_logs/
  │   └── auth.log                      # Sample auth.log for testing
  ├── enrichment/
  │   └── threat_intel.py            # AbuseIPDB + VirusTotal enrichment
  ├── notifier/
  │   └── email_notifier.py          # Critical alert notifications
  ├── reporter/
  │   └── report_generator.py        # Incident report generation
  ├── logger/
  │   └── false_positive_logger.py   # False positive registry
  ├── l2_investigator/
  │   └── l2_engine.py                  # L2 automated investigation engine
  ├── correlator/
  │   └── alert_correlator.py           # Multi-vector alert correlation
  ├── integrations/
  │   └── wazuh_ingestor.py             # Wazuh SIEM ingestion layer
  ├── l2_reports/                        # L2 investigation reports
  ├── correlation_reports/               # Correlation reports
  ├── anomaly/
  │   └── anomaly_detector.py           # Z-score based anomaly detection
  ├── playbooks/
  │   └── response_playbooks.py         # Automated incident response playbooks
  ├── dashboard/
  │   ├── app.py                        # Flask dashboard server
  │   └── templates/
  │       └── index.html                # SOC dashboard UI
  ├── reports/                       # Generated incident reports
  ├── requirements.txt               # Dependencies
  └── README.md                      # Documentation

  ```

  ---

  ## DEPLOYMENT

  **Requirements**
  - Python 3.x
  - AbuseIPDB API key — [abuseipdb.com](https://abuseipdb.com)
  - VirusTotal API key — [virustotal.com](https://virustotal.com)
  - Gmail account with App Password enabled

  **Installation**
  ```bash
  git clone https://github.com/rudrasingh-007/Aegis-SOC.git
  cd Aegis-SOC
  pip install -r requirements.txt
  ```

  **Environment Configuration**

  Create a `.env` file in the root directory:
  ```
  ABUSEIPDB_API_KEY=your_abuseipdb_key
  VIRUSTOTAL_API_KEY=your_virustotal_key
  EMAIL_SENDER=your_gmail@gmail.com
  EMAIL_PASSWORD=your_gmail_app_password
  EMAIL_RECEIVER=your_gmail@gmail.com
  DASHBOARD_USERNAME=your_dashboard_username
  DASHBOARD_PASSWORD=your_dashboard_password
  FLASK_SECRET_KEY=your_secret_key
  ```

  **Execute**
  ```bash
  python main.py
  ```

  **Run Dashboard**
  ```bash
  python -m dashboard.app
  ```
  ```Then open``` http://localhost:5000 ```in your browser.```

  ```To logout: click the Logout button in the sidebar or visit``` http://localhost:5000/logout ```in your browser```

  ---

  **Upload Real Logs**
  
  Upload a Linux auth.log file through the dashboard UI to process real log data instead of simulated alerts.
  
  ## TESTING

  Run all 43 unit tests with:
  ```bash
  python -m pytest tests/ -v
  ```


  ## ROADMAP

  ```
  [COMPLETE]  V1 — Core triage pipeline
  [COMPLETE]  V2 — Dual threat intel, email alerts, FP tracking
  [COMPLETE]  V3 — L2 automation, Wazuh SIEM integration, alert correlation
  [COMPLETE]  V4 — Dashboard UI, anomaly detection, response playbooks
  [COMPLETE]  V5 — Kill-chain detection, threat intel reclassification, SQLite baseline, dashboard auth, 43 unit tests
  [PLANNED]   V6 — ML based detection, live SIEM feed, multi-user support
  ```

  ---

  ## CONTRIBUTING

  ```
  1. Fork the repository
  2. git checkout -b feature/your-feature
  3. git commit -m "Add your feature"
  4. git push origin feature/your-feature
  5. Open a Pull Request
  ```

  ---

  ## LICENSE

  MIT License — free to use, modify, and distribute.

  ---

  ```
  [ AEGIS-SOC ] — AUTOMATED THREAT TRIAGE — OPEN SOURCE
  ```