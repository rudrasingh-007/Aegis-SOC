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
VERSION    : 2.0
STATUS     : ACTIVE
CLEARANCE  : OPEN SOURCE
```

---

## OVERVIEW

Aegis-SOC is a modular, open source cybersecurity automation tool built to eliminate the bottleneck of manual L1 SOC triage. The system ingests simulated security alerts, runs them through a rule-based classification engine, enriches threat indicators against dual external intelligence sources, dispatches real-time critical notifications, and maintains a structured false positive registry.

Built by a cybersecurity aspirant as a serious contribution to the SOC automation space.

---

## THREAT PIPELINE

```
[SIMULATOR] → [RULE ENGINE] → [THREAT INTEL] → [NOTIFIER] → [REPORTER] → [FP LOGGER]
```

| Stage | Module | Function |
|---|---|---|
| 01 | Alert Simulator | Generates synthetic security alerts across 10 attack vectors |
| 02 | Rule Engine | Classifies severity — LOW / MEDIUM / HIGH / CRITICAL |
| 03 | Threat Intel | Dual source enrichment via AbuseIPDB + VirusTotal |
| 04 | Email Notifier | Dispatches analyst notifications for CRITICAL incidents |
| 05 | Report Generator | Outputs structured console + JSON incident reports |
| 06 | FP Logger | Maintains persistent false positive registry |

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
├── enrichment/
│   └── threat_intel.py            # AbuseIPDB + VirusTotal enrichment
├── notifier/
│   └── email_notifier.py          # Critical alert notifications
├── reporter/
│   └── report_generator.py        # Incident report generation
├── logger/
│   └── false_positive_logger.py   # False positive registry
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
git clone https://github.com/yourusername/Aegis-SOC.git
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
```

**Execute**
```bash
python main.py
```

---

## ROADMAP

```
[COMPLETE]  V1 — Core triage pipeline
[COMPLETE]  V2 — Dual threat intel, email alerts, FP tracking
[PLANNED]   V3 — L2 automation, SIEM integration, alert correlation
[PLANNED]   V4 — Dashboard UI, ML detection, response playbooks
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