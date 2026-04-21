# 🛡️ Aegis-SOC
### Automated L1 SOC Triage System

![Python](https://img.shields.io/badge/Python-3.x-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Version](https://img.shields.io/badge/Version-2.0-orange)

Aegis-SOC is an open source cybersecurity tool that automates the first layer of SOC alert triage. It simulates security alerts, classifies them by severity using a rule engine, enriches suspicious alerts with dual source threat intelligence, sends real time email notifications for critical threats, and logs false positives for analyst review.

> Built by a cybersecurity aspirant as an open source contribution to the SOC automation community.

---

## 🚨 The Problem

L1 SOC analysts are overwhelmed with hundreds of alerts daily — most of which are false positives. Manual triage is slow, inconsistent, and delays response to genuine threats. Aegis-SOC automates this first layer, allowing analysts to focus only on verified, high priority incidents.

---

## ✅ Features

- 🔍 **Realistic Alert Simulation** — Generates fake but realistic security alerts covering 10 attack scenarios
- ⚙️ **Rule Based Classification** — Classifies alerts as LOW, MEDIUM, HIGH, or CRITICAL using a predefined rule engine
- 🌐 **Dual Source Threat Intel** — Enriches suspicious alerts using both AbuseIPDB and VirusTotal APIs
- 📧 **Email Notifications** — Automatically sends email alerts to analysts for CRITICAL severity incidents
- 📄 **Structured Report Generation** — Outputs detailed incident reports to console and saves as JSON files
- 🗂️ **False Positive Tracking** — Logs likely false positives over time for analyst review and rule tuning
- 🧩 **Modular Architecture** — Built to scale, designed for L2 automation in future versions

---

## 🏗️ Architecture
Alert Simulator → Rule Engine → Threat Intel Enrichment → Email Notifier → Report Generator → False Positive Logger

| Layer | Module | Responsibility |
|-------|--------|----------------|
| 1 | Alert Simulator | Generates realistic fake security alerts |
| 2 | Rule Engine | Classifies alerts by severity using rules |
| 3 | Threat Intel | Enriches alerts via AbuseIPDB + VirusTotal |
| 4 | Email Notifier | Sends email for CRITICAL alerts |
| 5 | Report Generator | Outputs console + JSON reports |
| 6 | False Positive Logger | Logs false positives for review |

---

## 📁 Project Structure
Aegis-SOC/
│
├── main.py                        # Entry point
├── config/
│   └── config.py                  # Central configuration
├── simulator/
│   └── alert_simulator.py         # Alert simulation module
├── engine/
│   └── rule_engine.py             # Rule based classification
├── enrichment/
│   └── threat_intel.py            # AbuseIPDB + VirusTotal enrichment
├── notifier/
│   └── email_notifier.py          # Critical alert email notifications
├── reporter/
│   └── report_generator.py        # Report generation module
├── logger/
│   └── false_positive_logger.py   # False positive tracking
├── reports/                       # Generated JSON reports
├── requirements.txt               # Dependencies
└── README.md                      # Documentation

---

## ⚙️ Setup

### Prerequisites
- Python 3.x
- Free API keys from AbuseIPDB and VirusTotal
- Gmail account with App Password enabled

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/Aegis-SOC.git
cd Aegis-SOC
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Create a `.env` file in the root folder
ABUSEIPDB_API_KEY=your_abuseipdb_key
VIRUSTOTAL_API_KEY=your_virustotal_key
EMAIL_SENDER=your_gmail@gmail.com
EMAIL_PASSWORD=your_gmail_app_password
EMAIL_RECEIVER=your_gmail@gmail.com

### 4. Run Aegis-SOC
```bash
python main.py
```

---

## 🎯 Severity Levels

| Level | Description | Action |
|-------|-------------|--------|
| 🔴 CRITICAL | Confirmed threat pattern | Immediate escalation to L2 |
| 🟠 HIGH | Probable threat | Investigate immediately |
| 🟡 MEDIUM | Suspicious activity | Monitor closely |
| 🟢 LOW | Likely false positive | Log and ignore |

---

## 🗺️ Roadmap

- [x] V1 — Core triage pipeline
- [x] V2 — Email alerts, VirusTotal, expanded simulation, false positive tracking
- [ ] V3 — L2 automation, SIEM integration, alert correlation
- [ ] V4 — Dashboard UI, ML based detection, incident response playbooks

---

## 🤝 Contributing

Contributions are welcome. If you'd like to improve Aegis-SOC:

1. Fork the repository
2. Create a new branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m "Add your feature"`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

---

## 📜 License

This project is licensed under the MIT License — free to use, modify, and distribute.

---

> Aegis-SOC is a growing project. Star ⭐ the repo if you find it useful.