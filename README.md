# Aegis-SOC
### Automated L1 SOC Triage System

Aegis-SOC is an open source cybersecurity tool that automates 
the first layer of SOC alert triage. It simulates security alerts, 
classifies them by severity using a rule engine, enriches suspicious 
alerts with real world threat intelligence via AbuseIPDB, and generates 
structured incident reports.

## Features
- Realistic security alert simulation
- Rule based severity classification
- Live threat intel enrichment via AbuseIPDB API
- Structured console and JSON report generation
- Modular and scalable architecture

## Setup
1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Create a `.env` file with your AbuseIPDB API key:
   `ABUSEIPDB_API_KEY=your_key_here`
4. Run: `python main.py`

## Project Structure
- `simulator/` — Alert simulation module
- `engine/` — Rule based classification engine
- `enrichment/` — Threat intel enrichment via AbuseIPDB
- `reporter/` — Report generation module
- `config/` — Central configuration

## Roadmap
- V2: Email alerts, multiple threat intel sources
- V3: L2 automation, SIEM integration
- V4: Dashboard UI, ML based detection