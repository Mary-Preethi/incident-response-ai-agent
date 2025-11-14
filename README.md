
**Author:** Mary Preethi  
**Project:** AI-Augmented Incident Response Playbook System — Aegisz Research Internship  
**Date:** 13 November 2025

## Summary
This is a Python-based interactive mini-agent that reads simulated alerts and recommends incident response actions using a rules-based mock LLM. The agent supports both sample alerts and custom scenarios, computes a risk score and severity, maps recommendations to IR phases (Containment, Eradication, Recovery, Post-Incident), and saves analyst-approved results to `agent_results.json`. The system is designed to be safely extended to a real LLM.

---

## Features
- Interactive CLI workflow (choose sample alerts or create custom scenarios)
- Threat categorization (Credential Compromise, Malware, Data Exfiltration, Reconnaissance, Other)
- Heuristic risk scoring (0–100) with severity labels (Low/Medium/High/Critical)
- Confidence scoring based on matched indicators
- Phase-wise IR recommendations (Containment, Eradication, Recovery, Post-Incident)
- Flat prioritized action list for fast triage
- Save accepted recommendations to `agent_results.json` for auditing and reporting
- Modular design ready for future LLM integration

---

## Screenshots
Below are sample screenshots from the interactive agent (replace the example image paths with actual paths from your repo):

### 1. Interactive analysis of a suspicious login alert

![CLI Analysis 1](https://github.com/user-attachments/assets/6975aadc-501d-4ba3-8f1b-96cd243accca)

![CLI Analysis 2](https://github.com/user-attachments/assets/d2ea50e8-7688-4e71-8cba-739787df099f)


### 2. Saved analysis inside `agent_results.json`

![Saved Results 1](https://github.com/user-attachments/assets/c25e674e-e24d-4ad0-b0e2-0c9679612f52)

![Saved Results 2](https://github.com/user-attachments/assets/496f2082-f537-489a-b796-9d97fa22d0b8)

---

## Project Files
- `agent.py` — interactive CLI agent with deep IR logic  
- `alerts.json` — sample alert dataset  
- `agent_results.json` — saved analysis results  
- `README.md` — project overview and setup instructions  
- `report.pdf` — full project report (submitted for the internship)

---

## Project Architecture
- **agent.py:** Loads alerts → computes risk → generates IR recommendations → maps actions to IR phases → saves analyst-approved analysis.  
- **alerts.json:** Contains simulated SOC alerts.  
- **agent_results.json:** Stores saved results for auditing and reporting.  
- **README.md:** Project explanation, instructions, and screenshots.  
- **report.pdf:** Detailed write-up of the entire system.

---

## Setup (Windows)
1. Clone or download the repository.
2. Open the project folder in VS Code.
3. Create and activate the virtual environment:
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
