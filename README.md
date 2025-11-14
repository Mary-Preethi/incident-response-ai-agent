# AI-Augmented Incident Response Playbook — Mini Agent

**Author:** Mary Preethi  
**Project:** AI-Augmented Incident Response Playbook System — Aegisz Research Internship  
**Date:** 13 November 2025

## Summary
This is a Python-based interactive mini-agent that reads simulated alerts and recommends incident response actions using a rules-based mock LLM. The agent supports sample alerts and custom alerts, computes a risk score and severity, maps recommendations to IR phases (Containment, Eradication, Recovery, Post-Incident), and saves analyst-accepted recommendations to `agent_results.json`. The system is designed to be extended to a real LLM.

## Project files
- `agent.py` — interactive CLI agent (deeper IR logic included)
- `alerts.json` — sample alerts dataset
- `agent_results.json` — saved analysis results (example outputs)
- `README.md` — this file
- `report.docx` / `report.pdf` — project report (add to repo)

## Setup (Windows)
1. Open the project folder in VS Code.
2. Create & activate the virtual environment:
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
