# agent.py — Interactive agent with deeper IR logic
import json
import uuid
from datetime import datetime
from pathlib import Path

ALERTS_FILE = "alerts.json"
RESULTS_FILE = "agent_results.json"

# --- Simple local IP reputation list (example) ---
# In real systems this is replaced by threat-intel feeds.
KNOWN_BAD_IPS = {
    "203.0.113.12": "suspicious-credential-probe",
    "198.51.100.45": "data-exfil-target"
}

SENSITIVE_HOSTS = {"db-server-2", "payment-db", "domain-controller", "dc1", "dc-prod"}

# --- Utility: basic text matcher ---
def contains_any(text, keywords):
    tx = (text or "").lower()
    return any(k.lower() in tx for k in keywords)

# --- Threat categorization rules ---
def categorize_threat(alert):
    a = alert.get("alert_type", "").lower()
    desc = alert.get("description", "")
    if "login" in a or contains_any(desc, ["failed login", "successful admin login", "credential", "mfa", "password"]):
        return "Credential Compromise"
    if "malware" in a or contains_any(desc, ["trojan", "ransom", "malware", ".exe", "infect"]):
        return "Malware"
    if "exfil" in a or contains_any(desc, ["data exfiltration", "large outbound", "sensitive data", "upload to"]):
        return "Data Exfiltration"
    if contains_any(desc, ["port scan", "nmap", "scan", "recon", "suspicious connection", "scan detected"]):
        return "Reconnaissance"
    return "Other"

# --- Heuristic severity/risk scoring ---
def compute_risk_and_severity(alert):
    """
    Returns a tuple: (risk_score [0-100], severity_label, confidence [0-1])
    Heuristics:
      - base points for alert type
      - +30 if host is sensitive
      - +30 if IP is in KNOWN_BAD_IPS
      - +20 for keywords indicating active compromise
      - cap at 100
    Confidence is fraction of matched indicators over possible indicators considered.
    """
    base = 0
    atype = (alert.get("alert_type") or "").lower()
    desc = alert.get("description") or ""
    host = (alert.get("host") or "").lower()
    points_matched = 0
    indicators_considered = 5  # type, desc_keywords, sensitive_host, known_ip, file_indicator

    # base by type
    if "login" in atype:
        base += 30
        points_matched += 1
    if "malware" in atype:
        base += 35
        points_matched += 1
    if "exfil" in atype or "exfiltration" in atype:
        base += 40
        points_matched += 1
    if "scan" in atype or "recon" in atype:
        base += 15
        points_matched += 1

    # keywords indicating active compromise
    if contains_any(desc, ["failed login", "successful admin login", "trojan", "ransom", "large outbound", "data exfiltration", "exploit", "privilege escalation", "pwned"]):
        base += 20
        points_matched += 1

    # sensitive host
    if host in SENSITIVE_HOSTS:
        base += 30
        points_matched += 1

    # known bad ip
    src = alert.get("source_ip") or alert.get("dest_ip") or ""
    if src and src in KNOWN_BAD_IPS:
        base += 30
        points_matched += 1

    # file indicator (executable-like)
    if alert.get("file_name") and any(ext in alert.get("file_name").lower() for ext in [".exe", ".dll", ".scr", ".bat", ".ps1"]):
        base += 15
        points_matched += 1

    # Normalize score
    score = int(min(base, 100))

    # Derive severity label
    if score >= 75:
        severity = "Critical"
    elif score >= 50:
        severity = "High"
    elif score >= 25:
        severity = "Medium"
    else:
        severity = "Low"

    # Confidence: how many of the top indicators matched divided by indicators_considered
    # We clamp to 0.2..0.95 to avoid 0 or 1 extremes in mock logic.
    confidence = points_matched / max(indicators_considered, 1)
    # clamp numeric step-by-step: avoid float issues (we'll keep 2 decimal)
    if confidence < 0.2:
        confidence = 0.2
    if confidence > 0.95:
        confidence = 0.95
    confidence = round(confidence, 2)

    return score, severity, confidence

# --- Map recommended actions into IR phases ---
PHASE_ACTIONS = {
    "Containment": {
        "Credential Compromise": [
            "Isolate affected host from network",
            "Force password reset and revoke sessions",
            "Block suspicious source IPs at perimeter"
        ],
        "Malware": [
            "Quarantine endpoint",
            "Disable network interfaces for host",
            "Block known malicious hashes/URLs"
        ],
        "Data Exfiltration": [
            "Block destination IPs and domains",
            "Stop affected data transfer processes",
            "Throttle/deny large outbound transfers"
        ],
        "Reconnaissance": [
            "Block scanning IPs",
            "Rate-limit suspicious ports",
            "Apply network ACLs"
        ],
        "Other": [
            "Isolate host for investigation",
            "Capture volatile data"
        ]
    },
    "Eradication": {
        "Credential Compromise": [
            "Search for indicators of compromise and remove backdoors",
            "Rotate credentials and reissue secrets",
            "Patch vulnerable services"
        ],
        "Malware": [
            "Run full AV and EDR cleanup",
            "Reimage host if persistence is detected",
            "Remove scheduled tasks/backdoors"
        ],
        "Data Exfiltration": [
            "Identify and remove exfil tools or scripts",
            "Revoke compromised accounts",
            "Close data exfiltration channels"
        ],
        "Reconnaissance": [
            "Harden exposed services",
            "Remove test/unused accounts"
        ],
        "Other": [
            "Remove malicious artifacts",
            "Perform targeted scans across environment"
        ]
    },
    "Recovery": {
        "Credential Compromise": [
            "Restore services and re-enable accounts with new credentials",
            "Monitor for re-occurrence"
        ],
        "Malware": [
            "Restore from clean backups",
            "Rebuild systems as needed, bring back to production carefully"
        ],
        "Data Exfiltration": [
            "Verify data integrity",
            "Notify stakeholders and begin remediation plan"
        ],
        "Reconnaissance": [
            "Monitor logs for follow-up activity",
            "Enable additional detection signatures"
        ],
        "Other": [
            "Validate system integrity and resume normal operations"
        ]
    },
    "Post-Incident": {
        "Credential Compromise": [
            "Perform root-cause analysis and update playbooks",
            "User awareness/training if phishing involved"
        ],
        "Malware": [
            "Perform malware triage and IOC sharing",
            "Update detection rules"
        ],
        "Data Exfiltration": [
            "Report to compliance/legal as required",
            "Perform forensic evidence preservation"
        ],
        "Reconnaissance": [
            "Threat-hunting to find any follow-up activity",
            "Improve network segmentation"
        ],
        "Other": [
            "Document lessons learned and update IR playbook"
        ]
    }
}

# --- Mock LLM recommendation (rules-based) enhanced by IR logic ---
def mock_llm_recommendation(alert):
    # Basic narrative recommendations (kept for readability)
    threat_cat = categorize_threat(alert)
    score, severity_label, confidence = compute_risk_and_severity(alert)

    # Compose phase-wise recommendations by selecting top items per phase for the category
    phase_recommendations = {}
    for phase, mapping in PHASE_ACTIONS.items():
        actions = mapping.get(threat_cat) or mapping.get("Other", [])
        # choose first 3 actions as recommended for brevity
        phase_recommendations[phase] = actions[:3]

    # Also keep a flat prioritized list: containment first, then eradication, recovery, post
    flat_recommendations = []
    for phase in ["Containment", "Eradication", "Recovery", "Post-Incident"]:
        flat_recommendations.extend(phase_recommendations.get(phase, [])[:2])  # up to 2 per phase

    explanation = f"Threat categorized as {threat_cat}. Heuristic risk score {score} suggests {severity_label} severity."

    return {
        "threat_category": threat_cat,
        "risk_score": score,
        "severity": severity_label,
        "confidence": confidence,
        "phase_recommendations": phase_recommendations,
        "recommendations": flat_recommendations,
        "explanation": explanation
    }

# --- Save result (append) ---
def save_result(result, path=RESULTS_FILE):
    p = Path(path)
    existing = []
    if p.exists():
        try:
            with open(p, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except Exception:
            existing = []
    existing.append(result)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2)
    print(f"Saved analysis to {p.resolve()} (id={result.get('result_id')})")

# --- Load alerts ---
def load_alerts(path=ALERTS_FILE):
    p = Path(path)
    if not p.exists():
        return []
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)

# --- Create a custom alert by asking user for fields ---
def create_custom_alert(next_id):
    print("\nCreate a custom alert (press enter to skip a field):")
    alert_type = input("Alert type (e.g., Suspicious login, Malware detected): ").strip() or "Custom"
    description = input("Short description: ").strip() or ""
    host = input("Host (e.g., PC-23, web-server-1): ").strip() or "unknown"
    username = input("Username (if applicable): ").strip()
    source_ip = input("Source IP (if known): ").strip()
    dest_ip = input("Destination IP (if known): ").strip()
    file_name = input("File name (if applicable): ").strip()
    timestamp = datetime.now().astimezone().isoformat()
    return {
        "id": next_id,
        "timestamp": timestamp,
        "alert_type": alert_type,
        "description": description,
        "host": host,
        "username": username,
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "file_name": file_name
    }

# --- Pretty-print an alert ---
def print_alert(a):
    print("\n--- ALERT ---")
    for k, v in a.items():
        if v:
            print(f"{k}: {v}")
    print("-------------")

# --- Main interactive loop ---
def main():
    alerts = load_alerts()
    if not alerts:
        print(f"No sample alerts loaded from {ALERTS_FILE}. You can still create custom alerts.")
    next_id = max([a.get("id", 0) for a in alerts], default=0) + 1

    while True:
        print("\n\n=== AI-Augmented Incident Response — Interactive (Deeper IR Logic) ===")
        print("Choose an option:")
        print("  1) List sample alerts")
        print("  2) Analyze a sample alert by ID")
        print("  3) Create and analyze a custom alert")
        print("  4) Show last results file path")
        print("  5) Exit")
        choice = input("Enter choice (1-5): ").strip()

        if choice == "1":
            if not alerts:
                print("No sample alerts found.")
            else:
                print("\nSample alerts:")
                for a in alerts:
                    print(f"  ID {a.get('id')}: {a.get('alert_type')} — {a.get('description')[:60]}")

        elif choice == "2":
            if not alerts:
                print("No sample alerts to choose from.")
                continue
            try:
                aid = int(input("Enter alert ID to analyze: ").strip())
            except ValueError:
                print("Invalid ID.")
                continue
            found = next((a for a in alerts if a.get("id") == aid), None)
            if not found:
                print(f"No alert with ID {aid}")
                continue
            print_alert(found)
            rec = mock_llm_recommendation(found)
            # Show outputs with phases
            print("\n=== AI RECOMMENDATION ===")
            print("Threat category:", rec["threat_category"])
            print("Risk score:", rec["risk_score"], "Severity:", rec["severity"], "Confidence:", rec["confidence"])
            print("\nPhase-wise recommendations:")
            for phase, actions in rec["phase_recommendations"].items():
                print(f"  {phase}:")
                for i, act in enumerate(actions, 1):
                    print(f"    {i}. {act}")
            print("\nFlat prioritized recommendations:")
            for i, r in enumerate(rec["recommendations"], 1):
                print(f"  {i}. {r}")
            print("Explanation:", rec["explanation"])

            decision = input("\nSave this analysis? (y/n): ").strip().lower()
            if decision == "y":
                result = {
                    "result_id": str(uuid.uuid4()),
                    "alert": found,
                    "analysis": rec,
                    "saved_by": "interactive_user",
                    "timestamp_saved": datetime.utcnow().isoformat()
                }
                save_result(result)
            else:
                print("Analysis not saved.")

        elif choice == "3":
            custom = create_custom_alert(next_id)
            next_id += 1
            print_alert(custom)
            rec = mock_llm_recommendation(custom)
            print("\n=== AI RECOMMENDATION ===")
            print("Threat category:", rec["threat_category"])
            print("Risk score:", rec["risk_score"], "Severity:", rec["severity"], "Confidence:", rec["confidence"])
            print("\nPhase-wise recommendations:")
            for phase, actions in rec["phase_recommendations"].items():
                print(f"  {phase}:")
                for i, act in enumerate(actions, 1):
                    print(f"    {i}. {act}")
            print("\nFlat prioritized recommendations:")
            for i, r in enumerate(rec["recommendations"], 1):
                print(f"  {i}. {r}")
            print("Explanation:", rec["explanation"])

            decision = input("\nSave this analysis? (y/n): ").strip().lower()
            if decision == "y":
                result = {
                    "result_id": str(uuid.uuid4()),
                    "alert": custom,
                    "analysis": rec,
                    "saved_by": "interactive_user",
                    "timestamp_saved": datetime.utcnow().isoformat()
                }
                save_result(result)
            else:
                print("Analysis not saved.")

        elif choice == "4":
            print(f"Results file: {Path(RESULTS_FILE).absolute()} (will be created when you save analysis)")

        elif choice == "5":
            print("Exiting. Goodbye 👋")
            break

        else:
            print("Invalid choice — enter 1,2,3,4 or 5.")

if __name__ == "__main__":
    main()
