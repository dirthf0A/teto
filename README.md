# Teto ASM

Open-source **Attack Surface Management (ASM) platform** for discovering, monitoring, and securing internet-facing assets.

Teto automatically maps your organization's external attack surface and continuously scans it for vulnerabilities.

---

# Overview

Modern organizations expose many assets to the internet:

• domains  
• subdomains  
• APIs  
• cloud infrastructure  
• exposed services  
• web applications  

Teto discovers these assets automatically and monitors them for security issues.

The platform builds a **centralized asset inventory**, tracks **changes in attack surface**, and identifies **security vulnerabilities with risk scoring**.

---

# Key Features

### Asset Discovery

Automatically discovers:

• subdomains  
• IP addresses  
• services and ports  
• web applications  
• cloud buckets  
• endpoints

Discovery sources include:

- certificate transparency
- passive DNS
- ASN range discovery
- JavaScript extraction
- subdomain permutations

---

### Vulnerability Scanning

Teto integrates well-known security scanning tools including:

- :contentReference[oaicite:0]{index=0}
- :contentReference[oaicite:1]{index=1}
- :contentReference[oaicite:2]{index=2}
- :contentReference[oaicite:3]{index=3}
- :contentReference[oaicite:4]{index=4}
- :contentReference[oaicite:5]{index=5}
- :contentReference[oaicite:6]{index=6}
- :contentReference[oaicite:7]{index=7}

Scanning pipeline:


domain
↓
subdomain discovery
↓
DNS resolution
↓
service detection
↓
web crawling
↓
endpoint discovery
↓
vulnerability scanning


---

# Architecture


User
│
Web Dashboard
│
API (FastAPI)
│
Worker Queue
│
Workers
│
Database


Main components:

• Web dashboard  
• REST API  
• scanning workers  
• scheduler  
• asset database

---

# Screenshots

(you can add screenshots here)


docs/screenshots/dashboard.png
docs/screenshots/assets.png
docs/screenshots/vulnerabilities.png


---

# Installation

Clone repository:


git clone https://github.com/dirthf0A/teto

cd teto


Create virtual environment:


python -m venv .venv
.venv\Scripts\activate


Install dependencies:


pip install -e .


Start the backend server:


uvicorn app.main:app --reload


Start the dashboard:


cd frontend
npm install
npm run dev


Open the web interface:


http://localhost:3000


---

# Using the Platform

All operations are performed through the **web dashboard**.

---

# 1. Create Organization

Open the dashboard and create an organization and admin user.

This account will manage assets and scans.

---

# 2. Add Assets

Navigate to:


Assets → Add Domain


Enter a root domain:


example.com


The platform will automatically start asset discovery.

---

# 3. Run a Scan

Go to:


Scans → New Scan


Select scan type:

• Asset Discovery  
• Vulnerability Scan  
• Secret Scan  

Start the scan.

Workers will process the job in background.

---

# 4. View Results

Scan results appear in the dashboard.

You can explore:


Assets
Services
Endpoints
Vulnerabilities
Asset Changes


Each finding includes:

• severity  
• description  
• affected asset  
• remediation hints

---

# Continuous Monitoring

Teto continuously monitors your attack surface.

It detects:

• new subdomains  
• newly opened ports  
• new endpoints  
• new vulnerabilities  

Changes are tracked in:


asset_history
asset_changes


---

# Alerts

Alerts can be sent via:

• Email  
• Slack  
• Discord  
• Webhooks  

Configuration example:


ASM_ALERTS_ENABLED=true
ASM_SLACK_WEBHOOK=
ASM_DISCORD_WEBHOOK=


---

# Risk Scoring

Findings are scored using severity weights:

| Severity | Score |
|--------|------|
Critical | 80 |
High | 50 |
Medium | 20 |
Low | 5 |
Info | 1 |

Additional risk factors:

• asset exposure  
• asset importance  
• service type

---

# Distributed Scanning

Large environments can run multiple workers.

Example:


docker-compose up --scale worker=10


Workers will process scanning jobs concurrently.

---

# Deployment

Run using Docker:


docker-compose up --build


This starts:

• API server  
• workers  
• scheduler  
• database  
• dashboard

---

# Roadmap

Future improvements:

• attack surface graph  
• SaaS deployment  
• Kubernetes support  
• advanced analytics  
• AI-assisted vulnerability prioritization

---

# License

MIT License

---

# Disclaimer

This project is intended for **authorized security testing only**.

Do not scan systems without permission.
