# Teto ASM

Open-source **Attack Surface Management (ASM) platform** for discovering, monitoring, and securing external assets.

Teto helps security teams, pentesters, and bug bounty hunters automatically map their attack surface and detect vulnerabilities across domains, services, and infrastructure.

---

# Overview

Modern organizations expose many assets to the internet:

• domains  
• subdomains  
• APIs  
• cloud services  
• exposed ports  
• web applications  

Teto continuously discovers these assets and scans them for vulnerabilities using industry-standard reconnaissance tools.

The platform builds an **asset inventory**, tracks **changes in attack surface**, and generates **security findings with risk scoring**.

---

# Key Features

### Asset Discovery

Automatically discovers external assets:

• root domains  
• subdomains  
• IP addresses  
• services and ports  
• web endpoints  
• cloud assets

Discovery sources include:

- certificate transparency
- passive DNS
- ASN range expansion
- JS file extraction
- subdomain permutations
- cloud bucket discovery

---

### Vulnerability Scanning

Detects vulnerabilities across discovered assets using:

- :contentReference[oaicite:1]{index=1}
- :contentReference[oaicite:2]{index=2}
- :contentReference[oaicite:3]{index=3}
- :contentReference[oaicite:4]{index=4}
- :contentReference[oaicite:5]{index=5}
- :contentReference[oaicite:6]{index=6}
- :contentReference[oaicite:7]{index=7}
- :contentReference[oaicite:8]{index=8}

Scanning pipeline:


domain
↓
passive discovery
↓
DNS resolution
↓
service detection
↓
HTTP probing
↓
web crawling
↓
endpoint discovery
↓
vulnerability scanning


---

# Architecture

High-level architecture:

          User
           │
       REST API
       (FastAPI)
           │
  ┌────────┴────────┐
  │                 │

Asset Discovery Scan Engine
│ │
└────────┬────────┘
│
Worker Queue
│
Database
(assets, scans, findings)


Main components:

• API server  
• distributed workers  
• scheduler  
• database  
• optional web dashboard

---

# Repository Structure


teto/
├── app/
│ ├── api/
│ ├── models/
│ ├── scanners/
│ ├── tasks/
│ └── core/
│
├── frontend/
│
├── frontend-next/
│
├── docs/
│
└── docker-compose.yml


---

# Quick Start

Clone repository:


git clone https://github.com/dirthf0A/teto

cd teto


Create virtual environment:


python -m venv .venv
.venv\Scripts\activate


Install dependencies:


pip install -e .


Start API server:


uvicorn app.main:app --reload


API will start on:


http://127.0.0.1:8000


---

# Register Organization

Create an organization and admin user.


curl -X POST http://127.0.0.1:8000/auth/register

-H "Content-Type: application/json"
-d '{"org_name":"Acme","email":"admin@acme.com
","password":"change-me-now"}'


Response will include a **JWT token**.

---

# Asset Ingestion

Add a domain to the platform:


curl -X POST http://127.0.0.1:8000/assets/ingest

-H "Authorization: Bearer <token>"
-H "Content-Type: application/json"
-d '{"domain":"example.com","environment":"prod"}'


---

# Start a Scan


curl -X POST http://127.0.0.1:8000/scans

-H "Authorization: Bearer <token>"
-H "Content-Type: application/json"
-d '{"scan_type":"vuln"}'


Secret scanning:


curl -X POST http://127.0.0.1:8000/scans

-H "Authorization: Bearer <token>"
-d '{"scan_type":"secret"}'


---

# Run Worker

Workers process scan jobs.


python -m app.tasks.worker


Workers execute:

• asset discovery  
• vulnerability scans  
• secret scans  

Multiple workers can run in parallel.

---

# Run Scheduler

Scheduler runs continuous monitoring.


python -m app.tasks.scheduler


Default schedule:


Asset discovery → every 6 hours
Vulnerability scan → daily
Deep scan → weekly


---

# Dashboard

Run React dashboard:


cd frontend
npm install
npm run dev


Run Next.js dashboard:


cd frontend-next
npm install
npm run dev


---

# Continuous Monitoring

Teto tracks changes in the attack surface.

Examples:

• new subdomains  
• new services  
• new open ports  
• new endpoints  
• new vulnerabilities

Changes are stored in:


asset_history
asset_changes


Alerts can be triggered when changes are detected.

---

# Alerts & Notifications

Supported integrations:

• Email  
• Slack  
• Discord  
• Webhooks  

Example configuration:


ASM_ALERTS_ENABLED=true
ASM_SLACK_WEBHOOK=
ASM_DISCORD_WEBHOOK=
ASM_ALERT_WEBHOOK=


---

# Risk Scoring

Findings are scored based on severity:

| Severity | Score |
|--------|------|
Critical | 80 |
High | 50 |
Medium | 20 |
Low | 5 |
Info | 1 |

Additional factors:

• asset exposure  
• service type  
• asset importance

---

# Environment Configuration

Example environment variables:


ASM_JWT_SECRET=change-me
ASM_SCAN_RATE=100
ASM_QUEUE_BACKEND=redis
REDIS_URL=redis://localhost:6379


Scanner configuration:


ASM_SUBFINDER_ARGS
ASM_AMASS_ARGS
ASM_HTTPX_ARGS
ASM_NAABU_ARGS
ASM_NUCLEI_ARGS


---

# Distributed Scanning

For large scans, run multiple workers.

Example:


docker-compose up --scale worker=10


Workers will pull jobs from queue.

---

# Deployment

Run with Docker:


docker-compose up --build


This will start:

• API server  
• worker nodes  
• scheduler  
• database

---

# Security

Important recommendations:

• never expose API without authentication  
• set strong JWT secret  
• restrict scanning permissions  

Example:


ASM_JWT_SECRET=<secure-random-value>


---

# Roadmap

Future improvements:

• asset graph visualization  
• Kubernetes deployment  
• SaaS mode  
• AI vulnerability prioritization  
• large scale distributed scanning  

---

# License

MIT License

---

# Disclaimer

This tool is intended for **authorized security testing only**.

Do not scan systems without permission.
