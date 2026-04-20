# 🟣 Purple Lab Lite

> A lightweight, Docker-based purple team detection lab. Emulate common attacks against a vulnerable target, ship logs to Elastic and automatically score whether your detections fired — all in a single `docker compose up`.

![License](https://img.shields.io/badge/license-MIT-purple)
![Docker](https://img.shields.io/badge/docker-required-blue)
![Elastic](https://img.shields.io/badge/elastic-8.x-green)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS-lightgrey)

---

## ⚠️ Security Notice

This deployment contains a **highly vulnerable web server (DVWA)**. Always run this lab inside a VM and on a **host-only network**. Do not expose any port to the internet or a production network.

---

## What is This?

Purple Lab Lite bridges the gap between offensive emulation and defensive validation. You run an attack script and the lab tells you whether your SIEM caught it. This provides a repeatable, measurable feedback loop for detection engineering.

```
┌─────────────────────────────────────────────────────┐
│                  Docker Network                     │
│                                                     │
│  ┌──────────┐   attacks   ┌──────────────────────┐  │
│  │ attacker │ ──────────► │  DVWA (victim app)   │  │
│  │ container│             │  localhost:8080      │  │
│  └──────────┘             └──────────┬───────────┘  │
│                                      │ logs         │
│                              ┌───────▼──────┐       │
│                              │   Filebeat   │       │
│                              └───────┬──────┘       │
│                                      │              │
│                              ┌───────▼──────┐       │
│                              │Elastic/Kibana│       │
│                              │localhost:5601│       │
│                              └──────────────┘       │
└─────────────────────────────────────────────────────┘
```

---

## 📦 Stack

| Component | Role | Port |
|-----------|------|------|
| **DVWA** | Vulnerable target (PHP web app) | `8080` |
| **Attacker** | Container with pre-built attack scripts | — |
| **Filebeat** | Log shipper (DVWA → Elastic) | — |
| **Elasticsearch** | Log storage and search | `9200` |
| **Kibana** | SIEM-style analysis UI | `5601` |

---

## 🚀 Quick Start

### Prerequisites

- Docker + Docker Compose
- Git
- Ideally running inside a VM on a host-only network

### 1 — Clone and prepare

```bash
git clone https://github.com/Incogn1toBro/Purple_Lab_Lite
cd Purple_Lab_Lite

# Filebeat requires strict ownership
sudo chown root ./infra/filebeat.yml
sudo chmod go-w ./infra/filebeat.yml

# Make attack scripts executable
sudo chmod +x ./infra/attack-scripts/*
```

### 2 — Start the lab

```bash
sudo docker compose up -d
sudo docker ps          # confirm all containers are running
```

### 3 — Configure Elastic

1. Navigate to **Kibana** → `http://localhost:5601`
2. Go to **Stack Management → Data Views → Create Data View**
3. Set the index pattern to `dvwa-raw-*`
4. Click **Save data view to Kibana**

### 4 — Configure DVWA

1. Navigate to **DVWA** → `http://localhost:8080`
2. Log in with `dvwa` / `Password1!`
3. Click **Create / Reset Database**
4. Log in again with `admin` / `password`
5. Confirm data is flowing: in Kibana, open **Discover** and check for entries

### 5 — Run an attack

Open each attack script and set the `TARGET_IP` variable to your DVWA container's IP, then run:

```bash
sudo docker exec -it attacker /scripts/<ATTACK_SCRIPT>.sh
```

### 6 — Analyse results

In Kibana, go to **Discover** and filter on the `message` field to find attack artefacts in the logs.

---

## ⚔️ Attack Playbooks

Attack scripts live in `infra/attack-scripts/`. Each script emulates a specific threat scenario.

| Script | Technique | Tool | MITRE ATT&CK |
|--------|-----------|------|--------------|
| `sqli_attack.sh` | SQL injection against DVWA `/vulnerabilities/sqli/` | `curl` | T1190 — Exploit Public-Facing Application |
| `port_scan.sh` | Network reconnaissance | `nmap` | T1046 — Network Service Discovery |
| `bruteforce_attack.sh` | HTTP login brute-force against `/login.php` | `curl` | T1110.001 — Brute Force: Password Guessing |

### How the SQLi script works

`sqli_attack.sh` authenticates to DVWA by first grabbing the rotating CSRF `user_token` from the login page, then submits credentials via `curl` to obtain a `PHPSESSID` session cookie. It then fires URL-encoded injection payloads (e.g. `1' OR 1=1--`) at the SQLi endpoint with `security=low` set as a cookie. Output is stripped of HTML tags and formatted as `First name: … Surname: …` pairs.

### How the brute force script works

`bruteforce_attack.sh` follows the same authentication pattern — it fetches a fresh `user_token` before **every** attempt since DVWA rotates the token on each request. It then submits each password in the wordlist, checks whether the response redirects to `index.php` (success) or back to `login.php` (failure), and logs the result. All 20 attempts are made even after a hit so that enough entries land in Elastic to score as **Detected** in the report.

> **Adding a new playbook:** Create a `.sh` script in `infra/attack-scripts/`, document the MITRE technique it maps to, and update this table.

---

## 📊 Generating a Detection Report

After running one or more attack scripts, generate an HTML coverage report:

```bash
python3 report.py --elastic http://localhost:9200 --output report.html
```

The report scores each playbook:
- ✅ **Detected** — at least one matching log entry was found within the window
- ⚠️ **Partial** — log entries found but below expected volume
- ❌ **Missed** — no matching entries found

Open `report.html` in any browser — it's fully self-contained with no external dependencies.

---

## 📁 Project Structure

```
Purple_Lab_Lite/
├── README.md
└── infra/
    ├── docker-compose.yml          # Defines all containers
    ├── Dockerfile      
    ├── filebeat.yml            # Filebeat config (must be owned by root)
    ├── report.py                   # Detection report generator
    ├── attack-scripts/
    │   ├── sqli_attack.sh      # SQL injection via curl (T1190)
    │   ├── port_scan.sh        # Network recon via nmap (T1046)
    │   └── bruteforce_attack.sh# HTTP brute force via curl (T1110.001)
```

---

## 🔍 Detection Engineering Tips

- **SQL Injection** — In Kibana Discover, filter `message` for `vulnerabilities/sqli`, `OR+1`, `1%3D1`, or `security=low`. The script fires URL-encoded payloads so look for percent-encoded characters in GET request logs.
- **Port Scan** — Nmap scans leave characteristic connection bursts from a single source IP hitting many destination ports in a short window. Filter by your attacker container's IP and count unique destination ports.
- **Brute Force** — Look for rapid repeated `POST /login.php` requests all carrying `Login=Login` and `user_token` parameters. A successful login shows a redirect to `index.php` after a chain of `login.php` redirects.

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch: `git checkout -b feat/my-new-playbook`
3. Add your attack script to `infra/attack-scripts/` and document the MITRE mapping
4. Open a pull request with a description of what the playbook emulates and what log artefacts it produces

---

## 📄 License

MIT — see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgements

- [DVWA](https://github.com/digininja/DVWA) — Damn Vulnerable Web Application
- [Elastic](https://www.elastic.co/elastic-stack) — Elasticsearch + Kibana
- [Filebeat](https://www.elastic.co/beats/filebeat) — Log shipping
- [sqlmap](https://sqlmap.org/) — SQL injection testing
- [nmap](https://nmap.org/) — Network reconnaissance
