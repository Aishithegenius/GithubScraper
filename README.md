# 🔍 GitHub Recon Scraper v3.7 — "The Omniscient"

**Enterprise-grade GitHub intelligence gathering, secret scanning, and OSINT reconnaissance.**

> ⚠️ **Authorized Penetration Testing Only** — This tool is designed for cybersecurity professionals conducting authorized security assessments. Unauthorized use is illegal.

---

## ✨ Features

### 🧠 Secret Detection (50+ Patterns)

Detect **secrets** including:
| Category | Examples |
|----------|----------|
| ☁️ **Cloud Keys** | AWS Access Keys, Google API Keys, Azure Storage Keys, DigitalOcean Tokens |
| 💬 **Communication** | Slack Tokens, Discord Webhooks, Twilio API Keys, SendGrid Keys |
| 🔑 **Auth Credentials** | Passwords, Private Keys (RSA/DSA/EC/OpenSSH), JWT Tokens |
| 🗄️ **Databases** | MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch Connection Strings |
| 🐙 **Version Control** | GitHub PATs (new & old), GitLab Tokens, BitBucket Tokens |
| 🌐 **Webhooks & URLs** | Slack/Discord Webhooks, Callback URLs, Internal Hostnames |
| 📄 **Config Files** | `.env`, `Dockerfile`, `docker-compose`, `kubeconfig`, Terraform Tokens |

### 🧬 Entropy-Based Heuristic Scanning

Catches **custom/proprietary secret formats** that regex-based scanners miss using Shannon entropy analysis (>3.5 = flagged).

### 🔄 Recursive Directory Traversal

Walks entire repository trees (configurable depth up to 5 levels) — not just root directories.

### 📊 Triple-Report Output

| Report          | Format | Use Case                                             |
| --------------- | ------ | ---------------------------------------------------- |
| **Dashboard**   | HTML   | Visual summary with severity color-coding            |
| **Structured**  | JSON   | Programmatic analysis, SIEM ingestion                |
| **Spreadsheet** | CSV    | Excel/Sheets, client reporting, remediation tracking |

### 🚀 Advanced Capabilities

- 🧵 **Multi-threaded** architecture for speed
- 🔐 **GitHub PAT support** for private repos + higher rate limits
- 🎭 **Anti-bot evasion** (custom user-agent, headless mode)
- ⏱️ **Rate limiting** with configurable delays
- 🔄 **Auto-retry** with exponential backoff
- 📸 **Screenshot capture** per repository
- 🚨 **Webhook alerts** on critical findings (Slack/Discord)
- 🎨 **Colorized real-time logging**

---

## 📦 Installation

### Prerequisites

- Python 3.8+
- Firefox browser
- Geckodriver

# Install Python dependencies

pip install -r requirements.txt

# Download geckodriver (Linux)

wget https://github.com/mozilla/geckodriver/releases/download/v0.35.0/geckodriver-v0.35.0-linux64.tar.gz
tar -xzf geckodriver-v0.35.0-linux64.tar.gz
sudo mv geckodriver /usr/local/bin/

# To Test

python main.py -t octocat -d 1 --headless
