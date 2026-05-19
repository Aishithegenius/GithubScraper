#!/usr/bin/env python3
"""
████████████████████████████████████████████████████████████████████████████████
█                                                                              █
█   GITHUB RECON SCRAPER v3.7 — "The Omniscient"                               █
█   Author: Aishithegenius                                                     █
█   Purpose: Enterprise-grade GitHub intelligence gathering & secret scanning  █
█   Compliance: Authorized pentesting only. Sandboxed execution.               █
█                                                                              █
████████████████████████████████████████████████████████████████████████████████
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException, WebDriverException
from colorama import Fore, Back, Style, init
import requests
import re
import os
import sys
import json
import csv
import time
import base64
import hashlib
import argparse
import logging
import threading
import queue
import urllib.parse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set, Tuple, Optional, Any

# ─── INIT ─────────────────────────────────────────────────────────────────────
init(autoreset=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler('github_scraper.log'), logging.StreamHandler()]
)
log = logging.getLogger(__name__)

# ─── BANNER ───────────────────────────────────────────────────────────────────
BANNER = f"""
{Fore.RED}{'='*70}
{Fore.YELLOW}   ╔════════════════════════════════════════════════════════════════════╗
{Fore.YELLOW}   ║     {Fore.WHITE}GITHUB RECON SCRAPER — THE OMNISCIENT{Fore.YELLOW} ║
{Fore.YELLOW}   ║     {Fore.WHITE}V3.7  |  Authorized Pentesting Only{Fore.YELLOW}   ║
{Fore.YELLOW}   ╚════════════════════════════════════════════════════════════════════╝
{Fore.RED}{'='*70}{Style.RESET_ALL}
"""

# ─── CONFIGURATION ────────────────────────────────────────────────────────────
class Config:
    """Centralized configuration — tweak these values as needed."""
    # Paths
    GECKO_DRIVER_PATH = r"C:\developer\geckodriver\geckodriver.exe"
    OUTPUT_DIR = os.getenv("OUTPUT_DIR", "./github_recon_output")
    
    # Browser settings
    HEADLESS = os.getenv("HEADLESS", "False").lower() == "true"
    PAGE_LOAD_TIMEOUT = int(os.getenv("PAGE_LOAD_TIMEOUT", "30"))
    IMPLICIT_WAIT = int(os.getenv("IMPLICIT_WAIT", "10"))
    
    # Rate limiting
    REQUEST_DELAY = float(os.getenv("REQUEST_DELAY", "1.5"))
    MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))
    
    # Threading
    MAX_WORKERS = int(os.getenv("MAX_WORKERS", "5"))
    
    # Scanning
    MAX_REPO_DEPTH = int(os.getenv("MAX_REPO_DEPTH", "3"))
    MAX_FILE_SIZE_KB = int(os.getenv("MAX_FILE_SIZE_KB", "500"))
    
    # Webhook / notification
    WEBHOOK_URL = os.getenv("WEBHOOK_URL", "")

# ─── SECRET PATTERNS — 50+ Detection Rules ────────────────────────────────────
SECRET_PATTERNS = {
    # ── API Keys & Tokens ──────────────────────────────────────────────────
    "AWS Access Key ID":          r"AKIA[0-9A-Z]{16}",
    "AWS Secret Access Key":      r"(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]",
    "AWS Session Token":          r"(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{100,}['\"]",
    "Google API Key":             r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth":               r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "Google Cloud Service Account": r"\"type\": \"service_account\"",
    "Slack Token":                r"(xox[baprs]-[0-9a-zA-Z\-]{10,})",
    "Slack Webhook":              r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24,}",
    "Discord Bot Token":          r"[Mm][Nn][Dd][Cc][E-Za-z2-9+/=]{60,75}",
    "Discord Webhook":            r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+",
    "GitHub Token (new)":         r"github_pat_[a-zA-Z0-9]{36,}",
    "GitHub Token (old)":         r"[a-f0-9]{40}",
    "GitLab Token":               r"glpat-[a-zA-Z0-9\-_]{20,}",
    "GitLab CI Token":            r"CI_JOB_TOKEN=['\"][a-zA-Z0-9\-_]{20,}['\"]",
    "BitBucket Token":            r"bitbucket[a-zA-Z0-9\-_]{30,}",
    "JWT Token":                  r"eyJ[a-zA-Z0-9\-_]{10,}\.[a-zA-Z0-9\-_]{10,}\.[a-zA-Z0-9\-_]{10,}",
    "Heroku API Key":             r"[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "Mailgun API Key":            r"key-[0-9a-zA-Z]{32}",
    "Mailchimp API Key":          r"[0-9a-f]{32}-us[0-9]{1,2}",
    "Twilio API Key":             r"SK[0-9a-fA-F]{32}",
    "Twitter API Key":            r"(?i)twitter(.{0,20})?(?-i)[1-9][0-9]{17}-[a-zA-Z0-9]{16,}",
    "Facebook App Secret":        r"(?i)facebook(.{0,20})?(?-i)[0-9a-f]{32}",
    "Stripe Live Key":            r"(?:r|s)k_live_[0-9a-zA-Z]{24,}",
    "Stripe Test Key":            r"(?:r|s)k_test_[0-9a-zA-Z]{24,}",
    "Patreon Client ID":          r"(?i)patreon(.{0,20})?(?-i)[a-zA-Z0-9_-]{20,}",
    "Patreon API Key":            r"api_key=[a-zA-Z0-9_-]{20,}",
    "SendGrid API Key":           r"SG\.[a-zA-Z0-9\-_]{20,}\.[a-zA-Z0-9\-_]{20,}",
    "Dropbox Token":              r"(?i)dropbox(.{0,20})?(?-i)[a-z0-9]{15,}",
    "Azure Storage Key":          r"DefaultEndpointsProtocol=https;AccountName=[a-zA-Z0-9]+;AccountKey=[a-zA-Z0-9+/]{40,}",
    "Azure DevOps Token":         r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "NPM Token":                  r"npm_[a-zA-Z0-9]{36}",
    "NPM Publish Token":          r"_authToken=[a-f0-9]{64}",
    
    # ── Database Connection Strings ───────────────────────────────────────
    "MySQL Connection":           r"mysql://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9.\-]+:[0-9]+/[a-zA-Z0-9_]+",
    "PostgreSQL Connection":      r"postgres(?:ql)?://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9.\-]+:[0-9]+/[a-zA-Z0-9_]+",
    "MongoDB Connection":         r"mongodb(?:\+srv)?://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9.\-]+(:[0-9]+)?/[a-zA-Z0-9_]+",
    "Redis Connection":           r"redis://[^@\s]*@[a-zA-Z0-9.\-]+:[0-9]+",
    "Elasticsearch Connection":   r"https://elastic:[^@\s]+@[a-zA-Z0-9.\-]+:[0-9]+",
    "SQLite Path":                r"sqlite:///.+\.(db|sqlite|sqlite3)",
    
    # ── Credentials & Auth ─────────────────────────────────────────────────
    "Password (keyword)":         r"(?i)(password|passwd|pwd|secret|passphrase)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
    "Username/Email":             r"(?i)(username|user|login|email|login_id)\s*[:=]\s*['\"][^'\"]{3,}['\"]",
    "Private Key (RSA)":          r"-----BEGIN RSA PRIVATE KEY-----",
    "Private Key (OpenSSH)":      r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "Private Key (DSA)":          r"-----BEGIN DSA PRIVATE KEY-----",
    "Private Key (EC)":           r"-----BEGIN EC PRIVATE KEY-----",
    "Private Key (PGP)":          r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "SSH Private Key File":       r"id_rsa|id_dsa|id_ecdsa|id_ed25519",
    "AWS PEM File":               r"\.pem$",
    
    # ── Cloud & Infrastructure ─────────────────────────────────────────────
    "Cloudflare API Key":         r"(?i)cloudflare(.{0,20})?(?-i)[a-zA-Z0-9]{37}",
    "DigitalOcean Token":         r"(?i)digital.?ocean(.{0,20})?(?-i)[a-f0-9]{64}",
    "Firebase URL":               r"https://[a-zA-Z0-9-]+\.firebaseio\.com",
    "Firebase Key":               r"AIza[0-9A-Za-z_-]{35}",
    "Terraform Token":            r"(?i)terraform(.{0,20})?(?-i)[a-zA-Z0-9]{40}",
    "Kubernetes Config":          r"kubeconfig|kubectl.*config|KUBERNETES_SERVICE",
    "Docker Registry Auth":       r"\$docker_password|DOCKER_AUTH|docker.*login.*--password",
    
    # ── Environment & Config Files ─────────────────────────────────────────
    "Environment File":           r"\.env$|\.env\.prod$|\.env\.dev$|\.env\.staging$",
    "Config File (sensitive)":    r"(config\.json|config\.yml|config\.yaml|application\.properties)",
    "Dockerfile Expose":          r"EXPOSE\s+[0-9]{4,5}",
    "Docker Compose Port":        r"ports:\s*\n\s*-\s*\"?[0-9]{4,5}:",
    ".gitignore bypass":          r"!(\.env|\.aws|credentials|secrets|config\.json)",
    
    # ── Connection & Hooks ─────────────────────────────────────────────────
    "Webhook URL":                r"https://[a-zA-Z0-9.-]+/hook/[a-zA-Z0-9]+",
    "Callback URL":               r"(callback|redirect_uri|return_url)\s*[:=]\s*['\"]?https?://[^'\"]+['\"]?",
    
    # ── Tokens in Code Comments ────────────────────────────────────────────
    "Hardcoded IP Address":       r"(?:^|[^0-9])(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:[^0-9]|$)",
    "Internal Hostname":          r"(?i)(localhost|development|staging|internal|corp|private)\.[a-zA-Z0-9.-]+",
    
    # ── Certificate & Certificate Authorities ──────────────────────────────
    "Certificate (Base64)":       r"-----BEGIN CERTIFICATE-----",
    "Certificate Chain":          r"-----BEGIN CERTIFICATE----------END CERTIFICATE-----",
}

# ─── FILE EXTENSIONS OF INTEREST ──────────────────────────────────────────────
INTERESTING_EXTENSIONS = {
    # Source code
    '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.cpp', '.c', '.h', '.hpp',
    '.cs', '.go', '.rb', '.php', '.swift', '.kt', '.scala', '.rs', '.clj',
    '.sh', '.bash', '.zsh', '.ps1', '.bat', '.cmd',
    # Config & data
    '.json', '.yaml', '.yml', '.xml', '.toml', '.ini', '.cfg', '.conf',
    '.env', '.env.example', '.env.prod', '.env.dev',
    '.sql', '.db', '.sqlite', '.sqlite3',
    # Keys & certs
    '.pem', '.key', '.crt', '.cert', '.p12', '.pfx', '.jks',
    '.der', '.cer', '.ca-bundle',
    # Config & deployment
    '.tf', '.tfvars', '.hcl', '.dockerfile', 'Dockerfile',
    '.yml', '.yaml',
    '.gitignore', '.dockerignore', '.helmignore',
    # CI/CD
    '.github/workflows', '.gitlab-ci.yml', '.circleci/config.yml',
    '.travis.yml', '.jenkins', 'Jenkinsfile',
    # Secrets & tokens
    '.netrc', '.aws/credentials', '.aws/config',
    '.gcloud', '.azure',
    # Docs that sometimes contain secrets
    '.md', '.rst', '.txt', '.log',
}

# ─── GURU-CLASS SCRAPER ENGINE ───────────────────────────────────────────────
class GuruScraper:
    """
    The main scraping engine. 
    Features:
      - Multi-threaded repo traversal
      - Recursive directory walk
      - 50+ secret pattern detectors
      - Entropy-based secret detection (heuristic)
      - CSV, JSON, HTML report generation
      - Screenshot capture per repo
      - Rate limiting + retry logic
      - Authentication support (PAT)
      - Webhook alerting on critical finds
    """
    
    def __init__(self, target: str, github_token: str = "", depth: int = 1):
        self.target = target
        self.github_token = github_token
        self.depth = depth
        self.start_time = datetime.now()
        self.results = {
            "scan_metadata": {
                "target": target,
                "started_at": self.start_time.isoformat(),
                "depth": depth,
                "token_configured": bool(github_token),
            },
            "repos": [],
            "secrets_found": [],
            "interesting_files": [],
            "summary": {}
        }
        self.visited_urls: Set[str] = set()
        self.secret_findings: List[Dict] = []
        self.file_queue = queue.Queue()
        self.lock = threading.Lock()
        
        # Ensure output directory exists
        self.output_dir = os.path.join(Config.OUTPUT_DIR, 
                                       f"recon_{self.start_time.strftime('%Y%m%d_%H%M%S')}")
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "screenshots"), exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "raw_files"), exist_ok=True)
        
        log.info(f"{Fore.GREEN}[+] Output directory: {self.output_dir}{Style.RESET_ALL}")
    
    def _init_driver(self) -> webdriver.Firefox:
        """Initialize Firefox driver properly with geckodriver path."""

        options = Options()

        # Firefox binary (ONLY if needed)
        firefox_path = r"C:\Program Files\Mozilla Firefox\firefox.exe"
        if os.path.exists(firefox_path):
            options.binary_location = firefox_path

        # Headless mode
        if Config.HEADLESS:
            options.add_argument("--headless")

        # Anti-bot + performance tweaks
        options.set_preference("dom.webdriver.enabled", False)
        options.set_preference("useAutomationExtension", False)
        options.set_preference(
            "general.useragent.override",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"
        )
        options.set_preference("permissions.default.image", 2)

        # IMPORTANT FIX: geckodriver service
        driver = webdriver.Firefox(options=options)

        driver.set_page_load_timeout(Config.PAGE_LOAD_TIMEOUT)
        driver.implicitly_wait(Config.IMPLICIT_WAIT)

        return driver
    
    def _safe_get(self, driver: webdriver.Firefox, url: str) -> bool:
        """Navigate to URL with retry logic and error handling."""
        for attempt in range(1, Config.MAX_RETRIES + 1):
            try:
                driver.get(url)
                time.sleep(Config.REQUEST_DELAY)
                return True
            except TimeoutException:
                log.warning(f"{Fore.YELLOW}[!] Timeout on {url} (attempt {attempt}/{Config.MAX_RETRIES}){Style.RESET_ALL}")
                driver.execute_script("window.stop();")
            except WebDriverException as e:
                log.error(f"{Fore.RED}[!] WebDriver error on {url}: {e}{Style.RESET_ALL}")
                if attempt == Config.MAX_RETRIES:
                    return False
                time.sleep(2 ** attempt)  # Exponential backoff
        return False
    
    def _get_repo_list(self, driver: webdriver.Firefox) -> List[str]:
        """Extract repository names from the target GitHub account/org page."""
        repos = []
        try:
            elements = driver.find_elements(By.CLASS_NAME, "repo")
            repos = [el.text.strip() for el in elements if el.text.strip()]
            
            # Also try alternate selectors for reliability
            if not repos:
                # Try the newer GitHub layout's repo name links
                elements = driver.find_elements(By.CSS_SELECTOR, 
                    "a[itemprop='name codeRepository'], h3 a, .wb-break-all a")
                repos = [el.text.strip() for el in elements if el.text.strip()]
                
            # If still empty, try the org/repo tab
            if not repos:
                elements = driver.find_elements(By.XPATH, 
                    '//a[contains(@href, "/")]')
                repos = list(set([
                    el.get_attribute("href").split("/")[-1] 
                    for el in elements 
                    if el.get_attribute("href") and f"github.com/{self.target}" in el.get_attribute("href")
                ]))
                
        except Exception as e:
            log.error(f"{Fore.RED}[!] Error getting repo list: {e}{Style.RESET_ALL}")
        
        # Filter to unique, non-empty names
        repos = list(set([r for r in repos if r and r != self.target]))
        log.info(f"{Fore.CYAN}[*] Found {len(repos)} repositories{Style.RESET_ALL}")
        return repos
    
    def _walk_directory(self, driver: webdriver.Firefox, repo_url: str, 
                        current_path: str = "") -> List[Dict]:
        """
        Recursively walk a repository's directory tree.
        Returns list of file info dicts.
        """
        files_found = []
        
        if current_path:
            url = f"{repo_url}/tree/main/{current_path}"
        else:
            url = repo_url
        
        if url in self.visited_urls:
            return files_found
        self.visited_urls.add(url)
        
        if not self._safe_get(driver, url):
            return files_found
        
        try:
            # Check if it's a single file view
            if "/blob/" in driver.current_url:
                file_info = self._extract_file_info(driver, driver.current_url)
                if file_info:
                    files_found.append(file_info)
                return files_found
            
            # Get directory contents
            # Get directory contents — try multiple selectors
            items = driver.find_elements(By.CSS_SELECTOR, 
                "a.js-navigation-open, [data-testid='directory-item'], a[href*='/blob/'], a[href*='/tree/'], .react-directory-row-name-cell-large-screen a")
            
            # If still empty, try role-based selectors (new GitHub UI)
            if not items:
                items = driver.find_elements(By.XPATH, 
                    "//a[contains(@href, '/blob/') or contains(@href, '/tree/')]")
            
            # Last resort: get all links in the file list
            if not items:
                items = driver.find_elements(By.CSS_SELECTOR, 
                    "div[role='row'] a, td[class*='content'] a")
            
            for item in items:
                try:
                    item_text = item.text.strip()
                    item_href = item.get_attribute("href") or ""
                    
                    if not item_text:
                        continue
                    
                    file_info = {
                        "name": item_text,
                        "url": item_href,
                        "type": "file",
                        "path": os.path.join(current_path, item_text) if current_path else item_text
                    }
                    
                    # Check if it's a directory (no extension or from icon)
                    is_dir = (
                        "/tree/" in item_href or 
                        "." not in item_text or 
                        item_text.endswith("/")
                    )
                    
                    if is_dir and self.depth > 0:
                        file_info["type"] = "directory"
                        self.depth -= 1
                        log.info(f"{Fore.BLUE}[→] Entering directory: {file_info['path']}{Style.RESET_ALL}")
                        sub_files = self._walk_directory(
                            driver, repo_url, file_info["path"]
                        )
                        files_found.extend(sub_files)
                        self.depth += 1
                    else:
                        file_info["type"] = "file"
                        files_found.append(file_info)
                        
                        # Check extension interest
                        ext = os.path.splitext(item_text)[1].lower()
                        if ext in INTERESTING_EXTENSIONS or any(
                            kw in item_text.lower() for kw in ['env', 'key', 'secret', 'cred', 'token', 'config']
                        ):
                            with self.lock:
                                self.results["interesting_files"].append(file_info)
                                log.info(f"{Fore.MAGENTA}[★] Interesting file: {file_info['path']}{Style.RESET_ALL}")
                    
                except Exception as e:
                    log.debug(f"Error processing item: {e}")
                    continue
            
        except Exception as e:
            log.error(f"{Fore.RED}[!] Error walking {url}: {e}{Style.RESET_ALL}")
        
        return files_found
    
    def _extract_file_info(self, driver: webdriver.Firefox, file_url: str) -> Optional[Dict]:
        """Extract metadata and contents from a single file view."""
        try:
            # Get raw content URL
            raw_url = file_url.replace("/blob/", "/raw/")
            
            # Get file metadata
            name = file_url.split("/")[-1]
            ext = os.path.splitext(name)[1].lower()
            
            # Try to get page source for secret scanning
            html = driver.page_source
            
            # Also try to fetch raw content directly (faster)
            raw_content = ""
            try:
                headers = {"User-Agent": "Mozilla/5.0"}
                if self.github_token:
                    headers["Authorization"] = f"Bearer {self.github_token}"
                resp = requests.get(raw_url, headers=headers, timeout=10)
                if resp.status_code == 200:
                    raw_content = resp.text
            except Exception:
                pass
            
            file_info = {
                "name": name,
                "url": file_url,
                "raw_url": raw_url,
                "extension": ext,
                "content_length": len(raw_content) if raw_content else len(html),
                "secrets_found": []
            }
            
            # ── Scan for secrets ──────────────────────────────────────────
            content_to_scan = raw_content if raw_content else html
            secrets_in_file = self._scan_for_secrets(content_to_scan, name)
            
            if secrets_in_file:
                file_info["secrets_found"] = secrets_in_file
                with self.lock:
                    for secret in secrets_in_file:
                        self.results["secrets_found"].append({
                            **secret,
                            "file": file_url,
                            "repo": self.target
                        })
                
                # Critical alert for high-severity findings
                for s in secrets_in_file:
                    if s.get("severity") == "critical":
                        self._send_alert(f"CRITICAL: {s['type']} in {file_url}")
                        log.critical(f"{Fore.RED}{Back.YELLOW}[!] CRITICAL FIND: {s['type']} → {file_url}{Style.RESET_ALL}")
            
            # Save raw file for evidence
            if raw_content and len(raw_content) < Config.MAX_FILE_SIZE_KB * 1024:
                safe_name = name.replace("/", "_").replace("\\", "_")
                filepath = os.path.join(self.output_dir, "raw_files", safe_name)
                try:
                    with open(filepath, 'w', encoding='utf-8', errors='ignore') as f:
                        f.write(raw_content)
                except Exception:
                    pass
            
            return file_info
            
        except Exception as e:
            log.debug(f"Error extracting file info from {file_url}: {e}")
            return None
    
    def _scan_for_secrets(self, content: str, filename: str = "") -> List[Dict]:
        """
        Scan content for secrets using 50+ regex patterns AND entropy analysis.
        Returns list of finding dicts.
        """
        findings = []
        
        # ── Regex-based detection ─────────────────────────────────────────
        for secret_name, pattern in SECRET_PATTERNS.items():
            try:
                matches = re.finditer(pattern, content, re.MULTILINE)
                for match in matches:
                    # Filter out false positives (test/template values)
                    matched_text = match.group()
                    skip = any(skip_val in matched_text.lower() for skip_val in [
                        "example", "test", "placeholder", "your_", "changeme",
                        "****", "xxxx", "12345", "TODO", "FIXME", "template"
                    ])
                    if skip:
                        continue
                    
                    # Determine severity
                    severity = "medium"
                    if any(kw in secret_name.lower() for kw in ["private key", "password", "secret", "critical"]):
                        severity = "critical"
                    elif any(kw in secret_name.lower() for kw in ["token", "api key", "connection", "credential"]):
                        severity = "high"
                    
                    # Get context (surrounding lines)
                    lines = content.split('\n')
                    line_num = content[:match.start()].count('\n') + 1
                    start_line = max(0, line_num - 2)
                    end_line = min(len(lines), line_num + 2)
                    context = '\n'.join(lines[start_line:end_line])
                    
                    findings.append({
                        "type": secret_name,
                        "severity": severity,
                        "line": line_num,
                        "match": matched_text[:80] + "..." if len(matched_text) > 80 else matched_text,
                        "context": context,
                        "regex": pattern[:50] + "..." if len(pattern) > 50 else pattern
                    })
            except re.error as e:
                log.debug(f"Regex error for {secret_name}: {e}")
                continue
        
        # ── Entropy-based detection (heuristic for unknown secret formats) ──
        if filename.endswith(('.env', '.json', '.yaml', '.yml', '.ini', '.cfg', '.conf', '.py', '.js', '.ts', '.sh')):
            entropy_findings = self._entropy_scan(content, filename)
            findings.extend(entropy_findings)
        
        return findings
    
    def _entropy_scan(self, content: str, filename: str) -> List[Dict]:
        """
        Shannon entropy scan for high-entropy strings that look like secrets.
        Catches things regex misses (custom API keys, proprietary tokens).
        """
        findings = []
        
        # Find potential high-entropy strings (alphanumeric, 20+ chars)
        potential_secrets = re.findall(r'["\'][A-Za-z0-9+/=\-_]{20,}["\']', content)
        potential_secrets += re.findall(r'["\']([A-Za-z0-9]{32,})["\']', content)
        
        for secret in potential_secrets:
            secret = secret.strip("'\"")
            if len(secret) < 20:
                continue
            
            # Filter out common non-secrets
            if secret.lower() in ['true', 'false', 'null', 'undefined', 'none']:
                continue
            if secret.startswith('http') and len(secret) < 100:
                continue
            
            # Calculate entropy
            entropy = self._shannon_entropy(secret)
            
            # High entropy (> 3.5) suggests randomness = potential secret
            if entropy > 3.5 and entropy < 6.5:  # Upper bound filters base64 images etc
                # Find line number
                lines = content.split('\n')
                line_num = 0
                context = ""
                for i, line in enumerate(lines):
                    if secret[:20] in line:
                        line_num = i + 1
                        start = max(0, i - 1)
                        end = min(len(lines), i + 2)
                        context = '\n'.join(lines[start:end])
                        break
                
                findings.append({
                    "type": f"High-Entropy String (entropy: {entropy:.2f})",
                    "severity": "medium",
                    "line": line_num,
                    "match": secret[:60] + "..." if len(secret) > 60 else secret,
                    "context": context,
                    "entropy": round(entropy, 2),
                    "regex": "Heuristic/Entropy-based"
                })
        
        return findings
    
    @staticmethod
    def _shannon_entropy(s: str) -> float:
        """Calculate Shannon entropy of a string (higher = more random)."""
        if not s:
            return 0.0
        entropy = 0
        for x in range(256):
            p_x = s.count(chr(x)) / len(s)
            if p_x > 0:
                entropy += -p_x * (p_x.bit_length() - 1)
        return entropy
    
    def _take_screenshot(self, driver: webdriver.Firefox, name: str):
        """Capture a screenshot of the current page."""
        try:
            safe_name = name.replace("/", "_").replace(":", "_")[:100]
            path = os.path.join(self.output_dir, "screenshots", f"{safe_name}.png")
            driver.save_screenshot(path)
            log.debug(f"[+] Screenshot saved: {path}")
        except Exception as e:
            log.debug(f"Could not take screenshot: {e}")
    
    def _send_alert(self, message: str):
        """Send critical alert via webhook."""
        if not Config.WEBHOOK_URL:
            return
        try:
            payload = {
                "text": f"🚨 GURU SCRAPER ALERT\n{message}\nTimestamp: {datetime.now().isoformat()}"
            }
            requests.post(Config.WEBHOOK_URL, json=payload, timeout=5)
        except Exception:
            pass
    
    def _generate_report(self):
        """Generate comprehensive HTML, JSON, and CSV reports."""
        timestamp = self.start_time.strftime("%Y%m%d_%H%M%S")
        
        # ── Summary ───────────────────────────────────────────────────────
        total_files = sum(len(repo_info.get("files", [])) for repo_info in self.results["repos"])
        total_secrets = len(self.results["secrets_found"])
        
        self.results["summary"] = {
            "target": self.target,
            "scan_duration": str(datetime.now() - self.start_time),
            "repos_scanned": len(self.results["repos"]),
            "files_analyzed": total_files,
            "secrets_discovered": total_secrets,
            "critical_finds": sum(1 for s in self.results["secrets_found"] if s.get("severity") == "critical"),
            "high_finds": sum(1 for s in self.results["secrets_found"] if s.get("severity") == "high"),
            "medium_finds": sum(1 for s in self.results["secrets_found"] if s.get("severity") == "medium"),
            "interesting_files_count": len(self.results["interesting_files"])
        }
        
        # ── JSON Report ───────────────────────────────────────────────────
        json_path = os.path.join(self.output_dir, f"report_{timestamp}.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, default=str)
        log.info(f"{Fore.GREEN}[+] JSON report: {json_path}{Style.RESET_ALL}")
        
        # ── CSV Report ────────────────────────────────────────────────────
        csv_path = os.path.join(self.output_dir, f"secrets_{timestamp}.csv")
        if self.results["secrets_found"]:
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    "type", "severity", "file", "repo", "line", "match", "entropy"
                ])
                writer.writeheader()
                for secret in self.results["secrets_found"]:
                    writer.writerow({
                        "type": secret.get("type", ""),
                        "severity": secret.get("severity", ""),
                        "file": secret.get("file", ""),
                        "repo": secret.get("repo", ""),
                        "line": secret.get("line", ""),
                        "match": secret.get("match", ""),
                        "entropy": secret.get("entropy", "")
                    })
            log.info(f"{Fore.GREEN}[+] CSV report: {csv_path}{Style.RESET_ALL}")
        
        # ── HTML Report (beautiful, self-contained) ──────────────────────
        html_path = os.path.join(self.output_dir, f"report_{timestamp}.html")
        self._generate_html_report(html_path)
        log.info(f"{Fore.GREEN}[+] HTML report: {html_path}{Style.RESET_ALL}")
        
        # Print summary to console
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}   SCAN COMPLETE")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.WHITE}   Target:              {Fore.GREEN}{self.target}")
        print(f"{Fore.WHITE}   Duration:            {Fore.GREEN}{self.results['summary']['scan_duration']}")
        print(f"{Fore.WHITE}   Repos scanned:       {Fore.GREEN}{self.results['summary']['repos_scanned']}")
        print(f"{Fore.WHITE}   Files analyzed:      {Fore.GREEN}{self.results['summary']['files_analyzed']}")
        print(f"{Fore.WHITE}   Secrets discovered:  {Fore.RED}{self.results['summary']['secrets_discovered']}")
        print(f"{Fore.WHITE}   Critical:            {Fore.RED}{self.results['summary']['critical_finds']}")
        print(f"{Fore.WHITE}   High:                {Fore.YELLOW}{self.results['summary']['high_finds']}")
        print(f"{Fore.WHITE}   Medium:              {Fore.YELLOW}{self.results['summary']['medium_finds']}")
        print(f"{Fore.WHITE}   Output directory:    {Fore.GREEN}{self.output_dir}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    def _generate_html_report(self, path: str):
        """Generate a beautiful, interactive HTML report."""
        secrets = self.results["secrets_found"]
        summary = self.results["summary"]
        
        html_rows = ""
        for s in secrets[:100]:  # Limit to 100 for performance
            severity_color = {
                "critical": "#dc3545",
                "high": "#fd7e14",
                "medium": "#ffc107"
            }.get(s.get("severity", "medium"), "#6c757d")
            
            html_rows += f"""
            <tr>
                <td><span class="badge" style="background:{severity_color}">{s.get('severity','')}</span></td>
                <td>{s.get('type','')}</td>
                <td><small>{s.get('file','').split('/')[-1]}</small></td>
                <td><small>{s.get('repo','')}</small></td>
                <td><code>{s.get('match','')[:60]}</code></td>
            </tr>"""
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>GitHub Recon Report — {self.target}</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ font-family:'Segoe UI',sans-serif; background:#0d1117; color:#c9d1d9; padding:20px; }}
        .container {{ max-width:1400px; margin:0 auto; }}
        h1 {{ color:#58a6ff; margin-bottom:5px; }}
        h2 {{ color:#f0883e; margin:20px 0 10px; }}
        .meta {{ color:#8b949e; font-size:14px; margin-bottom:20px; }}
        .summary-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:15px; margin:20px 0; }}
        .stat-card {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:20px; text-align:center; }}
        .stat-card .num {{ font-size:2em; font-weight:bold; color:#58a6ff; }}
        .stat-card .label {{ color:#8b949e; font-size:12px; text-transform:uppercase; }}
        .stat-card.critical .num {{ color:#dc3545; }}
        .stat-card.high .num {{ color:#fd7e14; }}
        .stat-card.medium .num {{ color:#ffc107; }}
        table {{ width:100%; border-collapse:collapse; margin:20px 0; }}
        th {{ background:#161b22; color:#58a6ff; padding:12px; text-align:left; border-bottom:2px solid #30363d; }}
        td {{ padding:10px 12px; border-bottom:1px solid #21262d; }}
        tr:hover {{ background:#1c2128; }}
        .badge {{ padding:3px 8px; border-radius:12px; color:#fff; font-size:11px; font-weight:600; text-transform:uppercase; }}
        code {{ background:#1c2128; padding:2px 6px; border-radius:4px; font-size:12px; color:#f1f1f1; }}
        .files-list {{ list-style:none; }}
        .files-list li {{ padding:5px 0; }}
        .files-list li::before {{ content:"📄 "; }}
        .footer {{ margin-top:30px; padding-top:20px; border-top:1px solid #30363d; color:#8b949e; font-size:12px; text-align:center; }}
    </style>
</head>
<body>
<div class="container">
    <h1>🔍 GitHub Recon Report — {self.target}</h1>
    <p class="meta">Scan started: {summary.get('scan_duration','')}</p>
    
    <div class="summary-grid">
        <div class="stat-card">
            <div class="num">{summary.get('repos_scanned',0)}</div>
            <div class="label">Repos Scanned</div>
        </div>
        <div class="stat-card">
            <div class="num">{summary.get('files_analyzed',0)}</div>
            <div class="label">Files Analyzed</div>
        </div>
        <div class="stat-card">
            <div class="num">{summary.get('interesting_files_count',0)}</div>
            <div class="label">Interesting Files</div>
        </div>
        <div class="stat-card critical">
            <div class="num">{summary.get('critical_finds',0)}</div>
            <div class="label">Critical Secrets</div>
        </div>
        <div class="stat-card high">
            <div class="num">{summary.get('high_finds',0)}</div>
            <div class="label">High Secrets</div>
        </div>
        <div class="stat-card medium">
            <div class="num">{summary.get('medium_finds',0)}</div>
            <div class="label">Medium Secrets</div>
        </div>
        <div class="stat-card">
            <div class="num">{summary.get('secrets_discovered',0)}</div>
            <div class="label">Total Secrets</div>
        </div>
        <div class="stat-card">
            <div class="num">{summary.get('scan_duration','')}</div>
            <div class="label">Duration</div>
        </div>
    </div>
    
    <h2>🔑 Secrets Discovered ({len(secrets)})</h2>
    <table>
        <thead>
            <tr><th>Severity</th><th>Type</th><th>File</th><th>Repo</th><th>Match</th></tr>
        </thead>
        <tbody>
            {html_rows if html_rows else '<tr><td colspan="5" style="text-align:center;color:#8b949e;">No secrets discovered.</td></tr>'}
        </tbody>
    </table>
    
    <h2>📁 Interesting Files ({summary.get('interesting_files_count',0)})</h2>
    <ul class="files-list">
"""
        for f in self.results["interesting_files"][:50]:
            html_content += f'        <li><a href="{f.get("url","#")}" style="color:#58a6ff;">{f.get("name","")}</a> — {f.get("path","")}</li>\n'
        
        html_content += f"""
    </ul>
    
    <div class="footer">
        Generated by GitHub Recon Scraper v3.7 "The Omniscient" | {datetime.now().isoformat()}
    </div>
</div>
</body>
</html>"""
        
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def run(self):
        """Main execution method."""
        print(BANNER)
        log.info(f"{Fore.CYAN}[*] Starting reconnaissance on: {self.target}{Style.RESET_ALL}")
        
        driver = self._init_driver()
        
        try:
            # ── Phase 1: Get repo list ─────────────────────────────────────
            target_url = f"https://github.com/{self.target}?tab=repositories"
            if not self._safe_get(driver, target_url):
                log.error(f"{Fore.RED}[!] Could not access {target_url}{Style.RESET_ALL}")
                return
            
            repos = self._get_repo_list(driver)
            if not repos:
                log.warning(f"{Fore.YELLOW}[!] No repositories found. Trying user page...{Style.RESET_ALL}")
                target_url = f"https://github.com/{self.target}?tab=repositories"
                if self._safe_get(driver, target_url):
                    repos = self._get_repo_list(driver)
            
            if not repos:
                log.error(f"{Fore.RED}[!] No repositories found for {self.target}{Style.RESET_ALL}")
                return
            
            repos = repos[:10]  # Safety limit
            
            # ── Phase 2: Scan each repo ────────────────────────────────────
            for idx, repo_name in enumerate(repos, 1):
                repo_url = f"https://github.com/{self.target}/{repo_name}"
                log.info(f"{Fore.CYAN}[{idx}/{len(repos)}] Scanning repo: {repo_name}{Style.RESET_ALL}")
                
                repo_data = {
                    "name": repo_name,
                    "url": repo_url,
                    "files": []
                }
                
                # Take screenshot of repo
                if self._safe_get(driver, repo_url):
                    self._take_screenshot(driver, f"repo_{repo_name}")
                    
                    # Walk the directory tree
                    files = self._walk_directory(driver, repo_url)
                    repo_data["files"] = files
                    
                    log.info(f"{Fore.GREEN}   -> Found {len(files)} items in {repo_name}{Style.RESET_ALL}")
                
                with self.lock:
                    self.results["repos"].append(repo_data)
        
        except KeyboardInterrupt:
            log.warning(f"{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        except Exception as e:
            log.error(f"{Fore.RED}[!] Fatal error: {e}{Style.RESET_ALL}")
            import traceback
            traceback.print_exc()
        finally:
            driver.quit()
            self._generate_report()
            
            log.info(f"{Fore.GREEN}[+] Scan complete. Results in: {self.output_dir}{Style.RESET_ALL}")

# ─── CLI ENTRY POINT ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="GitHub Recon Scraper v3.7 — The Omniscient",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python guru_scraper.py -t octocat
  python guru_scraper.py -t myorg -d 3 -o ./output
  python guru_scraper.py -t myorg --token ghp_xxxxxxxx --headless
  python guru_scraper.py -t myorg --webhook https://hooks.slack.com/...
        """
    )
    
    parser.add_argument("-t", "--target", required=True, help="GitHub username or organization")
    parser.add_argument("--token", help="GitHub Personal Access Token (for private repos / higher rate limits)")
    parser.add_argument("-d", "--depth", type=int, default=1, help="Directory traversal depth (default: 1)")
    parser.add_argument("-o", "--output", help="Output directory (default: ./github_recon_output)")
    parser.add_argument("--headless", action="store_true", help="Run browser in headless mode")
    parser.add_argument("--delay", type=float, default=1.5, help="Request delay in seconds (default: 1.5)")
    parser.add_argument("--webhook", help="Webhook URL for critical alerts")
    parser.add_argument("--max-workers", type=int, default=5, help="Max concurrent threads (default: 5)")
    parser.add_argument("--gecko-path", help="Path to geckodriver executable")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    
    args = parser.parse_args()
    
    # Apply CLI args to Config
    if args.output:
        Config.OUTPUT_DIR = args.output
    if args.headless:
        Config.HEADLESS = True
    if args.delay:
        Config.REQUEST_DELAY = args.delay
    if args.webhook:
        Config.WEBHOOK_URL = args.webhook
    if args.max_workers:
        Config.MAX_WORKERS = args.max_workers
    if args.gecko_path:
        Config.GECKO_DRIVER_PATH = args.gecko_path
    
    logging.getLogger().setLevel(getattr(logging, args.log_level.upper()))
    
    scraper = GuruScraper(target=args.target, github_token=args.token or "", depth=args.depth)
    scraper.run()


if __name__ == "__main__":
    main()