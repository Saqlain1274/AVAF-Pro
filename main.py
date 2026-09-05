# ==========================================================
# main.py (FULL REWRITE - CLEAN / FIXED INDENTATION)
# ==========================================================

import os
import json
import asyncio
from colorama import init, Fore

from phase1_scanning_detection.crawler_playwright import PlaywrightCrawler
from phase1_scanning_detection.parameter_scanner import ParameterScanner
from phase2_refinement_validation.response_validator import ResponseValidator

# Optional report generator
try:
    from phase3_evaluation_exploitation_reporting import ReportGenerator
except Exception:
    ReportGenerator = None

init(autoreset=True)

# ==========================================================
# PATHS
# ==========================================================

# 

# ==========================================================
# PATHS
# ==========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# -----------------------------
# Phase-1 Output
# -----------------------------
PHASE1_OUTPUT = os.path.join(
    BASE_DIR,
    "phase1_scanning_detection",
    "output"
)

# -----------------------------
# Phase-2 Output
# -----------------------------
PHASE2_OUTPUT = os.path.join(
    BASE_DIR,
    "phase2_refinement_validation",
    "output"
)

os.makedirs(PHASE1_OUTPUT, exist_ok=True)
os.makedirs(PHASE2_OUTPUT, exist_ok=True)

SCAN_FILE = os.path.join(
    PHASE1_OUTPUT,
    "url_scan.json"
)

PARAM_FILE = os.path.join(
    PHASE1_OUTPUT,
    "parameter_candidates.json"
)

RESULT_FILE = os.path.join(
    PHASE2_OUTPUT,
    "vulnerabilities.json"
)

print("=" * 70)
print("PROJECT ROOT :", BASE_DIR)
print("PHASE1 OUT   :", PHASE1_OUTPUT)
print("PHASE2 OUT   :", PHASE2_OUTPUT)
print("SCAN FILE    :", SCAN_FILE)
print("PARAM FILE   :", PARAM_FILE)
print("RESULT FILE  :", RESULT_FILE)
print("=" * 70)

# ==========================================================
# HELPERS
# ==========================================================
def save_json(data, path):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(Fore.RED + f"[ERROR] Save failed: {e}")


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


# ==========================================================
# UI
# ==========================================================
def banner():
    print(Fore.CYAN + "=" * 63)
    print(Fore.CYAN + "   FYP WEB VULNERABILITY FRAMEWORK (ACADEMIC EDITION)")
    print(Fore.CYAN + "   Methodology: Web Application Hacker's Handbook")
    print(Fore.CYAN + "=" * 63)
    print()


def menu():
    print("1. Phase 1: Deep Scanning (Crawling)")
    print("2. Phase 2: Advanced Validation (Attack Simulation)")
    print("3. Phase 3: Reporting")
    print("4. FULL SYSTEM SCAN (Recommended)")
    print("5. Exit")
    print()


# ==========================================================
# PHASE 1
# ==========================================================
async def run_phase_1(target_url):

    print(
        Fore.YELLOW +
        f"[PHASE 1] Starting Deep Recursive Scanning on: {target_url}"
    )   

    print(
        Fore.YELLOW +
        "[PHASE 1] Analyzing Attack Surface (WAHH Methodology)..."
    )

    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    crawler = PlaywrightCrawler(
        target=target_url,
        max_depth=4,
        max_pages=60,
        workers=5,
        headless=True,
        progress_callback=None
    )

    # STEP 1 : Crawl
    pages = await crawler.start_scan()
    
    if pages is None:
        pages = []
    
    if not isinstance(pages, list):
        raise TypeError(
            "PlaywrightCrawler.start_scan() must return a list of discovered pages."
        )
    
    scan_data = {
        "target": target_url,
        "pages": pages,
        "page_count": len(pages),
    }

    # STEP 2 : Parameter Extraction
    print("[INFO] Extracting parameters...", flush=True)

    try:
        scanner = ParameterScanner(scan_data)

        candidates = await scanner.extract_candidates(
            save_to=PARAM_FILE
        )

    except Exception:
        candidates = scan_data.get("candidates", [])

    if candidates is None:
        candidates = []

    scan_data["candidates"] = candidates

    # STEP 3 : Save
    save_json(scan_data, SCAN_FILE)

    print(
        Fore.GREEN +
        f"[+] Phase 1 Complete. Found {len(candidates)} attack vectors."
    )
    print()

    return candidates


# ==========================================================
# PHASE 2
# ==========================================================
async def run_phase_2():

    print(Fore.YELLOW + "[PHASE 2] Starting Advanced Validation Engine...")
    print(Fore.YELLOW + "[i] Loaded Phase-1 candidates from JSON handoff.")

    candidates = load_json(PARAM_FILE)

    if not candidates:
        print(Fore.RED + "[!] No Phase-1 candidates found.")
        print()
        return []

    validator = ResponseValidator()

    try:
        results = await validator.validate_candidates(candidates)

    except Exception as e:
        print(Fore.RED + f"[!] Phase 2 Error: {e}")
        results = []

    if results is None:
        results = []

    save_json(results, RESULT_FILE)

    print(
        Fore.GREEN +
        f"[+] Phase 2 Complete. Confirmed {len(results)} security issues."
    )
    print()

    return results


# ==========================================================
# PHASE 3
# ==========================================================
def run_phase_3():

    print(Fore.YELLOW + "[PHASE 3] Generating Academic Report...")
    print()

    results = load_json(RESULT_FILE)

    try:
        if ReportGenerator:
            rg = ReportGenerator()
            rg.generate(results)

        print(Fore.GREEN + "[SUCCESS] Final Report Generated: report.html")

    except Exception as e:
        print(Fore.RED + f"[!] Phase 3 Error: {e}")

    print()


# ==========================================================
# FULL SCAN
# ==========================================================
async def run_full_scan(url):

    await run_phase_1(url)
    await run_phase_2()
    run_phase_3()


# ==========================================================
# MAIN LOOP
# ==========================================================
async def main():

    while True:

        os.system("cls" if os.name == "nt" else "clear")

        banner()
        menu()

        try:
            choice = input(
                Fore.YELLOW + "[?] Select Option: "
            ).strip()

        except EOFError:
            return

        # -----------------------------------
        if choice == "1":

            url = input("Enter URL: ").strip()
            print()

            try:
                await run_phase_1(url)

            except Exception as e:
                print(Fore.RED + f"[!] ERROR: {e}")

            input("Press Enter...")

        # -----------------------------------
        elif choice == "2":

            print()

            try:
                await run_phase_2()

            except Exception as e:
                print(Fore.RED + f"[!] ERROR: {e}")

            input("Press Enter...")

        # -----------------------------------
        elif choice == "3":

            print()

            try:
                run_phase_3()

            except Exception as e:
                print(Fore.RED + f"[!] ERROR: {e}")

            input("Press Enter...")

        # -----------------------------------
        elif choice == "4":

            url = input("Enter URL: ").strip()
            print()

            try:
                await run_full_scan(url)

            except Exception as e:
                print(Fore.RED + f"[!] ERROR: {e}")

            input("Press Enter...")

        # -----------------------------------
        elif choice == "5":

            print("Goodbye.")
            return

        else:
            print("Invalid Option.")
            input("Press Enter...")


# ==========================================================
# ENTRY
# ==========================================================
if __name__ == "__main__":
    asyncio.run(main())

