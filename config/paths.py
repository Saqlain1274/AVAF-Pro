# =========================================================
# PROJECT PATH RESOLUTION (SINGLE SOURCE OF TRUTH)
# =========================================================


import os


GUI_FILE = os.path.abspath(__file__)

# gui.py is INSIDE project root
PROJECT_ROOT = os.path.dirname(GUI_FILE)

PHASE1_DIR = os.path.join(PROJECT_ROOT, "phase1_scanning_detection")
PHASE2_DIR = os.path.join(PROJECT_ROOT, "phase2_refinement_validation")
PHASE3_DIR = os.path.join(
    PROJECT_ROOT, "phase3_evaluation_exploitation_reporting")

DATA_DIR = os.path.join(PROJECT_ROOT, "data", "raw")

PHASE1_OUT = os.path.join(PHASE1_DIR, "output")
PHASE2_OUT = os.path.join(PHASE2_DIR, "output")
PHASE3_OUT = os.path.join(PHASE3_DIR, "output")

SCREENSHOT_DIR = os.path.join(
    PROJECT_ROOT,
    "screenshots"
)
LOG_DIR = os.path.join(PROJECT_ROOT, "logs")

print("[PATH] PROJECT_ROOT =", PROJECT_ROOT)


# ---------------- DEBUG (TEMP) ----------------
print("[PATH] GUI_FILE      =", GUI_FILE)
print("[PATH] PROJECT_ROOT  =", PROJECT_ROOT)
print("[PATH] PHASE1_DIR    =", PHASE1_DIR)
print("[PATH] DATA_DIR      =", DATA_DIR)
