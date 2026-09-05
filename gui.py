# Standard libraries

from optparse import Values
import sys
import os
import json
import re
import csv
import random
import datetime
import asyncio
from threading import Thread
from urllib.parse import urlparse

from scipy.interpolate import make_interp_spline
import numpy as np

from matplotlib.animation import FuncAnimation
from matplotlib.collections import LineCollection
from matplotlib.colors import LinearSegmentedColormap

# Third-party
import numpy as np
import requests
from PySide6.QtCore import (
    Qt,
    QObject,
    Signal,
    QThread,
    QTimer,
    QProcess,
)
from PySide6.QtWidgets import QLabel

# PySide6
from PySide6.QtWidgets import *
from PySide6.QtCore import *
from PySide6.QtGui import *
from PySide6.QtPrintSupport import *
from pathlib import Path
import subprocess
from dashboard import DashboardPage
from utils.project_cleaner import ProjectCleaner


from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt

from wave_engine import WaveEngine

# ===============================
# CVSS SHORT → UI LABEL MAPPING
# ===============================
CVSS_KEY_MAP = {
    "AV": "Attack Vector",
    "AC": "Complexity",
    "PR": "Privileges",
    "UI": "User Interaction",
    "C": "Confidentiality",
    "I": "Integrity",
    "A": "Availability",
}


def convert_webm_to_mp4(webm_path: str) -> str | None:
    """
    Converts a Playwright-recorded .webm video into .mp4 using FFmpeg.

    Returns:
        - mp4 file path (string) if conversion succeeds
        - None if conversion fails or file does not exist
    """

    # 1️⃣ Convert string path → Path object
    webm_file = Path(webm_path)

    # 2️⃣ Check: does the .webm file actually exist?
    if not webm_file.exists():
        print("[VIDEO] WebM file not found:", webm_file)
        return None

    # 3️⃣ Create output path with same name but .mp4 extension
    mp4_file = webm_file.with_suffix(".mp4")

    # 4️⃣ Build FFmpeg command
    command = [
        "ffmpeg",  # FFmpeg executable
        "-y",  # overwrite output file if exists
        "-i",
        str(webm_file),  # input .webm file
        "-movflags",
        "faststart",  # better playback in players/GUI
        "-pix_fmt",
        "yuv420p",  # maximum compatibility
        str(mp4_file),  # output .mp4 file
    ]

    # 5️⃣ Run FFmpeg
    try:
        subprocess.run(
            command,
            stdout=subprocess.DEVNULL,  # hide ffmpeg spam
            stderr=subprocess.DEVNULL,
            check=True,  # raise error if conversion fails
        )

        print(f"[VIDEO] Converted → {mp4_file}", flush=True)
        return str(mp4_file)

    except Exception as e:
        print(f"[VIDEO] FFmpeg failed: {e}", flush=True)
        return None


class CVSSHeatmap(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(220)
        self.points = []  # (severity, confidence)
        self.anim_phase = 0
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._animate)
        self.timer.start(80)

    def add_point(self, severity: float, confidence: float):
        self.points.append((severity, confidence))
        self.update()

    def clear(self):
        self.points.clear()
        self.update()

    def _animate(self):
        self.anim_phase = (self.anim_phase + 1) % 20
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)

        w, h = self.width(), self.height()

        # grid
        p.setPen(QPen(QColor("#1f2937")))
        for i in range(1, 5):
            p.drawLine(i * w / 5, 0, i * w / 5, h)
            p.drawLine(0, i * h / 5, w, i * h / 5)

        # heat points
        for sev, conf in self.points:
            x = int((sev / 10) * w)
            y = int(h - (conf * h))

            glow = 120 + (self.anim_phase * 6)
            color = QColor(255, 80, 80, min(glow, 255))

            p.setBrush(QBrush(color))
            p.setPen(Qt.NoPen)
            p.drawEllipse(QPoint(x, y), 10, 10)


class AnimatedHeatmap(QWidget):
    """
    Risk Heatmap for AVAF Pro.

    Matrix meaning:

        Rows = CVSS risk
            Low
            Medium
            High / Critical

        Columns = Confidence
            Low
            Medium
            High

    matrix[row][column] = number of findings
    """

    ROW_LABELS = [
        "Low",
        "Medium",
        "High / Critical",
    ]

    COLUMN_LABELS = [
        "Low",
        "Medium",
        "High",
    ]

    def __init__(self, parent=None):
        super().__init__(parent)

        self.matrix = [
            [0, 0, 0],
            [0, 0, 0],
            [0, 0, 0],
        ]

        self.setMinimumHeight(420)
        self.setMinimumWidth(650)

        self.setSizePolicy(
            QSizePolicy.Expanding,
            QSizePolicy.Expanding,
        )

    def update_matrix(self, new_matrix):
        """
        Receive the calculated 3x3 risk matrix.

        Expected:

            [
                [low-confidence-low-risk,
                 medium-confidence-low-risk,
                 high-confidence-low-risk],

                [low-confidence-medium-risk,
                 medium-confidence-medium-risk,
                 high-confidence-medium-risk],

                [low-confidence-high-risk,
                 medium-confidence-high-risk,
                 high-confidence-high-risk],
            ]
        """

        if not isinstance(new_matrix, list):
            return

        if len(new_matrix) != 3:
            return

        cleaned = []

        for row in new_matrix:

            if not isinstance(row, list) or len(row) != 3:
                return

            cleaned_row = []

            for value in row:
                try:
                    value = int(value)
                except (TypeError, ValueError):
                    value = 0

                cleaned_row.append(max(0, value))

            cleaned.append(cleaned_row)

        self.matrix = cleaned

        self.update()

    def clear(self):
        self.matrix = [
            [0, 0, 0],
            [0, 0, 0],
            [0, 0, 0],
        ]

        self.update()

    def paintEvent(self, event):

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        rect = self.rect()

        # =====================================================
        # BACKGROUND
        # =====================================================

        painter.fillRect(
            rect,
            QColor("#0b1220")
        )

        # =====================================================
        # LAYOUT
        # =====================================================

        left_margin = 120
        right_margin = 30
        top_margin = 45
        bottom_margin = 70

        grid_x = left_margin
        grid_y = top_margin

        grid_width = max(
            1,
            self.width() - left_margin - right_margin
        )

        grid_height = max(
            1,
            self.height() - top_margin - bottom_margin
        )

        cell_width = grid_width / 3
        cell_height = grid_height / 3

        # =====================================================
        # TITLE
        # =====================================================

        painter.setPen(
            QColor("#00a8ff")
        )

        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)

        painter.setFont(title_font)

        painter.drawText(
            0,
            10,
            self.width(),
            25,
            Qt.AlignCenter,
            "Risk Exposure by CVSS Severity & Confidence",
        )

        # =====================================================
        # FIND MAX COUNT
        # =====================================================

        max_value = max(
            max(row)
            for row in self.matrix
        )

        # =====================================================
        # DRAW CELLS
        # =====================================================

        for row in range(3):

            for column in range(3):

                value = self.matrix[row][column]

                x = int(
                    grid_x + column * cell_width
                )

                y = int(
                    grid_y + row * cell_height
                )

                w = int(cell_width - 6)
                h = int(cell_height - 6)

                # -------------------------------------------------
                # Determine intensity.
                # -------------------------------------------------

                if max_value > 0 and value > 0:
                    intensity = 0.25 + (
                        0.75 * value / max_value
                    )
                else:
                    intensity = 0.0

                # -------------------------------------------------
                # Base risk color by row.
                # -------------------------------------------------

                if row == 0:
                    base = QColor(
                        34,
                        197,
                        94,
                    )       # Low = green

                elif row == 1:
                    base = QColor(
                        250,
                        204,
                        21,
                    )       # Medium = yellow

                else:
                    base = QColor(
                        239,
                        68,
                        68,
                    )       # High/Critical = red

                if value == 0:

                    cell_color = QColor(
                        "#172033"
                    )

                else:

                    cell_color = QColor(
                        int(base.red() * intensity),
                        int(base.green() * intensity),
                        int(base.blue() * intensity),
                    )

                # -------------------------------------------------
                # Cell background
                # -------------------------------------------------

                painter.setBrush(
                    QBrush(cell_color)
                )

                painter.setPen(
                    QPen(
                        QColor("#334155"),
                        1
                    )
                )

                painter.drawRoundedRect(
                    x,
                    y,
                    w,
                    h,
                    8,
                    8,
                )

                # -------------------------------------------------
                # COUNT
                # -------------------------------------------------

                count_font = QFont()
                count_font.setPointSize(24)
                count_font.setBold(True)

                painter.setFont(
                    count_font
                )

                painter.setPen(
                    QColor("#ffffff")
                )

                painter.drawText(
                    x,
                    y,
                    w,
                    h - 5,
                    Qt.AlignCenter,
                    str(value),
                )

                # -------------------------------------------------
                # Small "findings" label
                # -------------------------------------------------

                label_font = QFont()
                label_font.setPointSize(9)

                painter.setFont(
                    label_font
                )

                painter.setPen(
                    QColor("#dbeafe")
                )

                painter.drawText(
                    x,
                    y + 5,
                    w,
                    h,
                    Qt.AlignCenter,
                    "findings",
                )

        # =====================================================
        # Y-AXIS LABELS
        # =====================================================

        axis_font = QFont()
        axis_font.setPointSize(10)
        axis_font.setBold(True)

        painter.setFont(
            axis_font
        )

        for row, label in enumerate(
            self.ROW_LABELS
        ):

            y = int(
                grid_y
                + row * cell_height
            )

            painter.setPen(
                QColor("#cbd5e1")
            )

            painter.drawText(
                10,
                y,
                left_margin - 20,
                int(cell_height),
                Qt.AlignVCenter | Qt.AlignRight,
                label,
            )

        # =====================================================
        # X-AXIS LABELS
        # =====================================================

        for column, label in enumerate(
            self.COLUMN_LABELS
        ):

            x = int(
                grid_x
                + column * cell_width
            )

            painter.setPen(
                QColor("#cbd5e1")
            )

            painter.drawText(
                x,
                grid_y + grid_height + 8,
                int(cell_width),
                25,
                Qt.AlignCenter,
                label,
            )

        # =====================================================
        # AXIS TITLES
        # =====================================================

        small_font = QFont()
        small_font.setPointSize(10)
        small_font.setBold(True)

        painter.setFont(
            small_font
        )

        painter.setPen(
            QColor("#94a3b8")
        )

        painter.drawText(
            grid_x,
            self.height() - 30,
            grid_width,
            20,
            Qt.AlignCenter,
            "Detection Confidence",
        )

        painter.save()

        painter.translate(
            25,
            grid_y + grid_height / 2
        )

        painter.rotate(-90)

        painter.drawText(
            -grid_height / 2,
            -10,
            grid_height,
            20,
            Qt.AlignCenter,
            "CVSS Risk",
        )

        painter.restore()

        # =====================================================
        # SUMMARY
        # =====================================================

        total_findings = sum(
            sum(row)
            for row in self.matrix
        )

        painter.setPen(
            QColor("#94a3b8")
        )

        painter.setFont(
            small_font
        )

        painter.drawText(
            grid_x,
            35,
            grid_width,
            20,
            Qt.AlignRight,
            f"Total findings: {total_findings}",
        )

        painter.end()


class ConsoleEmitter(QObject):
    text = Signal(str)

# =========================================================
# PROJECT PATH RESOLUTION (SINGLE SOURCE OF TRUTH)
# =========================================================


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

# ---------------------------------------------------------
# 1. THEME LIBRARY (8 OPTIONS)
THEMES = {
    # =====================================================
    # DEFAULT (ORIGINAL)
    # =====================================================
    "Navy Pro (Default)": {
        "app_bg": "#0b1120",
        "panel_bg": "#1f2937",
        "border": "#374151",
        "accent": "#007acc",
        "accent_hover": "#005c99",
        "danger": "#ef4444",
        "success": "#10b981",
        "warning": "#f59e0b",
        "text_header": "#f3f4f6",
        "text_dim": "#9ca3af",
        "selection": "#1e293b",
        "log_bg": "#000000",
        "is_dark": True,
    },
    # =====================================================
    # BLUE / GREY PROFESSIONAL THEMES
    # =====================================================
    "Steel Blue": {
        "app_bg": "#0f172a",
        "panel_bg": "#1e293b",
        "border": "#334155",
        "accent": "#38bdf8",
        "accent_hover": "#0ea5e9",
        "danger": "#ef4444",
        "success": "#22c55e",
        "warning": "#f59e0b",
        "text_header": "#e5e7eb",
        "text_dim": "#94a3b8",
        "selection": "#1e3a8a",
        "log_bg": "#020617",
        "is_dark": True,
    },
    "Hacker Terminal": {
        "app_bg": "#0a0a0a",
        "panel_bg": "#121212",
        "border": "#333333",
        "accent": "#00ff41",
        "accent_hover": "#008f11",
        "danger": "#ff003c",
        "success": "#39ff14",
        "warning": "#f4c430",
        "text_header": "#00ff41",
        "text_dim": "#808080",
        "selection": "#1a361a",
        "log_bg": "#000000",
        "is_dark": True,
    },
    "Winter Chill": {
        "app_bg": "#f0f9ff",
        "panel_bg": "#e0f2fe",
        "border": "#bae6fd",
        "accent": "#0ea5e9",
        "accent_hover": "#0284c7",
        "danger": "#e11d48",
        "success": "#059669",
        "warning": "#d97706",
        "text_header": "#0c4a6e",
        "text_dim": "#7ca3af",
        "selection": "#bae6fd",
        "log_bg": "#f8fafc",
        "is_dark": False,
    },
    "Blue Ice Light": {
        "app_bg": "#f1f5f9",
        "panel_bg": "#ffffff",
        "border": "#cbd5e1",
        "accent": "#2563eb",
        "accent_hover": "#1e40af",
        "danger": "#b91c1c",
        "success": "#15803d",
        "warning": "#ca8a04",
        "text_header": "#020617",
        "text_dim": "#475569",
        "selection": "#e2e8f0",
        "log_bg": "#e5e7eb",
        "is_dark": False,
    },
    "Corporate Professional": {
        "app_bg": "#f8fafc",
        "panel_bg": "#ffffff",
        "border": "#e2e8f0",
        "accent": "#0f172a",
        "accent_hover": "#1e293b",
        "danger": "#ef4444",
        "success": "#22c55e",
        "warning": "#f59e0b",
        "text_header": "#0f172a",
        "text_dim": "#64748b",
        "selection": "#f1f5f9",
        "log_bg": "#f1f5f9",
        "is_dark": False,
    },
    "Cloud Dancer": {
        "app_bg": "#fcfcfc",
        "panel_bg": "#ffffff",
        "border": "#f0f0f0",
        "accent": "#27272a",
        "accent_hover": "#3f3f46",
        "danger": "#be123c",
        "success": "#15803d",
        "warning": "#a16207",
        "text_header": "#18181b",
        "text_dim": "#71717a",
        "selection": "#f4f4f5",
        "log_bg": "#fafafa",
        "is_dark": False,
    },
}

# ---------------------------------------------------------
# 2. LOGIC MAPPINGS
# ---------------------------------------------------------
MITRE_RISK_WEIGHT = {
    "Initial Access": 4,
    "Execution": 4,
    "Persistence": 3,
    "Privilege Escalation": 4,
    "Defense Evasion": 3,
    "Credential Access": 5,
    "Discovery": 2,
    "Lateral Movement": 4,
    "Collection": 2,
    "Command and Control": 5,
    "Exfiltration": 5,
    "Impact": 5,
    "Unknown": 1,
}

MITRE_MAP = {
    "SQLI_TIME_BLIND": {
        "TID": "T1190",
        "Tactic": "Initial Access",
        "Technique": "Exploit Public-Facing Application",
    },
    "SQLI_ERROR": {
        "TID": "T1190",
        "Tactic": "Initial Access",
        "Technique": "Exploit Public-Facing Application",
    },
    "SQLI_BOOLEAN": {
        "TID": "T1190",
        "Tactic": "Initial Access",
        "Technique": "Exploit Public-Facing Application",
    },
    "XSS_REFLECTED": {
        "TID": "T1189",
        "Tactic": "Initial Access",
        "Technique": "Drive-by Compromise",
    },
    "DOM_XSS": {
        "TID": "T1059",
        "Tactic": "Execution",
        "Technique": "Command and Scripting Interpreter",
    },
    "LFI_TRAVERSAL": {
        "TID": "T1083",
        "Tactic": "Discovery",
        "Technique": "File and Directory Discovery",
    },
    "RCE_COMMAND_INJECTION": {
        "TID": "T1059",
        "Tactic": "Execution",
        "Technique": "Command and Scripting Interpreter",
    },
    "WORKFLOW_STATE_BYPASS": {
        "TID": "T1565",
        "Tactic": "Impact",
        "Technique": "Data Manipulation",
    },
    "AUTHZ_ADMIN_ACCESS": {
        "TID": "T1068",
        "Tactic": "Privilege Escalation",
        "Technique": "Exploitation for Privilege Escalation",
    },
    "Generic": {
        "TID": "T0000",
        "Tactic": "Unknown",
        "Technique": "Unknown",
    },
}


PAYLOAD_PRESETS = {
    "SQL Injection": [
        ("' OR '1'='1' --", 15),
        ("' UNION SELECT NULL,NULL --", 20),
        ("admin'--", 10),
    ],
    "XSS": [
        ("<script>alert(1)</script>", 20),
        ('" onmouseover="alert(1)', 15),
        ("<img src=x onerror=alert(1)>", 18),
    ],
    "LFI": [
        ("../../../../etc/passwd", 20),
        ("../etc/passwd%00", 18),
        ("../../../../windows/win.ini", 15),
    ],
    "Generic": [("test123", 5), ("' OR 1=1 --", 8)],
}


class RequestWorker(QThread):
    result_ready = Signal(str, str, int)

    def __init__(self, method, url, data=None, headers=None):
        super().__init__()
        self.method = method
        self.url = url
        self.data = data
        self.headers = headers

    def run(self):
        try:
            if self.method == "GET":
                r = requests.get(self.url, headers=self.headers, timeout=10)
            elif self.method == "POST":
                r = requests.post(
                    self.url, data=self.data, headers=self.headers, timeout=10
                )
            else:
                r = requests.request(
                    self.method, self.url, headers=self.headers, timeout=10
                )
            header_str = "\n".join([f"{k}: {v}" for k, v in r.headers.items()])
            self.result_ready.emit(r.text, header_str, r.status_code)
        except Exception as e:
            self.result_ready.emit(f"Error: {str(e)}", "", 0)


MITRE_TACTIC_WEIGHT = {
    "Initial Access": 5,
    "Execution": 4,
    "Privilege Escalation": 4,
    "Persistence": 3,
    "Defense Evasion": 3,
    "Credential Access": 4,
    "Discovery": 2,
    "Lateral Movement": 3,
    "Collection": 2,
    "Exfiltration": 5,
    "Impact": 5,
}


# ---------------------------------------------------------
# MAIN WINDOW
# ---------------------------------------------------------
class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        # self.log_widgets = {}
        # self.current_phase_key = None

        self.project_root = PROJECT_ROOT
        self.setWindowTitle(
            "AVAF Pro | Web Vulnerability Assessment Framework")
        self.resize(1450, 900)

        # =========================
        # Console bridge
        # =========================
        self.console_emitter = ConsoleEmitter()
        self.console_emitter.text.connect(
            lambda msg: self.log_widgets.get(
                self.current_phase_key, QTextEdit()
            ).append(msg)
        )

        # =========================
        # 🎨 THEME / UI STATE
        # =========================
        self.current_theme_name = "Navy Pro (Default)"
        self.current_theme = THEMES[self.current_theme_name]

        self.search_query = ""
        self.payload_history = []
        self.req_res_history = {}

        # =========================
        # 🔥 SCAN STATE
        # =========================
        self.scan_process = None
        self.active_phase = None
        self.auto_chain = False
        self.paused = False

        # 🔒 HARD RESET SCAN STATE
        self.log_widgets = {}
        self.current_phase_key = None
        self.active_phase = None

        # =========================
        # 📊 PHASE FLAGS
        # =========================
        self.phase1_done = False
        self.phase2_done = False
        self.phase3_done = False

        # =====================================================
        # 📸 SCREENSHOT WIDGETS (CREATE BEFORE _init_ui)
        # =====================================================

        # =========================================
        # LIVE BROWSER VIEW
        # =========================================
        self.live_browser_label = QLabel()
        self.live_browser_label.setAlignment(Qt.AlignCenter)
        self.live_browser_label.setMinimumHeight(260)
        self.live_browser_label.setText("")
        self.live_browser_label.setStyleSheet("""
            border:1px solid #374151;
            background-color:#000000;
            color:#9ca3af;
        """)

        # =========================================
        # SCREENSHOT PREVIEW
        # =========================================
        self.screenshot_preview_label = QLabel()
        self.screenshot_preview_label.setAlignment(Qt.AlignCenter)
        self.screenshot_preview_label.setMinimumHeight(260)
        self.screenshot_preview_label.setText("")
        self.screenshot_preview_label.setStyleSheet("""
            border:1px solid #374151;
            background-color:#000000;
            color:#9ca3af;
        """)

        self.screenshot_label = QLabel()
        self.screenshot_label.setAlignment(Qt.AlignCenter)
        self.screenshot_label.setMinimumHeight(260)
        self.screenshot_label.setText("")
        self.screenshot_label.setStyleSheet(
            """
            border:1px solid #374151;
            background-color:#000000;
            color:#9ca3af;
            """
        )

        self.screenshot_counter_label = QLabel("No screenshots yet")
        self.screenshot_counter_label.setAlignment(Qt.AlignCenter)
        self.screenshot_counter_label.setStyleSheet(
            """
            color:#9ca3af;
            font-size:12px;
            padding:4px;
            """
        )

        # Screenshot state
        self.latest_screenshot = None
        self.current_screenshot_index = -1

        # Live refresh timer
        self.screenshot_timer = QTimer(self)

        self.screenshot_timer.timeout.connect(
            self._update_screenshot
        )

        self.current_risk_score = 0.0

        # ===============================
        # VIDEO PLAYER (GLOBAL – PHASE-1)
        # ===============================
        # from PySide6.QtMultimedia import QMediaPlayer, QAudioOutput
        # from PySide6.QtMultimediaWidgets import QVideoWidget

        # self.video_player = QMediaPlayer(self)
        # self.audio_output = QAudioOutput(self)
        # self.video_player.setAudioOutput(self.audio_output)

        # self.video_widget = QVideoWidget(self)
        # self.video_widget.setMinimumHeight(280)

        # # track current video
        # self.phase1_video_path = None

        # ===============================
        # VIDEO PATH STATE (SAFE STUB)
        # ===============================
        self.phase1_video_path = os.path.join(
            PROJECT_ROOT, "videos", "phase1_recording.webm"
        )

        self.recording_phase1 = False

        self.vuln_data = []
        self.current_vuln_index = None

        self.phase1_data = {}
        self.phase1_activity = []

        # =========================
        # 🧾 LOG SYSTEM
        # =========================
        self.error_count = 0
        self.warn_count = 0

        self.log_entries = []
        self.log_filter_level = "ALL"
        self.log_autoscroll = True
        self.siem_alert_count = 0

        # =========================
        # 🔗 UI REFERENCES
        # =========================
        self.phase_buttons = {}
        self.progress_bars = {}
        self.log_widgets = {}
        
        # One Pause/Resume button per phase
        self.pause_buttons = {}
        
        # Currently active phase button
        self.pause_btn = None

        self.mock_req_view = None
        self.mock_res_view = None
        self.breakdown_view = None
        self.search_input = None
        self.theme_selector = None

        # =========================
        # 📈 CHARTS
        # =========================
        self.fig_sev = None
        self.cv_sev = None
        self.fig_conf = None
        self.fig_ana = None
        self.cv_ana = None
        self.fig_heat = None
        self.cv_heat = None
        self.cvss_heatmap = CVSSHeatmap()

        # =========================
        # 🧱 INIT SEQUENCE
        # =========================
        self._ensure_project_structure()
        self.pages = {}
        self._init_ui()
        self._setup_statusbar()
        self.load_data()
        self._apply_stylesheet()
        self._enforce_phase_logic()

        # =========================
        # 🧪 STARTUP LOGS
        # =========================
        self.log("GUI started", "INFO")
        self.log("System initialized", "INFO")

        # Cached dashboard data
        # Cached dashboard data
        # IMPORTANT:
        # load_data() already populated self.vuln_data.
        # Do NOT reset it here.
        if not hasattr(self, "vuln_data"):
            self.vuln_data = []

        # Animation state
        self.scan_position = 0.0
        self.pulse_phase = 0.0
        self.wave_offset = 0.0

        # Particle animation
        self.particles = []

        # Radar animation
        self.radar_angle = 0

        self.wave_engine = WaveEngine()

        # Give engine the dashboard theme
        self.wave_engine.background = "#111827"
        self.wave_engine.panel = "#1B2332"
        self.wave_engine.grid = "#364152"
        self.wave_engine.primary = "#00D4FF"
        self.wave_engine.secondary = "#FF3D71"
        self.wave_engine.success = "#00E676"
        self.wave_engine.warning = "#FFC400"
        self.wave_engine.text = "#E6EDF5"

        self.dashboard_timer = QTimer(self)
        self.dashboard_timer.timeout.connect(self._animate_dashboard)
        self.dashboard_timer.start(33)   # ~30 FPS

        # ======================================
        # Dashboard Animation State
        # ======================================

        self.dashboard_frame = 0

        self.wave_values = []
        self.wave_target = []

        self.urls_target = 0
        self.urls_display = 0

        self.vulns_target = 0
        self.vulns_display = 0

        self.high_target = 0
        self.high_display = 0

        self.current_screenshot_index = 0

    def _ensure_project_structure(self):
        """
        Create all required folders using ROOT-AWARE paths.
        NO backend assumptions.
        """
        paths = [
            DATA_DIR,
            PHASE1_OUT,
            PHASE2_OUT,
            PHASE3_OUT,
            SCREENSHOT_DIR,
            LOG_DIR,
        ]

        for path in paths:
            try:
                os.makedirs(path, exist_ok=True)
            except Exception as e:
                print(f"[DIR ERROR] {path} -> {e}")

    # --- STYLE & LAYOUT ENGINE (BRICK PROGRESS BAR) ---
    def _get_stylesheet(self):
        t = self.current_theme
        return f"""
            QMainWindow {{ background-color: {t['app_bg']}; }}
            QWidget {{ color: {t['text_dim']}; font-family: 'Segoe UI', sans-serif; font-size: 10pt; }}
            
            QListWidget {{ background-color: {t['app_bg']}; border: none; border-right: 1px solid {t['border']}; outline: none; }}
            QListWidget::item {{ padding: 12px; border-left: 3px solid transparent; margin-bottom: 2px; color: {t['text_dim']}; }}
            QListWidget::item:selected {{ background-color: {t['panel_bg']}; border-left: 3px solid {t['accent']}; color: {t['text_header']}; font-weight: bold; }}
            QListWidget::item:hover {{ background-color: {t['panel_bg']}; }}

            QLabel#DashboardHeader {{ font-size: 24pt; font-weight: bold; color: {t['accent']}; margin-bottom: 10px; }}
            
            QLineEdit, QTextEdit, QPlainTextEdit, QComboBox {{ background-color: {t['panel_bg']}; border: 1px solid {t['border']}; color: {t['text_header']}; padding: 8px; border-radius: 4px; }}
            QLineEdit:focus {{ border: 1px solid {t['accent']}; }}

            QPushButton {{ background-color: {t['accent']}; color: white; border: none; padding: 8px 16px; border-radius: 4px; font-weight: bold; }}
            QPushButton:hover {{ background-color: {t['accent_hover']}; }}
            QPushButton:disabled {{ background-color: {t['panel_bg']}; border: 1px solid {t['border']}; color: {t['text_dim']}; }} 
            
            QFrame#InfoCard {{ background-color: {t['panel_bg']}; border-radius: 6px; }}
            QLabel#CardTitle {{ color: {t['text_dim']}; font-size: 11pt; font-weight: bold; }}
            QLabel#CardValue {{ color: {t['text_header']}; font-size: 36pt; font-weight: bold; }}
            
            QGroupBox {{ border: 1px solid {t['border']}; margin-top: 1.2em; padding-top: 10px; border-radius: 4px; }}
            QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 5px; color: {t['accent']}; font-weight: bold; }}

            QTableWidget {{ background-color: {t['panel_bg']}; gridline-color: {t['border']}; border: 1px solid {t['border']}; border-radius: 4px; }}
            QHeaderView::section {{ background-color: {t['app_bg']}; padding: 8px; border: none; font-weight: bold; color: {t['text_dim']}; }}
            
            /* Console - Green Text */
            QTextEdit#LogConsole {{ font-family: 'Consolas'; background-color: {t['log_bg']}; color: #00ff41; border: 1px solid {t['border']}; }}
            QPlainTextEdit#Traffic {{ font-family: 'Consolas'; background-color: {t['log_bg']}; color: #e6edf3; border: 1px solid {t['border']}; }}
            
            QToolBar {{ background-color: {t['panel_bg']}; border-bottom: 1px solid {t['border']}; spacing: 8px; padding: 8px; }}

            /* BRICK STYLE PROGRESS BAR - Filling One by One */
            QProgressBar {{
                border: 1px solid {t['border']};
                background-color: {t['app_bg']};
                text-align: center;
                color: {t['text_header']};
                border-radius: 4px;
            }}
            QProgressBar::chunk {{
                background-color: {t['accent']};
                width: 15px;       /* Width of one brick */
                margin: 2px;       /* Gap between bricks */
            }}
        """

    def _apply_stylesheet(self):
        self.setStyleSheet(self._get_stylesheet())
        self._update_chart_theme()

    def _change_theme(self):
        sender = self.sender()

        if isinstance(sender, QComboBox):
            name = sender.currentText()
        else:
            return

        if name in THEMES:
            self.current_theme_name = name
            self.current_theme = THEMES[name]
            self._apply_stylesheet()
            self._update_charts()

    def _update_chart_theme(self):

        t = self.current_theme

        charts = []

        # ==========================================
        # THREAT DISTRIBUTION
        # ==========================================
        if (
            hasattr(self, "fig_sev")
            and hasattr(self, "cv_sev")
            and self.fig_sev is not None
            and self.cv_sev is not None
        ):
            charts.append(
                (self.fig_sev, self.cv_sev)
            )

        # ==========================================
        # HEATMAP
        # ==========================================
        if (
            hasattr(self, "fig_heat")
            and hasattr(self, "cv_heat")
            and self.fig_heat is not None
            and self.cv_heat is not None
        ):
            charts.append(
                (self.fig_heat, self.cv_heat)
            )

        # ==========================================
        # APPLY THEME
        # ==========================================
        for fig, canvas in charts:

            fig.set_facecolor(
                t["panel_bg"]
            )

            for ax in fig.axes:

                ax.set_facecolor(
                    t["panel_bg"]
                )

                ax.tick_params(
                    colors=t["text_dim"]
                )

                for spine in ax.spines.values():

                    spine.set_color(
                        t["border"]
                    )

                ax.title.set_color(
                    t["text_header"]
                )

                ax.xaxis.label.set_color(
                    t["text_header"]
                )

                ax.yaxis.label.set_color(
                    t["text_header"]
                )

            canvas.draw_idle()

    # --- UI INIT ---
    def _init_ui(self):
        # ================= ROOT =================
        central = QWidget()
        self.setCentralWidget(central)

        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ================= STACK =================
        self.stack = QStackedWidget()

        # ================= SIDEBAR =================
        self.sidebar = QListWidget()
        self.sidebar.setFixedWidth(250)
        self.sidebar.setFocusPolicy(Qt.NoFocus)
        self.sidebar.currentRowChanged.connect(self._on_nav_change)

        # 🔒 SINGLE SOURCE OF TRUTH (DO NOT DUPLICATE)
        sidebar_items = [
            ("📊", "Dashboard", "dashboard"),
            ("🎯", "Scope Config", "target"),
            ("sep", "", None),
            ("🚀", "Phase 1: Scan", "phase1"),
            ("🛡️", "Phase 2: Validate", "phase2"),
            ("📝", "Phase 3: Report", "phase3"),
            ("⚡", "Full Auto Scan", "full"),
            ("sep", "", None),
            ("🔍", "Discovery", "discovery"),
            ("⚠️", "Findings List", "findings"),
            ("🖐️", "Repeater", "repeater"),
            ("📧", "Email Report", "email"),
            ("🧮", "CVSS Calc", "cvss"),
            ("🗺️", "MITRE Map", "mitre"),
            ("🔥", "Risk Heatmap", "heatmap"),
            ("📡", "Live Events (SIEM)", "siem"),
            ("🕘", "Scan History", "history"),
            ("📸", "Screenshots", "screenshots"),
            ("⚙️", "Settings", "settings"),
            
            ("sep", "", None),
            ("🖥️", "Logs", "logs"),
        ]

        # ================= ADD SIDEBAR ITEMS =================
        for icon, text, key in sidebar_items:
            if icon == "sep":
                item = QListWidgetItem()
                item.setFlags(Qt.NoItemFlags)
                item.setSizeHint(QSize(0, 18))
            else:
                item = QListWidgetItem(f" {icon}   {text}")
                item.setSizeHint(QSize(0, 46))
                item.setData(Qt.UserRole, key)  # 🔑 SAFE NAV KEY
            self.sidebar.addItem(item)

        layout.addWidget(self.sidebar)

        # ================= MAIN STACK (LOCKED ORDER) =================
        self.pages = {}

        self.dashboard_page = DashboardPage(self)
        self.pages["dashboard"] = self.dashboard_page
        self.stack.addWidget(self.pages["dashboard"])

        # Dashboard compatibility references
        # ==========================================================

        self.lbl_urls = self.dashboard_page.lbl_urls
        self.lbl_vulns = self.dashboard_page.lbl_vulns
        self.lbl_high = self.dashboard_page.lbl_high
        self.lbl_conf = self.dashboard_page.lbl_conf

        # DashboardPage owns these widgets.
        # Keep compatibility aliases only when they actually exist.
        self.dashboard_target_url = (
            self.dashboard_page.input_target_url
        )

        self.dashboard_scan_status = getattr(
            self.dashboard_page,
            "dashboard_scan_status",
            None,
        )

        self.pages["target"] = self._page_target()
        self.stack.addWidget(self.pages["target"])

        self.pages["phase1"] = self._page_phase1()
        self.stack.addWidget(self.pages["phase1"])

        self.pages["phase2"] = self._page_phase2()
        self.stack.addWidget(self.pages["phase2"])

        self.pages["phase3"] = self._page_phase3()
        self.stack.addWidget(self.pages["phase3"])
        
        self.pages["email"] = self._page_email()
        self.stack.addWidget(self.pages["email"])

        self.pages["full"] = self._page_full_scan()
        self.stack.addWidget(self.pages["full"])

        self.pages["discovery"] = self._page_discovery()
        self.stack.addWidget(self.pages["discovery"])

        self.pages["findings"] = self._page_issues()
        self.stack.addWidget(self.pages["findings"])

        self.pages["repeater"] = self._page_repeater()
        self.stack.addWidget(self.pages["repeater"])

        self.pages["cvss"] = self._page_cvss()
        self.stack.addWidget(self.pages["cvss"])

        self.pages["mitre"] = self._page_mitre()
        self.stack.addWidget(self.pages["mitre"])

        self.pages["heatmap"] = self._page_heatmap()
        self.stack.addWidget(self.pages["heatmap"])

        self.pages["siem"] = self._page_siem()
        self.stack.addWidget(self.pages["siem"])

        self.pages["screenshots"] = self._page_screenshots()
        self.stack.addWidget(self.pages["screenshots"])

        self.pages["settings"] = QWidget()
        self.stack.addWidget(self.pages["settings"])

        self.pages["history"] = self._page_history()
        self.stack.addWidget(self.pages["history"])

        self.pages["logs"] = self._page_logs()
        self.stack.addWidget(self.pages["logs"])

        layout.addWidget(self.stack)

        # ================= DEFAULT =================
        self.sidebar.setCurrentRow(0)
        self._setup_toolbar()

        # ==========================================
        # Dashboard Engines
        # ==========================================

        # Animation frame counter
        self.wave_frame = 0

    def _navigate_to_page(self, key):
        if key in self.pages:
            self.stack.setCurrentWidget(self.pages[key])

    def _setup_toolbar(self):
        tb = QToolBar()
        tb.setMovable(False)
        self.addToolBar(tb)

        # ===================== SCAN STATUS =====================

        # 🟢 Live Phase Status
        self.phase_status_lbl = QLabel("● Idle")
        self.phase_status_lbl.setStyleSheet(
            "padding: 6px; font-weight: bold; color: #9ca3af;"
        )
        tb.addWidget(self.phase_status_lbl)

        tb.addSeparator()

        # 🔒 Phase Lock Indicator
        self.phase_lock_lbl = QLabel("P2 🔒 | P3 🔒")
        self.phase_lock_lbl.setStyleSheet(
            "padding: 6px; font-weight: bold; color: #ef4444;"
        )
        tb.addWidget(self.phase_lock_lbl)

        tb.addSeparator()

        # ===================== CONTEXT INFO =====================

        # 🔹 Scan Mode (display only)
        self.scan_mode_lbl = QLabel("Mode: Manual")
        self.scan_mode_lbl.setStyleSheet(
            "font-weight: bold; padding: 6px; color: #9ca3af;"
        )
        tb.addWidget(self.scan_mode_lbl)

        tb.addSeparator()

        # 🔹 Active Target
        self.active_target_lbl = QLabel("Target: Not Set")
        self.active_target_lbl.setStyleSheet("padding: 6px; color: #9ca3af;")
        tb.addWidget(self.active_target_lbl)

        tb.addSeparator()

        # ===================== RIGHT SIDE =====================

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        tb.addWidget(spacer)

        # 🔍 Search Box
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search ID, URL, Type...")
        self.search_input.setFixedWidth(280)
        self.search_input.setStyleSheet(
            f"""
            QLineEdit {{
                background-color: {self.current_theme['app_bg']};
                border: 1px solid {self.current_theme['border']};
                color: {self.current_theme['text_header']};
                padding: 6px;
                border-radius: 4px;
            }}
            """
        )
        self.search_input.returnPressed.connect(self._perform_search)
        tb.addWidget(self.search_input)

        # 🔍 Search Button
        btn_search = QPushButton()
        btn_search.setIcon(self.style().standardIcon(
            QStyle.SP_FileDialogContentsView))
        btn_search.setFixedSize(32, 32)
        btn_search.clicked.connect(self._perform_search)
        tb.addWidget(btn_search)

        sep = QWidget()
        sep.setFixedWidth(15)
        tb.addWidget(sep)

        # 📸 Screenshot Button
        btn_shot = QPushButton()
        btn_shot.setIcon(self.style().standardIcon(QStyle.SP_DialogHelpButton))
        btn_shot.setToolTip("Take App Screenshot")
        btn_shot.setFixedSize(32, 32)
        btn_shot.clicked.connect(self._take_screenshot)
        tb.addWidget(btn_shot)

        sep2 = QWidget()
        sep2.setFixedWidth(8)
        tb.addWidget(sep2)

        # 📤 Export CSV (KEPT)
        btn_export = QPushButton("Export CSV")
        btn_export.setIcon(self.style().standardIcon(
            QStyle.SP_DialogSaveButton))
        btn_export.clicked.connect(self._export_csv)
        tb.addWidget(btn_export)

        sep_cleanup = QWidget()
        sep_cleanup.setFixedWidth(8)
        tb.addWidget(sep_cleanup)

        btn_cleanup = QPushButton("Project Cleanup")
        btn_cleanup.setIcon(
            self.style().standardIcon(QStyle.SP_TrashIcon)
        )
        btn_cleanup.clicked.connect(self.clean_project)
        tb.addWidget(btn_cleanup)

        sep3 = QWidget()
        sep3.setFixedWidth(15)
        tb.addWidget(sep3)

        # 🎨 Theme Selector
        self.theme_selector = QComboBox()
        self.theme_selector.addItems(THEMES.keys())
        self.theme_selector.setCurrentText(self.current_theme_name)
        self.theme_selector.setFixedWidth(160)
        self.theme_selector.currentIndexChanged.connect(self._change_theme)
        tb.addWidget(self.theme_selector)

    def clean_project(self):

        try:
            cleaner = ProjectCleaner()
            cleaner.full_cleanup()

            QMessageBox.information(
                self,
                "Project Maintenance",
                "Project cleaned successfully."
            )

        except Exception as e:

            QMessageBox.critical(
                self,
                "Project Maintenance",
                f"Cleanup failed:\n{e}"
            )

    def _setup_statusbar(self):
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        ("Ready | Pro Edition")

    def _make_card(self, title, value, color):
        frame = QFrame()
        frame.setMinimumHeight(110)

        # Sleek Rocker Card Style
        frame.setStyleSheet(f"""
            QFrame {{
                background-color: #1D2231;
                border-radius: 12px;
                border-top: 3px solid {color};
            }}
            QFrame:hover {{
                background-color: #242A3D;
            }}
        """)

        # Add a subtle drop shadow for depth
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(15)
        shadow.setColor(QColor(0, 0, 0, 100))
        shadow.setOffset(0, 4)
        frame.setGraphicsEffect(shadow)

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(20, 15, 20, 15)
        layout.setSpacing(2)

        lbl_title = QLabel(title)
        lbl_title.setStyleSheet(
            "color: #8A92A6; font-size: 13px; font-weight: 600; border: none; background: transparent;")

        lbl_value = QLabel(value)
        lbl_value.setStyleSheet(
            f"color: white; font-size: 32px; font-weight: 900; border: none; background: transparent;")

        lbl_sub = QLabel("Live")
        lbl_sub.setStyleSheet(
            f"color: {color}; font-size: 11px; font-weight: bold; border: none; background: transparent;")

        frame.value_label = lbl_value  # Preserved for your backend

        layout.addWidget(lbl_title)
        layout.addWidget(lbl_value)
        layout.addWidget(lbl_sub)
        layout.addStretch()

        return frame

    def _page_dashboard(self):
        w = QWidget()
        w.setStyleSheet("background-color: #12151E;")  # Main Rocker Background

        main = QVBoxLayout(w)
        main.setContentsMargins(25, 25, 25, 25)
        main.setSpacing(20)

        # =====================================================
        # TARGET BAR
        # =====================================================
        target_panel = QFrame()
        target_panel.setStyleSheet(
            "background-color: #1D2231; border-radius: 12px;")
        target_layout = QHBoxLayout(target_panel)
        target_layout.setContentsMargins(20, 12, 20, 12)

        self.dashboard_target_url = QLabel("Target: Not Set")
        self.dashboard_target_url.setStyleSheet(
            "color: #00D2FF; font-size: 15px; font-weight: bold;")

        self.dashboard_scan_status = QLabel("Status: Idle")
        self.dashboard_scan_status.setStyleSheet(
            "color: #00E676; font-size: 15px; font-weight: bold;")

        target_layout.addWidget(self.dashboard_target_url)
        target_layout.addStretch()
        target_layout.addWidget(self.dashboard_scan_status)
        main.addWidget(target_panel)

        # =====================================================
        # KPI CARDS
        # =====================================================
        cards = QHBoxLayout()
        cards.setSpacing(20)

        self.lbl_urls = self._make_card(
            "Unique URLs", "0", "#00D2FF")  # Neon Cyan
        self.lbl_vulns = self._make_card(
            "Total Threats", "0", "#FF007C")  # Neon Pink
        self.lbl_high = self._make_card(
            "High Risk", "0", "#FFAA00")  # Neon Orange
        self.lbl_conf = self._make_card(
            "Confidence", "0%", "#00E676")    # Neon Green

        cards.addWidget(self.lbl_urls)
        cards.addWidget(self.lbl_vulns)
        cards.addWidget(self.lbl_high)
        cards.addWidget(self.lbl_conf)
        main.addLayout(cards)

        # =====================================================
        # ROW 1 (MATCHING PAPER SKETCH)
        # =====================================================
        row1 = QHBoxLayout()
        row1.setSpacing(20)

        # LEFT CHART: Vertical Bar Chart (from Sketch)
        chart_panel = QFrame()
        chart_panel.setMinimumHeight(450)
        chart_panel.setStyleSheet(
            "background-color: #1D2231; border-radius: 16px;")
        chart_layout = QVBoxLayout(chart_panel)

        chart_title = QLabel("Threat Distribution")
        chart_title.setStyleSheet(
            "color: white; font-size: 18px; font-weight: bold; margin-bottom: 5px;")
        chart_layout.addWidget(chart_title)

        self.fig_sev = Figure(figsize=(10, 5), facecolor="#1D2231")
        self.cv_sev = FigureCanvas(self.fig_sev)
        chart_layout.addWidget(self.cv_sev)
        row1.addWidget(chart_panel, 7)  # 70% width (Like paper sketch)

        # RIGHT SUMMARY PANEL: The Analysis Breakdown
        summary_panel = QFrame()
        summary_panel.setStyleSheet(
            "background-color: #1D2231; border-radius: 16px;")
        summary_layout = QVBoxLayout(summary_panel)
        summary_layout.setContentsMargins(25, 25, 25, 25)

        lbl = QLabel("Threat Analysis")
        lbl.setStyleSheet(
            "color: #8A92A6; font-size: 16px; font-weight: bold;")
        summary_layout.addWidget(lbl)

        self.analysis_total = QLabel("0 Threats")
        self.analysis_total.setStyleSheet(
            "color: #FF007C; font-size: 36px; font-weight: 900; margin-bottom: 15px;")
        summary_layout.addWidget(self.analysis_total)

        self.analysis_layout = QVBoxLayout()
        self.analysis_layout.setSpacing(10)
        summary_layout.addLayout(self.analysis_layout)
        summary_layout.addStretch()

        row1.addWidget(summary_panel, 3)  # 30% width
        main.addLayout(row1)

        # =====================================================
        # ROW 2: CLEAN TABLES (Side by Side)
        # =====================================================
        row2 = QHBoxLayout()
        row2.setSpacing(20)

        # TABLE STYLESHEET (Rocker Theme: No borders, sleek padding)
        table_style = """
            QTableWidget {
                background-color: transparent;
                border: none;
                color: #E0E6ED;
                font-size: 13px;
                outline: none;
            }
            QTableWidget::item {
                padding: 12px;
                border-bottom: 1px solid #2A3042;
            }
            QTableWidget::item:selected {
                background-color: rgba(0, 210, 255, 0.15); /* Transparent Neon Cyan highlight */
                color: #00D2FF;
                font-weight: bold;
            }
            QHeaderView::section {
                background-color: #161925;
                color: #8A92A6;
                padding: 12px;
                border: none;
                font-size: 12px;
                font-weight: bold;
                text-transform: uppercase;
            }
        """

        # 1. ATTACK TYPE TABLE
        attack_panel = QFrame()
        attack_panel.setStyleSheet(
            "background-color: #1D2231; border-radius: 16px;")
        attack_layout = QVBoxLayout(attack_panel)

        attack_title = QLabel("Attack Type Breakdown")
        attack_title.setStyleSheet(
            "color: white; font-size: 16px; font-weight: bold;")
        attack_layout.addWidget(attack_title)

        self.attack_type_table = QTableWidget(0, 3)
        self.attack_type_table.setHorizontalHeaderLabels(
            ["Attack Type", "Count", "%"])
        self.attack_type_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.attack_type_table.setEditTriggers(
            QAbstractItemView.NoEditTriggers)
        self.attack_type_table.setSelectionBehavior(
            QAbstractItemView.SelectRows)
        self.attack_type_table.setShowGrid(False)
        self.attack_type_table.setStyleSheet(table_style)

        attack_layout.addWidget(self.attack_type_table)
        row2.addWidget(attack_panel, 1)

        # 2. FINDINGS TABLE
        findings_panel = QFrame()
        findings_panel.setStyleSheet(
            "background-color: #1D2231; border-radius: 16px;")
        findings_layout = QVBoxLayout(findings_panel)

        findings_title = QLabel("Recent Findings")
        findings_title.setStyleSheet(
            "color: white; font-size: 16px; font-weight: bold;")
        findings_layout.addWidget(findings_title)

        self.dashboard_table = QTableWidget(0, 5)
        self.dashboard_table.setHorizontalHeaderLabels(
            ["Severity", "Type", "URL", "CVSS", "Confidence"])
        self.dashboard_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.dashboard_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.dashboard_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.dashboard_table.setShowGrid(False)
        self.dashboard_table.setStyleSheet(table_style)

        findings_layout.addWidget(self.dashboard_table)
        row2.addWidget(findings_panel, 2)

        main.addLayout(row2)
        return w

    def _page_dashboard(self):

        # =====================================================
        # SCROLL AREA
        # =====================================================

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        scroll.setStyleSheet("""
        QScrollArea{
            border:none;
            background:#12141c;
        }
    
        QScrollBar:vertical{
            background:#12141c;
            width:12px;
            border:none;
        }
    
        QScrollBar::handle:vertical{
            background:#31374d;
            border-radius:6px;
        }
    
        QScrollBar::handle:vertical:hover{
            background:#00d4ff;
        }
        """)

        page = QWidget()
        page.setStyleSheet("background:#12141c;")

        scroll.setWidget(page)

        main = QVBoxLayout(page)
        main.setContentsMargins(28, 28, 28, 28)
        main.setSpacing(24)

        # =====================================================
        # HEADER
        # =====================================================

        header = QLabel("Security Intelligence Dashboard")

        header.setStyleSheet("""
        color:white;
        font-size:34px;
        font-weight:800;
        """)

        main.addWidget(header)

        # =====================================================
        # TARGET BAR
        # =====================================================

        target_panel = QFrame()
        self._style_rocker_panel(target_panel)

        target_layout = QHBoxLayout(target_panel)
        target_layout.setContentsMargins(22, 18, 22, 18)

        self.dashboard_target_url = QLabel("Target : Not Set")
        self.dashboard_target_url.setStyleSheet("""
        color:#00d4ff;
        font-size:15px;
        font-weight:bold;
        """)

        self.dashboard_scan_status = QLabel("Status : Idle")
        self.dashboard_scan_status.setStyleSheet("""
        color:#00e676;
        font-size:15px;
        font-weight:bold;
        """)

        target_layout.addWidget(self.dashboard_target_url)
        target_layout.addStretch()
        target_layout.addWidget(self.dashboard_scan_status)

        main.addWidget(target_panel)

        # =====================================================
        # KPI ROW
        # =====================================================

        kpi = QHBoxLayout()
        kpi.setSpacing(20)

        self.lbl_urls = self._make_rocker_kpi(
            "Unique URLs",
            "0",
            "#00D4FF",
            "Live",
            "🌐"
        )

        self.lbl_vulns = self._make_rocker_kpi(
            "Threats",
            "0",
            "#ff3d71",
            "Detected",
            "⚠"
        )

        self.lbl_high = self._make_rocker_kpi(
            "Critical",
            "0",
            "#ffaa00",
            "Priority",
            "🔥"
        )

        self.lbl_conf = self._make_rocker_kpi(
            "Confidence",
            "0%",
            "#00e676",
            "Validated",
            "✔"
        )

        kpi.addWidget(self.lbl_urls)
        kpi.addWidget(self.lbl_vulns)
        kpi.addWidget(self.lbl_high)
        kpi.addWidget(self.lbl_conf)

        main.addLayout(kpi)

        # =====================================================
        # ROW 1
        # =====================================================

        row1 = QHBoxLayout()
        row1.setSpacing(22)

        # -------------------------------------------------
        # WAVE PANEL
        # -------------------------------------------------

        wave_panel = QFrame()
        self._style_rocker_panel(wave_panel)
        wave_panel.setMinimumHeight(470)

        wave_layout = QVBoxLayout(wave_panel)

        title = QLabel("Live Scan Overview")
        title.setStyleSheet("""
        color:white;
        font-size:18px;
        font-weight:700;
        """)

        wave_layout.addWidget(title)

        # Figure
        self.fig_area = Figure(
            figsize=(8, 4),
            facecolor="#1A1D27"
        )

        # Canvas
        self.cv_area = FigureCanvas(self.fig_area)

        wave_layout.addWidget(self.cv_area)

        row1.addWidget(wave_panel, 5)

        # -------------------------------------------------
        # DONUT
        # -------------------------------------------------

        donut_panel = QFrame()
        self._style_rocker_panel(donut_panel)
        donut_panel.setMinimumHeight(420)

        donut_layout = QVBoxLayout(donut_panel)

        title = QLabel("Threat Severity")
        title.setStyleSheet("""
        color:white;
        font-size:18px;
        font-weight:700;
        """)

        donut_layout.addWidget(title)

        self.lbl_total_threats = QLabel()

        self.lbl_total_threats.setAlignment(Qt.AlignCenter)

        self.lbl_total_threats.setStyleSheet("""
        
        color:white;
        
        font-size:16px;
        
        font-weight:bold;
        
        padding:8px;
        
        """)

        donut_layout.addWidget(self.lbl_total_threats)

        self.fig_conf = Figure(facecolor="#1A1D27")
        self.cv_conf = FigureCanvas(self.fig_conf)

        donut_layout.addWidget(self.cv_conf)

        row1.addWidget(donut_panel, 2)

        main.addLayout(row1)

        # =====================================================
        # ROW 2
        # =====================================================

        row2 = QHBoxLayout()
        row2.setSpacing(22)

        # -------------------------------------------------
        # BAR GRAPH
        # -------------------------------------------------

        graph_panel = QFrame()
        self._style_rocker_panel(graph_panel)

        graph_layout = QVBoxLayout(graph_panel)

        lbl = QLabel("Threat Distribution")

        lbl.setStyleSheet("""
        color:white;
        font-size:18px;
        font-weight:700;
        """)

        graph_layout.addWidget(lbl)

        self.fig_sev = Figure(facecolor="#1a1d27")
        self.cv_sev = FigureCanvas(self.fig_sev)

        graph_layout.addWidget(self.cv_sev)

        row2.addWidget(graph_panel, 4)

        # -------------------------------------------------
        # SUMMARY
        # -------------------------------------------------

        summary_panel = QFrame()
        self._style_rocker_panel(summary_panel)

        summary_layout = QVBoxLayout(summary_panel)
        summary_layout.setContentsMargins(24, 24, 24, 24)

        lbl = QLabel("Threat Analysis")

        lbl.setStyleSheet("""
        color:#9ca3af;
        font-size:16px;
        font-weight:bold;
        """)

        summary_layout.addWidget(lbl)

        self.analysis_total = QLabel("0 Threats")

        self.analysis_total.setStyleSheet("""
        color:#ff3d71;
        font-size:34px;
        font-weight:900;
        """)

        summary_layout.addWidget(self.analysis_total)

        self.analysis_layout = QVBoxLayout()
        self.analysis_layout.setSpacing(12)

        summary_layout.addLayout(self.analysis_layout)
        summary_layout.addStretch()

        row2.addWidget(summary_panel, 2)

        main.addLayout(row2)

        # =====================================================
        # ROW 3
        # =====================================================

        row3 = QHBoxLayout()
        row3.setSpacing(22)

        attack_panel = QFrame()
        self._style_rocker_panel(attack_panel)

        attack_layout = QVBoxLayout(attack_panel)

        title = QLabel("Attack Types")
        title.setStyleSheet("color:white;font-size:18px;font-weight:bold;")

        attack_layout.addWidget(title)

        self.attack_type_table = QTableWidget(0, 3)

        self.attack_type_table.setHorizontalHeaderLabels(
            [
                "Attack",
                "Count",
                "%"
            ]
        )

        self.attack_type_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
        )

        attack_layout.addWidget(self.attack_type_table)

        row3.addWidget(attack_panel, 1)

        findings_panel = QFrame()
        self._style_rocker_panel(findings_panel)

        findings_layout = QVBoxLayout(findings_panel)

        title = QLabel("Recent Findings")
        title.setStyleSheet("color:white;font-size:18px;font-weight:bold;")

        findings_layout.addWidget(title)

        self.dashboard_table = QTableWidget(0, 5)

        self.dashboard_table.setHorizontalHeaderLabels(
            [
                "Severity",
                "Type",
                "URL",
                "CVSS",
                "Confidence"
            ]
        )

        self.dashboard_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
        )

        findings_layout.addWidget(self.dashboard_table)

        row3.addWidget(findings_panel, 2)

        main.addLayout(row3)

        return scroll

    def _style_rocker_panel(self, panel):
        """
        Rocker Dashboard Panel Style
        """

        panel.setObjectName("rockerPanel")

        panel.setStyleSheet("""
        QFrame#rockerPanel{
            background:qlineargradient(
                x1:0,
                y1:0,
                x2:1,
                y2:1,
                stop:0 #1B202C,
                stop:0.45 #1A1D27,
                stop:1 #181C24
            );
    
            border:1px solid #2A3042;
            border-radius:18px;
        }
    
        QFrame#rockerPanel:hover{
            border:1px solid #00D2FF;
            background:qlineargradient(
                x1:0,
                y1:0,
                x2:1,
                y2:1,
                stop:0 #202635,
                stop:0.45 #1F2431,
                stop:1 #1B202C
            );
        }
        """)

    def _make_rocker_kpi(
            self,
            title,
            value,
            color,
            trend="",
            icon=""
    ):

        frame = QFrame()
        frame.setObjectName("rockerCard")
        frame.setMinimumHeight(135)

        frame.setStyleSheet(f"""
        QFrame#rockerCard{{
            background:qlineargradient(
                x1:0,y1:0,
                x2:1,y2:1,
                stop:0 #1A1D27,
                stop:1 #202635
            );
    
            border:1px solid #2A3042;
            border-radius:18px;
        }}
    
        QFrame#rockerCard:hover{{
            border:1px solid {color};
        }}
        """)

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(6)

        # -------------------------
        # Top Row
        # -------------------------

        top = QHBoxLayout()

        lbl_title = QLabel(title)
        lbl_title.setStyleSheet("""
            color:#8A92A6;
            font-size:13px;
            font-weight:600;
        """)

        lbl_icon = QLabel(icon)
        lbl_icon.setAlignment(Qt.AlignRight)

        lbl_icon.setStyleSheet(f"""
            color:{color};
            font-size:24px;
        """)

        top.addWidget(lbl_title)
        top.addStretch()
        top.addWidget(lbl_icon)

        layout.addLayout(top)

        # -------------------------
        # VALUE
        # -------------------------

        lbl_value = QLabel(value)

        lbl_value.setStyleSheet(f"""
            color:{color};
            font-size:34px;
            font-weight:900;
        """)

        layout.addWidget(lbl_value)

        # -------------------------
        # TREND
        # -------------------------

        lbl_trend = QLabel(trend)

        lbl_trend.setStyleSheet(f"""
            color:{color};
            font-size:12px;
            font-weight:bold;
        """)

        layout.addWidget(lbl_trend)

        frame.value_label = lbl_value
        frame.trend_label = lbl_trend

        return frame

    # =====================================================
    # MATPLOTLIB CHART STYLING & UPDATES
    # =====================================================

    def _setup_matplotlib_axis(self, ax):
        ax.clear()

        ax.set_facecolor("#111A2A")

        ax.grid(
            color="#243149",
            linestyle="--",
            linewidth=0.7,
            alpha=0.45,
        )

        ax.tick_params(
            colors="#8D9AB0",
            labelsize=10
        )

        for spine in ax.spines.values():
            spine.set_color("#243149")

        ax.title.set_color("#F4F7FB")
        ax.xaxis.label.set_color("#F4F7FB")
        ax.yaxis.label.set_color("#F4F7FB")

        ax.set_axisbelow(True)

    def _load_phase1_dataset(self):

        path = os.path.join(
            PHASE1_DIR,
            "output",
            "url_scan.json",
        )

        dataset = {
            "target": self._get_saved_target() or "",
            "pages": [],
            "unique_urls": [],
            "parameters": 0,
            "forms": 0,
            "links": 0,
            "endpoints": 0,
            "runtime_events": 0,
            "network_requests": 0,
            "network_responses": 0,
        }

        if not os.path.exists(path):

            self.phase1_data = dataset

            return dataset

        try:

            with open(
                path,
                "r",
                encoding="utf-8"
            ) as f:

                raw = json.load(f)

            if not isinstance(raw, dict):
                raw = {}

            pages = raw.get(
                "pages_analyzed",
                []
            )

            if not isinstance(pages, list):
                pages = []

            dataset["target"] = (
                raw.get("target")
                or dataset["target"]
            )

            dataset["pages"] = pages

            urls = set()

            def add_url(value):

                if not value:
                    return

                value = str(value).strip()

                if value.startswith(
                    ("http://", "https://")
                ):
                    urls.add(
                        value.rstrip("/")
                    )

            def count_items(value):

                if isinstance(value, list):
                    return len(value)

                if isinstance(value, dict):

                    items = value.get("items")

                    if isinstance(items, list):
                        return len(items)

                    return len(value)

                return 0

            for page in pages:

                if not isinstance(page, dict):
                    continue

                add_url(
                    page.get("url")
                )

                add_url(
                    page.get("final_url")
                )

                discovery = (
                    page.get("discovery")
                    or {}
                )

                if isinstance(
                    discovery,
                    dict
                ):

                    dataset["parameters"] += count_items(
                        discovery.get("parameters")
                    )

                    dataset["forms"] += count_items(
                        discovery.get("forms")
                    )

                    dataset["links"] += count_items(
                        discovery.get("links")
                    )

                    dataset["endpoints"] += count_items(
                        discovery.get("endpoints")
                    )

                runtime = (
                    page.get("runtime")
                    or {}
                )

                if isinstance(
                    runtime,
                    dict
                ):

                    dataset["runtime_events"] += count_items(
                        runtime.get("events")
                    )

                    artifacts = (
                        runtime.get("artifacts")
                        or {}
                    )

                    if isinstance(
                        artifacts,
                        dict
                    ):

                        dataset["links"] += count_items(
                            artifacts.get("links")
                        )

                        dataset["endpoints"] += count_items(
                            artifacts.get("endpoints")
                        )

                        dataset["forms"] += count_items(
                            artifacts.get("forms")
                        )

                        dataset["parameters"] += count_items(
                            artifacts.get("parameters")
                        )

                network = (
                    page.get("network")
                    or {}
                )

                if isinstance(
                    network,
                    dict
                ):

                    dataset["network_requests"] += count_items(
                        network.get("requests")
                    )

                    dataset["network_responses"] += count_items(
                        network.get("responses")
                    )

                    dataset["endpoints"] += count_items(
                        network.get("endpoints")
                    )

            dataset["unique_urls"] = sorted(
                urls
            )

        except Exception as exc:

            print(
                f"[GUI][PHASE1] Failed loading url_scan.json: {exc}",
                flush=True
            )

        self.phase1_data = dataset

        return dataset

    def _update_charts(self):
        """
        Send real Phase-2 findings to the new backend-driven dashboard
        and update the visible Risk Heatmap.
        """

        # =====================================================
        # 1. GET REAL FINDINGS
        # =====================================================

        vulnerabilities = (
            self.vuln_data
            if isinstance(self.vuln_data, list)
            else []
        )

        # =====================================================
        # 2. UPDATE DASHBOARD
        # =====================================================

        if hasattr(self, "dashboard_page"):

            target = ""

            try:
                target = self._get_saved_target() or ""
            except Exception:
                pass

            if not target:
                try:
                    target = self.active_target_lbl.text()

                    if ":" in target:
                        target = target.split(":", 1)[1].strip()

                except Exception:
                    target = ""

            try:
                self.dashboard_page.update_dashboard(
                    vulnerabilities=vulnerabilities,
                    target_url=target or "Not Set",
                    scan_status=(
                        "Completed"
                        if vulnerabilities
                        else "Idle"
                    ),
                )

            except Exception as e:
                print(
                    f"[GUI] Dashboard update error: {e}",
                    flush=True,
                )

                # =====================================================
        # 3. UPDATE RISK HEATMAP
        # =====================================================

        if not hasattr(self, "animated_heatmap"):
            print(
                "[GUI][HEATMAP] Widget not available",
                flush=True,
            )
            return

        # -----------------------------------------------------
        # Matrix:
        #
        #             Confidence
        #          Low  Medium  High
        #
        # Low       [0]   [0]    [0]
        # Medium    [0]   [0]    [0]
        # High      [0]   [0]    [0]
        #
        # -----------------------------------------------------

        matrix = [
            [0, 0, 0],   # Low CVSS
            [0, 0, 0],   # Medium CVSS
            [0, 0, 0],   # High / Critical CVSS
        ]

        for vuln in vulnerabilities:

            if not isinstance(vuln, dict):
                continue

            # =================================================
            # CVSS
            # =================================================

            cvss_value = vuln.get(
                "cvss_score",
                None
            )

            if cvss_value is None:

                cvss_data = vuln.get(
                    "cvss",
                    {}
                )

                if isinstance(
                    cvss_data,
                    dict
                ):
                    cvss_value = cvss_data.get(
                        "score",
                        0
                    )

                else:
                    cvss_value = 0

            try:
                cvss = float(
                    str(cvss_value)
                    .replace(",", ".")
                    .strip()
                )

            except (
                TypeError,
                ValueError,
            ):
                cvss = 0.0

            cvss = max(
                0.0,
                min(10.0, cvss)
            )

            # =================================================
            # CONFIDENCE
            # =================================================

            confidence_raw = vuln.get(
                "confidence",
                0
            )

            # Numeric confidence:
            #
            # 97
            # "97"
            # "97%"
            #

            try:

                confidence = float(
                    str(
                        confidence_raw
                    )
                    .replace("%", "")
                    .strip()
                )

            except (
                TypeError,
                ValueError,
            ):

                confidence = 0.0

            # -------------------------------------------------
            # Text confidence support
            # -------------------------------------------------

            if isinstance(
                confidence_raw,
                str
            ):

                confidence_text = (
                    confidence_raw
                    .lower()
                    .strip()
                )

                if confidence_text == "high":
                    confidence = 90.0

                elif confidence_text == "medium":
                    confidence = 60.0

                elif confidence_text == "low":
                    confidence = 30.0

            confidence = max(
                0.0,
                min(100.0, confidence)
            )

            # =================================================
            # CVSS RISK BUCKET
            # =================================================

            if cvss >= 7.0:

                risk_y = 2

            elif cvss >= 4.0:

                risk_y = 1

            else:

                risk_y = 0

            # =================================================
            # CONFIDENCE BUCKET
            # =================================================

            if confidence >= 80.0:

                confidence_x = 2

            elif confidence >= 50.0:

                confidence_x = 1

            else:

                confidence_x = 0

            # =================================================
            # ADD FINDING TO CELL
            # =================================================

            matrix[
                risk_y
            ][
                confidence_x
            ] += 1

        # =====================================================
        # SEND DATA TO VISIBLE HEATMAP
        # =====================================================

        try:

            self.animated_heatmap.update_matrix(
                matrix
            )

            print(
                "[GUI][HEATMAP] Matrix:",
                matrix,
                flush=True,
            )

        except Exception as exc:

            print(
                "[GUI][HEATMAP] Update error:",
                exc,
                flush=True,
            )

    def _calculate_dashboard_data(self):
        """
        Build dashboard statistics exclusively from real
        Phase-2 vulnerability findings.

        No demo values.
        No hard-coded attack categories.
        """

        vulnerabilities = (
            self.vuln_data
            if isinstance(self.vuln_data, list)
            else []
        )

        total = len(vulnerabilities)

        type_counts = {}
        type_urls = {}

        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        confidence_values = []

        for vuln in vulnerabilities:

            vuln_type = str(
                vuln.get("type")
                or vuln.get("vulnerability")
                or "Unknown"
            ).strip()

            if not vuln_type:
                vuln_type = "Unknown"

            # -----------------------------------------------
            # TYPE COUNT
            # -----------------------------------------------

            type_counts[vuln_type] = (
                type_counts.get(vuln_type, 0) + 1
            )

            # -----------------------------------------------
            # AFFECTED URL
            # -----------------------------------------------

            url = str(
                vuln.get("url")
                or vuln.get("target")
                or vuln.get("endpoint")
                or ""
            ).strip()

            if url:
                type_urls.setdefault(
                    vuln_type,
                    set()
                ).add(url)

            # -----------------------------------------------
            # SEVERITY
            # -----------------------------------------------

            severity = str(
                vuln.get("severity", "info")
            ).lower().strip()

            if severity not in severity_counts:
                severity = "info"

            severity_counts[severity] += 1

            # -----------------------------------------------
            # CONFIDENCE
            # -----------------------------------------------

            confidence = vuln.get(
                "confidence",
                0
            )

            try:
                confidence = float(
                    str(confidence)
                    .replace("%", "")
                    .strip()
                )

                confidence = max(
                    0.0,
                    min(100.0, confidence)
                )

                confidence_values.append(
                    confidence
                )

            except (TypeError, ValueError):
                pass

        # ====================================================
        # DYNAMIC PERCENTAGES
        # ====================================================

        distribution = []

        for vuln_type, count in sorted(
            type_counts.items(),
            key=lambda item: item[1],
            reverse=True,
        ):

            percentage = (
                (count / total) * 100
                if total
                else 0.0
            )

            distribution.append({
                "type": vuln_type,
                "count": count,
                "percentage": round(
                    percentage,
                    1
                ),
                "urls": sorted(
                    type_urls.get(
                        vuln_type,
                        set()
                    )
                ),
                "url_count": len(
                    type_urls.get(
                        vuln_type,
                        set()
                    )
                ),
            })

        # ====================================================
        # UNIQUE AFFECTED URLS
        # ====================================================

        unique_urls = set()

        for urls in type_urls.values():
            unique_urls.update(urls)

        # ====================================================
        # HIGH / CRITICAL
        # ====================================================

        high_risk = (
            severity_counts["critical"]
            +
            severity_counts["high"]
        )

        # ====================================================
        # CONFIDENCE
        # ====================================================

        avg_confidence = (
            sum(confidence_values)
            / len(confidence_values)
            if confidence_values
            else 0
        )

        return {
            "total": total,

            "unique_urls": len(
                unique_urls
            ),

            "high_risk": high_risk,

            "avg_confidence": round(
                avg_confidence
            ),

            "type_counts": type_counts,

            "distribution": distribution,

            "severity_counts": severity_counts,

            "type_urls": {
                key: sorted(value)
                for key, value
                in type_urls.items()
            },
        }

    def _update_dashboard_kpis(self, data):
        """
        Update dashboard KPI cards.
        """

        self.urls_target = data["unique_urls"]
        self.vulns_target = data["total"]
        self.high_target = data["sev_counts"]["high"]

        self.lbl_conf.value_label.setText(
            f'{data["avg_conf"]}%'
        )

        if hasattr(self, "target_input"):

            target = self.target_input.text().strip()

            if target and self.dashboard_target_url is not None:

                self.dashboard_target_url.setText(
                    f"Target: {target}"
                )

        if self.dashboard_scan_status is not None:

            if data["total"]:

                self.dashboard_scan_status.setText(
                    "Status: Active Findings"
                )

            else:

                self.dashboard_scan_status.setText(
                    "Status: Idle"
                )

    def _update_area_chart(self, dashboard):

        ax = self.fig_area.subplots()

        values = dashboard["values"]

        if len(values) < 2:
            values = [0, 0]

        x = np.arange(len(values))

        self.wave_engine.render_wave(
            ax=ax,
            dashboard=dashboard,
            x=x,
            y=values,
            color="#00D4FF"
        )

    def _animate_dashboard(self):
        """
        Dashboard animation loop (30 FPS)
        """

        if not hasattr(self, "wave_engine"):
            return

        if not hasattr(self, "wave_target"):
            return

        if len(self.wave_target) == 0:
            return

        # -----------------------------
        # Animation
        # -----------------------------

        self.scan_position += 0.015
        self.wave_offset += 0.08
        self.pulse_phase += 0.10
        self.radar_angle = (self.radar_angle + 2) % 360

        if self.scan_position > 1:
            self.scan_position = 0

        # -----------------------------
        # Smooth Wave Transition
        # -----------------------------

        if len(self.wave_values) != len(self.wave_target):
            self.wave_values = self.wave_target.copy()

        else:

            for i in range(len(self.wave_values)):

                self.wave_values[i] += (

                    self.wave_target[i]

                    - self.wave_values[i]

                ) * 0.12

        # -----------------------------
        # Send data to engine
        # -----------------------------

        self.wave_engine.set_data(self.wave_values)

        self.wave_engine.render()

        # -----------------------------
        # Smooth KPI Counters
        # -----------------------------

        self.urls_display += (
            self.urls_target - self.urls_display
        ) * 0.15

        self.vulns_display += (
            self.vulns_target - self.vulns_display
        ) * 0.15

        self.high_display += (
            self.high_target - self.high_display
        ) * 0.15

        self.lbl_urls.value_label.setText(str(int(self.urls_display)))
        self.lbl_vulns.value_label.setText(str(int(self.vulns_display)))
        self.lbl_high.value_label.setText(str(int(self.high_display)))

    def _make_analysis_item(self, title, count, percent, color):

        frame = QFrame()

        frame.setStyleSheet(f"""
        QFrame {{
            background:#222735;
            border-left:5px solid {color};
            border-radius:8px;
        }}
        """)

        layout = QHBoxLayout(frame)
        layout.setContentsMargins(12, 10, 12, 10)

        name = QLabel(title)
        name.setStyleSheet("""
            color:white;
            font-size:14px;
            font-weight:600;
        """)

        value = QLabel(f"{count}   ({percent}%)")
        value.setAlignment(Qt.AlignRight)

        value.setStyleSheet(f"""
            color:{color};
            font-size:14px;
            font-weight:bold;
        """)

        layout.addWidget(name)
        layout.addStretch()
        layout.addWidget(value)

        return frame

    def _build_wave_chart(self):

        ax = self.fig_area.add_subplot(111)

        ax.set_facecolor("#1A1D27")
        self.fig_area.set_facecolor("#1A1D27")

        ax.set_xlim(0, 100)
        ax.set_ylim(0, 100)

        ax.grid(
            color="#30384f",
            linestyle="--",
            linewidth=0.6,
            alpha=0.4
        )

        ax.set_xticks([])
        ax.set_yticks([])

        for s in ax.spines.values():
            s.set_visible(False)

        x = np.linspace(0, 100, 500)

        self.wave1, = ax.plot([], [], lw=4, color="#00D2FF")
        self.wave2, = ax.plot([], [], lw=3, color="#00F7FF")
        self.wave3, = ax.plot([], [], lw=2, color="#82FFFF")

        self.wave_fill = ax.fill_between(
            x,
            np.zeros_like(x),
            np.zeros_like(x),
            color="#00D2FF",
            alpha=.18
        )

        def animate(frame):

            phase = frame*0.20

            progress = self.scan_progress

            amp = 5+(progress*0.12)

            y = 45+amp*np.sin(x/8+phase)

            # -----------------------------
            # Remove previous glow objects
            # -----------------------------
            while ax.lines:
                ax.lines.pop().remove()

            while ax.collections:
                ax.collections[0].remove()

            # -----------------------------
            # Gradient fill
            # -----------------------------
            ax.fill_between(
                x,
                y,
                0,
                color="#00D2FF",
                alpha=0.15
            )

            # -----------------------------
            # Neon Glow Layers
            # -----------------------------
            for lw, alpha in [
                (18, 0.03),
                (14, 0.05),
                (10, 0.08),
                (7, 0.12)
            ]:
                ax.plot(
                    x,
                    y,
                    color="#00D2FF",
                    lw=lw,
                    alpha=alpha,
                    solid_capstyle="round"
                )

            # -----------------------------
            # Main Neon Line
            # -----------------------------
            ax.plot(
                x,
                y,
                color="#00D2FF",
                lw=3,
                solid_capstyle="round"
            )

            # -----------------------------
            # Bright Highlight
            # -----------------------------
            ax.plot(
                x,
                y+0.5,
                color="#AFFFFF",
                lw=1.2,
                alpha=0.9
            )

            return ax.lines

        self.wave_animation = FuncAnimation(
            self.fig_area,
            animate,
            interval=35,
            blit=False
        )

        self.cv_area.draw()

    def _update_screenshot(self):
        """
        Updates the current screenshot in both:
            • Phase-1 Live Browser View
            • Screenshots Page

        Supports:
            ✓ Previous / Next buttons
            ✓ Live updating during scan
            ✓ Auto-clamp index
        """

        if not os.path.isdir(SCREENSHOT_DIR):
            return

        images = sorted(
            [
                f for f in os.listdir(SCREENSHOT_DIR)
                if f.lower().endswith(".png")
            ],
            key=lambda f: os.path.getmtime(
                os.path.join(SCREENSHOT_DIR, f)
            )
        )

        if not images:
            if hasattr(self, "screenshot_counter_label"):
                self.screenshot_counter_label.setText("No screenshots")

            if hasattr(self, "gallery_counter"):
                self.gallery_counter.setText("No screenshots")

            return

        # -----------------------------------------
        # Initialize index
        # -----------------------------------------

        if not hasattr(self, "current_screenshot_index"):
            self.current_screenshot_index = len(images) - 1

        # -----------------------------------------
        # Auto-follow newest screenshot ONLY
        # if user was already on latest image
        # -----------------------------------------

        if self.current_screenshot_index >= len(images):
            self.current_screenshot_index = len(images) - 1

        self.current_screenshot_index = max(
            0,
            min(self.current_screenshot_index, len(images) - 1)
        )

        image_path = os.path.join(
            SCREENSHOT_DIR,
            images[self.current_screenshot_index]
        )

        pixmap = QPixmap(image_path)

        if pixmap.isNull():
            return

        # =====================================================
        # Phase-1 Live Browser View
        # =====================================================

        if (
            hasattr(self, "live_browser_label")
            and self.live_browser_label is not None
        ):
            self._live_browser_pixmap = pixmap

            target_size = (
                self.live_browser_label
                .contentsRect()
                .size()
            )
            
            if (
                target_size.width() > 20
                and target_size.height() > 20
            ):
            
                self.live_browser_label.setPixmap(
                    pixmap.scaled(
                        target_size,
                        Qt.KeepAspectRatio,
                        Qt.SmoothTransformation,
                    )
                )
            
            else:
            
                self.live_browser_label.setPixmap(
                    pixmap
                )

        # =====================================================
        # Screenshot Gallery Preview
        # =====================================================

        if (
            hasattr(self, "gallery_preview")
            and self.gallery_preview is not None
        ):
            self.gallery_preview.setPixmap(
                pixmap.scaled(
                    self.gallery_preview.size(),
                    Qt.KeepAspectRatio,
                    Qt.SmoothTransformation,
                )
            )

        # =====================================================
        # Counter
        # =====================================================

        counter = (
            f"Screenshot {self.current_screenshot_index + 1} / {len(images)}"
        )

        if hasattr(self, "screenshot_counter_label"):
            self.screenshot_counter_label.setText(counter)

        if hasattr(self, "gallery_counter"):
            self.gallery_counter.setText(counter)

        # =====================================================
        # Navigation Buttons
        # =====================================================

        first = self.current_screenshot_index == 0
        last = self.current_screenshot_index == len(images) - 1

        if hasattr(self, "btn_prev_shot"):
            self.btn_prev_shot.setEnabled(not first)

        if hasattr(self, "btn_next_shot"):
            self.btn_next_shot.setEnabled(not last)

        if hasattr(self, "gallery_prev_btn"):
            self.gallery_prev_btn.setEnabled(not first)

        if hasattr(self, "gallery_next_btn"):
            self.gallery_next_btn.setEnabled(not last)

        # =====================================================
        # Refresh Thumbnail Gallery
        # =====================================================

        if hasattr(self, "_populate_screenshot_gallery"):
            try:
                self._populate_screenshot_gallery()
            except Exception as e:
                print("[Gallery]", e)

        QApplication.processEvents()

        print(
            f"[GUI] Showing screenshot "
            f"{self.current_screenshot_index + 1}/{len(images)} : "
            f"{images[self.current_screenshot_index]}"
        )

    def _load_screenshot_by_index(self, index):
        """
        Load one screenshot into the Live Browser View.

        The screenshot list is always rebuilt from the real
        screenshots directory so newly captured screenshots
        become available immediately.
        """

        images = self._get_screenshot_files()

        if not images:

            self.current_screenshot_index = -1

            if hasattr(
                self,
                "screenshot_counter_label",
            ):
                self.screenshot_counter_label.setText(
                    "No screenshots yet"
                )

            if hasattr(
                self,
                "gallery_counter",
            ):
                self.gallery_counter.setText(
                    "No screenshots"
                )

            if hasattr(
                self,
                "btn_prev_shot",
            ):
                self.btn_prev_shot.setEnabled(False)

            if hasattr(
                self,
                "btn_next_shot",
            ):
                self.btn_next_shot.setEnabled(False)

            return

        # ---------------------------------------------------------
        # Clamp index safely
        # ---------------------------------------------------------

        index = max(
            0,
            min(
                int(index),
                len(images) - 1,
            ),
        )

        self.current_screenshot_index = index

        image_path = images[index]

        print(
            "[GUI] Showing screenshot "
            f"{index + 1}/{len(images)}: "
            f"{os.path.basename(image_path)}",
            flush=True,
        )

        pixmap = QPixmap(image_path)

        if pixmap.isNull():

            print(
                f"[GUI] Failed to load screenshot: {image_path}",
                flush=True,
            )

            return

        # ---------------------------------------------------------
        # Live Browser View
        # ---------------------------------------------------------

        if (
            hasattr(
                self,
                "live_browser_label",
            )
            and self.live_browser_label is not None
        ):

            self.live_browser_label.setPixmap(
                pixmap.scaled(
                    self.live_browser_label.size(),
                    Qt.KeepAspectRatio,
                    Qt.SmoothTransformation,
                )
            )

        # ---------------------------------------------------------
        # Gallery Preview
        # ---------------------------------------------------------

        if (
            hasattr(
                self,
                "gallery_preview",
            )
            and self.gallery_preview is not None
        ):

            self.gallery_preview.setPixmap(
                pixmap.scaled(
                    self.gallery_preview.size(),
                    Qt.KeepAspectRatio,
                    Qt.SmoothTransformation,
                )
            )

        # ---------------------------------------------------------
        # Counter
        # ---------------------------------------------------------

        counter = (
            f"Screenshot "
            f"{index + 1} / {len(images)}"
        )

        if hasattr(
            self,
            "screenshot_counter_label",
        ):

            self.screenshot_counter_label.setText(
                counter
            )

        if hasattr(
            self,
            "gallery_counter",
        ):

            self.gallery_counter.setText(
                counter
            )

        # ---------------------------------------------------------
        # Navigation state
        # ---------------------------------------------------------

        first = index == 0
        last = index == len(images) - 1

        if hasattr(
            self,
            "btn_prev_shot",
        ):

            self.btn_prev_shot.setEnabled(
                not first
            )

        if hasattr(
            self,
            "btn_next_shot",
        ):

            self.btn_next_shot.setEnabled(
                not last
            )

        if hasattr(
            self,
            "gallery_prev_btn",
        ):

            self.gallery_prev_btn.setEnabled(
                not first
            )

        if hasattr(
            self,
            "gallery_next_btn",
        ):

            self.gallery_next_btn.setEnabled(
                not last
            )

        QApplication.processEvents()

    def _get_screenshot_files(self):
        """
        Return real screenshot files ordered chronologically.
        """

        if not os.path.isdir(SCREENSHOT_DIR):
            return []

        files = []

        for filename in os.listdir(SCREENSHOT_DIR):

            if not filename.lower().endswith(".png"):
                continue

            path = os.path.join(
                SCREENSHOT_DIR,
                filename,
            )

            if os.path.isfile(path):
                files.append(path)

        files.sort(
            key=lambda path: os.path.getmtime(path)
        )

        return files

    def _log(self, msg):
        self.console_emitter.text.emit(msg)

    def _page_target(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(20)

        title = QLabel("Target Scope Configuration")
        title.setStyleSheet(
            f"font-size: 20pt; font-weight: bold; color: {self.current_theme['accent']};"
        )
        layout.addWidget(title)

        # =========================
        # Target URL
        # =========================
        layout.addWidget(QLabel("Root Target URL"))

        self.target_inp = QLineEdit()
        self.target_inp.setPlaceholderText("https://example.com")
        layout.addWidget(self.target_inp)

        # =========================
        # 🔐 Authentication Settings (ADDED HERE)
        # =========================
        auth_box = QGroupBox("Authentication (Optional)")
        auth_layout = QVBoxLayout(auth_box)

        self.login_url_input = QLineEdit()
        self.login_url_input.setPlaceholderText("Login URL (optional)")

        self.login_user_input = QLineEdit()
        self.login_user_input.setPlaceholderText("Username")

        self.login_pass_input = QLineEdit()
        self.login_pass_input.setPlaceholderText("Password")
        self.login_pass_input.setEchoMode(QLineEdit.Password)

        auth_layout.addWidget(self.login_url_input)
        auth_layout.addWidget(self.login_user_input)
        auth_layout.addWidget(self.login_pass_input)

        layout.addWidget(auth_box)

        # =========================
        # Save Button
        # =========================
        btn = QPushButton("💾 Save Target")
        btn.clicked.connect(self._save_target)
        layout.addWidget(btn)

        layout.addStretch()
        return w

    def _page_settings(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(20)

        title = QLabel("Application Settings")
        title.setStyleSheet("font-size:22px; font-weight:bold;")
        layout.addWidget(title)

        # ---------- Appearance ----------
        appearance = QGroupBox("Appearance")
        a_layout = QFormLayout(appearance)

        # Font family
        self.font_family_cb = QComboBox()
        self.font_family_cb.addItems(
            ["Segoe UI", "Arial", "Consolas", "Times New Roman"]
        )
        self.font_family_cb.currentTextChanged.connect(
            self._apply_font_settings)

        # Font size
        self.font_size_cb = QComboBox()
        self.font_size_cb.addItems(["9", "10", "11", "12", "14", "16"])
        self.font_size_cb.setCurrentText("10")
        self.font_size_cb.currentTextChanged.connect(self._apply_font_settings)

        a_layout.addRow("Font Family:", self.font_family_cb)
        a_layout.addRow("Font Size:", self.font_size_cb)

        layout.addWidget(appearance)
        layout.addStretch()

    def _apply_font_settings(self):
        font = QFont(
            self.font_family_cb.currentText(), int(self.font_size_cb.currentText())
        )
        QApplication.instance().setFont(font)

    def _page_scan(self, key):
        """
        Unified Phase UI
        Phase-1: Crawl depth + live screenshots
        Phase-2: Validation console + heatmap
        Phase-3: Report generation + preview
        """

        # ================= ROOT =================
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)
        layout.setAlignment(Qt.AlignTop)

        # =========================================================
        # PAGE HEADER
        # =========================================================
        # Phase-1 and Phase-2 do NOT need a separate empty header
        # box. This saves vertical space for the scanner interface.
        #
        # Phase-3 and Full Auto Scan keep their descriptive header.
        # =========================================================
        
        info_map = {
            "phase3": (
                "Reporting Engine",
                "Risk scoring & report generation",
            ),
        
            "full": (
                "Full Automation",
                "Phase-1 → Phase-2 → Phase-3",
            ),
        }
        
        if key in info_map:
        
            title, desc = info_map[key]
        
            gb_head = QGroupBox(title)
        
            hl = QVBoxLayout(gb_head)
        
            lbl_desc = QLabel(desc)
        
            lbl_desc.setStyleSheet(
                f"color:{self.current_theme['text_dim']}; "
                f"font-size:11pt;"
            )
        
            hl.addWidget(
                lbl_desc
            )
        
            layout.addWidget(
                gb_head
            )
    
        # ================= EXECUTION CONTROL =================
        gb_ctrl = QGroupBox("Execution Control")
        cl = QHBoxLayout(gb_ctrl)

        btn = QPushButton("▶ Start Module")
        self.phase_buttons[key] = btn
        btn.setIcon(self.style().standardIcon(QStyle.SP_MediaPlay))
        btn.setMinimumHeight(40)

        if key == "phase1":
            btn.clicked.connect(lambda: self._start_scan(key))
            # gb_video = QGroupBox("Scan Video")
            # vl = QVBoxLayout(gb_video)
            # vl.addWidget(self.video_widget)
            # layout.addWidget(gb_video)

        elif key == "phase2":
            btn.clicked.connect(lambda: self._start_scan(key))
        elif key == "phase3":
            btn.clicked.connect(lambda: self._start_scan(key))

        self.phase_buttons[key] = btn
        cl.addWidget(btn)

        pause_btn = QPushButton("⏸ Pause")

        pause_btn.clicked.connect(
            self._toggle_pause_scan
        )
        
        # Store this button for THIS phase.
        self.pause_buttons[key] = pause_btn
        
        # Keep current active button reference too.
        if key == self.current_phase_key:
            self.pause_btn = pause_btn
        
        cl.addWidget(pause_btn)

        pbar = QProgressBar()
        pbar.setRange(0, 100)
        pbar.setValue(0)
        self.progress_bars[key] = pbar
        cl.addWidget(pbar)

        layout.addWidget(gb_ctrl)

        # ================= SPLIT VIEW =================
        split = QSplitter(Qt.Vertical)
        split.setHandleWidth(8)
        split.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        split.setChildrenCollapsible(False)

        # -------- LIVE CONSOLE (Only for Phase-1 and Phase-2) --------
        if key in ("phase1", "phase2"):
            gb_log = QGroupBox("Live Console")
            gb_log.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
            ll = QVBoxLayout(gb_log)

            log = QTextEdit()
            log.setReadOnly(True)
            log.setObjectName("LogConsole")
            log.setMinimumHeight(150)
            log.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

            self.log_widgets[key] = log
            ll.addWidget(log)

            split.addWidget(gb_log)

        if key == "phase1":

            # ================= CRAWL DEPTH =================
            depth_box = QGroupBox("Crawl Depth")
            depth_layout = QHBoxLayout(depth_box)

            self.depth_slider = QSlider(Qt.Horizontal)
            self.depth_slider.setRange(1, 5)
            self.depth_slider.setValue(2)
            self.depth_slider.setTickInterval(1)
            self.depth_slider.setTickPosition(QSlider.TicksBelow)

            depth_label = QLabel("Depth: 2")

            self.depth_slider.valueChanged.connect(
                lambda v: depth_label.setText(f"Depth: {v}")
            )

            depth_layout.addWidget(depth_label)
            depth_layout.addWidget(self.depth_slider)

            layout.addWidget(depth_box)

            # =========================================================
            # LIVE BROWSER VIEW
            # =========================================================

            gb_shot = QGroupBox("Live Browser View")

            gb_shot.setSizePolicy(
                QSizePolicy.Expanding,
                QSizePolicy.Expanding,
            )

            sl = QVBoxLayout(gb_shot)

            sl.setContentsMargins(
                12,
                12,
                12,
                12,
            )

            sl.setSpacing(8)

            # =========================================================
            # SCREENSHOT NAVIGATION
            # =========================================================

            nav_widget = QWidget()

            nav = QHBoxLayout(nav_widget)

            nav.setContentsMargins(
                0,
                0,
                0,
                0,
            )

            nav.setSpacing(10)

            # ---------------------------------------------------------
            # Previous
            # ---------------------------------------------------------

            self.btn_prev_shot = QPushButton(
                "◀ Previous"
            )

            self.btn_prev_shot.setMinimumSize(
                140,
                38,
            )

            self.btn_prev_shot.setToolTip(
                "Show the previous Phase-1 browser screenshot"
            )

            self.btn_prev_shot.setEnabled(False)

            self.btn_prev_shot.clicked.connect(
                self._prev_screenshot
            )

            nav.addWidget(
                self.btn_prev_shot
            )

            # ---------------------------------------------------------
            # Center counter
            # ---------------------------------------------------------

            nav.addStretch(1)

            self.screenshot_counter_label = QLabel(
                "Screenshot 0 / 0"
            )

            self.screenshot_counter_label.setAlignment(
                Qt.AlignCenter
            )

            self.screenshot_counter_label.setMinimumWidth(
                220
            )

            self.screenshot_counter_label.setStyleSheet("""
                QLabel {
                    color: #9ca3af;
                    font-size: 13px;
                    font-weight: bold;
                    padding: 5px;
                }
            """)

            nav.addWidget(
                self.screenshot_counter_label
            )

            nav.addStretch(1)

            # ---------------------------------------------------------
            # Next
            # ---------------------------------------------------------

            self.btn_next_shot = QPushButton(
                "Next ▶"
            )

            self.btn_next_shot.setMinimumSize(
                140,
                38,
            )

            self.btn_next_shot.setToolTip(
                "Show the next Phase-1 browser screenshot"
            )

            self.btn_next_shot.setEnabled(False)

            self.btn_next_shot.clicked.connect(
                self._next_screenshot
            )

            nav.addWidget(
                self.btn_next_shot
            )

            # Add navigation ONCE
            sl.addWidget(
                nav_widget,
                0
            )

            # =========================================================
            # SCREENSHOT DISPLAY
            # =========================================================

            self.live_browser_label = QLabel()

            self.live_browser_label.setAlignment(
                Qt.AlignCenter
            )

            self.live_browser_label.setSizePolicy(
                QSizePolicy.Expanding,
                QSizePolicy.Expanding
            )

            self.live_browser_label.setMinimumSize(
                900,
                420
            )

            self.live_browser_label.setScaledContents(
                False
            )

            self.live_browser_label.setText(
                "Waiting for screenshots..."
            )

            self.live_browser_label.setStyleSheet("""
                QLabel {
                    background-color: #000000;
                    color: #9ca3af;
                    border: 1px solid #26364d;
                    border-radius: 6px;
                }
            """)

            # Add screenshot display ONCE
            sl.addWidget(
                self.live_browser_label,
                1
            )

            # =========================================================
            # ADD LIVE BROWSER VIEW TO OUTER SPLITTER
            # =========================================================

            split.addWidget(
                gb_shot
            )

            split.setStretchFactor(
                0,
                1
            )

            split.setStretchFactor(
                1,
                3
            )

            # =========================================================
            # INITIAL SPLITTER SIZE
            # =========================================================

            QTimer.singleShot(
                100,
                lambda: split.setSizes(
                    [260, 850]
                )
            )

        # ================= PHASE-3 REPORT PREVIEW =================
        if key == "phase3":
            gb_rep = QGroupBox("Report Preview")
            rl = QVBoxLayout(gb_rep)

            self.report_status = QLabel("Waiting for Phase-3 execution…")
            self.report_status.setStyleSheet("color:#9ca3af;")
            rl.addWidget(self.report_status)

            from PySide6.QtWebEngineWidgets import QWebEngineView

            self.report_view = QWebEngineView()
            self.report_view.setMinimumHeight(300)
            rl.addWidget(self.report_view)

            layout.addWidget(gb_rep)

        print(split.count())
        # Add splitter after all widgets have been inserted
        layout.addWidget(split, 1)
        print("Splitter widgets =", split.count())
        return page

    # def _start_scan(self, phase: str):
    #     """
    #     Stable Single Scan Launcher
    #     ---------------------------
    #     ✔ Prevents double start
    #     ✔ Smooth progress reset
    #     ✔ No stuck old process
    #     ✔ Clean runner launch
    #     ✔ Safe GUI updates
    #     """

    #     # -------------------------------------------------
    #     # Prevent duplicate running scan
    #     # -------------------------------------------------
    #     if self.scan_process:
    #         try:
    #             if self.scan_process.state() == QProcess.Running:
    #                 QMessageBox.warning(
    #                     self,
    #                     "Scan Running",
    #                     "A scan is already running."
    #                 )
    #                 return

    #             self.scan_process.kill()
    #             self.scan_process.waitForFinished(1000)
    #             self.scan_process.deleteLater()

    #         except Exception:
    #             pass

    #         self.scan_process = None

    #     # -------------------------------------------------
    #     # Get Target
    #     # -------------------------------------------------
    #     target = self._get_saved_target()

    #     if not target:
    #         QMessageBox.warning(
    #             self,
    #             "Target Missing",
    #             "Save a target first."
    #         )
    #         return

    #     self.active_target_lbl.setText(
    #         f"Target: {target}"
    #     )

    #     self.lbl_urls.value_label.setText(
    #         target
    #     )

    #     # -------------------------------------------------
    #     # Resolve Runner
    #     # -------------------------------------------------
    #     runner = None
    #     args = []

    #     if phase == "phase1":

    #         import shutil

    #         shot_dir = os.path.join(
    #             PROJECT_ROOT,
    #             "screenshots"
    #         )

    #         if os.path.exists(shot_dir):
    #             shutil.rmtree(shot_dir)

    #         os.makedirs(
    #             shot_dir,
    #             exist_ok=True
    #         )

    #         runner = os.path.join(
    #             PROJECT_ROOT,
    #             "gui_runner.py"
    #         )

    #         args = [
    #             sys.executable,
    #             runner,
    #             "--target",
    #             target,
    #             "--depth",
    #             str(self.depth_slider.value())
    #         ]

    #     elif phase == "phase2":

    #         runner = os.path.join(
    #             PHASE2_DIR,
    #             "gui_runner.py"
    #         )

    #         args = [
    #             sys.executable,
    #             runner,
    #             "--target",
    #             target
    #         ]

    #     elif phase == "phase3":

    #         runner = os.path.join(
    #             PHASE3_DIR,
    #             "gui_runner.py"
    #         )

    #         args = [
    #             sys.executable,
    #             runner,
    #             "--target",
    #             target
    #         ]

    #     else:
    #         QMessageBox.warning(
    #             self,
    #             "Invalid Phase",
    #             f"Unknown phase: {phase}"
    #         )
    #         return

    #     # -------------------------------------------------
    #     # File Exists Check
    #     # -------------------------------------------------
    #     if not os.path.exists(runner):
    #         QMessageBox.warning(
    #             self,
    #             "Runner Missing",
    #             runner
    #         )
    #         return

    #     # -------------------------------------------------
    #     # GUI Reset
    #     # -------------------------------------------------
    #     self.active_phase = phase
    #     self.current_phase_key = phase

    #     self.phase_status_lbl.setText(
    #         f"● {phase.upper()} Running"
    #     )

    #     # Reset only active bar
    #     if phase in self.progress_bars:

    #         bar = self.progress_bars[phase]

    #         bar.blockSignals(True)
    #         bar.setValue(0)
    #         bar.setFormat("0%")
    #         bar.repaint()
    #         bar.blockSignals(False)

    #     # Clear log area
    #     if phase in self.log_widgets:
    #         try:
    #             self.log_widgets[phase].clear()
    #         except Exception:
    #             pass

    #     self._set_scan_controls_enabled(False)

    #     QApplication.processEvents()

    #     # -------------------------------------------------
    #     # Create Fresh Process
    #     # -------------------------------------------------
    #     self.scan_process = QProcess(self)

    #     self.scan_process.setProcessChannelMode(
    #         QProcess.MergedChannels
    #     )

    #     # Ready output
    #     self.scan_process.readyReadStandardOutput.connect(
    #         lambda: self._on_scan_output(phase)
    #     )

    #     # Finish event
    #     self.scan_process.finished.connect(
    #         self._on_process_finished
    #     )

    #     # Error event
    #     try:
    #         self.scan_process.errorOccurred.connect(
    #             lambda err: self.log(
    #                 f"Process Error: {err}",
    #                 "ERROR",
    #                 "GUI",
    #                 phase.upper()
    #             )
    #         )
    #     except Exception:
    #         pass

    #     # -------------------------------------------------
    #     # Log Start
    #     # -------------------------------------------------
    #     self.log(
    #         f"Starting {phase.upper()}",
    #         "INFO",
    #         "GUI",
    #         phase.upper()
    #     )

    #     # -------------------------------------------------
    #     # Start Process
    #     # -------------------------------------------------
    #     self.scan_process.start(
    #         args[0],
    #         args[1:]
    #     )

    #     started = self.scan_process.waitForStarted(
    #         3000
    #     )

    #     if not started:

    #         QMessageBox.warning(
    #             self,
    #             "Launch Failed",
    #             f"Could not start {phase}"
    #         )

    #         self._set_scan_controls_enabled(True)
    #         return

    #     # -------------------------------------------------
    #     # Screenshot Timer
    #     # -------------------------------------------------
    #     if phase == "phase1":
    #         try:
    #             self.screenshot_timer.stop()
    #             self.screenshot_timer.start(500)
    #         except Exception:
    #             pass

    #     QApplication.processEvents()

    def _page_phase1(self):
        return self._page_scan("phase1")

    def _page_phase2(self):
        return self._page_scan("phase2")

    def _page_phase3(self):
        return self._page_scan("phase3")
    
    def _page_email(self):
        """
        AVAF Pro Email Reporting.
    
        Only confirmed Phase-2 findings may be sent.
        """
    
        page = QWidget()
    
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(16)
    
        # =========================================================
        # TITLE
        # =========================================================
    
        title = QLabel(
            "📧 Security Report Email"
        )
    
        title.setStyleSheet(
            f"""
            font-size: 20pt;
            font-weight: bold;
            color: {self.current_theme['accent']};
            """
        )
    
        layout.addWidget(title)
    
        description = QLabel(
            "Send confirmed AVAF Pro findings to a security team "
            "or administrator using a professional assessment email."
        )
    
        description.setWordWrap(True)
    
        description.setStyleSheet(
            f"color: {self.current_theme['text_dim']};"
        )
    
        layout.addWidget(description)
    
        # =========================================================
        # REPORT STATUS
        # =========================================================
    
        status_box = QGroupBox(
            "Assessment Status"
        )
    
        status_layout = QFormLayout(
            status_box
        )
    
        self.email_target_label = QLabel(
            "Not available"
        )
    
        self.email_findings_label = QLabel(
            "0"
        )
    
        self.email_status_label = QLabel(
            "Phase-3 report not completed."
        )
    
        status_layout.addRow(
            "Target:",
            self.email_target_label,
        )
    
        status_layout.addRow(
            "Confirmed Findings:",
            self.email_findings_label,
        )
    
        status_layout.addRow(
            "Status:",
            self.email_status_label,
        )
    
        layout.addWidget(status_box)
    
        # =========================================================
        # RECIPIENTS
        # =========================================================
    
        recipient_box = QGroupBox(
            "Recipients"
        )
    
        recipient_layout = QVBoxLayout(
            recipient_box
        )
    
        recipient_hint = QLabel(
            "Enter one or more email addresses separated by commas."
        )
    
        recipient_hint.setStyleSheet(
            f"color: {self.current_theme['text_dim']};"
        )
    
        self.email_recipients = QLineEdit()
    
        self.email_recipients.setPlaceholderText(
            "security@company.com, administrator@company.com"
        )
    
        recipient_layout.addWidget(
            recipient_hint
        )
    
        recipient_layout.addWidget(
            self.email_recipients
        )
    
        layout.addWidget(
            recipient_box
        )
    
        # =========================================================
        # SUBJECT
        # =========================================================
    
        subject_box = QGroupBox(
            "Email"
        )
    
        subject_layout = QFormLayout(
            subject_box
        )
    
        self.email_subject = QLineEdit()
    
        self.email_subject.setPlaceholderText(
            "AVAF Pro Security Assessment Report"
        )
    
        self.email_message = QPlainTextEdit()
    
        self.email_message.setPlaceholderText(
            "Optional message to the security team..."
        )
    
        self.email_message.setMinimumHeight(
            110
        )
    
        subject_layout.addRow(
            "Subject:",
            self.email_subject,
        )
    
        subject_layout.addRow(
            "Message:",
            self.email_message,
        )
    
        layout.addWidget(
            subject_box
        )
    
        # =========================================================
        # SMTP CONFIGURATION
        # =========================================================
    
        smtp_box = QGroupBox(
            "SMTP Configuration"
        )
    
        smtp_layout = QFormLayout(
            smtp_box
        )
    
        self.email_smtp_host = QLineEdit()
    
        self.email_smtp_host.setPlaceholderText(
            "smtp.gmail.com"
        )
    
        self.email_smtp_port = QLineEdit(
            "587"
        )
    
        self.email_sender = QLineEdit()
    
        self.email_sender.setPlaceholderText(
            "scanner@company.com"
        )
    
        self.email_password = QLineEdit()
    
        self.email_password.setEchoMode(
            QLineEdit.Password
        )
    
        self.email_password.setPlaceholderText(
            "SMTP password / app password"
        )
    
        self.email_tls = QCheckBox(
            "Use TLS encryption"
        )
    
        self.email_tls.setChecked(
            True
        )
    
        smtp_layout.addRow(
            "SMTP Server:",
            self.email_smtp_host,
        )
    
        smtp_layout.addRow(
            "SMTP Port:",
            self.email_smtp_port,
        )
    
        smtp_layout.addRow(
            "Sender:",
            self.email_sender,
        )
    
        smtp_layout.addRow(
            "Password:",
            self.email_password,
        )
    
        smtp_layout.addRow(
            "",
            self.email_tls,
        )
    
        layout.addWidget(
            smtp_box
        )
    
        # =========================================================
        # ATTACHMENTS
        # =========================================================
    
        attachment_box = QGroupBox(
            "Report Attachments"
        )
    
        attachment_layout = QVBoxLayout(
            attachment_box
        )
    
        self.email_attach_html = QCheckBox(
            "Attach Phase-3 HTML report"
        )
    
        self.email_attach_html.setChecked(
            True
        )
    
        self.email_attach_txt = QCheckBox(
            "Attach Phase-3 TXT report"
        )
    
        self.email_attach_txt.setChecked(
            True
        )
    
        attachment_layout.addWidget(
            self.email_attach_html
        )
    
        attachment_layout.addWidget(
            self.email_attach_txt
        )
    
        layout.addWidget(
            attachment_box
        )
    
        # =========================================================
        # BUTTONS
        # =========================================================
    
        buttons = QHBoxLayout()
    
        self.email_test_btn = QPushButton(
            "🔌 Test SMTP"
        )
    
        self.email_test_btn.clicked.connect(
            self._test_email_smtp
        )
    
        self.email_send_btn = QPushButton(
            "📨 Send Security Report"
        )
    
        self.email_send_btn.clicked.connect(
            self._send_security_report
        )
    
        buttons.addWidget(
            self.email_test_btn
        )
    
        buttons.addStretch()
    
        buttons.addWidget(
            self.email_send_btn
        )
    
        layout.addLayout(
            buttons
        )
    
        layout.addStretch()
    
        self._refresh_email_page()
    
        return page

    def _page_full_scan(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(40, 40, 40, 40)
        l.setSpacing(20)

        title = QLabel("⚡ Full Auto Scan")
        title.setStyleSheet(
            f"font-size: 20pt; font-weight: bold; color: {self.current_theme['accent']};"
        )

        desc = QLabel(
            "Runs Phase 1 → Phase 2 → Phase 3 automatically in sequence.\n"
            "All controls are locked during execution."
        )
        desc.setStyleSheet(
            f"color: {self.current_theme['text_dim']};"
        )

        btn = QPushButton("▶ Start Full Auto Scan")
        btn.setMinimumHeight(45)
        btn.setIcon(
            self.style().standardIcon(
                QStyle.SP_MediaPlay
            )
        )
        btn.clicked.connect(self._start_full_auto)

        self.phase_buttons["full"] = btn

        pbar = QProgressBar()
        pbar.setValue(0)
        pbar.setFormat("0%")

        self.progress_bars["full"] = pbar

        l.addWidget(title)
        l.addWidget(desc)
        l.addSpacing(20)
        l.addWidget(btn)
        l.addWidget(pbar)
        l.addStretch()

        return w

    def _page_discovery(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        title = QLabel("Discovery Results (Phase 1)")
        title.setStyleSheet(
            f"font-size: 18pt; font-weight: bold; color: {self.current_theme['accent']};"
        )
        layout.addWidget(title)

        self.discovery_table = QTableWidget(0, 5)
        self.discovery_table.setHorizontalHeaderLabels(
            ["Parameter", "Location", "Method", "URL", "Phase"]
        )
        self.discovery_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
        )
        self.discovery_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.discovery_table.setSelectionBehavior(QAbstractItemView.SelectRows)

        layout.addWidget(self.discovery_table)

        return w

    def _sync_repeater_toolbar(self, index=None):
        """
        Synchronize the Repeater top controls with the currently
        selected Repeater tab.

        The request editor is the source of truth.

        Example request:

            GET /products?id=1 HTTP/1.1
            Host: example.com

        The toolbar will therefore show:

            Method -> GET
            URL    -> /products?id=1
        """

        # ---------------------------------------------------------
        # 1. Safety
        # ---------------------------------------------------------

        tabs = getattr(self, "repeater_tabs", None)

        if tabs is None:
            return

        tab = tabs.currentWidget()

        if tab is None:
            return

        method_cb = getattr(self, "repeater_method", None)
        url_edit = getattr(self, "repeater_url", None)

        if method_cb is None or url_edit is None:
            return

        # ---------------------------------------------------------
        # 2. Find request editor
        # ---------------------------------------------------------

        request_editor = None

        # Preferred object name
        request_editor = tab.findChild(
            QPlainTextEdit,
            "RepeaterRequest",
        )

        # QTextEdit compatibility
        if request_editor is None:
            request_editor = tab.findChild(
                QTextEdit,
                "RepeaterRequest",
            )

        # Existing older implementation used "Traffic"
        if request_editor is None:
            editors = tab.findChildren(QPlainTextEdit)

            if editors:
                request_editor = editors[0]

        if request_editor is None:
            editors = tab.findChildren(QTextEdit)

            if editors:
                request_editor = editors[0]

        if request_editor is None:
            return

        # ---------------------------------------------------------
        # 3. Read request
        # ---------------------------------------------------------

        try:
            request_text = request_editor.toPlainText().strip()
        except Exception:
            return

        if not request_text:
            return

        lines = request_text.splitlines()

        if not lines:
            return

        # ---------------------------------------------------------
        # 4. Parse HTTP request line
        # ---------------------------------------------------------

        request_line = lines[0].strip()

        parts = request_line.split()

        if len(parts) < 2:
            return

        method = parts[0].upper()
        target = parts[1]

        # ---------------------------------------------------------
        # 5. Synchronize method
        # ---------------------------------------------------------

        method_index = method_cb.findText(
            method,
            Qt.MatchFixedString,
        )

        if method_index >= 0:

            old_block = method_cb.blockSignals(True)

            try:
                method_cb.setCurrentIndex(
                    method_index
                )
            finally:
                method_cb.blockSignals(old_block)

        # ---------------------------------------------------------
        # 6. Synchronize URL
        # ---------------------------------------------------------

        # Absolute URL
        if target.startswith("http://") or target.startswith("https://"):

            url = target

        else:

            # Try to obtain Host header
            host = ""

            for line in lines[1:]:

                if ":" not in line:
                    continue

                name, value = line.split(
                    ":",
                    1,
                )

                if name.strip().lower() == "host":

                    host = value.strip()
                    break

            if host:

                # Determine scheme from current URL if possible
                current_url = url_edit.text().strip()

                if current_url.startswith("https://"):
                    scheme = "https"
                else:
                    scheme = "http"

                url = f"{scheme}://{host}{target}"

            else:

                url = target

        # ---------------------------------------------------------
        # 7. Update URL control
        # ---------------------------------------------------------

        old_block = url_edit.blockSignals(True)

        try:
            url_edit.setText(url)
        finally:
            url_edit.blockSignals(old_block)

        # ---------------------------------------------------------
        # 8. Diagnostic
        # ---------------------------------------------------------

        print(
            "[GUI][REPEATER] Toolbar synced:",
            method,
            url,
            flush=True,
        )

    def _page_repeater(self):
        """
        AVAF Pro HTTP Repeater.

        The request editor is editable.
        Send performs a REAL HTTP request.
        The response is displayed in the same repeater tab.
        """

        w = QWidget()

        layout = QVBoxLayout(w)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        # =========================================================
        # PAYLOAD HELPERS
        # =========================================================

        payload_bar = QHBoxLayout()

        btn_sqli = QPushButton("💉 SQLi")
        btn_xss = QPushButton("🔥 XSS")

        btn_sqli.clicked.connect(
            lambda: self._inject_payload("sqli")
        )

        btn_xss.clicked.connect(
            lambda: self._inject_payload("xss")
        )

        payload_bar.addWidget(btn_sqli)
        payload_bar.addWidget(btn_xss)
        payload_bar.addStretch()

        layout.addLayout(payload_bar)

        # =========================================================
        # REQUEST CONTROL BAR
        # =========================================================

        top = QHBoxLayout()
        top.setSpacing(8)

        self.repeater_method = QComboBox()

        self.repeater_method.addItems(
            [
                "GET",
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
                "HEAD",
                "OPTIONS",
            ]
        )

        self.repeater_url = QLineEdit()

        self.repeater_url.setPlaceholderText(
            "https://target/path"
        )

        self.repeater_target_cb = QComboBox()

        self.repeater_target_cb.setPlaceholderText(
            "Load from findings…"
        )

        self.repeater_target_cb.currentIndexChanged.connect(
            self._load_repeater_target
        )

        new_btn = QPushButton("＋ New")

        new_btn.clicked.connect(
            self._new_repeater_tab
        )

        send_btn = QPushButton("▶ Send")

        send_btn.setIcon(
            self.style().standardIcon(
                QStyle.SP_ArrowRight
            )
        )

        send_btn.clicked.connect(
            self._send_repeater_request
        )

        resend_btn = QPushButton("🔁 Resend")

        resend_btn.clicked.connect(
            self._resend_current_tab
        )

        top.addWidget(
            self.repeater_method,
            1
        )

        top.addWidget(
            self.repeater_url,
            4
        )

        top.addWidget(
            self.repeater_target_cb,
            3
        )

        top.addWidget(
            new_btn,
            1
        )

        top.addWidget(
            resend_btn,
            1
        )

        top.addWidget(
            send_btn,
            1
        )

        layout.addLayout(top)

        # =========================================================
        # REPEATER TABS
        # =========================================================

        self.repeater_tabs = QTabWidget()

        self.repeater_tabs.setTabsClosable(True)

        self.repeater_tabs.tabCloseRequested.connect(
            self._close_repeater_tab
        )

        self.repeater_tabs.currentChanged.connect(
            self._sync_repeater_toolbar
        )

        layout.addWidget(
            self.repeater_tabs,
            1
        )

        # =========================================================
        # FIRST TAB
        # =========================================================

        self._new_repeater_tab()

        return w

    def _new_repeater_tab(self):
        """
        Create a new independent Repeater tab.

        Each tab owns:
            - its request editor
            - its response editor

        The toolbar is synchronized with the active tab.
        """

        if not hasattr(self, "repeater_tabs"):
            return

        tab = QWidget()
        tab_layout = QHBoxLayout(tab)
        tab_layout.setContentsMargins(8, 8, 8, 8)
        tab_layout.setSpacing(10)

        # =========================================================
        # REQUEST
        # =========================================================

        request_box = QGroupBox("Request")
        request_layout = QVBoxLayout(request_box)

        request_editor = QPlainTextEdit()
        request_editor.setObjectName("RepeaterRequest")
        request_editor.setReadOnly(False)
        request_editor.setPlaceholderText(
            "GET /path HTTP/1.1\n"
            "Host: example.com\n"
            "\n"
            "Edit the request and press Send."
        )

        request_editor.setPlainText(
            "GET / HTTP/1.1\n"
            "Host: example.com\n"
            "User-Agent: AVAF-Repeater\n"
            "Accept: */*\n"
            "\n"
        )

        request_layout.addWidget(request_editor)

        # =========================================================
        # RESPONSE
        # =========================================================

        response_box = QGroupBox("Response")
        response_layout = QVBoxLayout(response_box)

        response_editor = QPlainTextEdit()
        response_editor.setObjectName("RepeaterResponse")
        response_editor.setReadOnly(True)
        response_editor.setPlaceholderText(
            "HTTP response will appear here..."
        )

        response_layout.addWidget(response_editor)

        # =========================================================
        # TAB LAYOUT
        # =========================================================

        tab_layout.addWidget(
            request_box,
            1
        )

        tab_layout.addWidget(
            response_box,
            1
        )

        # =========================================================
        # ADD TAB
        # =========================================================

        tab_number = self.repeater_tabs.count() + 1

        index = self.repeater_tabs.addTab(
            tab,
            f"Repeater #{tab_number}"
        )

        self.repeater_tabs.setCurrentIndex(index)

        # =========================================================
        # REQUEST EDIT -> TOOLBAR SYNC
        # =========================================================

        request_editor.textChanged.connect(
            self._sync_repeater_toolbar
        )

        # =========================================================
        # INITIAL TOOLBAR SYNC
        # =========================================================

        self._sync_repeater_toolbar(index)

        self.statusBar().showMessage(
            f"Repeater #{tab_number} created."
        )

    def _close_repeater_tab(self, index):
        if self.repeater_tabs.count() <= 1:
            self.statusBar().showMessage
            (
                "At least one Repeater tab must remain."
            )
            return

        self.repeater_tabs.removeTab(
            index
        )

    def _repeater_tab_changed(self, index):
        if index < 0:
            return

        request_editor, _ = (
            self._get_repeater_editors()
        )

        if request_editor is None:
            return

        # Keep URL/method controls synchronized
        lines = request_editor.toPlainText().splitlines()

        if not lines:
            return

        first = lines[0].split()

        if len(first) >= 2:
            method = first[0].upper()
            path = first[1]

            if method in [
                "GET",
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
                "HEAD",
                "OPTIONS",
            ]:
                self.repeater_method.setCurrentText(
                    method
                )

            host = ""

            for line in lines[1:]:
                if line.lower().startswith("host:"):
                    host = line.split(
                        ":",
                        1
                    )[1].strip()
                    break

            if host:
                scheme = "https"

                current_url = (
                    self.repeater_url.text()
                )

                if current_url.startswith(
                    "http://"
                ):
                    scheme = "http"

                self.repeater_url.setText(
                    f"{scheme}://{host}{path}"
                )

    def _get_repeater_editors(self):
        tab = self.repeater_tabs.currentWidget()

        if tab is None:
            return None, None

        request_editor = tab.findChild(
            QPlainTextEdit,
            "RepeaterRequest"
        )

        response_editor = tab.findChild(
            QPlainTextEdit,
            "RepeaterResponse"
        )

        return request_editor, response_editor

    def _clear_repeater_response(self):
        _, response_editor = (
            self._get_repeater_editors()
        )

        if response_editor is not None:
            response_editor.clear()

            self.statusBar().showMessage(
            "Repeater response cleared."
        )

    def _resend_current_tab(self):
        """
        Resend the request currently present in the active
        Repeater tab.
        """

        request_editor, _ = self._get_repeater_editors()

        if request_editor is None:
            QMessageBox.warning(
                self,
                "Repeater",
                "No active Repeater request."
            )
            return

        if not request_editor.toPlainText().strip():
            QMessageBox.warning(
                self,
                "Repeater",
                "Request is empty."
            )
            return

        self._send_repeater_request()

    def _page_issues(self):
        w = QWidget()
        l = QVBoxLayout(w)

        l.setContentsMargins(8, 8, 8, 8)
        l.setSpacing(8)

        # =========================================================
        # SEVERITY FILTER
        # =========================================================

        filter_bar = QHBoxLayout()

        filter_bar.addWidget(QLabel("Filter Severity:"))

        self.severity_filter = QComboBox()
        self.severity_filter.addItems(
            ["All", "High", "Medium", "Low"]
        )

        self.severity_filter.currentIndexChanged.connect(
            self._apply_severity_filter
        )

        filter_bar.addWidget(self.severity_filter)
        filter_bar.addStretch()

        l.addLayout(filter_bar)

        # =========================================================
        # FINDINGS TABLE
        # =========================================================

        self.table = QTableWidget(0, 6)

        self.table.setHorizontalHeaderLabels(
            [
                "ID",
                "Type",
                "Severity",
                "CVSS",
                "Confidence",
                "URL",
            ]
        )

        # ---------------------------------------------------------
        # IMPORTANT:
        # Keep the findings area large enough for ~5 rows.
        # More findings automatically scroll vertically.
        # ---------------------------------------------------------

        self.table.setMinimumHeight(250)
        self.table.setMaximumHeight(310)

        self.table.setVerticalScrollBarPolicy(
            Qt.ScrollBarAsNeeded
        )

        self.table.setHorizontalScrollBarPolicy(
            Qt.ScrollBarAsNeeded
        )

        self.table.setSizePolicy(
            QSizePolicy.Expanding,
            QSizePolicy.Fixed
        )

        # ---------------------------------------------------------
        # Row sizing
        # ---------------------------------------------------------

        self.table.verticalHeader().setDefaultSectionSize(34)
        self.table.verticalHeader().setMinimumSectionSize(30)

        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
        )

        # ---------------------------------------------------------
        # Selection
        # ---------------------------------------------------------

        self.table.setSelectionBehavior(
            QAbstractItemView.SelectRows
        )

        self.table.setSelectionMode(
            QAbstractItemView.SingleSelection
        )

        self.table.setEditTriggers(
            QAbstractItemView.NoEditTriggers
        )

        # ---------------------------------------------------------
        # Finding interaction
        # ---------------------------------------------------------

        self.table.cellClicked.connect(
            self._on_finding_clicked
        )

        self.table.cellDoubleClicked.connect(
            self._on_finding_clicked
        )

        l.addWidget(self.table)

        # =========================================================
        # REQUEST / RESPONSE SEARCH
        # =========================================================

        search_bar = QHBoxLayout()

        self.rr_search_input = QLineEdit()

        self.rr_search_input.setPlaceholderText(
            "Search in request / response..."
        )

        self.rr_search_input.returnPressed.connect(
            self._search_req_res
        )

        search_btn = QPushButton("Search")

        search_btn.clicked.connect(
            self._search_req_res
        )

        search_bar.addWidget(
            self.rr_search_input,
            1
        )

        search_bar.addWidget(
            search_btn
        )

        l.addLayout(search_bar)

        # =========================================================
        # EXPORT SELECTED
        # =========================================================

        export_btn = QPushButton(
            "📄 Export Selected to PDF"
        )

        export_btn.clicked.connect(
            self._export_selected_vuln_pdf
        )

        l.addWidget(export_btn)

        # =========================================================
        # EXPORT FULL REPORT
        # =========================================================

        export_all_btn = QPushButton(
            "📄 Export FULL Scan Report (PDF)"
        )

        export_all_btn.clicked.connect(
            self._export_full_report_pdf
        )

        l.addWidget(export_all_btn)

        # =========================================================
        # SEND TO REPEATER
        # =========================================================

        send_repeater_btn = QPushButton(
            "🚀 Send Selected to Repeater"
        )

        send_repeater_btn.clicked.connect(
            self._send_selected_to_repeater
        )

        l.addWidget(send_repeater_btn)

        # =========================================================
        # FINDING DETAILS
        # =========================================================

        self.detail_panel = QTextEdit()

        self.detail_panel.setReadOnly(True)

        self.detail_panel.setMinimumHeight(150)

        self.detail_panel.setPlaceholderText(
            "Click a finding to view full details..."
        )

        self.detail_panel.setSizePolicy(
            QSizePolicy.Expanding,
            QSizePolicy.Expanding
        )

        l.addWidget(self.detail_panel, 1)

        # =========================================================
        # REQUEST / RESPONSE HISTORY
        # =========================================================

        self.req_res_view = QTextEdit()

        self.req_res_view.setReadOnly(True)

        self.req_res_view.setMinimumHeight(150)

        self.req_res_view.setPlaceholderText(
            "Request / Response history for selected finding..."
        )

        self.req_res_view.setSizePolicy(
            QSizePolicy.Expanding,
            QSizePolicy.Expanding
        )

        l.addWidget(self.req_res_view, 1)

        return w

    def _on_finding_double_clicked(self, row, column):
        """
        Double-click on a finding
        Currently mirrors single-click behavior
        """
        self._on_finding_clicked(row, column)

    def run_async_task(self, coro):
        def runner():
            asyncio.run(coro)
        Thread(target=runner).start()

    # --- RESTORED LOGIC ---
    def _page_analytics(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(30, 30, 30, 30)
        gb = QGroupBox("Trend Analysis")
        gl = QVBoxLayout(gb)
        self.fig_ana = Figure(
            figsize=(8, 4), facecolor=self.current_theme["panel_bg"])
        self.cv_ana = FigureCanvas(self.fig_ana)
        gl.addWidget(self.cv_ana)
        l.addWidget(gb)
        return w

    def _page_heatmap(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(30, 30, 30, 30)

        gb = QGroupBox("Risk Heatmap")
        gl = QVBoxLayout(gb)

        # Use the same heatmap widget that load_data()
        # and _update_charts() already feed.
        self.animated_heatmap = AnimatedHeatmap()

        gl.addWidget(self.animated_heatmap)

        l.addWidget(gb)

        return w

    def _page_cvss(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(40, 40, 40, 40)
        gb = QGroupBox("CVSS v3.1 Calculator")
        gl = QGridLayout(gb)
        metrics = [
            "Attack Vector",
            "Complexity",
            "Privileges",
            "User Interaction",
            "Confidentiality",
            "Integrity",
            "Availability",
        ]
        self.cvss_cbs = {}
        for i, m in enumerate(metrics):
            gl.addWidget(QLabel(f"{m}:"), i, 0)
            cb = QComboBox()
            cb.addItems(["Low/None", "Medium", "High"])
            cb.currentIndexChanged.connect(self._calc_cvss)
            gl.addWidget(cb, i, 1)
            self.cvss_cbs[m] = cb
        self.cvss_res = QLabel("Score: 0.0")
        self.cvss_res.setStyleSheet(
            f"font-size: 24pt; font-weight: bold; color: {self.current_theme['success']};"
        )
        gl.addWidget(self.cvss_res, len(metrics), 0, 1, 2, Qt.AlignCenter)
        l.addWidget(gb)
        l.addStretch()
        # 🔒 Disable CVSS until a finding is selected
        for cb in self.cvss_cbs.values():
            cb.setEnabled(False)
        return w

    def _page_mitre(self):
        # ---------------- Root Widget ----------------
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(30, 30, 30, 30)
        l.setSpacing(12)

        # ---------------- Group Box ----------------
        gb = QGroupBox("MITRE ATT&CK Mapping")
        gl = QVBoxLayout(gb)

        # ---------------- MITRE Table ----------------
        self.mitre_table = QTableWidget(0, 3)
        self.mitre_table.setHorizontalHeaderLabels(
            ["Tactic", "Technique ID", "Technique Name"]
        )
        self.mitre_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.mitre_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.mitre_table.setSelectionBehavior(QAbstractItemView.SelectRows)

        gl.addWidget(self.mitre_table)
        l.addWidget(gb)

        return w

    def _update_mitre_view(self):
        """
        Populate the MITRE ATT&CK table from self.vuln_data.

        The method accepts both:
            1. Canonical internal vulnerability IDs
               e.g. RCE_COMMAND_INJECTION
            2. Human-readable vulnerability names
               e.g. Command Injection

        MITRE metadata is normalized back into the finding so that
        other GUI components can use the same canonical structure.
        """

        # =========================================================
        # 1. SAFETY
        # =========================================================

        table = getattr(
            self,
            "mitre_table",
            None,
        )

        if table is None:
            print(
                "[GUI][MITRE] mitre_table not available",
                flush=True,
            )
            return

        # =========================================================
        # 2. CLEAR OLD ROWS
        # =========================================================

        table.setRowCount(0)

        # =========================================================
        # 3. READ FINDINGS
        # =========================================================

        findings = getattr(
            self,
            "vuln_data",
            [],
        )

        if not isinstance(
            findings,
            list,
        ):
            findings = []

        # =========================================================
        # 4. HUMAN-READABLE TYPE -> INTERNAL MITRE KEY
        # =========================================================

        type_aliases = {
            # SQL Injection
            "sql injection": "SQLI_ERROR",
            "sqli": "SQLI_ERROR",
            "sql": "SQLI_ERROR",
            "sql injection (confirmed)": "SQLI_ERROR",

            # XSS
            "xss": "XSS_REFLECTED",
            "reflected xss": "XSS_REFLECTED",
            "reflected xss (confirmed)": "XSS_REFLECTED",

            # DOM XSS
            "dom xss": "DOM_XSS",

            # LFI
            "lfi": "LFI_TRAVERSAL",
            "local file inclusion": "LFI_TRAVERSAL",
            "path traversal": "LFI_TRAVERSAL",

            # Command Injection / RCE
            "command injection": "RCE_COMMAND_INJECTION",
            "command injection (confirmed)": "RCE_COMMAND_INJECTION",
            "rce": "RCE_COMMAND_INJECTION",
            "remote code execution": "RCE_COMMAND_INJECTION",

            # Workflow
            "workflow state bypass": "WORKFLOW_STATE_BYPASS",

            # Authorization
            "authorization bypass": "AUTHZ_ADMIN_ACCESS",
            "admin access": "AUTHZ_ADMIN_ACCESS",
            "privilege escalation": "AUTHZ_ADMIN_ACCESS",
        }

        # =========================================================
        # 5. PROCESS EACH FINDING
        # =========================================================

        loaded = 0

        for vuln in findings:

            if not isinstance(
                vuln,
                dict,
            ):
                continue

            # -----------------------------------------------------
            # Existing MITRE metadata
            # -----------------------------------------------------

            mitre = vuln.get(
                "mitre",
                {},
            )

            if not isinstance(
                mitre,
                dict,
            ):
                mitre = {}

            tactic = str(
                mitre.get(
                    "tactic",
                    "",
                )
                or mitre.get(
                    "Tactic",
                    "",
                )
                or ""
            ).strip()

            technique_id = str(
                mitre.get(
                    "technique_id",
                    "",
                )
                or mitre.get(
                    "TID",
                    "",
                )
                or ""
            ).strip()

            technique_name = str(
                mitre.get(
                    "technique",
                    "",
                )
                or mitre.get(
                    "Technique",
                    "",
                )
                or ""
            ).strip()

            # -----------------------------------------------------
            # Determine vulnerability type
            # -----------------------------------------------------

            vuln_type = str(
                vuln.get(
                    "type",
                    "",
                )
                or ""
            ).strip()

            normalized_type = vuln_type.lower().strip()

            # -----------------------------------------------------
            # Resolve internal MITRE key
            # -----------------------------------------------------

            mitre_key = type_aliases.get(
                normalized_type
            )

            # If it is already a canonical MITRE_MAP key,
            # use it directly.
            if not mitre_key:
                if vuln_type in MITRE_MAP:
                    mitre_key = vuln_type

            # Also support uppercase/internal values
            # with harmless normalization.
            if not mitre_key:

                upper_type = (
                    vuln_type
                    .upper()
                    .strip()
                    .replace(" ", "_")
                    .replace("-", "_")
                )

                if upper_type in MITRE_MAP:
                    mitre_key = upper_type

            # -----------------------------------------------------
            # Derive MITRE mapping when metadata is missing
            # -----------------------------------------------------

            if not (
                tactic
                and technique_id
                and technique_name
            ):

                mapping = None

                if mitre_key:
                    mapping = MITRE_MAP.get(
                        mitre_key
                    )

                if not isinstance(
                    mapping,
                    dict,
                ):
                    mapping = MITRE_MAP.get(
                        "Generic",
                        {},
                    )

                tactic = str(
                    mapping.get(
                        "Tactic",
                        "Unknown",
                    )
                    or "Unknown"
                ).strip()

                technique_id = str(
                    mapping.get(
                        "TID",
                        "T0000",
                    )
                    or "T0000"
                ).strip()

                technique_name = str(
                    mapping.get(
                        "Technique",
                        "Unknown",
                    )
                    or "Unknown"
                ).strip()

            # -----------------------------------------------------
            # Final safety fallback
            # -----------------------------------------------------

            tactic = tactic or "Unknown"
            technique_id = technique_id or "T0000"
            technique_name = technique_name or "Unknown"

            # =====================================================
            # 6. WRITE NORMALIZED MITRE DATA BACK TO FINDING
            # =====================================================

            vuln["mitre"] = {
                "tactic": tactic,
                "technique_id": technique_id,
                "technique": technique_name,
            }

            # Keep the internal key available for other GUI logic.
            if mitre_key:
                vuln["mitre_key"] = mitre_key

            # =====================================================
            # 7. INSERT TABLE ROW
            # =====================================================

            row = table.rowCount()

            table.insertRow(
                row
            )

            values = (
                tactic,
                technique_id,
                technique_name,
            )

            for column, value in enumerate(
                values
            ):

                item = QTableWidgetItem(
                    str(value)
                )

                item.setFlags(
                    item.flags()
                    & ~Qt.ItemIsEditable
                )

                table.setItem(
                    row,
                    column,
                    item
                )

            loaded += 1

        # =========================================================
        # 8. SELECT CURRENT FINDING
        # =========================================================

        current_index = getattr(
            self,
            "current_vuln_index",
            None,
        )

        if (
            current_index is not None
            and 0 <= current_index < table.rowCount()
        ):

            table.selectRow(
                current_index
            )

        # =========================================================
        # 9. RESIZE
        # =========================================================

        try:

            table.resizeRowsToContents()

        except Exception:
            pass

        # =========================================================
        # 10. DIAGNOSTIC
        # =========================================================

        print(
            "[GUI][MITRE] Rows loaded:",
            loaded,
            flush=True,
        )

        print(
            "[GUI][MITRE] Current findings:",
            len(findings),
            flush=True,
        )

    def _page_history(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(30, 30, 30, 30)

        title = QLabel("Execution History")
        title.setStyleSheet(
            f"font-size: 20pt; font-weight: bold; color: {self.current_theme['accent']};"
        )
        layout.addWidget(title)

        self.history_table = QTableWidget(0, 4)
        self.history_table.setHorizontalHeaderLabels(
            ["Time", "Phase", "Target", "Status"]
        )
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.history_table.setEditTriggers(QAbstractItemView.NoEditTriggers)

        layout.addWidget(self.history_table)
        return w

    def _page_logs(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(15)

        title = QLabel("System Logs")
        title.setStyleSheet(
            f"font-size: 20pt; font-weight: bold; color: {self.current_theme['accent']};"
        )
        layout.addWidget(title)

        desc = QLabel("Unified runtime logs (stable view)")
        desc.setStyleSheet(f"color: {self.current_theme['text_dim']};")
        layout.addWidget(desc)

        # 🔒 CREATE A DEDICATED LOG WIDGET
        self.logs_page_console = QTextEdit()
        self.logs_page_console.setReadOnly(True)
        self.logs_page_console.setObjectName("LogConsole")
        self.logs_page_console.setPlaceholderText(
            "System logs will appear here...")

        layout.addWidget(self.logs_page_console, 1)

        return w

    def _page_screenshots(self):

        w = QWidget()

        layout = QVBoxLayout(w)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(15)

        # ===================================================
        # TITLE
        # ===================================================
        title = QLabel("📸 Captured Screenshots")
        title.setStyleSheet(
            f"font-size:20pt; font-weight:bold; color:{self.current_theme['accent']};"
        )
        layout.addWidget(title)

        # ===================================================
        # LARGE PREVIEW
        # ===================================================
        self.gallery_preview = QLabel()

        self.gallery_preview.setMinimumHeight(450)
        self.gallery_preview.setAlignment(Qt.AlignCenter)

        self.gallery_preview.setStyleSheet("""
            border:1px solid #2f3d55;
            background:#0f172a;
            border-radius:8px;
        """)

        layout.addWidget(self.gallery_preview)

        # ===================================================
        # NAVIGATION
        # ===================================================
        nav = QHBoxLayout()

        self.gallery_prev_btn = QPushButton("◀ Previous")
        self.gallery_next_btn = QPushButton("Next ▶")

        self.gallery_prev_btn.clicked.connect(self._prev_screenshot)
        self.gallery_next_btn.clicked.connect(self._next_screenshot)

        self.gallery_counter = QLabel("0 / 0")
        self.gallery_counter.setAlignment(Qt.AlignCenter)
        self.gallery_counter.setStyleSheet("""
        color:#9ca3af;
        font-size:12px;
        font-weight:bold;
        """)

        nav.addWidget(self.gallery_prev_btn)
        nav.addStretch()
        nav.addWidget(self.gallery_counter)
        nav.addStretch()
        nav.addWidget(self.gallery_next_btn)

        # ===================================================
        # THUMBNAIL GALLERY
        # ===================================================
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)

        container = QWidget()

        self.screenshots_layout = QGridLayout(container)
        self.screenshots_layout.setSpacing(15)

        scroll.setWidget(container)

        layout.addWidget(scroll)

        # ===================================================
        # LOAD EXISTING SCREENSHOTS
        # ===================================================
        QTimer.singleShot(500, self._populate_screenshot_gallery)
        QTimer.singleShot(100, self._update_screenshot)

        return w

    def _page_siem(self):
        w = QWidget()
        layout = QVBoxLayout(w)

        title = QLabel("📡 Live Security Events (SIEM View)")
        layout.addWidget(title)

        # 🔽 FILTER BAR
        filter_bar = QHBoxLayout()

        filter_bar.addWidget(QLabel("Level:"))

        self.siem_level_filter = QComboBox()
        self.siem_level_filter.addItems(
            ["ALL", "INFO", "WARN", "ERROR", "SUCCESS"])
        self.siem_level_filter.currentTextChanged.connect(
            self._apply_siem_filter)

        filter_bar.addWidget(self.siem_level_filter)
        filter_bar.addStretch()

        layout.addLayout(filter_bar)

        # 🔽 SIEM TABLE
        self.siem_table = QTableWidget(0, 6)
        self.siem_table.setHorizontalHeaderLabels(
            ["Time", "Source", "Event Type", "Level", "Message"]
        )
        self.siem_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.siem_table.setEditTriggers(QAbstractItemView.NoEditTriggers)

        layout.addWidget(self.siem_table)

        return w

    # ---------------------------------------------------------
    # 4. LOGIC
    # ---------------------------------------------------------
    def _apply_siem_filter(self):
        if not hasattr(self, "siem_table"):
            return

        level = self.siem_level_filter.currentText()

        for row in range(self.siem_table.rowCount()):
            level_item = self.siem_table.item(row, 3)

            if not level_item:
                continue

            show = (level == "ALL") or (level_item.text() == level)
            self.siem_table.setRowHidden(row, not show)

    def _set_log_filter(self, level):
        self.log_filter_level = level
        self.logs_page_console.clear()

        for entry in getattr(self, "log_entries", []):
            if level != "ALL" and entry["level"] != level:
                continue
            self.log(
                entry["message"], entry["level"], entry["source"], entry["event_type"]
            )

    def _toggle_log_scroll(self):
        self.log_autoscroll = not getattr(self, "log_autoscroll", True)

        if self.log_autoscroll:
            self.autoscroll_btn.setText("⏸ Pause Scroll")
        else:
            self.autoscroll_btn.setText("▶ Resume Scroll")

    def _export_logs(self):
        fn, _ = QFileDialog.getSaveFileName(
            self, "Export Logs", "avaf_logs.txt", "Text Files (*.txt)"
        )
        if not fn:
            return

        with open(fn, "w", encoding="utf-8") as f:
            for e in getattr(self, "log_entries", []):
                f.write(f"[{e['time']}] [{e['level']}] {e['message']}\n")

        QMessageBox.information(self, "Exported", "Logs exported successfully")

    def _save_logs_to_file(self):
        log_dir = os.path.join(PROJECT_ROOT, "logs")
        os.makedirs(log_dir, exist_ok=True)

        path = os.path.join(
            log_dir, f"session_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )

        with open(path, "w", encoding="utf-8") as f:
            for e in self.log_entries:
                f.write(f"[{e['time']}] [{e['level']}] {e['message']}\n")

        return path

    def log(self, message, level="INFO", source="GUI", event_type="SYSTEM"):
        """
        Central SIEM-style logging function (MITRE + Risk Scoring)
        """

        timestamp = datetime.datetime.now().strftime("%H:%M:%S")

        level = level.upper()
        source = source.upper()
        event_type = event_type.upper()

        # ================= DETERMINE MITRE TACTIC =================
        tactic = MITRE_MAP.get(event_type.title(), MITRE_MAP["Generic"]).get(
            "Tactic", "Unknown"
        )

        # ================= RISK SCORING =================
        risk_weight = MITRE_RISK_WEIGHT.get(tactic, 1)

        severity_weight = {
            "INFO": 1,
            "SUCCESS": 1,
            "WARN": 3,
            "ERROR": 5,
        }.get(level, 1)

        risk_score = risk_weight * severity_weight

        # ================= BUILD ENTRY =================
        entry = {
            "time": timestamp,
            "level": level,
            "source": source,
            "event_type": event_type,
            "message": message,
            "tactic": tactic,
            "risk": risk_score,
        }

        # ================= STORE ENTRY =================
        self.log_entries.append(entry)

        # ================= ALERT COUNTERS =================
        if level in ("ERROR", "WARN"):
            self.siem_alert_count += 1
            self.statusBar().showMessage(
            f"⚠️ SIEM Alerts: {self.siem_alert_count}")

        # ================= FILTER =================
        if self.log_filter_level != "ALL" and level != self.log_filter_level:
            return

        # ================= LOG TEXT =================
        text = (
            f"[{timestamp}] "
            f"[{source}] "
            f"[{event_type}] "
            f"[{level}] "
            f"[RISK:{risk_score}] "
            f"{message}"
        )

        colors = {
            "INFO": "#60a5fa",
            "WARN": "#facc15",
            "ERROR": "#ef4444",
            "SUCCESS": "#22c55e",
        }

        color = colors.get(level, "#e5e7eb")

        # ================= LOGS PAGE =================
        if hasattr(self, "logs_page_console"):
            cursor = self.logs_page_console.textCursor()
            fmt = QTextCharFormat()
            fmt.setForeground(QColor(color))

            cursor.movePosition(QTextCursor.End)
            cursor.setCharFormat(fmt)
            cursor.insertText(text + "\n")

            if self.log_autoscroll:
                self.logs_page_console.ensureCursorVisible()

        # ================= SIEM TABLE =================
        if hasattr(self, "siem_table"):
            row = self.siem_table.rowCount()
            self.siem_table.insertRow(row)

            self.siem_table.setItem(row, 0, QTableWidgetItem(timestamp))
            self.siem_table.setItem(row, 1, QTableWidgetItem(source))
            self.siem_table.setItem(row, 2, QTableWidgetItem(event_type))
            self.siem_table.setItem(row, 3, QTableWidgetItem(level))
            self.siem_table.setItem(row, 4, QTableWidgetItem(str(risk_score)))
            self.siem_table.setItem(row, 5, QTableWidgetItem(message))

            level_colors = {
                "INFO": QColor("#60a5fa"),
                "WARN": QColor("#facc15"),
                "ERROR": QColor("#ef4444"),
                "SUCCESS": QColor("#22c55e"),
            }

            col_color = level_colors.get(level, QColor("#e5e7eb"))

            for col in range(6):
                item = self.siem_table.item(row, col)
                if item:
                    item.setForeground(col_color)

            self.siem_table.scrollToBottom()

        # ================= SAVE SIEM EVENTS =================
        siem_path = os.path.join(PROJECT_ROOT, "data", "siem_events.json")
        os.makedirs(os.path.dirname(siem_path), exist_ok=True)

        try:
            existing = []
            if os.path.exists(siem_path):
                with open(siem_path, "r", encoding="utf-8") as f:
                    existing = json.load(f)

            existing.append(entry)

            with open(siem_path, "w", encoding="utf-8") as f:
                json.dump(existing, f, indent=2)

        except Exception:
            pass

    def _search_logs(self, text):
        self.logs_page_console.clear()

        for e in self.log_entries:
            blob = f"{e['time']} {e['level']} {e['message']}".lower()
            if text.lower() in blob:
                self.log(e["message"], e["level"],
                         e["source"], e["event_type"])

    def _on_nav_change(self, row):
        item = self.sidebar.item(row)
        if not item:
            return

        text = item.text().strip().lower()

        mapping = {
            "dashboard": "dashboard",
            "scope": "target",
            "phase 1": "phase1",
            "phase 2": "phase2",
            "phase 3": "phase3",
            "email": "email",
            "full": "full",
            "discovery": "discovery",
            "findings": "findings",
            "repeater": "repeater",
            "cvss": "cvss",
            "mitre": "mitre",
            "heatmap": "heatmap",
            "siem": "siem",
            "screenshot": "screenshots",
            "setting": "settings",
            "history": "history",
            "log": "logs",
        }

        for key, page in mapping.items():
            if key in text:
                self.stack.setCurrentWidget(self.pages[page])

                if key == "mitre":
                    self._update_mitre_view()
                elif key == "heatmap":
                    self._update_charts()
                elif key == "screenshot":
                    self._populate_screenshot_gallery()

                break

        if "dashboard" in text:
            self.stack.setCurrentWidget(self.pages["dashboard"])

        elif "scope" in text:
            self.stack.setCurrentWidget(self.pages["target"])

        elif "phase 1" in text:
            self.stack.setCurrentWidget(self.pages["phase1"])

        elif "phase 2" in text:
            self.stack.setCurrentWidget(self.pages["phase2"])

        elif "phase 3" in text:
            self.stack.setCurrentWidget(self.pages["phase3"])
            
        elif "email" in text:
            self.stack.setCurrentWidget(
                self.pages["email"]
            )
            self._refresh_email_page()

        elif "full" in text:
            self.stack.setCurrentWidget(self.pages["full"])

        elif "discovery" in text:

            self.stack.setCurrentWidget(
                self.pages["discovery"]
            )
            # -------------------------------------------------
            # Refresh Phase-1 Discovery from backend output
            # -------------------------------------------------
            try:
                self._load_phase1_findings()
            except Exception as e:
                print(
                    f"[GUI][DISCOVERY_REFRESH_ERROR] {e}",
                    flush=True,
                )

            self._load_phase1_findings()
            self._refresh_discovery_page()

        elif "finding" in text:
            self.stack.setCurrentWidget(self.pages["findings"])

        elif "repeater" in text:
            self.stack.setCurrentWidget(self.pages["repeater"])

        elif "cvss" in text:
            self.stack.setCurrentWidget(self.pages["cvss"])

        elif "mitre" in text:
            self.stack.setCurrentWidget(self.pages["mitre"])
            self._update_mitre_view()

        elif "heatmap" in text:
            self.stack.setCurrentWidget(self.pages["heatmap"])
            self._update_charts()

        elif "siem" in text:
            self.stack.setCurrentWidget(self.pages["siem"])

        elif "screenshot" in text:
            self.stack.setCurrentWidget(self.pages["screenshots"])
            self._populate_screenshot_gallery()
            self._update_screenshot()

        elif "setting" in text:
            self.stack.setCurrentWidget(self.pages["settings"])

        elif "history" in text:
            self.stack.setCurrentWidget(self.pages["history"])

        elif "log" in text:
            self.stack.setCurrentWidget(self.pages["logs"])

    def _take_screenshot(self):
        pixmap = self.grab()
        fn, _ = QFileDialog.getSaveFileName(
            self, "Save Screenshot", "screenshot.png", "Images (*.png *.jpg)"
        )
        if fn:
            pixmap.save(fn)
            self.statusBar().showMessage
            (f"Screenshot saved to {fn}")

    def _save_target(self):
        # 1. Read input
        url = self.target_inp.text().strip()

        # ✅ FIX: Normalize URL like CLI
        if url and not url.startswith(("http://", "https://")):
            url = "http://" + url

        # 2. Empty check
        if not url:
            QMessageBox.warning(self, "Scope Error",
                                "Root URL cannot be empty.")
            return

        # 3. Ensure data directory exists
        os.makedirs(DATA_DIR, exist_ok=True)

        # 4. Prepare payload
        payload = {
            "root_url": url,
            "saved_at": datetime.datetime.now().isoformat(),
            "auth": None
        }

        # 🔐 Add authentication if provided
        login_url = self.login_url_input.text().strip()
        username = self.login_user_input.text().strip()
        password = self.login_pass_input.text().strip()

        if login_url and username and password:
            payload["auth"] = {
                "login_url": login_url,
                "username": username,
                "password": password
            }

        # 5. Save to JSON
        target_path = os.path.join(DATA_DIR, "target.json")
        try:
            with open(target_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=4)

            # 6. UI feedback
            self.log(f"Target saved: {url}", "INFO",
                     source="GUI", event_type="CONFIG")
            self.statusBar().showMessage(f"✅ Scope saved: {url}")
            QMessageBox.information(self, "Success", f"Target saved:\n{url}")

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

        self.active_target_lbl.setText(f"Target: {url}")

    def _get_saved_target(self):
        target_file = os.path.join(DATA_DIR, "target.json")
        if not os.path.exists(target_file):
            return None
        try:
            with open(target_file, "r", encoding="utf-8") as f:
                return json.load(f).get("root_url")
        except Exception:
            return None

    def _load_phase1_findings(self):
        """
        Load the canonical Phase-1 parameter candidates into
        the existing Discovery UI.

        GUI responsibility only:
            parameter_candidates.json -> discovery_table

        No scanning or discovery logic is performed here.
        """

        p1_path = os.path.join(
            PROJECT_ROOT,
            "phase1_scanning_detection",
            "output",
            "parameter_candidates.json",
        )

        if not hasattr(self, "discovery_table"):
            print(
                "[GUI] Discovery table is not initialized.",
                flush=True,
            )
            return

        self.discovery_table.setRowCount(0)

        if not os.path.exists(p1_path):
            print(
                f"[GUI] Phase-1 output not found: {p1_path}",
                flush=True,
            )
            return

        try:
            with open(
                p1_path,
                "r",
                encoding="utf-8",
            ) as f:
                raw = json.load(f)

        except Exception as exc:
            print(
                f"[GUI] Failed to load Phase-1 output: "
                f"{type(exc).__name__}: {exc}",
                flush=True,
            )
            return

        # ------------------------------------------------------
        # Normalize existing Phase-1 output
        # ------------------------------------------------------

        if isinstance(raw, dict):
            findings = (
                raw.get("candidates")
                or raw.get("parameters")
                or raw.get("results")
                or raw.get("findings")
                or []
            )

        elif isinstance(raw, list):
            findings = raw

        else:
            findings = []

        if not isinstance(findings, list):
            findings = []

        self.phase1_findings = findings

        # ------------------------------------------------------
        # Populate existing Discovery table
        # ------------------------------------------------------

        for item in findings:

            if not isinstance(item, dict):
                continue

            row = self.discovery_table.rowCount()

            self.discovery_table.insertRow(row)

            parameter = (
                item.get("parameter")
                or item.get("param")
                or item.get("name")
                or ""
            )

            location = (
                item.get("location")
                or item.get("source")
                or item.get("where")
                or ""
            )

            method = (
                item.get("method")
                or item.get("http_method")
                or "GET"
            )

            url = (
                item.get("url")
                or item.get("endpoint")
                or ""
            )

            values = (
                parameter,
                location,
                method,
                url,
                "Phase 1",
            )

            for column, value in enumerate(values):

                self.discovery_table.setItem(
                    row,
                    column,
                    QTableWidgetItem(
                        str(value)
                    ),
                )

        print(
            "[GUI] Phase-1 discovery rows loaded: "
            f"{self.discovery_table.rowCount()}",
            flush=True,
        )

        # Existing dashboard counter.
        if hasattr(self, "lbl_vulns"):
            self.lbl_vulns.value_label.setText(
                str(self.discovery_table.rowCount())
            )

    def _update_phase1_dashboard(self):
        """
        Synchronize dashboard counters with real Phase-1 discovery.
        """

        data = getattr(
            self,
            "phase1_data",
            {},
        )

        pages = data.get(
            "pages",
            [],
        )

        parameters = data.get(
            "parameters",
            [],
        )

        # ---------------------------------------------------------
        # Dashboard URL/page count
        # ---------------------------------------------------------

        if hasattr(
            self,
            "lbl_urls",
        ):

            self.lbl_urls.value_label.setText(
                str(len(pages))
            )

        # ---------------------------------------------------------
        # Discovery status
        # ---------------------------------------------------------

        if hasattr(
            self,
            "dashboard_scan_status",
        ):

            if pages or parameters:

                self.dashboard_scan_status.setText(
                    "Status: Phase-1 Discovery Complete"
                )

            else:

                self.dashboard_scan_status.setText(
                    "Status: No Discovery Data"
                )

        # ---------------------------------------------------------
        # Phase-1 activity
        # ---------------------------------------------------------

        self.phase1_activity = pages

    def _refresh_discovery_page(self):
        """
        Refresh the Discovery page directly from the canonical
        Phase-1 parameter_candidates.json output.

        Discovery UI is read-only.

        Source:
            phase1_scanning_detection/output/parameter_candidates.json

        Only actual parameter candidates are displayed.
        Route-only observations are intentionally excluded because
        this table represents discovered parameters.
        """

        import json

        # =========================================================
        # 1. Resolve canonical Phase-1 output
        # =========================================================

        path = os.path.join(
            PHASE1_DIR,
            "output",
            "parameter_candidates.json",
        )

        table = getattr(
            self,
            "discovery_table",
            None,
        )

        if table is None:
            print(
                "[GUI][DISCOVERY] discovery_table not available",
                flush=True,
            )
            return

        # =========================================================
        # 2. Always clear current UI state
        # =========================================================

        table.setRowCount(0)

        # =========================================================
        # 3. Check Phase-1 output
        # =========================================================

        if not os.path.exists(path):

            print(
                "[GUI][DISCOVERY] Phase-1 output not found:",
                path,
                flush=True,
            )

            return

        # =========================================================
        # 4. Load JSON
        # =========================================================

        try:

            with open(
                path,
                "r",
                encoding="utf-8-sig",
            ) as f:

                raw = json.load(f)

        except Exception as exc:

            print(
                "[GUI][DISCOVERY] Failed to load "
                "parameter_candidates.json:",
                f"{type(exc).__name__}: {exc}",
                flush=True,
            )

            return

        # =========================================================
        # 5. Normalize JSON structure
        # =========================================================

        if isinstance(raw, dict):

            candidates = (
                raw.get("candidates")
                or raw.get("parameters")
                or raw.get("results")
                or []
            )

        elif isinstance(raw, list):

            candidates = raw

        else:

            candidates = []

        # =========================================================
        # 6. Populate Discovery table
        #
        # Columns:
        #
        #   0 = Parameter
        #   1 = Location
        #   2 = Method
        #   3 = URL
        #   4 = Phase
        # =========================================================

        loaded = 0

        for item in candidates:

            if not isinstance(
                item,
                dict,
            ):
                continue

            # -----------------------------------------------------
            # Parameter
            # -----------------------------------------------------

            parameter = str(
                item.get("parameter")
                or item.get("param")
                or item.get("name")
                or ""
            ).strip()

            # -----------------------------------------------------
            # Route-only observations are NOT parameters.
            #
            # Example:
            #
            # candidate_type = observed-route
            # parameter = ""
            #
            # Do not display these in this table.
            # -----------------------------------------------------

            if not parameter:
                continue

            # -----------------------------------------------------
            # Location
            # -----------------------------------------------------

            location = str(
                item.get("location")
                or item.get("where")
                or ""
            ).strip()

            # -----------------------------------------------------
            # Method
            # -----------------------------------------------------

            method = str(
                item.get("method")
                or item.get("http_method")
                or "GET"
            ).upper().strip()

            # -----------------------------------------------------
            # URL
            # -----------------------------------------------------

            url = str(
                item.get("url")
                or item.get("endpoint")
                or ""
            ).strip()

            # -----------------------------------------------------
            # Insert row
            # -----------------------------------------------------

            row = table.rowCount()

            table.insertRow(row)

            values = (
                parameter,
                location,
                method,
                url,
                "Phase 1",
            )

            for column, value in enumerate(values):

                cell = QTableWidgetItem(
                    str(value)
                )

                cell.setFlags(
                    cell.flags()
                    & ~Qt.ItemIsEditable
                )

                table.setItem(
                    row,
                    column,
                    cell,
                )

            loaded += 1

        # =========================================================
        # 7. Resize / presentation
        # =========================================================

        try:

            table.resizeRowsToContents()

        except Exception:
            pass

        # Keep URL column wide enough.
        try:

            table.horizontalHeader().setStretchLastSection(
                True
            )

        except Exception:
            pass

        # =========================================================
        # 8. Update GUI counters
        # =========================================================

        if hasattr(
            self,
            "lbl_vulns",
        ):

            try:

                self.lbl_vulns.value_label.setText(
                    str(loaded)
                )

            except Exception:
                pass

        # =========================================================
        # 9. Diagnostic
        # =========================================================

        print(
            "[GUI][DISCOVERY] Phase-1 parameter rows loaded:",
            loaded,
            flush=True,
        )

    def _set_scan_controls_enabled(self, enabled: bool):

        for key, btn in self.phase_buttons.items():

            if key == "full":
                btn.setEnabled(True)

            else:
                btn.setEnabled(enabled)

        # NEVER disable navigation
        self.sidebar.setEnabled(True)

        # NEVER disable stacked pages
        self.stack.setEnabled(True)

        # Pause button always usable
        if self.pause_btn:
            self.pause_btn.setEnabled(True)

        # Screenshot navigation is always a GUI operation.
        # It must remain usable while Phase-1 is running.

        if hasattr(
            self,
            "btn_next_shot",
        ):
            self.btn_next_shot.setEnabled(
                True
            )

        if hasattr(
            self,
            "gallery_prev_btn",
        ):
            self.gallery_prev_btn.setEnabled(
                True
            )

        if hasattr(
            self,
            "gallery_next_btn",
        ):
            self.gallery_next_btn.setEnabled(
                True
            )

    def _handle_stderr(self):
        if not self.scan_process:
            return

        data = self.scan_process.readAllStandardError()
        if not data:
            return

        text = bytes(data).decode("utf-8", errors="ignore")
        self._on_scan_output(self.current_phase_key)

    def _process_backend_lines(self, text: str):
        for line in text.splitlines():
            line = line.strip()

            if not line:
                continue

            # =====================================================
            # 1. ALWAYS show raw backend output in Live Console
            # =====================================================

            if self.current_phase_key in self.log_widgets:
                self.log_widgets[
                    self.current_phase_key
                ].append(line)

            # =====================================================
            # 2. Structured progress event
            # =====================================================

            if line.startswith("[PROGRESS]"):
                self._update_progress_from_line(line)
                continue

            # =====================================================
            # 3. Live vulnerability event
            # =====================================================

            if line.startswith("[VULN]"):
                self._handle_live_vuln(line)
                continue

            # =====================================================
            # 4. Phase status event
            # =====================================================

            if line.startswith("[PHASE"):
                self._update_phase_status(line)
                continue

            # =====================================================
            # 5. Send ordinary backend events to SIEM / Logs
            # =====================================================

            level = "INFO"

            upper_line = line.upper()

            if "[ERROR]" in upper_line:
                level = "ERROR"

            elif "[WARN]" in upper_line or "[WARNING]" in upper_line:
                level = "WARN"

            elif "[DONE]" in upper_line or "[SUCCESS]" in upper_line:
                level = "SUCCESS"

            self.log(
                line,
                level,
                (
                    self.current_phase_key.upper()
                    if self.current_phase_key
                    else "BACKEND"
                ),
                "BACKEND",
            )

    def _capture_live_gui_screenshot(self, url):
        try:
            from PySide6.QtGui import QPixmap, QPainter
            from PySide6.QtCore import Qt

            pix = QPixmap(self.screenshot_label.size())
            pix.fill(Qt.black)

            painter = QPainter(pix)
            painter.setPen(Qt.green)
            painter.drawText(
                pix.rect(),
                Qt.AlignCenter,
                f"LIVE VIEW\n\n{url}"
            )
            painter.end()

            self.live_browser_label.setPixmap(pix)

            self.screenshot_counter_label.setText(url)

        except Exception as e:
            print(e)

    def _append_live_vulnerability(self, vuln):

        # ------------------------------------------------
        # SAFETY GUARDS
        # ------------------------------------------------
        if not hasattr(self, "cvss_heatmap"):
            return

        if not hasattr(self, "vuln_data"):
            self.vuln_data = []

        # ------------------------------------------------
        # STORE VULNERABILITY (ONCE)
        # ------------------------------------------------
        self.vuln_data.append(vuln)

        # ------------------------------------------------
        # UPDATE TABLE & CHARTS
        # ------------------------------------------------
        self._populate_findings_table()
        self._update_charts()
        self.load_data()   # 🔥 Live refresh of dashboard cards
        cvss = float(vuln.get("cvss_score", 0))
        conf = float(vuln.get("confidence", 0)) / 100.0
        self.current_risk_score = cvss * conf

        # ------------------------------------------------
        # AUTO-SELECT FIRST FINDING (CRITICAL)
        # ------------------------------------------------
        if self.current_vuln_index is None and len(self.vuln_data) == 1:
            self.current_vuln_index = 0
            self.table.selectRow(0)
            self._update_cvss_view()
            self._update_mitre_view()

        # ------------------------------------------------
        # 🔥 HIGHLIGHT NEW ROW
        # ------------------------------------------------
        row = self.table.rowCount() - 1
        for col in range(self.table.columnCount()):
            item = self.table.item(row, col)
            if item:
                item.setBackground(QColor(59, 130, 246, 120))  # blue flash

        # ------------------------------------------------
        # 🔁 FADE EFFECT
        # ------------------------------------------------
        QTimer.singleShot(600, lambda r=row: self._clear_row_highlight(r))

        # ------------------------------------------------
        # 🔥 LIVE CVSS HEATMAP UPDATE
        # ------------------------------------------------
        if hasattr(self, "cvss_heatmap"):
            try:
                sev_map = {
                    "critical": 9.5,
                    "high": 8.0,
                    "medium": 5.5,
                    "low": 3.0,
                }

                # Default severity mapping
                # ===============================
                # 🔥 MITRE → HEATMAP WIRING
                # ===============================

                sev_map = {
                    "critical": 9.5,
                    "high": 8.0,
                    "medium": 5.5,
                    "low": 3.0,
                }

                # X-axis = CVSS severity
                sev = sev_map.get(
                    vuln.get("severity", "").lower(),
                    float(vuln.get("cvss_score", 5.0))
                )

                # Y-axis = MITRE tactic intensity
                conf = self._mitre_to_heatmap_weight(
                    vuln.get("mitre", {})
                )

                self.cvss_heatmap.add_point(sev, conf)

            except Exception:
                pass

        # ------------------------------------------------
        # 🔥 CVSS ↔ VIDEO SYNC (PREP ONLY)
        # ------------------------------------------------
        if hasattr(self, "cvss_heatmap"):
            sev_map = {
                "critical": 9.5,
                "high": 8.0,
                "medium": 5.5,
                "low": 3.0,
            }

            sev = sev_map.get(vuln.get("severity", "").lower(), 5.0)
            conf = vuln.get("confidence", 50) / 100.0

        # 🔥 HARD MITRE REFRESH
        self._update_mitre_view()

        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

        for v in self.vuln_data:
            sev = (v.get("severity") or "").capitalize()
            if sev in counts:
                counts[sev] += 1

        self.severity_history.append(counts)

    def _clear_row_highlight(self, row):
        if row >= self.table.rowCount():
            return
        for col in range(self.table.columnCount()):
            item = self.table.item(row, col)
            if item:
                item.setBackground(QColor(0, 0, 0, 0))

    def _populate_screenshot_gallery(self):

        if not hasattr(self, "screenshots_layout"):
            return

        if not os.path.exists(SCREENSHOT_DIR):
            return

        # cache already loaded images
        if not hasattr(self, "_loaded_shots"):
            self._loaded_shots = set()

        images = sorted(
            f for f in os.listdir(SCREENSHOT_DIR)
            if f.lower().endswith(".png")
        )

        row = 0
        col = 0

        # current count
        existing = self.screenshots_layout.count()

        for i, img in enumerate(images):

            path = os.path.join(SCREENSHOT_DIR, img)

            # already exists skip
            if path in self._loaded_shots:
                continue

            lbl = QLabel()
            lbl.setMinimumSize(220, 140)
            lbl.setCursor(Qt.PointingHandCursor)

            pix = QPixmap(path)

            if not pix.isNull():
                lbl.setPixmap(
                    pix.scaled(
                        220,
                        140,
                        Qt.KeepAspectRatio,
                        Qt.SmoothTransformation
                    )
                )

            lbl.mousePressEvent = lambda e, p=path: self._open_full_image(p)

            index = self.screenshots_layout.count()

            row = index // 4
            col = index % 4

            self.screenshots_layout.addWidget(lbl, row, col)

            self._loaded_shots.add(path)

    def _refresh_vulnerability_table(self):
        try:
            self.load_data()
        except Exception:
            pass

    # =========================================================================
    # THE CORRECTED _START_SCAN FUNCTION
    # =========================================================================

    def _start_full_auto(self):
        self.auto_chain = True
        self.progress_bars["full"].setValue(0)
        self._start_scan("phase1")
        self._set_scan_controls_enabled(False)

    def _get_scan_process_tree(self):
        """
        Return the running scan process and its child processes.
    
        On Windows the Phase-1 crawler may create browser child
        processes, so pausing only QProcess is not sufficient.
        """
    
        if self.scan_process is None:
            return []
    
        try:
            root_pid = int(
                self.scan_process.processId()
            )
        except Exception:
            return []
    
        if not root_pid:
            return []
    
        if os.name != "nt":
            return [root_pid]
    
        try:
    
            import ctypes
            from ctypes import wintypes
    
            TH32CS_SNAPPROCESS = 0x00000002
    
            INVALID_HANDLE_VALUE = (
                ctypes.c_void_p(-1).value
            )
    
            class PROCESSENTRY32W(
                ctypes.Structure
            ):
    
                _fields_ = [
                    (
                        "dwSize",
                        wintypes.DWORD
                    ),
                    (
                        "cntUsage",
                        wintypes.DWORD
                    ),
                    (
                        "th32ProcessID",
                        wintypes.DWORD
                    ),
                    (
                        "th32DefaultHeapID",
                        ctypes.c_size_t
                    ),
                    (
                        "th32ModuleID",
                        wintypes.DWORD
                    ),
                    (
                        "cntThreads",
                        wintypes.DWORD
                    ),
                    (
                        "th32ParentProcessID",
                        wintypes.DWORD
                    ),
                    (
                        "pcPriClassBase",
                        wintypes.LONG
                    ),
                    (
                        "dwFlags",
                        wintypes.DWORD
                    ),
                    (
                        "szExeFile",
                        wintypes.WCHAR * 260
                    ),
                ]
    
            kernel32 = ctypes.windll.kernel32
    
            snapshot = (
                kernel32.CreateToolhelp32Snapshot(
                    TH32CS_SNAPPROCESS,
                    0,
                )
            )
    
            if snapshot == INVALID_HANDLE_VALUE:
                return [root_pid]
    
            try:
    
                entry = PROCESSENTRY32W()
    
                entry.dwSize = ctypes.sizeof(
                    PROCESSENTRY32W
                )
    
                parent_map = {}
    
                ok = (
                    kernel32.Process32FirstW(
                        snapshot,
                        ctypes.byref(entry),
                    )
                )
    
                while ok:
    
                    pid = int(
                        entry.th32ProcessID
                    )
    
                    parent = int(
                        entry.th32ParentProcessID
                    )
    
                    parent_map[pid] = parent
    
                    ok = (
                        kernel32.Process32NextW(
                            snapshot,
                            ctypes.byref(entry),
                        )
                    )
    
                tree = [root_pid]
    
                known = {
                    root_pid
                }
    
                changed = True
    
                while changed:
    
                    changed = False
    
                    for pid, parent in (
                        parent_map.items()
                    ):
    
                        if (
                            parent in known
                            and pid not in known
                        ):
    
                            known.add(pid)
    
                            tree.append(pid)
    
                            changed = True
    
                return tree
    
            finally:
    
                kernel32.CloseHandle(
                    snapshot
                )
    
        except Exception as exc:
    
            print(
                "[GUI][PAUSE] "
                f"Process tree error: {exc}",
                flush=True,
            )
    
            return [root_pid]
    
    
    def _set_process_suspended(
        self,
        pid,
        suspend=True,
    ):
        """
        Suspend/resume one Windows process.
        """
    
        if os.name != "nt":
            return False
    
        try:
    
            import ctypes
    
            PROCESS_SUSPEND_RESUME = 0x0800
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    
            handle = (
                ctypes.windll.kernel32.OpenProcess(
                    PROCESS_SUSPEND_RESUME
                    | PROCESS_QUERY_LIMITED_INFORMATION,
                    False,
                    int(pid),
                )
            )
    
            if not handle:
                return False
    
            try:
    
                ntdll = ctypes.windll.ntdll
    
                if suspend:
    
                    status = (
                        ntdll.NtSuspendProcess(
                            handle
                        )
                    )
    
                else:
    
                    status = (
                        ntdll.NtResumeProcess(
                            handle
                        )
                    )
    
                return status == 0
    
            finally:
    
                ctypes.windll.kernel32.CloseHandle(
                    handle
                )
    
        except Exception as exc:
    
            print(
                "[GUI][PAUSE] "
                f"PID {pid} error: {exc}",
                flush=True,
        )
        
        return False
    
    def _toggle_pause_scan(self):
        """
        Real Pause / Resume for the complete scan process tree.
    
        PAUSE:
            Suspends the scan process and every currently running child
            process, including Playwright/Chromium processes.
    
        RESUME:
            Resumes every PID that was suspended during PAUSE.
        """
    
        # =========================================================
        # BASIC STATE
        # =========================================================
    
        process = self.scan_process
    
        if process is None:
            print(
                "[GUI][PAUSE] No scan process.",
                flush=True,
            )
            return
    
        if not hasattr(self, "paused"):
            self.paused = False
    
        if not hasattr(self, "_paused_process_pids"):
            self._paused_process_pids = []
    
    
        # =========================================================
        # PAUSE
        # =========================================================
    
        if not self.paused:
    
            # Get the COMPLETE process tree.
            pids = self._get_scan_process_tree()
    
            if not pids:
                print(
                    "[GUI][PAUSE] No process tree found.",
                    flush=True,
                )
                return
    
            suspended = []
    
            for pid in pids:
    
                try:
                    if self._set_process_suspended(
                        pid,
                        True,
                    ):
                        suspended.append(pid)
    
                except Exception as exc:
                    print(
                        f"[GUI][PAUSE] Failed to suspend PID {pid}: {exc}",
                        flush=True,
                    )
    
            if not suspended:
    
                QMessageBox.warning(
                    self,
                    "Pause",
                    "Unable to suspend the scan process tree."
                )
    
                return
    
    
            # IMPORTANT:
            # Remember EVERY process we actually suspended.
            self._paused_process_pids = list(
                dict.fromkeys(suspended)
            )
    
            self.paused = True
    
    
            # =====================================================
            # CHANGE BUTTON -> RESUME
            # =====================================================
    
            if self.pause_btn:
    
                self.pause_btn.setText(
                    "▶ Resume"
                )
    
                self.pause_btn.repaint()
    
    
            # =====================================================
            # LOG
            # =====================================================
    
            if (
                self.current_phase_key
                in self.log_widgets
            ):
    
                self.log_widgets[
                    self.current_phase_key
                ].append(
                    "[GUI] Scan paused"
                )
    
    
            print(
                "[GUI][PAUSE] Scan paused.",
                self._paused_process_pids,
                flush=True,
            )
    
            return
    
    
        # =========================================================
        # RESUME
        # =========================================================
    
        # DO NOT use only:
        #
        #     self.scan_process.processId()
        #
        # because Chromium / Playwright may be running in child
        # processes. We must resume every PID that was suspended.
    
        pids = list(
            getattr(
                self,
                "_paused_process_pids",
                [],
            )
        )
    
        if not pids:
    
            # Fallback: rebuild the process tree if needed.
            pids = self._get_scan_process_tree()
    
        if not pids:
    
            print(
                "[GUI][RESUME] No suspended processes found.",
                flush=True,
            )
    
            return
    
    
        resumed = []
    
        for pid in reversed(pids):
    
            try:
    
                if self._set_process_suspended(
                    pid,
                    False,
                ):
    
                    resumed.append(pid)
    
            except Exception as exc:
    
                print(
                    f"[GUI][RESUME] Failed to resume PID {pid}: {exc}",
                    flush=True,
                )
    
    
        # =========================================================
        # CHECK RESULT
        # =========================================================
    
        if not resumed:
    
            QMessageBox.warning(
                self,
                "Resume",
                "Unable to resume the suspended scan process."
            )
    
            return
    
    
        # =========================================================
        # CLEAR PAUSE STATE
        # =========================================================
    
        self._paused_process_pids = []
    
        self.paused = False
    
    
        # =========================================================
        # CHANGE BUTTON -> PAUSE
        # =========================================================
    
        if self.pause_btn:
    
            self.pause_btn.setText(
                "⏸ Pause"
            )
    
            self.pause_btn.repaint()
    
    
        # =========================================================
        # LOG
        # =========================================================
    
        if (
            self.current_phase_key
            in self.log_widgets
        ):
    
            self.log_widgets[
                self.current_phase_key
            ].append(
                "[GUI] Scan resumed"
            )
    
    
        print(
            "[GUI][RESUME] Scan resumed.",
            resumed,
            flush=True,
        )
    
    def _start_scan(self, phase: str):
        """
        Stable Scan Launcher (Fixed)
        ---------------------------
        ✔ Removes old pause.flag
        ✔ Resets paused state
        ✔ Prevents instant pause bug
        ✔ Smooth launch
        """
        # =========================================================
        # RESET PAUSE STATE FOR NEW SCAN
        # =========================================================

        self.paused = False

        if self.pause_btn:
            self.pause_btn.setText(
                "⏸ Pause"
            )
            self.pause_btn.setEnabled(
                True
            )

        # Remove any stale pause flag from a previous scan.
        pause_file = os.path.join(
            PROJECT_ROOT,
            "control",
            "pause.flag"
        )

        try:
            if os.path.exists(pause_file):
                os.remove(pause_file)
        except Exception as exc:
            print(
                f"[GUI][PAUSE] Could not clear pause flag: {exc}",
                flush=True,
            )
        
        # -----------------------------------
        # Kill old process
        # -----------------------------------
        if self.scan_process:
            try:
                if self.scan_process.state() == QProcess.Running:
                    QMessageBox.warning(
                        self,
                        "Scan Running",
                        "A scan is already running."
                    )
                    return

                self.scan_process.kill()
                self.scan_process.waitForFinished(1000)
                self.scan_process.deleteLater()

            except Exception:
                pass

            self.scan_process = None

        # -----------------------------------
        # CRITICAL FIX:
        # remove stale pause.flag
        # -----------------------------------
        pause_file = os.path.join(
            PROJECT_ROOT,
            "control",
            "pause.flag"
        )

        try:
            if os.path.exists(pause_file):
                os.remove(pause_file)
        except Exception:
            pass

        self.paused = False

        # reset current phase pause button text
        try:
            pause_button = self.pause_buttons.get(phase)
        
            if pause_button:
                pause_button.setText(
                    "⏸ Pause"
                )
        
        except Exception:
            pass

        # -----------------------------------
        # Target
        # -----------------------------------
        target = self._get_saved_target()

        if not target:
            QMessageBox.warning(
                self,
                "Target Missing",
                "Save a target first."
            )
            return

        self.active_target_lbl.setText(
            f"Target: {target}"
        )

        self.lbl_urls.value_label.setText(
            target
        )

        # -----------------------------------
        # Resolve runner
        # -----------------------------------
        runner = ""
        args = []

        if phase == "phase1":

            import shutil

            shot_dir = os.path.join(
                PROJECT_ROOT,
                "screenshots"
            )

            if os.path.exists(shot_dir):
                shutil.rmtree(shot_dir)

            os.makedirs(
                shot_dir,
                exist_ok=True
            )

            self.current_screenshot_index = -1

            if hasattr(self, "_loaded_shots"):
                self._loaded_shots.clear()

            runner = os.path.join(
                PHASE1_DIR,
                "gui_runner.py"
            )

            args = [
                sys.executable,
                runner,
                "--target", target,
                "--depth",
                str(self.depth_slider.value())
            ]

        elif phase == "phase2":

            runner = os.path.join(
                PHASE2_DIR,
                "gui_runner.py"
            )

            args = [
                sys.executable,
                runner,
                "--target", target
            ]

        elif phase == "phase3":

            runner = os.path.join(
                PHASE3_DIR,
                "gui_runner.py"
            )

            args = [
                sys.executable,
                runner,
                "--target", target
            ]

        else:
            QMessageBox.warning(
                self,
                "Invalid Phase",
                f"Unknown phase: {phase}"
            )
            return

        if not os.path.exists(runner):
            QMessageBox.warning(
                self,
                "Runner Missing",
                runner
            )
            return

        # -----------------------------------
        # GUI Reset
        # -----------------------------------
        self.active_phase = phase
        self.current_phase_key = phase
        
        # =========================================================
        # SELECT PAUSE BUTTON FOR CURRENT PHASE
        # =========================================================
        
        self.pause_btn = self.pause_buttons.get(
            phase
        )
        
        if self.pause_btn:
            self.pause_btn.setText(
                "⏸ Pause"
            )
            self.pause_btn.setEnabled(
                True
            )

        self.phase_status_lbl.setText(
            f"● {phase.upper()} Running"
        )

        if phase in self.progress_bars:

            bar = self.progress_bars[phase]

            bar.setValue(0)
            bar.setFormat("0%")
            bar.repaint()

        if phase in self.log_widgets:
            try:
                self.log_widgets[phase].clear()
            except Exception:
                pass

        self._set_scan_controls_enabled(False)

        QApplication.processEvents()

        # -----------------------------------
        # Process
        # -----------------------------------
        self.scan_process = QProcess(self)

        self.scan_process.setProcessChannelMode(
            QProcess.MergedChannels
        )

        self.scan_process.readyReadStandardOutput.connect(
            lambda: self._on_scan_output(phase)
        )

        self.scan_process.finished.connect(
            self._on_process_finished
        )

        self.scan_process.start(
            args[0],
            args[1:]
        )

        started = self.scan_process.waitForStarted(
            3000
        )

        if not started:

            QMessageBox.warning(
                self,
                "Launch Failed",
                f"Could not start {phase}"
            )

            self._set_scan_controls_enabled(True)
            return

        if phase == "phase1":
            try:
                self.screenshot_timer.stop()
                self.screenshot_timer.start(1500)
            except Exception:
                pass

        QApplication.processEvents()

    def _on_process_finished(self):
        """
        Final process cleanup.

        IMPORTANT:
        Drain stdout BEFORE destroying QProcess so the final
        backend progress events are not lost.
        """

        # ==================================================
        # 1. FINAL STDOUT DRAIN
        # ==================================================

        finished_process = self.scan_process

        if finished_process is not None:

            try:
                self._on_scan_output(
                    self.current_phase_key
                )
            except Exception as exc:
                print(
                    f"[GUI FINAL OUTPUT ERROR] {exc}",
                    flush=True,
                )

            # Process any remaining complete buffered line.
            if hasattr(
                self,
                "_stdout_buffer",
            ):

                remaining = (
                    self._stdout_buffer.strip()
                )

                self._stdout_buffer = ""

                if remaining:

                    try:

                        import re

                        match = re.search(
                            r"\[PROGRESS\]\s*PHASE\s*(\d+)\s+(\d+)",
                            remaining.upper(),
                        )

                        if match:

                            phase_number = int(
                                match.group(1)
                            )

                            value = int(
                                match.group(2)
                            )

                            phase_key = (
                                f"phase{phase_number}"
                            )

                            if phase_key in self.progress_bars:

                                bar = self.progress_bars[
                                    phase_key
                                ]

                                if value >= bar.value():

                                    bar.setValue(
                                        value
                                    )

                                    bar.setFormat(
                                        f"{value}%"
                                    )

                    except Exception as exc:
                        print(
                            f"[GUI FINAL PROGRESS ERROR] {exc}",
                            flush=True,
                        )

        QApplication.processEvents()

        # ==================================================
        # 2. NOW UNLOCK GUI
        # ==================================================

        self._set_scan_controls_enabled(
            True
        )

        # ==================================================
        # 3. PRESERVE FINISHED PHASE
        # ==================================================

        finished_key = (
            self.current_phase_key
        )

        if not finished_key:
            print(
                "[GUI] Process finished but no active phase",
                flush=True,
            )
            return

        # ==================================================
        # 4. STOP LIVE TIMER
        # ==================================================

        try:

            if hasattr(
                self,
                "screenshot_timer",
            ):

                if self.screenshot_timer.isActive():

                    self.screenshot_timer.stop()

        except Exception:
            pass

        # ==================================================
        # 5. ONLY NOW RELEASE PROCESS
        # ==================================================

        process = self.scan_process

        self.scan_process = None

        if process is not None:

            try:
                process.deleteLater()
            except Exception:
                pass

        # ==================================================
        # 6. RESET PHASE BUTTON
        # ==================================================

        if finished_key in self.phase_buttons:

            try:

                self.phase_buttons[
                    finished_key
                ].setText(
                    "▶ Re-Run"
                )

                self.phase_buttons[
                    finished_key
                ].setEnabled(
                    True
                )

            except Exception:
                pass

        # ==================================================
        # 7. EXISTING PHASE-FINISH LOGIC
        # ==================================================

        if finished_key == "phase1":

            self.phase1_done = True

            try:
                self._load_phase1_findings()
            except Exception as exc:
                print(
                    "[GUI] Phase1 findings load error:",
                    exc,
                )

            try:

                self.load_data()
                self._populate_findings_table()
                self._update_charts()
                self._check_siem_alerts()
                self._enforce_phase_logic()

            except Exception as exc:

                print(
                    f"[GUI][PHASE2_REFRESH_ERROR] {exc}",
                    flush=True,
                )

            try:

                self._update_screenshot()
                self._populate_screenshot_gallery()

            except Exception as exc:

                print(
                    "[GUI] Screenshot refresh failed:",
                    exc,
                )

            try:

                self._load_screenshots()

                if hasattr(
                    self,
                    "screenshot_label",
                ):
                    self.screenshot_label.setText("")

            except Exception as exc:

                print(
                    "[GUI] Screenshot refresh failed:",
                    exc,
                )

            self.log(
                "Phase-1 discovery completed successfully",
                "SUCCESS",
                "PHASE1",
                "DISCOVERY",
            )

            if getattr(
                self,
                "recording_phase1",
                False,
            ):

                self.recording_phase1 = False

                self.log(
                    f"Phase-1 video saved: {self.phase1_video_path}",
                    "SUCCESS",
                    "GUI",
                    "VIDEO",
                )

            if getattr(
                self,
                "auto_chain",
                False,
            ) is True:

                QTimer.singleShot(
                    300,
                    lambda: self._start_scan("phase2"),
                )

                return

            QTimer.singleShot(
                100,
                self._enforce_phase_logic,
            )

        elif finished_key == "phase2":

            # ==================================================
            # PHASE-2 COMPLETED
            # ==================================================

            self.phase2_done = True

            try:
                self.load_data()
                self._populate_findings_table()
                self._update_charts()
            except Exception as ex:
                print(
                    f"[GUI][PHASE2 FINISH ERROR] {exc}",
                    flush=True,
                )

            self.log(
                "Phase-2 validation completed successfully",
                "SUCCESS",
                "PHASE2",
                "VALIDATION",
            )

            # Unlock Phase-3.
            QTimer.singleShot(
                100,
                self._enforce_phase_logic,
            )

            # Full Auto Scan:
            # automatically continue to Phase-3.
            if getattr(
                self,
                "auto_chain",
                False,
            ) is True:

                QTimer.singleShot(
                    300,
                    lambda: self._start_scan("phase3"),
                )

                return


        elif finished_key == "phase3":

            # ==================================================
            # PHASE-3 COMPLETED
            # ==================================================

            self.phase3_done = True

            try:
                self._load_phase3_report()
            except Exception as exc:
                print(
                    f"[GUI][PHASE3 REPORT ERROR] {exc}",
                    flush=True,
                )

            if hasattr(
                self,
                "report_status",
            ):
                self.report_status.setText(
                    "Phase-3 report generated successfully."
                )

            self.log(
                "Phase-3 reporting completed successfully",
                "SUCCESS",
                "PHASE3",
                "REPORT",
            )

            self._enforce_phase_logic()

            # Full Auto Scan finished.
            self.auto_chain = False

    def _on_scan_output(self, phase):
        """
        Single authoritative QProcess stdout reader.

        Responsibilities:
            - consume all available stdout
            - parse [PROGRESS] PHASE1 <value>
            - update the correct GUI progress bar
            - forward normal backend messages to the log
            - retain incomplete stdout fragments

        No progress is calculated here.
        """

        process = self.scan_process

        if process is None:
            return

        import re
        from PySide6.QtWidgets import QApplication

        if not hasattr(self, "_stdout_buffer"):
            self._stdout_buffer = ""

        try:
            raw = process.readAllStandardOutput()

            if not raw:
                return

            text = bytes(raw).decode(
                "utf-8",
                errors="replace",
            )

        except Exception as exc:
            print(
                f"[GUI OUTPUT ERROR] {type(exc).__name__}: {exc}",
                flush=True,
            )
            return

        self._stdout_buffer += text

        # Normalize Windows CRLF and standalone CR.
        self._stdout_buffer = (
            self._stdout_buffer
            .replace("\r\n", "\n")
            .replace("\r", "\n")
        )

        lines = self._stdout_buffer.split("\n")

        # Keep the final incomplete line for the next signal.
        self._stdout_buffer = lines.pop()

        for raw_line in lines:

            line = raw_line.strip()

            if not line:
                continue

            upper = line.upper()

            # ==================================================
            # REAL BACKEND PROGRESS
            # ==================================================

            if upper.startswith("[PROGRESS]"):

                match = re.search(
                    r"\[PROGRESS\]\s*PHASE\s*(\d+)\s+(\d+)",
                    upper,
                )

                if match:

                    phase_number = int(
                        match.group(1)
                    )

                    value = int(
                        match.group(2)
                    )

                    phase_key = (
                        f"phase{phase_number}"
                    )

                    if phase_key in self.progress_bars:

                        bar = self.progress_bars[
                            phase_key
                        ]

                        # Never move backwards.
                        if value >= bar.value():

                            bar.setValue(
                                value
                            )

                            bar.setFormat(
                                f"{value}%"
                            )

                            bar.update()

                    QApplication.processEvents()

                # Progress is protocol data, not a normal log line.
                continue

            # ==================================================
            # NORMAL BACKEND LOG
            # ==================================================

            if phase in self.log_widgets:

                if "[SCREENSHOT]" not in upper:

                    self.log_widgets[
                        phase
                    ].append(line)

            # ==================================================
            # SCREENSHOT EVENT
            # ==================================================

            if (
                phase == "phase1"
                and "[SCREENSHOT]" in upper
            ):

                try:
                    self._update_screenshot()
                    self._populate_screenshot_gallery()
                except Exception as exc:
                    print(
                        f"[GUI SCREENSHOT ERROR] {exc}",
                        flush=True,
                    )

        QApplication.processEvents()

    def _next_screenshot(self):
        """
        Show the next available Phase-1 screenshot.

        This only changes the GUI preview.
        It does NOT affect the running crawler.
        """

        print(
            "[GUI] NEXT SCREENSHOT CLICKED",
            flush=True,
        )

        images = self._get_screenshot_files()

        if not images:
            print(
                "[GUI] No screenshots available.",
                flush=True,
            )
            return

        # -----------------------------------------------------
        # If no screenshot is currently selected,
        # start from the newest screenshot.
        # -----------------------------------------------------

        if (
            not hasattr(
                self,
                "current_screenshot_index",
            )
            or self.current_screenshot_index < 0
            or self.current_screenshot_index >= len(images)
        ):
            self.current_screenshot_index = len(images) - 1

        # -----------------------------------------------------
        # Move forward
        # -----------------------------------------------------

        if (
            self.current_screenshot_index
            < len(images) - 1
        ):
            self.current_screenshot_index += 1

        # -----------------------------------------------------
        # Display selected screenshot
        # -----------------------------------------------------

        self._load_screenshot_by_index(
            self.current_screenshot_index
        )

    def _prev_screenshot(self):
        """
        Show the previous available Phase-1 screenshot.

        This only changes the GUI preview.
        It does NOT affect the running crawler.
        """

        print(
            "[GUI] PREVIOUS SCREENSHOT CLICKED",
            flush=True,
        )

        images = self._get_screenshot_files()

        if not images:
            print(
                "[GUI] No screenshots available.",
                flush=True,
            )
            return

        # -----------------------------------------------------
        # If nothing is selected, start at the newest image.
        # -----------------------------------------------------

        if (
            not hasattr(
                self,
                "current_screenshot_index",
            )
            or self.current_screenshot_index < 0
            or self.current_screenshot_index >= len(images)
        ):
            self.current_screenshot_index = len(images) - 1

        # -----------------------------------------------------
        # Move backward
        # -----------------------------------------------------

        if self.current_screenshot_index > 0:
            self.current_screenshot_index -= 1

        # -----------------------------------------------------
        # Display selected screenshot
        # -----------------------------------------------------

        self._load_screenshot_by_index(
            self.current_screenshot_index
        )

    def _check_siem_alerts(self):
        high_risk = [e for e in self.log_entries if e.get("risk", 0) >= 15]
        medium_risk = [e for e in self.log_entries if 10 <=
                       e.get("risk", 0) < 15]

        if len(high_risk) >= 2:
            QMessageBox.critical(
                self,
                "🚨 CRITICAL SOC ALERT",
                f"{len(high_risk)} critical security events detected!\n"
                "Immediate response required.",
            )
        elif len(medium_risk) >= 3:
            QMessageBox.warning(
                self,
                "⚠️ SOC WARNING",
                f"{len(medium_risk)} elevated-risk events detected.",
            )

    def _enforce_phase_logic(self):

        p2 = self.phase_buttons.get("phase2")
        if p2:
            p2.setEnabled(self.phase1_done)
            p2.setText(
                "🔒 Locked (Run Phase 1)" if not self.phase1_done else "▶ Start Module"
            )
            p2.setIcon(
                self.style().standardIcon(QStyle.SP_BrowserReload)
                if self.phase1_done
                else QIcon()
            )
            if not self.phase1_done:
                p2.setStyleSheet(
                    f"background-color: {self.current_theme['panel_bg']}; border: 1px solid {self.current_theme['border']}; color: {self.current_theme['text_dim']};"
                )
            else:
                p2.setStyleSheet(
                    f"background-color: {self.current_theme['accent']}; color: white; border: none;"
                )

        p3 = self.phase_buttons.get("phase3")
        if p3:
            p3.setEnabled(self.phase2_done)
            p3.setText(
                "🔒 Locked (Run Phase 2)" if not self.phase2_done else "▶ Start Module"
            )
            p3.setIcon(
                self.style().standardIcon(QStyle.SP_BrowserReload)
                if self.phase2_done
                else QIcon()
            )
            if not self.phase2_done:
                p3.setStyleSheet(
                    f"background-color: {self.current_theme['panel_bg']}; border: 1px solid {self.current_theme['border']}; color: {self.current_theme['text_dim']};"
                )
            else:
                p3.setStyleSheet(
                    f"background-color: {self.current_theme['accent']}; color: white; border: none;"
                )

        # 🔒 Update phase lock indicator
        if self.phase1_done and not self.phase2_done:
            self.phase_lock_lbl.setText("P2 🔓 | P3 🔒")
            self.phase_lock_lbl.setStyleSheet(
                "color: #facc15; font-weight: bold;")
        elif self.phase2_done:
            self.phase_lock_lbl.setText("P2 🔓 | P3 🔓")
            self.phase_lock_lbl.setStyleSheet(
                "color: #22c55e; font-weight: bold;")
        else:
            self.phase_lock_lbl.setText("P2 🔒 | P3 🔒")
            self.phase_lock_lbl.setStyleSheet(
                "color: #ef4444; font-weight: bold;")

    def _apply_payload(self):
        if not self.vuln_data:
            QMessageBox.warning(self, "No Data", "No findings available.")
            return

        cat = self.payload_category_cb.currentText()
        payload = (
            self.payload_input.text()
            or random.choice(PAYLOAD_PRESETS.get(cat, [("test", 10)]))[0]
        )
        impact = 15
        target = self.vuln_data[0]
        target["confidence"] = min(100, target.get("confidence", 50) + impact)
        row = self.payload_history_table.rowCount()
        self.payload_history_table.insertRow(row)
        self.payload_history_table.setItem(
            row, 0, QTableWidgetItem(str(target["id"])))
        self.payload_history_table.setItem(row, 1, QTableWidgetItem(payload))
        self.payload_history_table.setItem(
            row, 2, QTableWidgetItem(f"{target['confidence']}%")
        )
        self.payload_history_table.setItem(
            row, 3, QTableWidgetItem(datetime.datetime.now().strftime("%H:%M"))
        )
        self._update_charts()
        self.statusBar().showMessage(f"Payload injected. Confidence updated.")

    def _inject_payload(self, ptype):
        payloads = {"sqli": "' OR '1'='1 --",
                    "xss": "<script>alert(1)</script>"}

        payload = payloads.get(ptype)
        if not payload:
            return

        tab = self.repeater_tabs.currentWidget()
        if not tab:
            self.statusBar().showMessage("⚠️ No active Repeater tab")
            return

        editors = tab.findChildren(QPlainTextEdit)
        if not editors:
            return

        req_editor = editors[0]

        cursor = req_editor.textCursor()

        # 🔥 BURP-LIKE CURSOR INSERT
        cursor.insertText(payload)

        req_editor.setTextCursor(cursor)
        req_editor.setFocus()

        self.statusBar().showMessage(f"Injected {ptype.upper()} at cursor")

    def _inject_param_payload(self, ptype):
        payloads = {"sqli": "' OR '1'='1 --",
                    "xss": "<script>alert(1)</script>"}

        payload = payloads.get(ptype)
        if not payload:
            return

        row = self.table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Repeater", "Select a finding first")
            return

        v = self.vuln_data[row]
        param = v.get("param")

        if not param:
            QMessageBox.warning(
                self, "Repeater", "No vulnerable parameter found")
            return

        tab = self.repeater_tabs.currentWidget()
        editors = tab.findChildren(QTextEdit)
        req_editor = editors[0]

        text = req_editor.toPlainText()

        # 🔥 Replace ONLY param=value
        import re

        pattern = rf"({param}=)([^&\s]+)"
        new_text, count = re.subn(pattern, rf"\1{payload}", text, count=1)

        if count == 0:
            QMessageBox.warning(
                self, "Repeater", "Parameter not found in request")
            return
        before = req_editor.toPlainText()
        self._show_request_diff(before, new_text)

        req_editor.setPlainText(new_text)
        self.statusBar().showMessage(f"Injected payload into parameter: {param}")

    def _show_request_diff(self, before, after):
        diff = []
        import difflib

        for line in difflib.unified_diff(
            before.splitlines(),
            after.splitlines(),
            fromfile="Original",
            tofile="Modified",
            lineterm="",
        ):
            diff.append(line)

        diff_text = "\n".join(diff)

        dlg = QMessageBox(self)
        dlg.setWindowTitle("Request Diff")
        dlg.setTextInteractionFlags(Qt.TextSelectableByMouse)
        dlg.setDetailedText(diff_text)
        dlg.setText("Request changed (Diff below)")
        dlg.exec()

    def _format_http_pretty(self, raw_text):
        if not raw_text:
            return ""

        lines = raw_text.splitlines()
        html = []

        for i, line in enumerate(lines):
            # Request / Status line
            if i == 0:
                html.append(
                    f"<span style='color:#38bdf8;font-weight:bold'>{line}</span>"
                )
                continue

            # Header lines
            if ":" in line:
                html.append(f"<span style='color:#9ca3af'>{line}</span>")
                continue

            # Empty line (header/body separator)
            if line.strip() == "":
                html.append("<br>")
                continue

            # Body
            html.append(f"<span style='color:#e5e7eb'>{line}</span>")

        return "<br>".join(html)

    def _store_req_res(self, vuln_id, request_text, response_text):
        if not vuln_id:
            return

        if vuln_id not in self.req_res_history:
            self.req_res_history[vuln_id] = []

        self.req_res_history[vuln_id].append(
            {
                "request": request_text,
                "response": response_text,
                "time": datetime.datetime.now().isoformat(),
            }
        )

    def _load_repeater_target(self):
        data = self.repeater_target_cb.currentData()

        if not isinstance(data, dict):
            return

        url = str(
            data.get("url", "")
            or ""
        ).strip()

        if not url:
            return

        method = str(
            data.get("method", "GET")
            or "GET"
        ).upper()

        parsed = urlparse(url)

        path = parsed.path or "/"

        if parsed.query:
            path += "?" + parsed.query

        host = parsed.netloc

        self.repeater_url.setText(
            url
        )

        if method not in [
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
            "HEAD",
            "OPTIONS",
        ]:
            method = "GET"

        self.repeater_method.setCurrentText(
            method
        )

        request = (
            f"{method} {path} HTTP/1.1\n"
            f"Host: {host}\n"
            f"User-Agent: AVAF-Repeater\n"
            f"Accept: */*\n"
            "\n"
        )

        request_editor, response_editor = (
            self._get_repeater_editors()
        )

        if request_editor is not None:
            request_editor.setPlainText(
                request
            )

        if response_editor is not None:
            response_editor.clear()

        self.statusBar().showMessage(
            "Finding loaded into Repeater."
        )

    def _store_repeater_history(self, request, response):
        if not hasattr(self, "repeater_history"):
            self.repeater_history = []

        self.repeater_history.append(
            {
                "time": datetime.datetime.now().strftime("%H:%M:%S"),
                "request": request,
                "response": response,
            }
        )

    def _send_repeater_request(self):
        """
        Execute the manually edited HTTP request.

        The Repeater is independent from Phase-2.
        It sends the request currently present in the
        active Repeater tab and displays the actual
        HTTP response in that same tab.
        """

        request_editor, response_editor = (
            self._get_repeater_editors()
        )

        if request_editor is None:
            QMessageBox.warning(
                self,
                "Repeater",
                "No active Repeater request."
            )
            return

        request_text = (
            request_editor.toPlainText()
            .replace("\r\n", "\n")
            .strip()
        )

        if not request_text:
            QMessageBox.warning(
                self,
                "Repeater",
                "Request is empty."
            )
            return

        # =========================================================
        # PARSE REQUEST
        # =========================================================

        lines = request_text.split("\n")

        if not lines:
            return

        request_line = lines[0].strip()
        parts = request_line.split()

        if len(parts) < 2:
            QMessageBox.warning(
                self,
                "Invalid HTTP Request",
                "First line must look like:\n\n"
                "GET /path HTTP/1.1"
            )
            return

        method = parts[0].upper()
        target = parts[1]

        # =========================================================
        # HEADERS + BODY
        # =========================================================

        header_lines = []
        body_lines = []

        separator_found = False

        for line in lines[1:]:

            if not separator_found:

                if line.strip() == "":
                    separator_found = True
                    continue

                header_lines.append(line)

            else:
                body_lines.append(line)

        headers = {}

        for line in header_lines:

            if ":" not in line:
                continue

            name, value = line.split(
                ":",
                1
            )

            name = name.strip()
            value = value.strip()

            if name:
                headers[name] = value

        body = "\n".join(
            body_lines
        )

        # =========================================================
        # URL
        # =========================================================

        url = self.repeater_url.text().strip()

        # If URL field is empty, build it from Host + request target.
        if not url:

            host = headers.get(
                "Host",
                ""
            ).strip()

            if not host:
                QMessageBox.warning(
                    self,
                    "Missing Target",
                    "Enter a target URL or provide a Host header."
                )
                return

            scheme = "https"

            url = (
                f"{scheme}://{host}"
                f"{target if target.startswith('/') else '/' + target}"
            )

        # =========================================================
        # NORMALIZE ABSOLUTE / RELATIVE TARGET
        # =========================================================

        if target.startswith(
            "http://"
        ) or target.startswith(
            "https://"
        ):
            url = target

        # =========================================================
        # UPDATE METHOD CONTROL
        # =========================================================

        if method in [
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
            "HEAD",
            "OPTIONS",
        ]:

            self.repeater_method.setCurrentText(
                method
            )

        # =========================================================
        # EXECUTE REAL HTTP REQUEST
        # =========================================================

        self.repeater_send_btn.setEnabled(
            False
        )

        self.statusBar().showMessage(
            f"Sending {method} request..."
        )

        QApplication.processEvents()

        started = datetime.datetime.now()

        try:

            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                data=body if body else None,
                timeout=15,
                verify=False,
                allow_redirects=False,
            )

            elapsed = (
                datetime.datetime.now()
                - started
            ).total_seconds()

            # =====================================================
            # BUILD RAW RESPONSE
            # =====================================================

            response_lines = []

            response_lines.append(
                f"HTTP/{response.raw.version / 10:.1f} "
                f"{response.status_code} "
                f"{response.reason}"
            )

            for name, value in response.headers.items():

                response_lines.append(
                    f"{name}: {value}"
                )

            response_lines.append("")

            try:
                response_body = response.text
            except Exception:
                response_body = (
                    response.content.decode(
                        "utf-8",
                        errors="replace"
                    )
                )

            response_lines.append(
                response_body
            )

            response_text = "\n".join(
                response_lines
            )

            # =====================================================
            # DISPLAY RESPONSE IN CURRENT TAB
            # =====================================================

            if response_editor is not None:
                response_editor.setPlainText(
                    response_text
                )

            # =====================================================
            # STORE HISTORY
            # =====================================================

            self._store_repeater_history(
                request_text,
                response_text
            )

            # =====================================================
            # ALSO STORE FINDING TRAFFIC WHEN APPLICABLE
            # =====================================================

            row = -1

            if hasattr(
                self,
                "table"
            ):
                row = self.table.currentRow()

            if (
                row >= 0
                and row < len(
                    getattr(
                        self,
                        "vuln_data",
                        []
                    )
                )
            ):

                vuln = self.vuln_data[row]
                vuln_id = vuln.get("id")

                if vuln_id:

                    self._store_req_res(
                        vuln_id,
                        request_text,
                        response_text
                    )

            # =====================================================
            # LOG
            # =====================================================

            self.log(
                (
                    f"Repeater {method} "
                    f"{url} -> "
                    f"{response.status_code} "
                    f"({elapsed:.3f}s)"
                ),
                level="INFO",
                source="REPEATER",
                event_type="HTTP",
            )

            self.statusBar().showMessage(
                (
                    f"{response.status_code} "
                    f"{response.reason} "
                    f"• {elapsed:.3f}s"
                )
            )

        except requests.exceptions.RequestException as exc:

            error_text = (
                "AVAF Repeater Error\n"
                "===================\n\n"
                f"{type(exc).__name__}: {exc}"
            )

            if response_editor is not None:
                response_editor.setPlainText(
                    error_text
                )

            self.log(
                f"Repeater request failed: {exc}",
                level="ERROR",
                source="REPEATER",
                event_type="HTTP",
            )

            self.statusBar().showMessage(
            
                "Repeater request failed."
            )

        except Exception as exc:

            if response_editor is not None:
                response_editor.setPlainText(
                    f"Unexpected Repeater error:\n\n{exc}"
                )

            print(
                "[REPEATER ERROR]",
                repr(exc),
                flush=True
            )

        finally:

            self.repeater_send_btn.setEnabled(
                True
            )

    def _handle_repeater_response(self, body, headers, status):
        tab = QWidget()
        layout = QHBoxLayout(tab)

        # -------- REQUEST VIEW --------
        req_box = QGroupBox("Request")
        req_layout = QVBoxLayout(req_box)

        req_view = QPlainTextEdit()
        req_view.setObjectName("Traffic")
        req_view.setReadOnly(True)

        req_view.setPlainText(self.repeater_request.toPlainText())
        req_layout.addWidget(req_view)

        # -------- RESPONSE VIEW --------
        res_box = QGroupBox("Response")
        res_layout = QVBoxLayout(res_box)

        res_view = QPlainTextEdit()
        res_view.setObjectName("Traffic")
        res_view.setReadOnly(True)

        response_text = f"""HTTP/1.1 {status}
    
    {headers}
    
    {body}
    """

        res_view.clear()
        cursor = res_view.textCursor()

        fmt_header = QTextCharFormat()
        fmt_header.setForeground(QColor("#60a5fa"))  # blue

        fmt_body = QTextCharFormat()
        fmt_body.setForeground(QColor("#e5e7eb"))  # white

        headers_part, body_part = response_text.split("\n\n", 1)
        cursor.setCharFormat(fmt_header)
        cursor.insertText(headers_part + "\n\n")
        cursor.setCharFormat(fmt_body)
        cursor.insertText(body_part)

        res_layout.addWidget(res_view)

        layout.addWidget(req_box)
        layout.addWidget(res_box)

        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        tab_index = self.repeater_tabs.addTab(
            tab, f"#{self.repeater_tabs.count()+1} {timestamp}"
        )
        self.repeater_tabs.setCurrentIndex(tab_index)

    def load_data(self):
        print("[GUI] load_data() called", flush=True)
        """
        SINGLE-SOURCE, SAFE loader
        Phase-2 → Findings → MITRE → CVSS → Heatmap
        """

        # =====================================================
        # 1️⃣ LOAD PHASE-2 VULNERABILITIES (ONCE)
        # =====================================================
        vuln_path = os.path.join(
            PROJECT_ROOT,
            "phase2_refinement_validation",
            "output",
            "vulnerabilities.json",
        )

        self.vuln_data = []   # ✅ initialize ONCE
        self.current_vuln_index = None

        print("[DEBUG] Vulnerability path:", vuln_path)
        print("[DEBUG] Exists:", os.path.exists(vuln_path))

        if os.path.exists(vuln_path) and os.path.getsize(vuln_path) > 0:
            try:
                with open(vuln_path, "r", encoding="utf-8") as f:
                    raw = json.load(f)

                # 🔥 NORMALIZE FORMAT (THIS IS THE CORE FIX)
                if isinstance(raw, dict):
                    self.vuln_data = (
                        raw.get("vulnerabilities")
                        or raw.get("findings")
                        or raw.get("results")
                        or []
                    )
                elif isinstance(raw, list):
                    self.vuln_data = raw

                print("[DEBUG] Normalized vuln count:", len(self.vuln_data))

                # =====================================================
                # 🔥 AUTO-GENERATE CVSS FOR LOADED FINDINGS
                # =====================================================

                for idx, vuln in enumerate(self.vuln_data):

                    # Skip findings already having CVSS
                    if "cvss_score" in vuln:
                        continue

                    # Temporary active finding
                    self.current_vuln_index = idx

                    # Safe default CVSS metrics
                    default_cvss = {
                        "Attack Vector": 2,        # Network
                        "Complexity": 1,           # Low
                        "Privileges": 2,           # None
                        "User Interaction": 1,     # None
                        "Confidentiality": 1,      # Low
                        "Integrity": 1,            # Low
                        "Availability": 1,         # Low
                    }

                    vuln["cvss"] = default_cvss

                    # Sync dropdowns with values
                    for metric, value in default_cvss.items():
                        if metric in self.cvss_cbs:
                            self.cvss_cbs[metric].setCurrentIndex(value)

                    # Generate score/vector/severity
                    self._calc_cvss()

                # Restore first finding selection
                if self.vuln_data:
                    self.current_vuln_index = 0

            except Exception as e:
                print("[ERROR] Failed loading vulnerabilities:", e)
                self.vuln_data = []

        # =====================================================
        # 2️⃣ AUTO-SELECT FIRST FINDING (CRITICAL)
        # =====================================================
        if self.vuln_data:
            self.current_vuln_index = 0

        # =====================================================
        # 3️⃣ CVSS HEATMAP (SAFE)
        # =====================================================
        if hasattr(self, "cvss_heatmap"):
            self.cvss_heatmap.clear()

            sev_map = {
                "critical": 9.5,
                "high": 8.0,
                "medium": 5.5,
                "low": 3.0,
            }

            for v in self.vuln_data:
                sev = sev_map.get(
                    v.get("severity", "").lower(), 5.0
                )
                conf = v.get("confidence", 50) / 100.0
                self.cvss_heatmap.add_point(sev, conf)

        # =====================================================
        # 5️⃣ REFRESH UI (ORDER MATTERS)
        # =====================================================
        self._populate_findings_table()

        if self.current_vuln_index is not None:
            self._update_mitre_view()

        self._update_charts()

    def _load_phase1_findings(self):
        """
        Loads Phase-1 parameter discovery results
        and populates the Findings list/table.
        """

        p1_path = os.path.join(
            PROJECT_ROOT,
            "phase1_scanning_detection",
            "output",
            "parameter_candidates.json",
        )

        if not os.path.exists(p1_path):
            print("[GUI] Phase-1 findings file not found")
            return

        try:
            with open(p1_path, "r", encoding="utf-8") as f:
                findings = json.load(f)
        except Exception as e:
            print("[GUI] Failed to load Phase-1 findings:", e)
            return

        # Store for reuse
        self.phase1_findings = findings

        # 🔥 CLEAR DISCOVERY TABLE FIRST
        self.discovery_table.setRowCount(0)

        for row, item in enumerate(findings):
            self.discovery_table.insertRow(row)

            self.discovery_table.setItem(
                row, 0, QTableWidgetItem(
                    item.get("parameter", item.get("param", "")))
            )

            self.discovery_table.setItem(
                row, 1, QTableWidgetItem(item.get("location", ""))
            )

            self.discovery_table.setItem(
                row, 2, QTableWidgetItem(item.get("method", ""))
            )

            self.discovery_table.setItem(
                row, 3, QTableWidgetItem(item.get("url", "")))

            self.discovery_table.setItem(row, 4, QTableWidgetItem("Phase 1"))

        print(f"[GUI] Phase-1 findings loaded: {len(findings)}")

        self.lbl_vulns.value_label.setText(
            str(len(findings))
        )

        self.lbl_high.value_label.setText("0")

        self.lbl_conf.value_label.setText("N/A")

    def _apply_severity_filter(self):

        self._populate_findings_table()

        # ---------- Populate Repeater Targets ----------
        if hasattr(self, "repeater_target_cb"):
            self.repeater_target_cb.clear()
            for v in self.vuln_data:
                label = f"{v.get('type')} | {v.get('url')}"
                self.repeater_target_cb.addItem(label, v)

    def _populate_findings_table(self):
        if not hasattr(self, "table"):
            print("[DEBUG] Findings table not initialized yet")
            return

        print(f"[DEBUG] Populating table with {len(self.vuln_data)} findings")

        self.table.setRowCount(0)

        for v in self.vuln_data:
            severity = (v.get("severity") or "").lower()

            cvss = float(v.get("cvss_score", 0.0))

            # 🔍 Search filter (searches EVERYTHING)
            if self.search_query:
                blob = json.dumps(v).lower()
                if self.search_query not in blob:
                    continue

            # 🔽 Severity filter
            selected = self.severity_filter.currentText()
            if selected != "All":
                if v.get("severity", "").lower() != selected.lower():
                    continue

            row = self.table.rowCount()
            self.table.insertRow(row)

            fields = [
                str(v.get("id", "")),
                v.get("type", ""),
                v.get("severity", ""),
                f"{cvss}",  # CVSS
                f"{v.get('confidence', 0)}%",  # Confidence
                v.get("url", ""),
            ]

            for col, text in enumerate(fields):
                item = QTableWidgetItem(text)

                # ✨ Highlight search match
                if self.search_query and self.search_query in text.lower():
                    item.setBackground(QColor("#2563eb"))
                    item.setForeground(QColor("white"))

                self.table.setItem(row, col, item)

            # 🎨 Severity-based row coloring (ONLY ONCE)
            sev = v.get("severity", "").lower()

            if sev in ("high", "critical"):
                row_color = QColor(239, 68, 68, 60)
            elif sev == "medium":
                row_color = QColor(245, 158, 11, 60)
            elif sev == "low":
                row_color = QColor(34, 197, 94, 60)
            else:
                row_color = None

            if row_color:
                for col in range(self.table.columnCount()):
                    item = self.table.item(row, col)
                    if item:
                        item.setBackground(row_color)

            cvss_item = self.table.item(row, 3)

            if cvss >= 9.0:
                cvss_item.setForeground(QColor("#ef4444"))  # Critical
            elif cvss >= 7.0:
                cvss_item.setForeground(QColor("#f97316"))  # High
            elif cvss >= 4.0:
                cvss_item.setForeground(QColor("#facc15"))  # Medium
            else:
                cvss_item.setForeground(QColor("#22c55e"))  # Low

    def _on_finding_clicked(self, row, column):
        """
        Open a finding and synchronize:
            Findings -> selected vulnerability -> CVSS -> MITRE -> traffic

        CVSS is restored from stored finding data.
        After Phase-2, CVSS remains read-only.
        """

        # =========================================================
        # 1. BASIC SAFETY
        # =========================================================

        if not hasattr(self, "vuln_data"):
            print("[CVSS] vuln_data does not exist", flush=True)
            return

        if not hasattr(self, "table"):
            print("[CVSS] findings table does not exist", flush=True)
            return

        if row < 0 or row >= self.table.rowCount():
            print(f"[CVSS] Invalid table row: {row}", flush=True)
            return

        # =========================================================
        # 2. FIND THE REAL VULNERABILITY
        #
        # The table may be filtered/sorted, so do NOT blindly assume
        # table row == vuln_data index.
        # =========================================================

        vuln_index = None

        # ID is column 0
        id_item = self.table.item(row, 0)

        if id_item:
            selected_id = id_item.text().strip()

            for i, item in enumerate(self.vuln_data):
                if not isinstance(item, dict):
                    continue

                if str(item.get("id", "")).strip() == selected_id:
                    vuln_index = i
                    break

        # Fallback only if ID matching failed
        if vuln_index is None:
            if row < len(self.vuln_data):
                vuln_index = row
            else:
                print(
                    f"[CVSS] Could not resolve table row {row}",
                    flush=True,
                )
                return

        # =========================================================
        # 3. SET ACTIVE FINDING
        # =========================================================

        self.current_vuln_index = vuln_index

        v = self.vuln_data[vuln_index]

        if not isinstance(v, dict):
            print("[CVSS] Selected finding is not a dictionary", flush=True)
            return

        print(
            "[FINDING] Selected:",
            v.get("id"),
            flush=True,
        )

        # =========================================================
        # 4. SWITCH TO CVSS PAGE
        # =========================================================

        if hasattr(self, "pages") and "cvss" in self.pages:
            self.stack.setCurrentWidget(
                self.pages["cvss"]
            )

        # =========================================================
        # 5. READ STORED CVSS DATA
        # =========================================================

        cvss_data = v.get("cvss", {})

        if not isinstance(cvss_data, dict):
            cvss_data = {}

        # =========================================================
        # 6. CVSS METRIC ALIASES
        #
        # Supports BOTH:
        #
        #   AV / AC / PR / UI / C / I / A
        #
        # and:
        #
        #   Attack Vector / Complexity / ...
        # =========================================================

        aliases = {
            "AV": "Attack Vector",
            "Attack Vector": "Attack Vector",

            "AC": "Complexity",
            "Complexity": "Complexity",

            "PR": "Privileges",
            "Privileges": "Privileges",

            "UI": "User Interaction",
            "User Interaction": "User Interaction",

            "C": "Confidentiality",
            "Confidentiality": "Confidentiality",

            "I": "Integrity",
            "Integrity": "Integrity",

            "A": "Availability",
            "Availability": "Availability",
        }

        # =========================================================
        # 7. PREPARE METRIC VALUES
        # =========================================================

        restored_metrics = {}

        for stored_key, stored_value in cvss_data.items():

            full_key = aliases.get(
                str(stored_key).strip()
            )

            if not full_key:
                continue

            try:
                restored_metrics[full_key] = int(
                    stored_value
                )
            except (TypeError, ValueError):
                continue

        # =========================================================
        # 8. FALLBACK: READ METRICS FROM CVSS VECTOR
        #
        # This is important for findings where:
        #
        #   cvss_score
        #   cvss_severity
        #   cvss_vector
        #
        # exist but cvss{} is missing/incomplete.
        #
        # Example:
        #
        # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        # =========================================================

        vector = str(
            v.get("cvss_vector", "")
            or ""
        ).strip()

        vector_values = {}

        if vector.startswith("CVSS:3.1/"):

            parts = vector.split("/")[1:]

            for part in parts:

                if ":" not in part:
                    continue

                key, value = part.split(
                    ":",
                    1
                )

                vector_values[
                    key.strip().upper()
                ] = value.strip().upper()

        # =========================================================
        # 9. CONVERT VECTOR VALUES -> COMBO INDEX
        # =========================================================

        vector_to_index = {

            "AV": {
                "P": 0,
                "L": 1,
                "N": 2,
            },

            "AC": {
                "H": 0,
                "L": 1,
            },

            "PR": {
                "H": 0,
                "L": 1,
                "N": 2,
            },

            "UI": {
                "R": 0,
                "N": 1,
            },

            "C": {
                "N": 0,
                "L": 1,
                "H": 2,
            },

            "I": {
                "N": 0,
                "L": 1,
                "H": 2,
            },

            "A": {
                "N": 0,
                "L": 1,
                "H": 2,
            },
        }

        vector_aliases = {
            "AV": "Attack Vector",
            "AC": "Complexity",
            "PR": "Privileges",
            "UI": "User Interaction",
            "C": "Confidentiality",
            "I": "Integrity",
            "A": "Availability",
        }

        # Only use vector as fallback
        for short_key, vector_value in vector_values.items():

            full_key = vector_aliases.get(
                short_key
            )

            if not full_key:
                continue

            if full_key in restored_metrics:
                continue

            index_map = vector_to_index.get(
                short_key
            )

            if not index_map:
                continue

            if vector_value in index_map:
                restored_metrics[full_key] = (
                    index_map[vector_value]
                )

        # =========================================================
        # 10. RESTORE CVSS DROPDOWNS
        # =========================================================

        if hasattr(self, "cvss_cbs"):

            # Block signals so changing the dropdowns does NOT call
            # _calc_cvss() seven times while restoring the finding.

            for metric, cb in self.cvss_cbs.items():

                try:
                    cb.blockSignals(True)

                    # Reset first
                    cb.setCurrentIndex(0)

                    # Restore stored/vector value
                    if metric in restored_metrics:

                        index = restored_metrics[metric]

                        if 0 <= index < cb.count():
                            cb.setCurrentIndex(index)

                finally:
                    cb.blockSignals(False)

                # CVSS becomes read-only after Phase-2
                cb.setEnabled(
                    not getattr(
                        self,
                        "phase2_done",
                        False
                    )
                )

        # =========================================================
        # 11. RESTORE STORED SCORE
        # =========================================================

        stored_score = v.get(
            "cvss_score"
        )

        if stored_score is None:

            nested_score = cvss_data.get(
                "score"
            )

            if nested_score is not None:
                stored_score = nested_score

        if stored_score is None:
            stored_score = 0.0

        # =========================================================
        # 12. RESTORE SEVERITY
        # =========================================================

        stored_severity = v.get(
            "cvss_severity"
        )

        if not stored_severity:
            stored_severity = v.get(
                "severity",
                "Unknown"
            )

        # =========================================================
        # 13. UPDATE SCORE LABEL
        # =========================================================

        if hasattr(self, "cvss_res"):

            self.cvss_res.setText(
                f"Score: {stored_score} ({stored_severity})"
            )

            severity_lower = str(
                stored_severity
            ).lower()

            if severity_lower == "critical":
                color = self.current_theme.get(
                    "danger",
                    "#ef4444"
                )

            elif severity_lower == "high":
                color = self.current_theme.get(
                    "danger",
                    "#f97316"
                )

            elif severity_lower == "medium":
                color = self.current_theme.get(
                    "warning",
                    "#facc15"
                )

            elif severity_lower == "low":
                color = self.current_theme.get(
                    "success",
                    "#22c55e"
                )

            else:
                color = self.current_theme.get(
                    "text",
                    "#ffffff"
                )

            self.cvss_res.setStyleSheet(
                f"""
                font-size: 24pt;
                font-weight: bold;
                color: {color};
                """
            )

        # =========================================================
        # 14. DEBUG OUTPUT
        # =========================================================

        print(
            "[CVSS] Finding:",
            v.get("id"),
            "| score=",
            stored_score,
            "| severity=",
            stored_severity,
            "| vector=",
            vector,
            "| metrics=",
            restored_metrics,
            flush=True,
        )

        # =========================================================
        # 15. MITRE
        # =========================================================

        try:
            self._update_mitre_view()
        except Exception as exc:
            print(
                "[MITRE] Update error:",
                exc,
                flush=True,
            )

        # =========================================================
        # 16. REQUEST / RESPONSE HISTORY
        # =========================================================

        if hasattr(
            self,
            "req_res_view"
        ):

            vuln_id = v.get("id")

            history = self.req_res_history.get(
                vuln_id,
                []
            )

            self.req_res_view.clear()

            cursor = self.req_res_view.textCursor()

            fmt_req = QTextCharFormat()
            fmt_req.setForeground(
                QColor("#60a5fa")
            )

            fmt_res = QTextCharFormat()
            fmt_res.setForeground(
                QColor("#22c55e")
            )

            fmt_normal = QTextCharFormat()

            for i, h in enumerate(
                history,
                1
            ):

                cursor.insertText(
                    f"\n===== Interaction {i} "
                    f"({h.get('time', '')}) =====\n\n"
                )

                # REQUEST
                cursor.setCharFormat(
                    fmt_req
                )

                cursor.insertText(
                    "----- REQUEST -----\n"
                )

                cursor.setCharFormat(
                    fmt_normal
                )

                req = h.get(
                    "request",
                    ""
                )

                cursor.insertText(
                    req + "\n\n"
                )

                # RESPONSE
                cursor.setCharFormat(
                    fmt_res
                )

                cursor.insertText(
                    "----- RESPONSE -----\n"
                )

                cursor.setCharFormat(
                    fmt_normal
                )

                res = h.get(
                    "response",
                    ""
                )

                cursor.insertText(
                    res + "\n"
                )

        print(
            "[FINDING] CVSS synchronization complete",
            flush=True,
        )

    def _send_selected_to_repeater(self):
        row = self.table.currentRow()

        if row < 0 or row >= len(self.vuln_data):
            QMessageBox.warning(self, "No Selection",
                                "Please select a finding first.")
            return

        v = self.vuln_data[row]

        vid = v.get("id")

        history = self.req_res_history.get(vid, [])

        # --------------------------------------------------
        # Use captured Phase-2 traffic when available
        # --------------------------------------------------
        if history:
            request_raw = history[0].get("request", "")
        else:
            # --------------------------------------------------
            # No captured Phase-2 traffic:
            # build a request from the finding itself.
            #
            # This is NOT a vulnerability result and does NOT
            # fabricate a response. It only wires the finding
            # into the Repeater request editor.
            # --------------------------------------------------
            from urllib.parse import urlparse

            url = v.get("url", "")
            method = v.get("method", "GET") or "GET"

            parsed = urlparse(url)

            path = parsed.path or "/"

            if parsed.query:
                path += "?" + parsed.query

            host = parsed.netloc

            request_raw = (
                f"{method} {path} HTTP/1.1\n"
                f"Host: {host}\n"
                f"User-Agent: AVAF-Repeater\n"
                f"Accept: */*\n"
                "\n"
            )

        # 🔹 Extract URL safely
        url = v.get("url", "")

        # Try extracting from request line if possible
        first_line = request_raw.splitlines()[0] if request_raw else ""
        if first_line.startswith(("GET", "POST", "PUT", "DELETE")):
            try:
                parts = first_line.split()
                if len(parts) >= 2:
                    path = parts[1]
                    if url and path.startswith("/"):
                        # combine scheme + host + path
                        from urllib.parse import urlparse

                        parsed = urlparse(url)
                        url = f"{parsed.scheme}://{parsed.netloc}{path}"
            except Exception:
                pass

        # Fill repeater URL field
        if hasattr(self, "repeater_url"):
            self.repeater_url.setText(url)

        request_editor, response_editor = (
            self._get_repeater_editors()
        )

        if request_editor is not None:
            request_editor.setPlainText(
                request_raw
            )

        if response_editor is not None:
            response_editor.clear()

            self.statusBar().showMessage
            (
        "📡 Finding loaded into Repeater")

    def _search_req_res(self):
        keyword = self.rr_search_input.text().strip().lower()

        if not keyword:
            return

        self.table.clearSelection()

        for row, v in enumerate(self.vuln_data):
            vuln_id = v.get("id")
            history = self.req_res_history.get(vuln_id, [])

            for entry in history:
                req = entry.get("request", "").lower()
                res = entry.get("response", "").lower()

                if keyword in req or keyword in res:
                    self.table.selectRow(row)
                    self.table.scrollToItem(self.table.item(row, 0))
                    return

        QMessageBox.information(
            self, "No Match", f"No request/response contains: {keyword}"
        )

    def _export_selected_vuln_pdf(self):
        selected = self.table.currentRow()

        if selected < 0 or selected >= len(self.vuln_data):
            QMessageBox.warning(self, "No Selection",
                                "Select a vulnerability first.")
            return

        v = self.vuln_data[selected]
        vuln_id = v.get("id")
        history = self.req_res_history.get(vuln_id, [])

        fn, _ = QFileDialog.getSaveFileName(
            self,
            "Save Vulnerability Report",
            f"vuln_{vuln_id}.pdf",
            "PDF Files (*.pdf)",
        )

        if not fn:
            return

        from reportlab.pdfgen import canvas

        c = canvas.Canvas(fn)
        textobject = c.beginText(40, 800)

        # ---- BASIC DETAILS ----
        textobject.textLine(f"ID: {v.get('id')}")
        textobject.textLine(f"Type: {v.get('type')}")
        textobject.textLine(f"Severity: {v.get('severity')}")
        textobject.textLine(f"URL: {v.get('url')}")
        textobject.textLine(f"Parameter: {v.get('param', '')}")
        textobject.textLine(f"Confidence: {v.get('confidence', '')}%")
        textobject.textLine("")

        # ---- REQUEST / RESPONSE HISTORY ----
        textobject.textLine("Request / Response History")
        textobject.textLine("-" * 40)

        if not history:
            textobject.textLine("No request/response history recorded.")
        else:
            for i, h in enumerate(history, 1):
                textobject.textLine(f"Interaction {i} ({h['time']}):")
                textobject.textLine("REQUEST:")
                for line in h["request"].splitlines():
                    textobject.textLine(line)

                textobject.textLine("")
                textobject.textLine("RESPONSE:")
                for line in h["response"].splitlines():
                    textobject.textLine(line)

                textobject.textLine("-" * 40)

        c.drawText(textobject)
        c.save()
        QMessageBox.information(
            self, "Exported", "PDF report exported successfully.")

    def _setup_matplotlib_axis(self, ax):
        ax.set_facecolor("#1A1D27")

        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['left'].set_visible(False)
        ax.spines['bottom'].set_color('#2A3042')

        ax.tick_params(colors="#8A92A6")
        ax.yaxis.grid(True, linestyle="-", color="#2A3042", alpha=0.3)

        ax.set_axisbelow(True)

    def draw_wave_chart(self, labels, values):

        self.fig_wave.clear()
        ax = self.fig_wave.add_subplot(111)

        self._setup_matplotlib_axis(ax)
        self.fig_wave.set_facecolor("#1D2231")

        if not values:
            return

        x = np.arange(len(labels))
        y = np.array(values)

        # Smooth curve
        x_smooth = np.linspace(x.min(), x.max(), 300)
        spline = make_interp_spline(x, y, k=3)
        y_smooth = spline(x_smooth)

        # Glow layers
        ax.plot(x_smooth, y_smooth, linewidth=8, alpha=0.05, color="#00D2FF")
        ax.plot(x_smooth, y_smooth, linewidth=6, alpha=0.08, color="#00D2FF")
        ax.plot(x_smooth, y_smooth, linewidth=3, color="#00D2FF")

        ax.fill_between(x_smooth, y_smooth, color="#00D2FF", alpha=0.15)

        ax.set_xticks(x)
        ax.set_xticklabels(labels, color="#8A92A6")

        ax.set_title("Threat Trend Overview",
                     fontsize=18,
                     color="white",
                     fontweight="bold")

        self.cv_wave.draw()

    def draw_histogram(self, labels, values):

        self.fig_hist.clear()
        ax = self.fig_hist.add_subplot(111)

        self._setup_matplotlib_axis(ax)
        self.fig_hist.set_facecolor("#1D2231")

        x = np.arange(len(labels))

        bars = ax.bar(x, values,
                      color="#FF007C",
                      edgecolor="white",
                      linewidth=1.2)

        for bar in bars:
            bar.set_alpha(0.95)

        ax.set_xticks(x)
        ax.set_xticklabels(labels, color="#8A92A6")

        ax.set_title("Attack Histogram",
                     fontsize=18,
                     color="white",
                     fontweight="bold")

        self.cv_hist.draw()

    def _update_donut_chart(self, dashboard):

        if self.fig_conf is None:
            return

        self.fig_conf.clear()

        ax = self.fig_conf.add_subplot(111)

        self.wave_engine.render_severity_ring(
            ax=ax,
            dashboard=dashboard
        )

    def _update_phase1_heatmap(self):
        p1_path = os.path.join(
            PROJECT_ROOT,
            "phase1_scanning_detection",
            "output",
            "parameter_candidates.json",
        )

        if not os.path.exists(p1_path):
            return

        with open(p1_path, "r", encoding="utf-8") as f:
            params = json.load(f)

        buckets = {}
        for p in params:
            url = p.get("url")
            buckets.setdefault(url, 0)
            buckets[url] += 1

        matrix = [[0, 0, 0], [0, 0, 0], [0, 0, 0]]

        for count in buckets.values():
            y = 2 if count >= 7 else 1 if count >= 3 else 0
            x = y
            matrix[y][x] += 1

        if hasattr(self, "animated_heatmap"):
            self.animated_heatmap.update_matrix(matrix)

    def _open_html_report(self):
        report_path = os.path.join(PHASE3_DIR, "output", "report.html")

        if not os.path.exists(report_path):
            QMessageBox.warning(self, "Report Missing", "Run Phase 3 first.")
            return

        self.report_view.load(QUrl.fromLocalFile(report_path))
        QDesktopServices.openUrl(QUrl.fromLocalFile(report_path))

    def _perform_search(self):
        self.search_query = self.search_input.text().strip().lower()
        self._populate_findings_table()

        # =====================================================
        # REPEATER TARGETS ← FINDINGS
        # =====================================================

        if hasattr(self, "repeater_target_cb"):
            self.repeater_target_cb.clear()

            for vuln in self.vuln_data:
                label = (
                    f"{vuln.get('type', 'Unknown')} | "
                    f"{vuln.get('url', '')}"
                )

                self.repeater_target_cb.addItem(
                    label,
                    vuln
                )

    def _export_csv(self):
        if not self.vuln_data:
            QMessageBox.warning(
                self, "No Data", "No vulnerabilities to export.")
            return

        fn, _ = QFileDialog.getSaveFileName(
            self, "Export Findings to CSV", "vulnerabilities.csv", "CSV Files (*.csv)"
        )

        if not fn:
            return

        try:
            with open(fn, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(
                    [
                        "ID",
                        "Type",
                        "Severity",
                        "URL",
                        "Parameter",
                        "Confidence",
                        "Details",
                    ]
                )

                for v in self.vuln_data:
                    writer.writerow(
                        [
                            v.get("id", ""),
                            v.get("type", ""),
                            v.get("severity", ""),
                            v.get("url", ""),
                            v.get("param", ""),
                            v.get("confidence", ""),
                            v.get("details", ""),
                        ]
                    )

            QMessageBox.information(
                self, "Export Successful", f"CSV exported successfully:\n{fn}"
            )

        except Exception as e:
            QMessageBox.critical(self, "Export Failed", str(e))

    def _export_siem_csv(self):
        if not hasattr(self, "log_entries") or not self.log_entries:
            QMessageBox.warning(self, "SIEM Export",
                                "No SIEM events to export.")
            return

        fn, _ = QFileDialog.getSaveFileName(
            self, "Export SIEM Events", "siem_events.csv", "CSV Files (*.csv)"
        )

        if not fn:
            return

        try:
            with open(fn, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(
                    ["Time", "Source", "Event Type", "Level", "Message"])

                for e in self.log_entries:
                    writer.writerow(
                        [
                            e["time"],
                            e["source"],
                            e["event_type"],
                            e["level"],
                            e["message"],
                        ]
                    )

            QMessageBox.information(
                self, "Exported", "SIEM events exported successfully."
            )

        except Exception as e:
            QMessageBox.critical(self, "Export Failed", str(e))

    def _export_full_report_pdf(self):
        if not self.phase3_done:
            QMessageBox.warning(self, "Locked", "Run Phase-3 first.")
            return
        if not self.phase3_done:
            QMessageBox.warning(
                self,
                "Locked",
                "Phase-3 must be completed before exporting the full report.",
            )
            return

        if not self.vuln_data:
            QMessageBox.warning(self, "No Data", "No findings to export.")
            return

        fn, _ = QFileDialog.getSaveFileName(
            self,
            "Export Full Scan Report",
            "AVAF_Full_Scan_Report.pdf",
            "PDF Files (*.pdf)",
        )
        if not fn:
            return

        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import A4

        c = canvas.Canvas(fn, pagesize=A4)
        width, height = A4

        # =========================================================
        # 1️⃣ TITLE PAGE
        # =========================================================
        c.setFont("Helvetica-Bold", 24)
        c.drawCentredString(width / 2, height - 120, "AVAF Pro")
        c.setFont("Helvetica", 16)
        c.drawCentredString(
            width / 2, height - 170, "Advanced Vulnerability Assessment Framework"
        )

        c.setFont("Helvetica", 12)
        c.drawCentredString(
            width / 2,
            height - 230,
            f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}",
        )

        c.showPage()  # END TITLE PAGE

        # =========================================================
        # 2️⃣ TABLE OF CONTENTS
        # =========================================================
        text = c.beginText(60, height - 80)
        text.setFont("Helvetica-Bold", 16)
        text.textLine("Table of Contents")
        text.textLine("")

        text.setFont("Helvetica", 11)
        text.textLine("1. Discovery Summary")
        text.textLine("2. Vulnerability Findings")
        text.textLine("3. HTTP Request / Response Evidence")

        c.drawText(text)
        c.showPage()

        # =========================================================
        # 3️⃣ DISCOVERY SUMMARY
        # =========================================================
        text = c.beginText(60, height - 80)
        text.setFont("Helvetica-Bold", 16)
        text.textLine("Discovery Summary")
        text.textLine("")

        text.setFont("Helvetica", 11)

        p1_path = os.path.join(PHASE1_DIR, "output",
                               "parameter_candidates.json")

        if os.path.exists(p1_path):
            with open(p1_path, "r", encoding="utf-8") as f:
                params = json.load(f)
            text.textLine(f"Total Parameters Discovered: {len(params)}")
        else:
            text.textLine("No Phase-1 discovery data found.")

        c.drawText(text)
        c.showPage()

        # =========================================================
        # 4️⃣ PER-FINDING DETAILED BLOCKS
        # =========================================================
        for idx, v in enumerate(self.vuln_data, 1):
            text = c.beginText(50, height - 60)
            text.setFont("Helvetica-Bold", 14)
            text.textLine(f"Finding #{idx}")
            text.textLine("")

            text.setFont("Helvetica", 11)
            text.textLine(f"ID: {v.get('id')}")
            text.textLine(f"Type: {v.get('type')}")
            text.textLine(f"Severity: {v.get('severity')}")
            text.textLine(f"CVSS Score: {v.get('cvss_score', 'N/A')}")
            text.textLine(f"CVSS Severity: {v.get('cvss_severity', 'N/A')}")
            text.textLine(f"CVSS Vector: {v.get('cvss_vector', 'N/A')}")
            text.textLine(f"URL: {v.get('url')}")
            text.textLine(f"Parameter: {v.get('parameter', '')}")
            text.textLine(f"Confidence: {v.get('confidence', '')}%")
            text.textLine("")

            # =====================================================
            # MITRE ATT&CK Mapping
            # =====================================================
            vtype = v.get("type", "Generic")
            mitre = MITRE_MAP.get(vtype, MITRE_MAP["Generic"])

            text.textLine("MITRE ATT&CK Mapping:")
            text.textLine(f"  Tactic: {mitre.get('Tactic')}")
            text.textLine(f"  Technique ID: {mitre.get('TID')}")
            text.textLine(f"  Technique Name: {mitre.get('Technique')}")
            text.textLine("")

            details = v.get("details", "")
            if details:
                text.textLine("Details:")
                for line in str(details).splitlines():
                    text.textLine(f"  {line}")

            text.textLine("")
            text.textLine("-" * 80)

            # =====================================================
            # HTTP TRAFFIC
            # =====================================================
            vid = v.get("id")
            history = self.req_res_history.get(vid, [])

            if history:
                for i, h in enumerate(history, 1):
                    text.textLine("")
                    text.textLine(f"Interaction {i}")
                    text.textLine("REQUEST:")
                    for line in h["request"].splitlines():
                        text.textLine(line)

                    text.textLine("")
                    text.textLine("RESPONSE:")
                    for line in h["response"].splitlines():
                        text.textLine(line)

                    text.textLine("-" * 60)
            else:
                text.textLine("No HTTP traffic recorded.")

            c.drawText(text)
            c.showPage()

        # =========================================================
        # SAVE PDF
        # =========================================================
        c.save()

        QMessageBox.information(self, "PDF Exported",
                                f"Full scan report saved:\n{fn}")

    def _calc_cvss(self):

        # 🔒 Prevent CVSS recalculation after Phase-2
        if hasattr(self, "phase2_done") and self.phase2_done:
            return

        """
        Live CVSS v3.1 Base Score calculator (simplified, academic-safe).
        Triggered whenever a CVSS metric dropdown changes.
        """

        if not hasattr(self, "current_vuln_index"):
            return

        idx = self.current_vuln_index
        if idx < 0 or idx >= len(self.vuln_data):
            return

        # =====================================================
        # 1️⃣ Read CVSS metric values from UI
        # =====================================================

        AV = [0.2, 0.55, 0.85][
            self.cvss_cbs["Attack Vector"].currentIndex()
        ]  # P / L / N
        AC = [0.77, 0.44][self.cvss_cbs["Complexity"].currentIndex()]  # H / L
        PR = [0.85, 0.62, 0.27][self.cvss_cbs["Privileges"].currentIndex()
                                ]  # H / L / N
        UI = [0.85, 0.62][self.cvss_cbs["User Interaction"].currentIndex()
                          ]  # R / N

        C = [0.0, 0.22, 0.56][self.cvss_cbs["Confidentiality"].currentIndex()]
        I = [0.0, 0.22, 0.56][self.cvss_cbs["Integrity"].currentIndex()]
        A = [0.0, 0.22, 0.56][self.cvss_cbs["Availability"].currentIndex()]

        # =====================================================
        # 2️⃣ CVSS v3.1 Base Score Formula
        # =====================================================

        ISS = 1 - ((1 - C) * (1 - I) * (1 - A))
        Impact = 6.42 * ISS
        Exploitability = 8.22 * AV * AC * PR * UI

        base_score = Impact + Exploitability
        final_score = round(min(base_score, 10.0), 1)

        # =====================================================
        # 3️⃣ Severity classification
        # =====================================================

        if final_score >= 9.0:
            severity = "Critical"
            color = self.current_theme["danger"]
        elif final_score >= 7.0:
            severity = "High"
            color = self.current_theme["danger"]
        elif final_score >= 4.0:
            severity = "Medium"
            color = self.current_theme["warning"]
        else:
            severity = "Low"
            color = self.current_theme["success"]

        # =====================================================
        # 4️⃣ CVSS Vector generation
        # =====================================================

        vector_map = {
            "Attack Vector": ["AV:P", "AV:L", "AV:N"],
            "Complexity": ["AC:H", "AC:L"],
            "Privileges": ["PR:H", "PR:L", "PR:N"],
            "User Interaction": ["UI:R", "UI:N", "UI:N"],
            "Confidentiality": ["C:N", "C:L", "C:H"],
            "Integrity": ["I:N", "I:L", "I:H"],
            "Availability": ["A:N", "A:L", "A:H"],
        }

        vector_parts = []
        for metric, cb in self.cvss_cbs.items():
            vector_parts.append(vector_map[metric][cb.currentIndex()])

        cvss_vector = "CVSS:3.1/" + "/".join(vector_parts)

        # =====================================================
        # 5️⃣ Update CVSS UI
        # =====================================================

        self.cvss_res.setText(f"Score: {final_score} ({severity})")
        self.cvss_res.setStyleSheet(
            f"font-size: 24pt; font-weight: bold; color: {color};"
        )

        # =====================================================
        # 6️⃣ Persist into vulnerability object + Phase-2 JSON
        # =====================================================

        self.vuln_data[idx]["cvss"] = {
            metric: cb.currentIndex() for metric, cb in self.cvss_cbs.items()
        }
        self.vuln_data[idx]["cvss_score"] = final_score
        self.vuln_data[idx]["cvss_severity"] = severity
        self.vuln_data[idx]["cvss_vector"] = cvss_vector
        # 🔥 LIVE HEATMAP + DASHBOARD SYNC
        self._update_charts()

        path = os.path.join(PHASE2_DIR, "output", "vulnerabilities.json")
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.vuln_data, f, indent=4)
        except Exception as e:
            print("[CVSS SAVE ERROR]", e)

        path = os.path.join(PHASE2_DIR, "output", "vulnerabilities.json")

    def _open_full_image(self, image_path):
        dialog = QDialog(self)
        dialog.setWindowTitle("Screenshot Viewer")
        dialog.resize(900, 600)

        layout = QVBoxLayout(dialog)

        lbl = QLabel()
        lbl.setStyleSheet("""
            border:1px solid #243244;
            border-radius:8px;
            background:#0b1220;
            padding:4px;
        """)
        pixmap = QPixmap(image_path)
        lbl.setPixmap(
            pixmap.scaled(850, 550, Qt.KeepAspectRatio,
                          Qt.SmoothTransformation)
        )
        lbl.setAlignment(Qt.AlignCenter)

        layout.addWidget(lbl)
        dialog.exec()

    def _load_phase3_report(self):
        report_path = os.path.join(
            PROJECT_ROOT,
            "phase3_evaluation_exploitation_reporting",
            "output",
            "report.html",
        )

        if not os.path.exists(report_path):
            return

        with open(report_path, "r", encoding="utf-8") as f:
            html = f.read()
        self.report_view.setHtml(html)
            
    def _refresh_email_page(self):
        """
        Refresh email-reporting status from real Phase-2/Phase-3 data.
        """
    
        if not hasattr(self, "email_target_label"):
            return
    
        target = ""
    
        try:
            target = self._get_saved_target() or ""
        except Exception:
            pass
    
        self.email_target_label.setText(
            target or "Not set"
        )
    
        findings = (
            self.vuln_data
            if isinstance(self.vuln_data, list)
            else []
        )
    
        confirmed = []
    
        for finding in findings:
    
            if not isinstance(finding, dict):
                continue
    
            status = str(
                finding.get("status", "")
            ).strip().lower()
    
            confidence = finding.get(
                "confidence",
                0,
            )
    
            try:
                confidence = float(confidence)
            except (TypeError, ValueError):
                confidence = 0
    
            if status in (
                "confirmed",
                "validated",
            ) or confidence >= 80:
    
                confirmed.append(
                    finding
                )
    
        self.email_findings_label.setText(
            str(len(confirmed))
        )
    
        if not self.phase3_done:
    
            self.email_status_label.setText(
                "🔒 Phase-3 must be completed first."
            )
    
            self.email_send_btn.setEnabled(
                False
            )
    
        elif not confirmed:
    
            self.email_status_label.setText(
                "⚠ No confirmed findings available."
            )
    
            self.email_send_btn.setEnabled(
                False
            )
    
        else:
    
            self.email_status_label.setText(
                "✅ Ready to send confirmed findings."
            )
    
            self.email_send_btn.setEnabled(
                True
            )
    
        if not self.email_subject.text().strip() and target:
    
            self.email_subject.setText(
                f"AVAF Pro Security Assessment Report - {target}"
            )
    
        if not self.email_message.toPlainText().strip() and target:
    
            self.email_message.setPlainText(
                "Security assessment completed.\n\n"
                f"Target: {target}\n"
                f"Confirmed findings: {len(confirmed)}\n\n"
                "Please review the attached AVAF Pro "
                "security assessment report."
            )
            
    def _test_email_smtp(self):
        """
        Test SMTP connectivity/authentication without sending a report.
        """
    
        host = self.email_smtp_host.text().strip()
    
        sender = self.email_sender.text().strip()
    
        password = self.email_password.text()
    
        try:
            port = int(
                self.email_smtp_port.text().strip()
            )
        except ValueError:
    
            QMessageBox.warning(
                self,
                "SMTP Error",
                "SMTP port must be a number.",
            )
    
            return
    
        if not host or not sender:
    
            QMessageBox.warning(
                self,
                "SMTP Configuration",
                "SMTP server and sender are required.",
            )
    
            return
    
        try:
    
            from phase3_evaluation_exploitation_reporting.email_reporter import (
                EmailReporter,
            )
    
            reporter = EmailReporter(
                smtp_host=host,
                smtp_port=port,
                sender=sender,
                password=password,
                use_tls=self.email_tls.isChecked(),
            )
    
            import smtplib
    
            with smtplib.SMTP(
                host,
                port,
                timeout=20,
            ) as server:
    
                server.ehlo()
    
                if self.email_tls.isChecked():
    
                    server.starttls()
                    server.ehlo()
    
                if password:
    
                    server.login(
                        sender,
                        password,
                    )
    
            self.email_status_label.setText(
                "✅ SMTP connection successful."
            )
    
            QMessageBox.information(
                self,
                "SMTP Test",
                "SMTP connection and authentication succeeded.",
            )
    
        except Exception as exc:
    
            self.email_status_label.setText(
                "❌ SMTP test failed."
            )
    
            QMessageBox.critical(
                self,
                "SMTP Test Failed",
                f"{type(exc).__name__}: {exc}",
            )
            
    def _send_security_report(self):
        """
        Send only confirmed findings with the existing Phase-3 reports.
        """
    
        # =========================================================
        # 1. PHASE-3 GUARD
        # =========================================================
    
        if not self.phase3_done:
    
            QMessageBox.warning(
                self,
                "Report Locked",
                "Phase-3 must be completed before "
                "sending a security report.",
            )
    
            return
    
        # =========================================================
        # 2. TARGET
        # =========================================================
    
        target = ""
    
        try:
            target = self._get_saved_target() or ""
        except Exception:
            pass
    
        if not target:
    
            QMessageBox.warning(
                self,
                "Target Missing",
                "No assessment target is available.",
            )
    
            return
    
        # =========================================================
        # 3. CONFIRMED FINDINGS ONLY
        # =========================================================
    
        findings = (
            self.vuln_data
            if isinstance(self.vuln_data, list)
            else []
        )
    
        confirmed = []
    
        for finding in findings:
    
            if not isinstance(finding, dict):
                continue
    
            status = str(
                finding.get("status", "")
            ).strip().lower()
    
            confidence = finding.get(
                "confidence",
                0,
            )
    
            try:
                confidence = float(confidence)
            except (TypeError, ValueError):
                confidence = 0
    
            if status in (
                "confirmed",
                "validated",
            ) or confidence >= 80:
    
                confirmed.append(
                    finding
                )
    
        if not confirmed:
    
            QMessageBox.warning(
                self,
                "No Confirmed Findings",
                "There are no confirmed findings available "
                "for email reporting.",
            )
    
            return
    
        # =========================================================
        # 4. RECIPIENTS
        # =========================================================
    
        recipients = (
            self.email_recipients.text()
            .strip()
        )
    
        if not recipients:
    
            QMessageBox.warning(
                self,
                "Recipients Required",
                "Enter at least one security team "
                "or administrator email address.",
            )
    
            return
    
        # =========================================================
        # 5. SMTP
        # =========================================================
    
        smtp_host = (
            self.email_smtp_host.text()
            .strip()
        )
    
        sender = (
            self.email_sender.text()
            .strip()
        )
    
        password = self.email_password.text()
    
        try:
    
            smtp_port = int(
                self.email_smtp_port.text()
                .strip()
            )
    
        except ValueError:
    
            QMessageBox.warning(
                self,
                "SMTP Error",
                "SMTP port must be numeric.",
            )
    
            return
    
        if not smtp_host or not sender:
    
            QMessageBox.warning(
                self,
                "SMTP Configuration",
                "SMTP server and sender are required.",
            )
    
            return
    
        # =========================================================
        # 6. ATTACHMENTS
        # =========================================================
    
        attachments = []
    
        html_path = os.path.join(
            PHASE3_DIR,
            "output",
            "report.html",
        )
    
        txt_path = os.path.join(
            PHASE3_DIR,
            "output",
            "report.txt",
        )
    
        if self.email_attach_html.isChecked():
    
            if os.path.exists(html_path):
    
                attachments.append(
                    html_path
                )
    
        if self.email_attach_txt.isChecked():
    
            if os.path.exists(txt_path):
    
                attachments.append(
                    txt_path
                )
    
        if not attachments:
    
            QMessageBox.warning(
                self,
                "Report Missing",
                "No Phase-3 report attachment is available.",
            )
    
            return
    
        # =========================================================
        # 7. CONFIRM BEFORE DELIVERY
        # =========================================================
    
        reply = QMessageBox.question(
            self,
            "Send Security Report",
            (
                f"Send the professional AVAF Pro report?\n\n"
                f"Target: {target}\n"
                f"Confirmed findings: {len(confirmed)}\n"
                f"Recipients: {recipients}\n\n"
                "Only confirmed findings will be reported."
            ),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
    
        if reply != QMessageBox.Yes:
            return
    
        # =========================================================
        # 8. SEND
        # =========================================================
    
        try:
    
            from phase3_evaluation_exploitation_reporting.email_reporter import (
                EmailReporter,
            )
    
            reporter = EmailReporter(
                smtp_host=smtp_host,
                smtp_port=smtp_port,
                sender=sender,
                password=password,
                use_tls=self.email_tls.isChecked(),
            )
    
            subject = (
                self.email_subject.text()
                .strip()
            )
    
            if not subject:
    
                subject = (
                    f"AVAF Pro Security Assessment Report - "
                    f"{target}"
                )
    
            reporter.send_report(
                recipients=recipients,
                target=target,
                findings=confirmed,
                attachments=attachments,
                subject=subject,
            )
    
            self.email_status_label.setText(
                "✅ Security report sent successfully."
            )
    
            self.log(
                (
                    "Security report emailed successfully "
                    f"to {recipients}"
                ),
                "SUCCESS",
                "EMAIL",
                "REPORT",
            )
    
            QMessageBox.information(
                self,
                "Report Sent",
                (
                    "Security assessment report sent successfully.\n\n"
                    f"Confirmed findings: {len(confirmed)}"
                ),
            )
    
        except Exception as exc:
    
            self.email_status_label.setText(
                "❌ Email delivery failed."
            )
    
            self.log(
                f"Email delivery failed: {exc}",
                "ERROR",
                "EMAIL",
                "REPORT",
            )
    
            QMessageBox.critical(
                self,
                "Email Delivery Failed",
                f"{type(exc).__name__}: {exc}",
            )

    def _animate_mitre_overlay(self, ax, mitre_risk):
        """
        Animated MITRE ATT&CK risk overlay
        """
        if not mitre_risk:
            return

        sorted_mitre = sorted(mitre_risk.items(),
                              key=lambda x: x[1], reverse=True)[:3]

        y = 0.95
        for tactic, score in sorted_mitre:
            ax.text(
                1.05,
                y,
                f"{tactic}: {score}",
                transform=ax.transAxes,
                fontsize=11,
                fontweight="bold",
                color="#facc15",
                alpha=0.0,
                animated=True,
            )
            y -= 0.08

    def _on_heatmap_click(self, event):
        if not event.inaxes:
            return

        x = int(round(event.xdata))
        y = int(round(event.ydata))

        def cvss_bucket(v):
            c = float(v.get("cvss_score", 0))
            return 2 if c >= 9 else 1 if c >= 7 else 0

        def conf_bucket(v):
            c = int(v.get("confidence", 0))
            return 2 if c >= 80 else 1 if c >= 50 else 0

        filtered = [
            v for v in self.vuln_data if cvss_bucket(v) == y and conf_bucket(v) == x
        ]

        # 🔥 TEMP FILTER (NO DATA LOSS)
        self._filtered_vulns = filtered
        self._populate_findings_table_from_filter(filtered)

    def _update_heatmap_from_mitre(self):
        if not hasattr(self, "cvss_heatmap"):
            return

        if not hasattr(self, "vuln_data"):
            return

        self.cvss_heatmap.clear()  # reset grid

        for v in self.vuln_data:
            mitre = v.get("mitre", {})
            tactic = mitre.get("tactic")

            if not tactic:
                continue

            intensity = MITRE_TACTIC_WEIGHT.get(tactic, 1)

            # 🔥 Feed heatmap (row, col, intensity)
            self.cvss_heatmap.add_signal(
                tactic=tactic, intensity=intensity, label=v.get(
                    "type", "UNKNOWN")
            )

    def _mitre_to_heatmap_weight(self, mitre: dict) -> float:
        """
        Convert MITRE tactic → normalized heatmap confidence (0.0–1.0)
        """
        if not isinstance(mitre, dict):
            return 0.2  # Unknown baseline

        tactic = mitre.get("tactic", "Unknown")
        weight = MITRE_RISK_WEIGHT.get(tactic, 1)

        # Normalize (max weight = 5)
        return min(weight / 5.0, 1.0)

    def _on_bar_click(self, event):
        bar = event.artist
        vuln_type = getattr(bar, "_vuln_type", None)

        if not vuln_type:
            return

        # Filter table rows
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 2)  # assuming column 2 = Type
            if item:
                self.table.setRowHidden(row, item.text() != vuln_type)

    def _draw_background(self):

        self.ax.grid(
            color="#293042",
            alpha=.35,
            linestyle="--"
        )

        for s in self.ax.spines.values():

            s.set_visible(False)

    def _draw_line(self, x, y):

        self.ax.plot(

            x,

            y,

            color="#00D2FF",

            lw=3,

            solid_capstyle="round"

        )

        self.ax.plot(

            x,

            y+0.3,

            color="#7DF9FF",

            lw=1.2,

            alpha=.9

        )

    def _draw_points(self, x, y):

        every = 18

        self.ax.scatter(

            x[::every],

            y[::every],

            s=40,

            color="#7DF9FF",

            edgecolors="white",

            linewidth=1,

            zorder=5

        )


class WaveChartEngine:

    def __init__(self, figure):

        self.fig = figure

        self.ax = self.fig.add_subplot(111)

        # ==========================================
        # Colors
        # ==========================================

        self.background = "#1A1D27"
        self.primary = "#00D2FF"
        self.secondary = "#FF007C"
        self.highlight = "#E8FFFF"
        self.grid = "#31374D"

        self.fig.patch.set_facecolor(self.background)
        self.ax.set_facecolor(self.background)

        # ==========================================
        # Animation State
        # ==========================================

        self.frame = 0
        self.phase = 0.0

        self.scan_position = 0.0
        self.highlight_position = 0.0
        self.pulse_phase = 0.0
        self.radar_angle = 0.0

        # ==========================================
        # Data
        # ==========================================

        self.data = []
        self.wave_x = None
        self.wave_y = None

        # ==========================================
        # Particles
        # ==========================================

        self.particles = []

        for _ in range(80):

            self.particles.append({

                "x": np.random.random(),

                "y": np.random.random(),

                "size": np.random.uniform(5, 35),

                "speed": np.random.uniform(0.001, 0.004),

                "alpha": np.random.uniform(0.05, 0.35)

            })

        # ==========================================
        # Animation
        # ==========================================

        self.animation = None

        # ==========================================
        # Graph Styling
        # ==========================================

        self.ax.grid(
            True,
            color=self.grid,
            linewidth=0.8,
            alpha=0.25
        )

        self.ax.set_axisbelow(True)

        self.ax.tick_params(
            left=False,
            bottom=False,
            labelleft=False,
            labelbottom=False
        )

        for spine in self.ax.spines.values():
            spine.set_visible(False)

    def set_data(self, values):

        self.data = values

        self.draw()

    def draw(self):

        self.ax.clear()

        self.ax.set_facecolor("#1A1D27")

        if len(self.data) < 2:

            self.ax.text(
                0.5,
                0.5,
                "No Scan Data",
                ha="center",
                va="center",
                color="white",
                fontsize=18
            )

            self.ax.set_xticks([])
            self.ax.set_yticks([])

            self.fig.canvas.draw_idle()

            return

        x = np.arange(len(self.data))

        y = np.array(self.data)

        spline = make_interp_spline(x, y, k=3)

        xs = np.linspace(x.min(), x.max(), 400)

        ys = spline(xs)

        self._draw_background()

        self._draw_gradient(xs, ys)

        self._draw_glow(xs, ys)

        self._draw_line(xs, ys)

        self._draw_points(xs, ys)

        self.ax.set_xlim(xs.min(), xs.max())

        self.ax.set_ylim(0, max(ys) * 1.25)

        self.ax.set_xticks([])

        self.ax.set_yticks([])

        self.fig.tight_layout()

        self.fig.canvas.draw_idle()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())

# __________this is the end __________#
