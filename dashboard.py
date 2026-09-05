"""
AVAF Pro - Dashboard
Backend-driven, compact single-screen dashboard.

IMPORTANT DESIGN RULES
----------------------
1. No predefined attack/vulnerability categories.
2. Finding types are taken directly from real backend dictionaries.
3. Percentages are calculated from the complete backend finding count.
4. The chart shows only the most frequently discovered finding types.
5. The table shows only the most important discovered findings.
6. Target URL is DISPLAY ONLY; Scope Config / gui2.py remains the source
   of truth for the actual target.
7. Security Activity / Heart Rate uses real finding order/timestamps.
8. No demo findings, random data, fake URLs, or synthetic attacks.
9. No dashboard scroll area. The layout is deliberately compact so the
   dashboard can fit inside the available GUI viewport.
10. Removed from this dashboard:
      - Threat Share Breakdown
      - Attack Breakdown table
      - Recent Targets
"""

from collections import Counter
from datetime import datetime

import numpy as np

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QWidget,
    QFrame,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QMessageBox,
    QSizePolicy,
    QAbstractItemView,
)

from matplotlib.figure import Figure
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas


# ============================================================
# AVAF / GUI COLOR FAMILY
# ============================================================

BG = "#0B1220"
PANEL = "#11191D"
PANEL_2 = "#0D1519"
BORDER = "#24343A"

TEXT = "#F4F7FA"
MUTED = "#8B9AA1"

CYAN = "#00B8FF"
BLUE = "#168CFF"
GREEN = "#00E676"
RED = "#FF3150"
ORANGE = "#FF851B"
YELLOW = "#FFC400"
PURPLE = "#7C3AED"


# ============================================================
# KPI CARD
# ============================================================

class DashboardKPI(QFrame):
    def __init__(self, title, value, footer, accent, icon):
        super().__init__()
        self.setObjectName("DashboardKPI")
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setFixedHeight(78)

        self.setStyleSheet(
            f"""
            QFrame#DashboardKPI {{
                background:{PANEL};
                border:1px solid {BORDER};
                border-radius:10px;
            }}
            """
        )

        root = QVBoxLayout(self)
        root.setContentsMargins(10, 6, 10, 5)
        root.setSpacing(0)

        top = QHBoxLayout()
        top.setSpacing(3)

        self.title_label = QLabel(title)
        self.title_label.setStyleSheet(
            f"color:{MUTED}; font-size:10px; font-weight:800;"
        )

        self.icon_label = QLabel(icon)
        self.icon_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.icon_label.setStyleSheet(
            f"color:{accent}; font-size:15px; font-weight:900;"
        )

        top.addWidget(self.title_label)
        top.addStretch()
        top.addWidget(self.icon_label)
        root.addLayout(top)

        self.value_label = QLabel(str(value))
        self.value_label.setStyleSheet(
            f"color:{TEXT}; font-size:22px; font-weight:900;"
        )
        root.addWidget(self.value_label)

        self.sparkline = QLabel("—")
        self.sparkline.setFixedHeight(12)
        self.sparkline.setStyleSheet(
            f"color:{accent}; font-size:11px; font-weight:900;"
        )
        root.addWidget(self.sparkline)

        self.footer_label = QLabel(footer)
        self.footer_label.setStyleSheet(
            f"color:{accent}; font-size:8px; font-weight:800;"
        )
        root.addWidget(self.footer_label)

    def setValue(self, value):
        self.value_label.setText(str(value))

    def setTrend(self, text):
        self.footer_label.setText(str(text))

    def set_activity(self, values):
        if not values or len(values) < 2:
            self.sparkline.setText("—")
            return

        self.sparkline.setText(
            "╱╲╱" if values[-1] >= values[0] else "╲╱╲"
        )


# ============================================================
# DASHBOARD PAGE
# ============================================================

class DashboardPage(QWidget):

    analysis_requested = Signal(str)
    report_requested = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)

        self.main = parent
        self.setObjectName("AVAFDashboard")

        self.vuln_data = []
        self.last_model = {}

        self.setSizePolicy(
            QSizePolicy.Expanding,
            QSizePolicy.Expanding,
        )

        self.setStyleSheet(
            f"""
            QWidget#AVAFDashboard {{
                background:{BG};
            }}

            QLabel {{
                background:transparent;
            }}
            """
        )

        self._build_ui()
        self._reset_dashboard_view()

    # ========================================================
    # PANEL FACTORY
    # ========================================================

    def _panel(self):
        panel = QFrame()
        panel.setObjectName("DashboardPanel")
        panel.setStyleSheet(
            f"""
            QFrame#DashboardPanel {{
                background:{PANEL};
                border:1px solid {BORDER};
                border-radius:10px;
            }}
            """
        )
        return panel

    def _section_title(self, title, subtitle=None, accent=TEXT):
        box = QVBoxLayout()
        box.setContentsMargins(0, 0, 0, 0)
        box.setSpacing(0)

        title_lbl = QLabel(title)
        title_lbl.setStyleSheet(
            f"color:{accent}; font-size:12px; font-weight:900;"
        )
        box.addWidget(title_lbl)

        if subtitle:
            sub = QLabel(subtitle)
            sub.setStyleSheet(
                f"color:{MUTED}; font-size:8px; font-weight:500;"
            )
            box.addWidget(sub)

        return box

    # ========================================================
    # UI
    # ========================================================

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 6, 8, 6)
        root.setSpacing(6)

        # ----------------------------------------------------
        # HEADER
        # ----------------------------------------------------

        header = self._panel()
        header.setFixedHeight(62)

        h = QHBoxLayout(header)
        h.setContentsMargins(12, 6, 12, 6)
        h.setSpacing(8)

        title_box = QVBoxLayout()
        title_box.setSpacing(0)

        title = QLabel("Security Intelligence")
        title.setStyleSheet(
            f"color:{TEXT}; font-size:17px; font-weight:900;"
        )

        subtitle = QLabel(
            "AVAF Pro • Web Vulnerability Assessment Framework"
        )
        subtitle.setStyleSheet(
            f"color:{MUTED}; font-size:8px;"
        )

        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        h.addLayout(title_box)

        h.addSpacing(8)

        target_label = QLabel("Target URL:")
        target_label.setStyleSheet(
            f"color:{TEXT}; font-size:9px; font-weight:900;"
        )
        h.addWidget(target_label)

        # DISPLAY ONLY — gui2.py / Scope Config owns the target.
        self.dashboard_target_url = QLabel("Not Set")
        self.dashboard_target_url.setObjectName("DashboardTarget")
        self.dashboard_target_url.setAlignment(
            Qt.AlignLeft | Qt.AlignVCenter
        )
        self.dashboard_target_url.setSizePolicy(
            QSizePolicy.Expanding,
            QSizePolicy.Fixed,
        )
        self.dashboard_target_url.setFixedHeight(30)

        self.dashboard_target_url.setStyleSheet(
            f"""
            QLabel#DashboardTarget {{
                color:{CYAN};
                background:{PANEL_2};
                border:1px solid {BORDER};
                border-radius:6px;
                padding:4px 9px;
                font-size:10px;
                font-weight:900;
            }}
            """
        )

        # Compatibility alias for existing gui2.py code.
        self.input_target_url = self.dashboard_target_url
        h.addWidget(self.dashboard_target_url, 1)

        self.analysis_btn = QPushButton("⚡ Analysis")
        self.analysis_btn.setFixedHeight(30)
        self.analysis_btn.setStyleSheet(
            f"""
            QPushButton {{
                background:{BLUE};
                color:white;
                border:none;
                border-radius:6px;
                padding:0 12px;
                font-size:9px;
                font-weight:900;
            }}
            QPushButton:hover {{
                background:{CYAN};
            }}
            """
        )
        self.analysis_btn.clicked.connect(self._emit_analysis)
        h.addWidget(self.analysis_btn)

        self.report_btn = QPushButton("▣ Generate Threat Report")
        self.report_btn.setFixedHeight(30)
        self.report_btn.setStyleSheet(
            f"""
            QPushButton {{
                background:{RED};
                color:white;
                border:none;
                border-radius:6px;
                padding:0 11px;
                font-size:9px;
                font-weight:900;
            }}
            QPushButton:hover {{
                background:#FF4F69;
            }}
            """
        )
        self.report_btn.clicked.connect(self._emit_report)
        h.addWidget(self.report_btn)

        self.dashboard_scan_status = QLabel("● Idle")
        self.dashboard_scan_status.setFixedWidth(108)
        self.dashboard_scan_status.setFixedHeight(30)
        self.dashboard_scan_status.setAlignment(Qt.AlignCenter)
        h.addWidget(self.dashboard_scan_status)

        root.addWidget(header)

        # ----------------------------------------------------
        # KPI ROW
        # ----------------------------------------------------

        kpi_row = QHBoxLayout()
        kpi_row.setSpacing(6)

        self.lbl_urls = DashboardKPI(
            "Unique Target URLs",
            "0",
            "Affected Endpoints",
            CYAN,
            "◉",
        )

        self.lbl_vulns = DashboardKPI(
            "Total Threats",
            "0",
            "Actual Findings",
            RED,
            "⚠",
        )

        self.lbl_high = DashboardKPI(
            "High / Critical Risk",
            "0",
            "Action Required",
            ORANGE,
            "!",
        )

        self.lbl_conf = DashboardKPI(
            "Confidence",
            "0%",
            "Average Engine Score",
            GREEN,
            "✓",
        )

        for card in (
            self.lbl_urls,
            self.lbl_vulns,
            self.lbl_high,
            self.lbl_conf,
        ):
            kpi_row.addWidget(card, 1)

        root.addLayout(kpi_row)

        # ----------------------------------------------------
        # CHART ROW
        # ----------------------------------------------------

        chart_row = QHBoxLayout()
        chart_row.setSpacing(6)

        # Distribution
        dist_panel = self._panel()
        dist_panel.setMinimumWidth(300)

        dist_layout = QVBoxLayout(dist_panel)
        dist_layout.setContentsMargins(10, 6, 10, 6)
        dist_layout.setSpacing(2)

        dist_layout.addLayout(
            self._section_title(
                "▥  Threat Type Distribution (%)",
                "Top discovered types • percentage = type count ÷ total findings × 100",
            )
        )

        self.distribution_figure = Figure(
            figsize=(5.2, 2.1),
            facecolor=PANEL,
        )

        self.distribution_canvas = FigureCanvas(
            self.distribution_figure
        )
        self.distribution_canvas.setSizePolicy(
            QSizePolicy.Expanding,
            QSizePolicy.Expanding,
        )

        dist_layout.addWidget(
            self.distribution_canvas,
            1,
        )

        chart_row.addWidget(dist_panel, 1)

        # Heart rate
        heart_panel = self._panel()
        heart_panel.setMinimumWidth(300)

        heart_layout = QVBoxLayout(heart_panel)
        heart_layout.setContentsMargins(10, 6, 10, 6)
        heart_layout.setSpacing(2)

        heart_header = QHBoxLayout()

        heart_header.addLayout(
            self._section_title(
                "〽  Security Activity / Heart Rate",
                "Real backend discovery/finding activity • no synthetic data",
            )
        )

        heart_header.addStretch()

        self.heart_rate_status = QLabel("● No scan activity")
        self.heart_rate_status.setStyleSheet(
            f"color:{MUTED}; font-size:8px; font-weight:800;"
        )
        heart_header.addWidget(self.heart_rate_status)

        heart_layout.addLayout(heart_header)

        self.heart_rate_chart = Figure(
            figsize=(5.2, 2.1),
            facecolor=PANEL,
        )

        self.heart_rate_canvas = FigureCanvas(
            self.heart_rate_chart
        )
        self.heart_rate_canvas.setSizePolicy(
            QSizePolicy.Expanding,
            QSizePolicy.Expanding,
        )

        heart_layout.addWidget(
            self.heart_rate_canvas,
            1,
        )

        chart_row.addWidget(heart_panel, 1)

        root.addLayout(chart_row, 1)

        # ----------------------------------------------------
        # IMPORTANT FINDINGS
        # ----------------------------------------------------

        findings_panel = self._panel()

        findings_layout = QVBoxLayout(findings_panel)
        findings_layout.setContentsMargins(10, 6, 10, 6)
        findings_layout.setSpacing(2)

        findings_header = QHBoxLayout()

        findings_header.addLayout(
            self._section_title(
                "◉  Important Discovered Threats",
                "Top findings selected from real Phase-2 backend data",
            )
        )

        findings_header.addStretch()

        self.top_findings_status = QLabel(
            "Top 5 • Real Backend Data"
        )
        self.top_findings_status.setStyleSheet(
            f"color:{GREEN}; font-size:8px; font-weight:900;"
        )

        findings_header.addWidget(
            self.top_findings_status
        )

        findings_layout.addLayout(findings_header)

        self.dashboard_table = QTableWidget(0, 7)
        self.dashboard_table.setHorizontalHeaderLabels(
            [
                "#",
                "Severity",
                "Finding Type",
                "Affected URL / Endpoint",
                "Method",
                "Confidence",
                "CVSS",
            ]
        )

        self.dashboard_table.setEditTriggers(
            QTableWidget.NoEditTriggers
        )
        self.dashboard_table.setSelectionBehavior(
            QTableWidget.SelectRows
        )
        self.dashboard_table.setSelectionMode(
            QTableWidget.SingleSelection
        )
        self.dashboard_table.verticalHeader().setVisible(False)
        self.dashboard_table.setShowGrid(False)
        self.dashboard_table.setAlternatingRowColors(False)
        self.dashboard_table.setFocusPolicy(Qt.NoFocus)

        self.dashboard_table.setStyleSheet(
            f"""
            QTableWidget {{
                background:{PANEL_2};
                color:{TEXT};
                border:none;
                font-size:8px;
                gridline-color:{BORDER};
            }}

            QTableWidget::item {{
                padding:2px 5px;
                border-bottom:1px solid {BORDER};
            }}

            QHeaderView::section {{
                background:#0A1117;
                color:#C7D0D5;
                border:none;
                border-bottom:1px solid {BORDER};
                padding:4px;
                font-size:8px;
                font-weight:900;
            }}
            """
        )

        header_view = self.dashboard_table.horizontalHeader()
        header_view.setSectionResizeMode(
            QHeaderView.Interactive
        )
        header_view.setStretchLastSection(True)

        header_view.resizeSection(0, 28)
        header_view.resizeSection(1, 72)
        header_view.resizeSection(2, 175)
        header_view.resizeSection(3, 360)
        header_view.resizeSection(4, 55)
        header_view.resizeSection(5, 75)
        header_view.resizeSection(6, 60)

        # Compact fixed table height = no vertical dashboard scrolling.
        self.dashboard_table.setFixedHeight(118)

        findings_layout.addWidget(
            self.dashboard_table
        )

        root.addWidget(
            findings_panel,
            0,
        )

    # ========================================================
    # SIGNALS
    # ========================================================

    def _emit_analysis(self):
        self.analysis_requested.emit(
            self._current_target()
        )

    def _emit_report(self):
        self.report_requested.emit(
            self._current_target()
        )

    def _current_target(self):
        text = self.dashboard_target_url.text().strip()

        if text.startswith("Target:"):
            text = text.split(":", 1)[1].strip()

        return text if text else "Not Set"

    # ========================================================
    # BACKEND DATA HELPERS
    # ========================================================

    @staticmethod
    def _finding_type(v):
        """
        Extract the attack/finding name from whatever the backend
        actually produced.

        Nothing is hard-coded as a vulnerability category.
        """
        value = (
            v.get("type")
            or v.get("vulnerability")
            or v.get("finding_type")
            or v.get("name")
            or v.get("title")
            or v.get("category")
            or v.get("issue")
            or ""
        )

        value = str(value).strip()

        return (
            value
            if value
            else "Unclassified Finding"
        )

    @staticmethod
    def _finding_url(v):
        return str(
            v.get("url")
            or v.get("affected_url")
            or v.get("endpoint")
            or v.get("target")
            or v.get("request_url")
            or ""
        ).strip()

    @staticmethod
    def _confidence(v):
        raw = v.get(
            "confidence",
            v.get(
                "confidence_score",
                v.get("confidence_percent", None),
            ),
        )

        if raw is None:
            return None

        try:
            if isinstance(raw, str):
                raw = raw.replace("%", "").strip()

            value = float(raw)

            if 0 <= value <= 1:
                value *= 100

            return max(
                0.0,
                min(100.0, value),
            )

        except (TypeError, ValueError):
            return None

    @staticmethod
    def _cvss(v):
        raw = (
            v.get("cvss_score")
            if v.get("cvss_score") is not None
            else v.get("cvss")
        )

        if isinstance(raw, dict):
            raw = (
                raw.get("score")
                or raw.get("base_score")
                or raw.get("value")
            )

        try:
            return float(raw)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _severity(v):
        return str(
            v.get("severity")
            or v.get("risk")
            or v.get("risk_level")
            or "unknown"
        ).strip().lower()

    @staticmethod
    def _method(v):
        return str(
            v.get("method")
            or v.get("http_method")
            or "—"
        ).strip().upper()

    @staticmethod
    def _timestamp(v):
        return str(
            v.get("discovered_at")
            or v.get("timestamp")
            or v.get("created_at")
            or v.get("time")
            or ""
        ).strip()

    # ========================================================
    # IMPORTANCE SCORE
    # ========================================================

    def _importance_score(self, v):
        severity_weight = {
            "critical": 100,
            "high": 85,
            "medium": 60,
            "low": 35,
            "info": 15,
            "informational": 15,
        }.get(
            self._severity(v),
            20,
        )

        confidence = self._confidence(v)
        cvss = self._cvss(v)

        confidence_weight = (
            confidence * 0.25
            if confidence is not None
            else 0
        )

        cvss_weight = (
            cvss * 3.0
            if cvss is not None
            else 0
        )

        return (
            severity_weight
            + confidence_weight
            + cvss_weight
        )

    # ========================================================
    # RESET
    # ========================================================

    def _reset_dashboard_view(self):
        self.vuln_data = []
        self.last_model = {}

        self.dashboard_target_url.setText("Not Set")
        self.set_status("Idle")

        self.lbl_urls.setValue(0)
        self.lbl_vulns.setValue(0)
        self.lbl_high.setValue(0)
        self.lbl_conf.setValue("0%")

        self.lbl_urls.set_activity([0])
        self.lbl_vulns.set_activity([0])
        self.lbl_high.set_activity([0])
        self.lbl_conf.set_activity([0])

        self._update_distribution_chart([])
        self._update_security_heart_rate([])
        self._update_findings_table([])

    # Compatibility for existing gui2.py / older callers.
    def reset_dashboard(self):
        self._reset_dashboard_view()

    # Compatibility for old callers that used this name.
    def _reset_view(self):
        self._reset_dashboard_view()

    # ========================================================
    # TARGET / STATUS
    # ========================================================

    def set_target(self, target):
        target = str(
            target or "Not Set"
        ).strip()

        self.dashboard_target_url.setText(
            target if target else "Not Set"
        )

    def set_status(self, status):
        status = str(
            status or "Idle"
        ).strip()

        self.dashboard_scan_status.setText(
            f"● {status}"
        )

        lowered = status.lower()

        if any(
            word in lowered
            for word in (
                "error",
                "failed",
                "failure",
            )
        ):
            color = RED

        elif any(
            word in lowered
            for word in (
                "complete",
                "completed",
                "done",
                "success",
            )
        ):
            color = GREEN

        elif any(
            word in lowered
            for word in (
                "scan",
                "running",
                "active",
                "phase",
                "analysis",
                "finding",
            )
        ):
            color = CYAN

        else:
            color = MUTED

        self.dashboard_scan_status.setStyleSheet(
            f"""
            QLabel {{
                color:{color};
                background:{PANEL_2};
                border:1px solid {BORDER};
                border-radius:6px;
                padding:4px 8px;
                font-size:8px;
                font-weight:900;
            }}
            """
        )

    # ========================================================
    # MASTER BACKEND UPDATE
    # ========================================================

    def update_dashboard(
        self,
        vulnerabilities=None,
        target_url=None,
        scan_status="Completed",
        **kwargs,
    ):
        """
        MASTER dashboard update.

        This method is the only place where backend findings are
        transformed into dashboard statistics.

        IMPORTANT:
        - No attack list is predefined.
        - Whatever finding type the backend returns is counted.
        - Percentages are based on ALL findings.
        - Only the most frequent types are visualized.
        - Only the most important individual findings are listed.
        """

        if not isinstance(
            vulnerabilities,
            list,
        ):
            vulnerabilities = []

        self.vuln_data = [
            item
            for item in vulnerabilities
            if isinstance(item, dict)
        ]

        target = str(
            target_url
            or kwargs.get("target")
            or kwargs.get("target_url")
            or "Not Set"
        ).strip()

        # Some existing gui2.py calls use "status" instead of
        # "scan_status", so support both without breaking anything.
        status = kwargs.get(
            "status",
            scan_status,
        )

        self.set_target(target)
        self.set_status(status)

        total = len(self.vuln_data)

        # ----------------------------------------------------
        # UNIQUE AFFECTED URLS
        # ----------------------------------------------------

        unique_urls = {
            self._finding_url(v)
            for v in self.vuln_data
            if self._finding_url(v)
        }

        # ----------------------------------------------------
        # DYNAMIC ATTACK / FINDING AGGREGATION
        # ----------------------------------------------------

        attack_counts = Counter(
            self._finding_type(v)
            for v in self.vuln_data
        )

        sorted_attacks = sorted(
            attack_counts.items(),
            key=lambda pair: (
                -pair[1],
                pair[0].lower(),
            ),
        )

        # ----------------------------------------------------
        # HIGH / CRITICAL
        # ----------------------------------------------------

        high_risk = sum(
            1
            for v in self.vuln_data
            if self._severity(v)
            in ("critical", "high")
        )

        # ----------------------------------------------------
        # CONFIDENCE
        # ----------------------------------------------------

        confidence_values = [
            self._confidence(v)
            for v in self.vuln_data
        ]

        confidence_values = [
            value
            for value in confidence_values
            if value is not None
        ]

        avg_conf = (
            round(
                sum(confidence_values)
                / len(confidence_values),
                1,
            )
            if confidence_values
            else 0.0
        )

        # ----------------------------------------------------
        # TOP ATTACK TYPES ONLY
        # ----------------------------------------------------
        #
        # Example:
        # 80 total findings
        # XSS = 40 -> 50.0%
        # SQLi = 30 -> 37.5%
        # DoS = 10 -> 12.5%
        #
        # If there are 20 different types, the dashboard does
        # NOT become a huge list. Only the most frequently found
        # types are shown.
        # ----------------------------------------------------

        MAX_VISIBLE_TYPES = 5

        distribution = []

        for attack_type, count in sorted_attacks[
            :MAX_VISIBLE_TYPES
        ]:
            percentage = (
                (count / total) * 100
                if total
                else 0.0
            )

            distribution.append(
                {
                    "type": attack_type,
                    "count": count,
                    "percentage": round(
                        percentage,
                        1,
                    ),
                }
            )

        # ----------------------------------------------------
        # IMPORTANT FINDINGS ONLY
        # ----------------------------------------------------

        important_findings = sorted(
            self.vuln_data,
            key=self._importance_score,
            reverse=True,
        )[:5]

        # ----------------------------------------------------
        # REAL ACTIVITY / HEART RATE
        # ----------------------------------------------------

        activity = self._build_activity(
            self.vuln_data
        )

        model = {
            "target_url": target,
            
            
            "total": total,
            "unique_urls": len(unique_urls),
            "high_risk_total": high_risk,
            "avg_conf": avg_conf,
            "attack_counts": dict(
                attack_counts
            ),
            "sorted_attacks": sorted_attacks,
            "distribution": distribution,
            "important_findings": important_findings,
            "activity": activity,
        }

        self.last_model = model

        # ----------------------------------------------------
        # KPI UPDATE
        # ----------------------------------------------------

        self.lbl_urls.setValue(
            len(unique_urls)
        )

        self.lbl_vulns.setValue(
            total
        )

        self.lbl_high.setValue(
            high_risk
        )

        self.lbl_conf.setValue(
            f"{avg_conf:.0f}%"
        )

        self.lbl_urls.set_activity(
            [0, len(unique_urls)]
        )

        self.lbl_vulns.set_activity(
            [0, total]
        )

        self.lbl_high.set_activity(
            [0, high_risk]
        )

        self.lbl_conf.set_activity(
            [0, avg_conf]
        )

        # ----------------------------------------------------
        # CHARTS
        # ----------------------------------------------------

        self._update_distribution_chart(
            distribution
        )

        self._update_security_heart_rate(
            self.vuln_data,
            activity=activity,
            high_risk=high_risk,
        )

        # ----------------------------------------------------
        # IMPORTANT FINDINGS TABLE
        # ----------------------------------------------------

        self._update_findings_table(
            important_findings
        )

        self.top_findings_status.setText(
            f"Top {min(5, total)} • Real Backend Data"
            if total
            else "No backend findings"
        )

        return model

    # ========================================================
    # REAL ACTIVITY TRACE
    # ========================================================

    def _build_activity(self, findings):
        """
        Build activity from real findings.

        1. If backend timestamps exist, group findings by minute.
        2. Otherwise use the actual finding sequence.

        No random numbers and no fake activity are created.
        """

        if not findings:
            return [0]

        dated = []

        for finding in findings:
            raw = self._timestamp(
                finding
            )

            if not raw:
                continue

            try:
                text = raw.replace(
                    "Z",
                    "+00:00",
                )

                dt = datetime.fromisoformat(
                    text
                )

                dated.append(dt)

            except (
                ValueError,
                TypeError,
            ):
                continue

        if dated:
            buckets = Counter(
                dt.strftime("%H:%M")
                for dt in dated
            )

            return [
                buckets[key]
                for key in sorted(
                    buckets.keys()
                )
            ]

        # Real finding sequence fallback.
        trace = []

        running = 0

        for _ in findings:
            running += 1
            trace.append(running)

        return trace or [0]

    # ========================================================
    # THREAT TYPE DISTRIBUTION
    # ========================================================

    def _update_distribution_chart(
        self,
        distribution,
    ):
        fig = self.distribution_figure
        fig.clear()
        fig.patch.set_facecolor(
            PANEL
        )

        ax = fig.add_subplot(111)
        ax.set_facecolor(PANEL)

        if not distribution:
            ax.text(
                0.5,
                0.5,
                "No Vulnerabilities Discovered",
                transform=ax.transAxes,
                ha="center",
                va="center",
                color=MUTED,
                fontsize=10,
                fontweight="bold",
            )

            ax.set_xticks([])
            ax.set_yticks([])

            for spine in ax.spines.values():
                spine.set_visible(False)

            fig.subplots_adjust(
                left=0.01,
                right=0.99,
                top=0.98,
                bottom=0.02,
            )

            self.distribution_canvas.draw_idle()
            return

        # Reverse so the largest item is visually on top.
        items = list(
            reversed(distribution)
        )

        labels = [
            item["type"]
            for item in items
        ]

        values = [
            item["percentage"]
            for item in items
        ]

        labels = [
            label
            if len(label) <= 25
            else label[:22] + "..."
            for label in labels
        ]

        # Colors are positional UI accents only. They do NOT
        # represent predefined vulnerability categories.
        colors = [
            CYAN,
            "#16B8A6",
            GREEN,
            PURPLE,
            "#65727A",
        ]

        y = np.arange(
            len(values)
        )

        ax.barh(
            y,
            values,
            height=0.52,
            color=colors[
                :len(values)
            ],
            alpha=0.95,
        )

        ax.set_yticks(y)
        ax.set_yticklabels(
            labels,
            color=TEXT,
            fontsize=7,
        )

        maximum = max(
            values
        ) if values else 1

        upper = max(
            50,
            int(
                np.ceil(
                    maximum / 10.0
                ) * 10
                + 10
            ),
        )

        ax.set_xlim(
            0,
            upper,
        )

        ax.tick_params(
            axis="x",
            colors=MUTED,
            labelsize=6,
        )

        ax.tick_params(
            axis="y",
            length=0,
        )

        ax.grid(
            axis="x",
            color=BORDER,
            alpha=0.45,
            linewidth=0.6,
        )

        ax.set_axisbelow(True)

        for index, value in enumerate(values):
            ax.text(
                value + upper * 0.012,
                index,
                f"{value:.1f}%",
                va="center",
                color=TEXT,
                fontsize=7,
                fontweight="bold",
            )

        for spine in ax.spines.values():
            spine.set_visible(False)

        fig.subplots_adjust(
            left=0.28,
            right=0.98,
            top=0.98,
            bottom=0.12,
        )

        self.distribution_canvas.draw_idle()

    # ========================================================
    # SECURITY ACTIVITY / HEART RATE
    # ========================================================

    def _update_security_heart_rate(
        self,
        findings,
        activity=None,
        high_risk=0,
    ):
        fig = self.heart_rate_chart
        fig.clear()
        fig.patch.set_facecolor(
            PANEL
        )

        ax = fig.add_subplot(111)
        ax.set_facecolor(PANEL)

        values = (
            activity
            if activity is not None
            else self._build_activity(
                findings
            )
        )

        if not values:
            values = [0]

        values = list(values)

        x = np.arange(
            len(values)
        )

        if len(values) == 1:
            x = np.array(
                [0, 1]
            )
            values = [
                values[0],
                values[0],
            ]

        ax.plot(
            x,
            values,
            color=CYAN,
            linewidth=2.0,
            marker="o",
            markersize=2.4,
            solid_capstyle="round",
        )

        ax.fill_between(
            x,
            values,
            0,
            color=CYAN,
            alpha=0.10,
        )

        highest = max(
            values
        ) if values else 0

        ax.set_ylim(
            0,
            max(
                2,
                highest
                + max(
                    1,
                    int(
                        highest * 0.20
                    ),
                ),
            ),
        )

        ax.grid(
            axis="y",
            color=BORDER,
            alpha=0.40,
            linewidth=0.6,
        )

        ax.tick_params(
            axis="y",
            colors=MUTED,
            labelsize=6,
        )

        ax.tick_params(
            axis="x",
            colors=MUTED,
            labelsize=6,
        )

        if len(values) <= 6:
            ax.set_xticks(x)
            ax.set_xticklabels(
                [
                    str(i + 1)
                    for i in range(
                        len(values)
                    )
                ],
                color=MUTED,
                fontsize=6,
            )
        else:
            tick_count = min(
                6,
                len(values),
            )

            ticks = np.linspace(
                0,
                len(values) - 1,
                tick_count,
                dtype=int,
            )

            ax.set_xticks(ticks)
            ax.set_xticklabels(
                [
                    str(
                        int(t) + 1
                    )
                    for t in ticks
                ],
                color=MUTED,
                fontsize=6,
            )

        for spine in ax.spines.values():
            spine.set_visible(False)

        if findings:
            self.heart_rate_status.setText(
                f"● Live Activity • {len(findings)} findings • {high_risk} high/critical"
            )

            self.heart_rate_status.setStyleSheet(
                f"color:{GREEN}; font-size:8px; font-weight:800;"
            )
        else:
            self.heart_rate_status.setText(
                "● No scan activity"
            )

            self.heart_rate_status.setStyleSheet(
                f"color:{MUTED}; font-size:8px; font-weight:800;"
            )

        fig.subplots_adjust(
            left=0.07,
            right=0.99,
            top=0.98,
            bottom=0.20,
        )

        self.heart_rate_canvas.draw_idle()

    # ========================================================
    # IMPORTANT FINDINGS TABLE
    # ========================================================

    def _update_findings_table(
        self,
        findings,
    ):
        table = self.dashboard_table
        table.setRowCount(0)

        for index, finding in enumerate(
            findings,
            start=1,
        ):
            row = table.rowCount()

            table.insertRow(row)
            table.setRowHeight(
                row,
                20,
            )

            finding_type = (
                self._finding_type(
                    finding
                )
            )

            url = self._finding_url(
                finding
            )

            severity = (
                self._severity(
                    finding
                ).title()
            )

            method = self._method(
                finding
            )

            confidence = (
                self._confidence(
                    finding
                )
            )

            confidence_text = (
                f"{confidence:.0f}%"
                if confidence is not None
                else "—"
            )

            cvss = self._cvss(
                finding
            )

            cvss_text = (
                f"{cvss:.1f}"
                if cvss is not None
                else "—"
            )

            values = [
                str(index),
                severity,
                finding_type,
                url or "—",
                method,
                confidence_text,
                cvss_text,
            ]

            for col, value in enumerate(
                values
            ):
                item = QTableWidgetItem(
                    value
                )

                item.setTextAlignment(
                    Qt.AlignLeft
                    | Qt.AlignVCenter
                )

                if col == 0:
                    item.setTextAlignment(
                        Qt.AlignCenter
                        | Qt.AlignVCenter
                    )

                if col == 3 and url:
                    item.setForeground(
                        QColor(CYAN)
                    )

                if col == 1:
                    sev = severity.lower()

                    if sev in (
                        "critical",
                        "high",
                    ):
                        item.setForeground(
                            QColor(RED)
                        )

                    elif sev == "medium":
                        item.setForeground(
                            QColor(ORANGE)
                        )

                    elif sev == "low":
                        item.setForeground(
                            QColor(GREEN)
                        )

                if col == 5:
                    item.setForeground(
                        QColor(GREEN)
                    )

                if (
                    col == 6
                    and cvss is not None
                ):
                    if cvss >= 7:
                        item.setForeground(
                            QColor(RED)
                        )

                    elif cvss >= 4:
                        item.setForeground(
                            QColor(ORANGE)
                        )

                    else:
                        item.setForeground(
                            QColor(GREEN)
                        )

                table.setItem(
                    row,
                    col,
                    item,
                )

        if not findings:
            table.insertRow(0)
            table.setRowHeight(
                0,
                20,
            )

            empty = QTableWidgetItem(
                "No vulnerabilities discovered from backend data."
            )

            empty.setForeground(
                QColor(MUTED)
            )

            empty.setTextAlignment(
                Qt.AlignCenter
                | Qt.AlignVCenter
            )

            table.setSpan(
                0,
                0,
                1,
                7,
            )

            table.setItem(
                0,
                0,
                empty,
            )


# ============================================================
# STANDALONE TEST MODE
# ============================================================

if __name__ == "__main__":
    import sys
    from PySide6.QtWidgets import QApplication

    app = QApplication(sys.argv)

    window = QWidget()
    window.setWindowTitle(
        "AVAF Pro Dashboard"
    )

    window.resize(
        1500,
        850,
    )

    layout = QVBoxLayout(
        window
    )
    layout.setContentsMargins(
        0,
        0,
        0,
        0,
    )

    page = DashboardPage()
    layout.addWidget(page)

    # Empty state only.
    # No fake findings are generated.
    window.show()

    sys.exit(
        app.exec()
    )
