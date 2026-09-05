"""
cyber_wave_engine.py

AVAF Pro
Rocker Style Cyber Visualization Engine

Used by DashboardCharts for optional animated / reusable
cyber visualization effects.
"""

import numpy as np

from PySide6.QtCore import QObject


class WaveEngine(QObject):

    def __init__(self):
        super().__init__()

        # =====================================================
        # ROCKER / AVAF COLORS
        # =====================================================

        self.background = "#111719"
        self.panel = "#111719"
        self.grid = "#273033"

        self.primary = "#008CFF"
        self.secondary = "#FF6333"

        self.success = "#00E676"
        self.warning = "#FF8A00"
        self.danger = "#FF3D5A"

        self.text = "#F5F7FA"
        self.muted = "#687275"

        # =====================================================
        # ANIMATION STATE
        # =====================================================

        self.phase = 0.0
        self.frame = 0

    # =========================================================
    # ANIMATION
    # =========================================================

    def update_animation(self):

        self.phase += 0.06
        self.frame += 1

    # =========================================================
    # MAIN WAVE
    # =========================================================

    def render_wave(
        self,
        ax,
        dashboard,
        x,
        y,
        color="#008CFF",
    ):

        ax.clear()

        ax.set_facecolor(
            self.panel
        )

        ax.figure.patch.set_facecolor(
            self.background
        )

        y = np.asarray(
            y,
            dtype=float,
        )

        x = np.asarray(
            x,
            dtype=float,
        )

        if len(y) < 2:

            x = np.array([0, 1])

            y = np.array([0, 0])

        # -----------------------------------------------------
        # Main curve
        # -----------------------------------------------------

        ax.plot(
            x,
            y,
            color=color,
            linewidth=2.7,
            solid_capstyle="round",
        )

        ax.fill_between(
            x,
            y,
            0,
            color=color,
            alpha=0.16,
        )

        # -----------------------------------------------------
        # Empty state
        # -----------------------------------------------------

        if np.max(y) == 0:

            ax.text(
                0.5,
                0.48,
                "Waiting for vulnerability data",
                transform=ax.transAxes,
                ha="center",
                va="center",
                color=self.muted,
                fontsize=13,
            )

        # -----------------------------------------------------
        # Grid
        # -----------------------------------------------------

        ax.grid(
            True,
            color=self.grid,
            linewidth=0.7,
            alpha=0.40,
        )

        ax.set_axisbelow(True)

        ax.tick_params(
            colors=self.muted,
            labelsize=9,
        )

        for spine in ax.spines.values():
            spine.set_visible(False)

        ax.margins(x=0)

    # =========================================================
    # CONFIDENCE RING
    # =========================================================

    def render_severity_ring(
        self,
        ax,
        dashboard,
    ):

        ax.clear()

        ax.set_facecolor(
            self.panel
        )

        ax.figure.patch.set_facecolor(
            self.background
        )

        confidence = dashboard.get(
            "avg_conf",
            dashboard.get(
                "confidence",
                0
            )
        )

        try:

            confidence = float(
                confidence
            )

        except (TypeError, ValueError):

            confidence = 0

        confidence = max(
            0,
            min(
                confidence,
                100
            )
        )

        remaining = (
            100 - confidence
        )

        # -----------------------------------------------------
        # Ring
        # -----------------------------------------------------

        ax.pie(
            [
                confidence,
                remaining
            ],
            startangle=90,
            counterclock=False,
            colors=[
                self.success,
                "#263438",
            ],
            wedgeprops={
                "width": 0.20,
                "edgecolor": self.panel,
                "linewidth": 2,
            },
        )

        # -----------------------------------------------------
        # Center
        # -----------------------------------------------------

        ax.text(
            0,
            0.08,
            f"{confidence:.0f}%",
            ha="center",
            va="center",
            color=self.text,
            fontsize=24,
            fontweight="bold",
        )

        ax.text(
            0,
            -0.17,
            "Confidence",
            ha="center",
            va="center",
            color="#8B9598",
            fontsize=11,
        )

        ax.set_aspect(
            "equal"
        )

        ax.set_xticks([])
        ax.set_yticks([])

        for spine in ax.spines.values():
            spine.set_visible(False)

    # =========================================================
    # THREAT TYPE DISTRIBUTION
    # =========================================================

    def render_distribution(
        self,
        ax,
        dashboard,
    ):

        ax.clear()

        ax.set_facecolor(
            self.panel
        )

        ax.figure.patch.set_facecolor(
            self.background
        )

        attacks = dashboard.get(
            "attack_types",
            {}
        )

        # -----------------------------------------------------
        # No findings
        # -----------------------------------------------------

        if not attacks:

            ax.text(
                0.5,
                0.50,
                "No threat data",
                transform=ax.transAxes,
                ha="center",
                va="center",
                color=self.muted,
                fontsize=13,
            )

            ax.set_xticks([])
            ax.set_yticks([])

            for spine in ax.spines.values():
                spine.set_visible(False)

            return

        # -----------------------------------------------------
        # Sort
        # -----------------------------------------------------

        items = sorted(
            attacks.items(),
            key=lambda item: item[1],
            reverse=True,
        )

        labels = [
            item[0]
            for item in items
        ]

        values = [
            item[1]
            for item in items
        ]

        x = np.arange(
            len(labels)
        )

        palette = [

            "#008CFF",
            "#FF6333",
            "#00E676",
            "#FF8A00",
            "#FF3D5A",

        ]

        colors = [

            palette[
                i % len(palette)
            ]

            for i in range(
                len(labels)
            )

        ]

        # -----------------------------------------------------
        # Bars
        # -----------------------------------------------------

        bars = ax.bar(
            x,
            values,
            width=0.45,
            color=colors,
        )

        # -----------------------------------------------------
        # Numbers
        # -----------------------------------------------------

        for bar, value in zip(
            bars,
            values,
        ):

            ax.text(
                bar.get_x()
                + bar.get_width() / 2,
                bar.get_height()
                + 0.15,
                str(value),
                ha="center",
                va="bottom",
                color=self.text,
                fontsize=9,
                fontweight="bold",
            )

        # -----------------------------------------------------
        # Labels
        # -----------------------------------------------------

        ax.set_xticks(
            x
        )

        ax.set_xticklabels(
            labels,
            color="#8B9598",
            fontsize=8,
            rotation=0,
        )

        # -----------------------------------------------------
        # Grid
        # -----------------------------------------------------

        ax.grid(
            axis="y",
            color=self.grid,
            linewidth=0.7,
            alpha=0.40,
        )

        ax.set_axisbelow(
            True
        )

        ax.tick_params(
            axis="y",
            colors=self.muted,
            labelsize=8,
        )

        for spine in ax.spines.values():
            spine.set_visible(False)

    # =========================================================
    # RISK DISTRIBUTION
    # =========================================================

    def render_risk_distribution(
        self,
        ax,
        dashboard,
    ):

        ax.clear()

        ax.set_facecolor(
            self.panel
        )

        ax.figure.patch.set_facecolor(
            self.background
        )

        severity = dashboard.get(
            "severity_counts",
            {}
        )

        labels = [
            "High",
            "Medium",
            "Low",
        ]

        values = [

            severity.get(
                "high",
                0
            ),

            severity.get(
                "medium",
                0
            ),

            severity.get(
                "low",
                0
            ),

        ]

        colors = [

            self.danger,
            self.warning,
            self.success,

        ]

        x = np.arange(
            len(labels)
        )

        bars = ax.bar(
            x,
            values,
            width=0.36,
            color=colors,
        )

        for bar, value in zip(
            bars,
            values,
        ):

            ax.text(
                bar.get_x()
                + bar.get_width() / 2,
                bar.get_height()
                + 0.1,
                str(value),
                ha="center",
                color=self.text,
                fontsize=10,
                fontweight="bold",
            )

        ax.set_xticks(
            x
        )

        ax.set_xticklabels(
            labels
        )

        ax.grid(
            axis="y",
            color=self.grid,
            alpha=0.40,
        )

        ax.tick_params(
            colors=self.muted,
        )

        for spine in ax.spines.values():
            spine.set_visible(False)