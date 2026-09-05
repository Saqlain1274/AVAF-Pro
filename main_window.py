from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QStackedWidget,
)

from dashboard import DashboardFactory


class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()

        self.setWindowTitle("AVAF Pro")
        self.resize(1600, 900)

        self._build_ui()

    # =====================================================
    # UI
    # =====================================================

    def _build_ui(self):

        central = QWidget()
        self.setCentralWidget(central)

        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)

        self.stack = QStackedWidget()

        layout.addWidget(self.stack)

        self._create_pages()

    # =====================================================
    # Pages
    # =====================================================

    def _create_pages(self):

        dashboard = DashboardFactory.create(self)

        self.dashboard = dashboard

        self.dashboard_page = dashboard["page"]

        self.dashboard_renderer = dashboard["renderer"]

        self.dashboard_controller = dashboard["controller"]

        self.stack.addWidget(self.dashboard_page)

        self.stack.setCurrentWidget(
            self.dashboard_page
        )