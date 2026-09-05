"""
===============================================================================
AVAF Pro

Project Cleaner

Removes generated files created during development.

===============================================================================
"""

from pathlib import Path
import shutil


class ProjectCleaner:

    def __init__(self, root="."):

        self.root = Path(root)

        self.deleted_dirs = 0
        self.deleted_files = 0

    # =========================================================

    def _remove_directory(self, folder_name: str):

        for folder in self.root.rglob(folder_name):

            try:

                shutil.rmtree(folder)

                self.deleted_dirs += 1

            except Exception:
                pass

    # =========================================================

    def _remove_files(self, pattern: str):

        for file in self.root.rglob(pattern):

            try:

                file.unlink()

                self.deleted_files += 1

            except Exception:
                pass

    # =========================================================

    def clean_python_cache(self):

        self._remove_directory("__pycache__")

        self._remove_files("*.pyc")

        self._remove_files("*.pyo")

    # =========================================================

    def clean_logs(self):

        self._remove_files("*.log")

    # =========================================================

    def clean_temp(self):

        self._remove_directory("temp")

    # =========================================================

    def clean_reports(self):

        reports = [

            "reports",

            "output",

        ]

        for folder in reports:

            self._remove_directory(folder)

    # =========================================================

    def full_cleanup(self):

        print("\n========== AVAF Project Maintenance ==========\n")

        self.clean_python_cache()

        self.clean_logs()

        self.clean_temp()

        # Uncomment later if desired
        # self.clean_reports()

        print(f"Folders removed : {self.deleted_dirs}")

        print(f"Files removed   : {self.deleted_files}")

        print("\nCleanup Finished.\n")