import os
import shutil


class ProjectCleaner:

    def __init__(self):
        self.project_root = os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))
        )

    def full_cleanup(self):

        folders = [
            "__pycache__",
        ]

        for root, dirs, files in os.walk(self.project_root):

            for folder in list(dirs):

                if folder in folders:

                    path = os.path.join(root, folder)

                    try:
                        shutil.rmtree(path)
                        print(f"[CLEANUP] Removed: {path}")
                    except Exception as e:
                        print(f"[CLEANUP ERROR] {path}: {e}")

        print("[CLEANUP] Project cleanup completed.")