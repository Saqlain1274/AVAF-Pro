"""
===============================================================================
AVAF Pro
Central Logger

Provides consistent logging across the entire framework.

Supports both styles:

    logger.info("BROWSER", "Starting...")

and

    logger.info("Starting...")
===============================================================================
"""

from __future__ import annotations

from datetime import datetime


class Logger:

    # ==========================================================
    # Internal
    # ==========================================================

    def _log(
        self,
        level: str,
        module: str,
        message: str
    ) -> None:

        now = datetime.now().strftime("%H:%M:%S")

        print(
            f"[{now}] [{level}] [{module}] {message}",
            flush=True
        )

    def _write(
        self,
        level: str,
        *args
    ) -> None:
        """
        Supports both:

            logger.info("BROWSER", "Started")
            logger.info("Started")
        """

        if len(args) == 2:

            module, message = args

        elif len(args) == 1:

            module = "SYSTEM"
            message = args[0]

        else:

            raise TypeError(
                "Logger expects either "
                "(module, message) or (message)"
            )

        self._log(
            level,
            str(module),
            str(message)
        )

    # ==========================================================
    # Public API
    # ==========================================================

    def info(self, *args) -> None:
        self._write("INFO", *args)

    def debug(self, *args) -> None:
        self._write("DEBUG", *args)

    def warn(self, *args) -> None:
        self._write("WARN", *args)

    def warning(self, *args) -> None:
        self._write("WARN", *args)

    def error(self, *args) -> None:
        self._write("ERROR", *args)


logger = Logger()