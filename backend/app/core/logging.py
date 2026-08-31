"""
app/core/logging.py

Structured logging configuration for the Attack Surface Engineering Platform.
Supports both standard text formatting (development) and JSON formatting (production).
"""

import json
import logging
import sys
from datetime import datetime, timezone

from app.core.config import settings


class JsonFormatter(logging.Formatter):
    """
    JSON log formatter for production log aggregation (ELK, Datadog, CloudWatch).
    """

    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Include standard extra attributes if attached
        if hasattr(record, "scan_id"):
            log_obj["scan_id"] = getattr(record, "scan_id")
        if hasattr(record, "tool"):
            log_obj["tool"] = getattr(record, "tool")
        if hasattr(record, "target"):
            log_obj["target"] = getattr(record, "target")

        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_obj)


def configure_logging() -> None:
    """
    Configure application-wide structured logging.

    Should be called once at application startup.
    Log level and log format are loaded from environment configuration.
    """
    log_level = settings.app_log_level.upper()

    numeric_level = getattr(logging, log_level, None)
    if not isinstance(numeric_level, int):
        numeric_level = logging.INFO

    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Remove existing handlers to avoid duplicates
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(numeric_level)

    # Determine formatter based on environment configuration
    if settings.app_log_format.lower() == "json" or settings.is_production:
        handler.setFormatter(JsonFormatter())
    else:
        log_format = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
        handler.setFormatter(logging.Formatter(log_format))

    root_logger.addHandler(handler)

    # Suppress verbose third-party library logs
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """
    Return a named logger instance.

    Args:
        name: Typically __name__ of the calling module.

    Returns:
        A configured Logger instance.
    """
    return logging.getLogger(name)
