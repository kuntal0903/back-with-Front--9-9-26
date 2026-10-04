"""
app/core/db.py

In-memory database lifecycle management.
Operating in pure in-memory mode without external database dependencies.
"""

import logging
from typing import Any

logger = logging.getLogger("app.db")


class MongoManager:
    """
    Lightweight in-memory DB manager handle preserving API contracts.
    """

    def __init__(self) -> None:
        self.client = None
        self.db = None
        self.is_connected: bool = False

    async def connect(self) -> None:
        """Operating in in-memory mode."""
        logger.info("Operating in 'in_memory' database mode.")
        self.is_connected = False

    async def disconnect(self) -> None:
        """No-op disconnect."""
        self.is_connected = False

    async def ping(self) -> dict[str, Any]:
        """Return healthy in-memory status."""
        return {"status": "healthy", "driver": "in_memory"}


mongo_manager = MongoManager()
