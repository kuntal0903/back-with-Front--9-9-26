"""
app/core/db.py

MongoDB connection lifecycle management using Motor (async MongoDB driver).
Provides connection pooling, ping health checks, and database index initialization.
"""

import logging
from typing import Any
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import PyMongoError, ServerSelectionTimeoutError

from app.core.config import settings

logger = logging.getLogger("app.db")


class MongoManager:
    """
    Singleton manager for MongoDB connection client and database handle.
    """

    def __init__(self) -> None:
        self.client: AsyncIOMotorClient | None = None
        self.db = None
        self.is_connected: bool = False

    async def connect(self) -> None:
        """
        Establish connection to MongoDB Atlas / server and ensure database indexes exist.
        """
        if not settings.mongodb_url:
            logger.info("MONGODB_URL not configured. Operating in 'in_memory' database mode.")
            return

        try:
            logger.info("Connecting to MongoDB instance...")
            kwargs = {
                "serverSelectionTimeoutMS": 5000,
                "connectTimeoutMS": 5000,
            }
            try:
                import certifi
                kwargs["tlsCAFile"] = certifi.where()
            except Exception:
                pass

            self.client = AsyncIOMotorClient(
                settings.mongodb_url,
                **kwargs,
            )
            self.db = self.client[settings.mongodb_db_name]

            # Verify connection with admin ping command
            await self.client.admin.command("ping")
            self.is_connected = True
            logger.info(f"Successfully connected to MongoDB database: '{settings.mongodb_db_name}'")

            # Initialize Indexes
            await self.init_indexes()
        except ServerSelectionTimeoutError as e:
            logger.warning(f"MongoDB connection timed out: {e}. Falling back to in-memory storage.")
            self.is_connected = False
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            self.is_connected = False

    async def init_indexes(self) -> None:
        """
        Initialize collection indexes for performance and uniqueness.
        """
        if self.db is None:
            return

        try:
            # 1. Scans Collection
            await self.db.scans.create_index("scan_id", unique=True)
            await self.db.scans.create_index([("created_at", -1)])

            # 2. Scan Results Collection
            await self.db.scan_results.create_index("scan_id", unique=True)

            # 3. Assets Collection
            await self.db.assets.create_index("asset_id", unique=True)
            await self.db.assets.create_index("scan_id")
            await self.db.assets.create_index([("normalized_value", 1), ("asset_type", 1)])

            # 4. Relationships Collection
            await self.db.relationships.create_index([("source_asset_id", 1), ("target_asset_id", 1)])
            await self.db.relationships.create_index("scan_id")

            logger.info("MongoDB indexes initialized successfully.")
        except Exception as e:
            logger.warning(f"Failed to create MongoDB indexes: {e}")

    async def disconnect(self) -> None:
        """
        Close MongoDB connection client.
        """
        if self.client:
            self.client.close()
            self.is_connected = False
            logger.info("MongoDB client connection closed.")

    async def ping(self) -> dict[str, Any]:
        """
        Check connectivity and health of MongoDB server.
        """
        if not self.is_connected or self.client is None:
            return {"status": "disconnected", "driver": "in_memory"}

        try:
            await self.client.admin.command("ping")
            return {"status": "healthy", "driver": "mongodb", "database": settings.mongodb_db_name}
        except Exception as e:
            return {"status": "unhealthy", "driver": "mongodb", "error": str(e)}


mongo_manager = MongoManager()
