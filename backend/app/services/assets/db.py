"""
app/services/assets/db.py

Thread-safe in-memory database mock storage for Attack Surface Assets and Relationships.
"""

import threading
from app.models.asset import Asset
from app.models.relationship import Relationship


class InMemoryAssetDb:
    """
    In-memory storage manager for assets and relationships.
    Uses locks to ensure thread-safety across concurrent scan operations.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._assets: dict[str, Asset] = {}
        self._relationships: dict[str, Relationship] = {}

    def save_asset(self, asset: Asset) -> None:
        """
        Save or update an asset in-memory.
        """
        with self._lock:
            self._assets[asset.asset_id] = asset

    def get_asset(self, asset_id: str) -> Asset | None:
        """
        Fetch an asset by its deterministic ID.
        """
        with self._lock:
            return self._assets.get(asset_id)

    def get_assets(self) -> list[Asset]:
        """
        Retrieve all stored assets.
        """
        with self._lock:
            return list(self._assets.values())

    def get_assets_by_scan_id(self, scan_id: str) -> list[Asset]:
        """
        Retrieve assets associated with a specific scan ID.
        """
        with self._lock:
            return [a for a in self._assets.values() if a.scan_id == scan_id]

    def save_relationship(self, rel: Relationship) -> None:
        """
        Save or update a relationship link.
        """
        key = f"{rel.scan_id or 'global'}:{rel.source_asset_id}:{rel.relationship_type}:{rel.target_asset_id}"
        with self._lock:
            self._relationships[key] = rel

    def get_relationship(self, source_id: str, rel_type: str, target_id: str) -> Relationship | None:
        """
        Fetch a relationship by its source, type, and target asset IDs.
        """
        with self._lock:
            for r in self._relationships.values():
                if r.source_asset_id == source_id and r.relationship_type == rel_type and r.target_asset_id == target_id:
                    return r
            return None

    def get_relationships(self) -> list[Relationship]:
        """
        Retrieve all stored relationships.
        """
        with self._lock:
            return list(self._relationships.values())

    def get_relationships_by_scan_id(self, scan_id: str) -> list[Relationship]:
        """
        Retrieve relationships associated with a specific scan ID.
        """
        with self._lock:
            return [r for r in self._relationships.values() if r.scan_id == scan_id]


    def clear(self) -> None:
        """
        Clear all stored assets and relationships.
        """
        with self._lock:
            self._assets.clear()
            self._relationships.clear()


# Single shared database instance
asset_db = InMemoryAssetDb()
