"""
app/services/assets/manager.py

Orchestrates Attack Surface Asset normalization, deduplication, and relationship correlation.
"""

from datetime import datetime, timezone
import ipaddress
import uuid
from urllib.parse import urlparse
from typing import Any

from app.models.asset import Asset
from app.models.relationship import Relationship
from app.scanners.base.models import ScannerResult
from app.services.assets.db import asset_db
from app.services.assets.correlation import extract_assets_and_relations


class AssetManager:
    """
    Asset Manager service.
    Normalizes asset values, deduplicates utilizing deterministic UUIDs,
    and updates relationship linkages chronologically.
    """

    def process_scanner_result(self, scanner_result: ScannerResult) -> None:
        """
        Process scan results to extract assets and relationships.
        
        Args:
            scanner_result: A ScannerResult container populated by a scanning tool execution.
        """
        tool_name = scanner_result.tool
        
        target_host = scanner_result.target.normalized
        for record in scanner_result.results:
            assets_extracted, relations_extracted = extract_assets_and_relations(
                tool_name, record, target_host
            )
            
            # 1. Process Assets
            for a_def in assets_extracted:
                self.get_or_create_asset(
                    asset_type=a_def["type"],
                    original_value=a_def["value"],
                    source_tool=tool_name,
                    metadata=a_def.get("metadata", {}),
                )
                
            # 2. Process Relationships
            for r_def in relations_extracted:
                # Generate source ID
                src_norm = self.normalize_value(r_def["source_type"], r_def["source_val"])
                src_id = self.generate_deterministic_id(r_def["source_type"], src_norm)
                
                # Generate target ID
                tgt_norm = self.normalize_value(r_def["target_type"], r_def["target_val"])
                tgt_id = self.generate_deterministic_id(r_def["target_type"], tgt_norm)
                
                relationship = Relationship(
                    source_asset_id=src_id,
                    relationship_type=r_def["type"],
                    target_asset_id=tgt_id,
                    source_tool=tool_name,
                    timestamp=datetime.now(timezone.utc),
                )
                asset_db.save_relationship(relationship)

    def get_or_create_asset(
        self,
        asset_type: str,
        original_value: str,
        source_tool: str,
        metadata: dict[str, Any],
    ) -> Asset:
        """
        Deduplicate, normalize, and save an asset.
        If it exists, merge metadata and update last_seen timestamp.
        """
        normalized_value = self.normalize_value(asset_type, original_value)
        asset_id = self.generate_deterministic_id(asset_type, normalized_value)
        
        now = datetime.now(timezone.utc)
        existing = asset_db.get_asset(asset_id)
        
        if existing:
            # Merge duplicate asset and maintain discovery sources history
            sources = list(existing.metadata.get("sources", [existing.source_tool]))
            if source_tool not in sources:
                sources.append(source_tool)

            merged_metadata = {**existing.metadata, **metadata, "sources": sources}
            updated = Asset(
                asset_id=existing.asset_id,
                asset_type=existing.asset_type,
                original_value=existing.original_value,
                normalized_value=existing.normalized_value,
                status=existing.status,
                source_tool=existing.source_tool,  # Keep initial source tool
                first_seen=existing.first_seen,    # Keep initial first seen
                last_seen=now,                     # Update last seen timestamp
                metadata=merged_metadata,
            )
            asset_db.save_asset(updated)
            return updated
        else:
            # Create new asset with initial sources list
            initial_metadata = {**metadata, "sources": [source_tool]}
            new_asset = Asset(
                asset_id=asset_id,
                asset_type=asset_type,
                original_value=original_value,
                normalized_value=normalized_value,
                status="confirmed",
                source_tool=source_tool,
                first_seen=now,
                last_seen=now,
                metadata=initial_metadata,
            )
            asset_db.save_asset(new_asset)
            return new_asset

    def normalize_value(self, asset_type: str, value: str) -> str:
        """
        Canonical value normalizer for different asset types.
        """
        cleaned = value.strip()
        
        if asset_type in ("domain", "hostname", "mail_server"):
            return cleaned.rstrip(".").lower()
            
        elif asset_type == "ip_address":
            try:
                candidate = cleaned.strip("[]")
                if "." in candidate and not ":" in candidate:
                    # Pre-strip leading zeros to avoid AddressValueError in ipaddress module
                    candidate = ".".join(str(int(part)) for part in candidate.split("."))
                ip_obj = ipaddress.ip_address(candidate)
                return str(ip_obj)
            except Exception:
                return cleaned.lower()
                
        elif asset_type == "network_port":
            # Format is host:port
            if ":" in cleaned:
                host, port = cleaned.rsplit(":", 1)
                host_norm = host.strip().rstrip(".").lower()
                return f"{host_norm}:{port.strip()}"
            return cleaned.lower()
            
        elif asset_type in ("url", "javascript_file"):
            # Normalize schemes/hostnames in URL
            try:
                parsed = urlparse(cleaned)
                scheme = parsed.scheme.lower()
                netloc = parsed.netloc.lower().rstrip(".")
                path = parsed.path
                query = parsed.query
                fragment = parsed.fragment
                
                # Reconstruct normalized URL without fragment
                url_norm = f"{scheme}://{netloc}{path}"
                if query:
                    url_norm += f"?{query}"
                return url_norm
            except Exception:
                return cleaned
                
        elif asset_type == "endpoint":
            # Ensure path prefix slash
            val = cleaned
            if not val.startswith("/"):
                val = "/" + val
            return val
            
        return cleaned.lower()

    def generate_deterministic_id(self, asset_type: str, normalized_value: str) -> str:
        """
        Generate deterministic UUID strings from type and normalized value.
        """
        namespace_input = f"{asset_type}:{normalized_value}"
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, namespace_input))
