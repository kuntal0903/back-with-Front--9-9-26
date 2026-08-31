"""
app/orchestrator/db.py

Thread-safe in-memory database mock storage for Scan lifecycle records and ScanResults.
"""

import threading
from app.models.scan import Scan
from app.models.results import ScanResult


class InMemoryScanDb:
    """
    In-memory storage manager for scan configurations and execution results.
    Uses locks to ensure thread-safety across concurrent scan operations.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._scans: dict[str, Scan] = {}
        self._results: dict[str, ScanResult] = {}

    def save_scan(self, scan: Scan) -> None:
        """
        Save or update a scan configuration/status record.
        """
        with self._lock:
            self._scans[scan.scan_id] = scan

    def get_scan(self, scan_id: str) -> Scan | None:
        """
        Fetch a scan record by its ID.
        """
        with self._lock:
            return self._scans.get(scan_id)

    def save_result(self, result: ScanResult) -> None:
        """
        Save or update an aggregated scan result record.
        """
        with self._lock:
            self._results[result.scan_id] = result

    def get_result(self, scan_id: str) -> ScanResult | None:
        """
        Fetch an aggregated scan result by its scan ID.
        """
        with self._lock:
            return self._results.get(scan_id)

    def clear(self) -> None:
        """
        Clear all stored scans and results.
        """
        with self._lock:
            self._scans.clear()
            self._results.clear()


# Single shared scan database instance
scan_db = InMemoryScanDb()
