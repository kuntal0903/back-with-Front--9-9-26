"""
app/scanners/base/base_scanner.py

Base scanner interface and lifecycle class.
All 10 attack surface scanning tools inherit from this class.

Lifecycle:
    INPUT (ScannerInput)
        ↓
    execute() [Standard Wrapper]
        ├─ validate_input() [Child hooks]
        ├─ _execute() [Child implementations]
        └─ Error Translation & Safety catch
        ↓
    OUTPUT (ScannerResult)
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import logging

from app.core.constants import SCAN_STATUS_COMPLETED, SCAN_STATUS_FAILED
from app.core.exceptions import AttackSurfaceEngineError
from app.core.logging import get_logger
from app.scanners.base.exceptions import ScannerInputValidationError
from app.scanners.base.models import ScannerErrorDetail, ScannerInput, ScannerResult


class BaseScanner(ABC):
    """
    Abstract Base Class for all scanning tools.
    Enforces a common execution wrapper that standardizes validation,
    concurrency controls, logging, error handling, and structured results.
    """

    tool_name: str

    def __init__(self) -> None:
        if not hasattr(self, "tool_name") or not self.tool_name:
            raise TypeError("Subclasses of BaseScanner must define a non-empty 'tool_name'.")
        self.logger = get_logger(f"app.scanners.{self.tool_name}")

    def validate_input(self, input_data: ScannerInput) -> None:
        """
        Subclasses override this to enforce target type compatibility or configuration rules.
        For example, a DNS scanner might reject IP targets with ScannerInputValidationError.
        
        Args:
            input_data: Unified scanner inputs.
            
        Raises:
            ScannerInputValidationError: If input is invalid for this specific tool.
        """
        pass

    async def execute(self, input_data: ScannerInput) -> ScannerResult:
        """
        Executes the scanner lifecycle. Handles validation, execution,
        concurrency metrics, timers, and error handling.
        
        Args:
            input_data: Standard input constraints.
            
        Returns:
            ScannerResult: Complete structured execution report.
        """
        started_at = datetime.now(timezone.utc)
        self.logger.info(
            "Scan tool execution started",
            extra={
                "tool": self.tool_name,
                "target": input_data.target.normalized,
            },
        )

        result = ScannerResult(
            tool=self.tool_name,
            status=SCAN_STATUS_FAILED,  # Default to failed until completed successfully
            target=input_data.target,
            started_at=started_at,
            completed_at=started_at,  # Placeholder, updated at end
        )

        try:
            # 1. Syntactic / Semantic Validation inside the scanner scope
            self.validate_input(input_data)

            # 2. Run child class scanning implementation
            await self._execute(input_data, result)

            # 3. If executed successfully, mark as completed
            result.status = SCAN_STATUS_COMPLETED

        except AttackSurfaceEngineError as e:
            # Specific domain error raised intentionally inside scanner
            self.logger.warning(
                "Scan tool encountered domain error",
                extra={
                    "tool": self.tool_name,
                    "target": input_data.target.normalized,
                    "error_type": e.error_type,
                    "error_message": e.message,
                },
            )
            result.errors.append(
                ScannerErrorDetail(
                    error_type=e.error_type,
                    message=e.message,
                )
            )
        except Exception as e:
            # Unexpected execution failure (crashes, library errors, etc.)
            self.logger.exception(
                "Scan tool crashed with unexpected error",
                extra={
                    "tool": self.tool_name,
                    "target": input_data.target.normalized,
                },
                exc_info=e,
            )
            result.errors.append(
                ScannerErrorDetail(
                    error_type="internal_error",
                    message=f"An unexpected internal scanner error occurred: {e}",
                )
            )

        result.completed_at = datetime.now(timezone.utc)
        self.logger.info(
            "Scan tool execution completed",
            extra={
                "tool": self.tool_name,
                "target": input_data.target.normalized,
                "status": result.status,
                "errors_count": len(result.errors),
                "results_count": len(result.results),
                "evidence_count": len(result.evidence),
                "duration_seconds": (result.completed_at - result.started_at).total_seconds(),
            },
        )
        return result

    @abstractmethod
    async def _execute(self, input_data: ScannerInput, result: ScannerResult) -> None:
        """
        Abstract method where scanner-specific implementation resides.
        Should populate result.results, result.evidence, and optionally result.errors.
        
        Args:
            input_data: Standard input constraints.
            result: The output object to populate.
        """
        pass
