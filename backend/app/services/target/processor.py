"""
app/services/target/processor.py

Target processor.

Responsibility: Coordinate the entire target processing workflow:
    1. syntactic pre-validation (validator.py)
    2. target classification (classifier.py)
    3. normalization (normalizer.py)
    4. scope authorization (scope_checker.py)

Returns a structured TargetInfo schema or raises appropriate domain exceptions.

Flow:
    raw_target (str)
        ↓
    validate_raw_input
        ↓
    classify_target
        ↓
    normalize_target
        ↓
    check_scope
        ↓
    TargetInfo schema
"""

from typing import Sequence

from app.schemas.scan_request import TargetInfo
from app.services.target.classifier import classify_target
from app.services.target.normalizer import extract_target_components, normalize_target
from app.services.target.scope_checker import ScopeChecker
from app.services.target.validator import validate_raw_input


class TargetProcessor:
    """
    Coordinates target validation, classification, normalization, and scope checks.
    """

    def __init__(
        self,
        allowed_targets: Sequence[str] | None = None,
        excluded_targets: Sequence[str] | None = None,
        allow_private_ips: bool | None = None,
    ) -> None:
        """
        Initialize the processor with configuration policies.
        """
        self.scope_checker = ScopeChecker(
            allowed_targets=allowed_targets,
            excluded_targets=excluded_targets,
            allow_private_ips=allow_private_ips,
        )

    def process(self, raw_target: str) -> TargetInfo:
        """
        Run the complete target processing pipeline.

        Args:
            raw_target: The user-supplied raw target string.

        Returns:
            TargetInfo: Structured data with enriched target details.

        Raises:
            InvalidInputError: If basic syntactic pre-validation fails.
            InvalidTargetError: If the target cannot be classified.
            ScopeRejectedError: If the target is not authorized or allowed.
        """
        # 1. Syntactic validation
        cleaned = validate_raw_input(raw_target)

        # 2. Extract components
        host_str, scheme, port, path = extract_target_components(cleaned)

        # 3. Classification
        target_type = classify_target(host_str)

        # 4. Normalization
        normalized_host = normalize_target(host_str, target_type)

        # 5. Scope authorization
        self.scope_checker.check_scope(normalized_host, target_type)

        # 6. Determine derived attributes
        hostname = normalized_host if target_type in ("domain", "hostname") else None
        ip = normalized_host if target_type in ("ipv4", "ipv6") else None

        if scheme:
            initial_asset = f"url:{raw_target}"
        elif target_type in ("domain", "hostname"):
            initial_asset = f"{target_type}:{normalized_host}"
        else:
            initial_asset = f"ip_address:{normalized_host}"

        # 7. Return structured representation
        return TargetInfo(
            original=raw_target,
            normalized=normalized_host,
            target_type=target_type,
            hostname=hostname,
            ip=ip,
            scheme=scheme,
            port=port,
            path=path,
            scope="in_scope",
            initial_asset=initial_asset,
        )
