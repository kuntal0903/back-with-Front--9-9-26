"""
app/api/routes/scans.py

Scan API routes implementing creation, background orchestration triggers, status tracking, and results aggregates retrieval.
"""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, HTTPException, status
from fastapi.responses import JSONResponse

from app.core.exceptions import AttackSurfaceEngineError
from app.core.constants import SCAN_STATUS_QUEUED
from app.models.scan import Scan
from app.schemas.scan_request import ScanRequest
from app.schemas.scan_response import ScanCreatedResponse
from app.services.target.processor import TargetProcessor

from app.orchestrator.db import scan_db
from app.orchestrator.scan_orchestrator import ScanOrchestrator

router = APIRouter()
orchestrator = ScanOrchestrator()


@router.post(
    "/scans",
    response_model=ScanCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit a Scan",
    description=(
        "Submits a target for scanning. The target is validated, classified, "
        "normalized, and scope-checked. If valid, a background scan is created."
    ),
    tags=["Scans"],
)
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks) -> ScanCreatedResponse:
    """
    Submit a scan target and queue background execution.
    """
    try:
        processor = TargetProcessor()
        target_info = processor.process(request.target)

        # Enforce that scans are populated if required by mode
        if request.requires_scans_field() and not request.scans:
            raise HTTPException(
                status_code=422,
                detail=f"Field 'scans' is required when mode is '{request.mode}'.",
            )

        # Build Scan record
        scan_id = str(uuid.uuid4())
        scan = Scan(
            scan_id=scan_id,
            target=target_info,
            status=SCAN_STATUS_QUEUED,
            mode=request.mode,
            scans=request.scans or [],
            progress=0,
            created_at=datetime.now(timezone.utc),
        )
        scan_db.save_scan(scan)

        # Trigger background orchestration task
        background_tasks.add_task(orchestrator.run_scan, scan_id)

        return ScanCreatedResponse(
            scan_id=scan_id,
            status=SCAN_STATUS_QUEUED,
            target=target_info,
            created_at=scan.created_at,
            message="Scan target accepted and queued successfully.",
        )
    except AttackSurfaceEngineError as e:
        raise e


@router.get(
    "/scans/{scan_id}",
    summary="Get Scan Status",
    description="Returns the status of a scan by ID.",
    tags=["Scans"],
)
async def get_scan_status(scan_id: str) -> JSONResponse:
    """
    Scan status endpoint — returns active progress, status, and messages.
    """
    scan = scan_db.get_scan(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID '{scan_id}' not found.",
        )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "scan_id": scan.scan_id,
            "status": scan.status,
            "progress": scan.progress,
            "message": scan.message or f"Scan is currently {scan.status}.",
            "created_at": scan.created_at.isoformat(),
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        },
    )


@router.get(
    "/scans/{scan_id}/results",
    summary="Get Scan Results",
    description="Returns the full results of a completed scan.",
    tags=["Scans"],
)
async def get_scan_results(scan_id: str) -> JSONResponse:
    """
    Scan results endpoint — returns aggregated discovered nodes, relationships, and execution errors.
    """
    scan = scan_db.get_scan(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID '{scan_id}' not found.",
        )

    result = scan_db.get_result(scan_id)
    if not result:
        # Results not aggregated yet (scan still queued or running)
        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content={
                "scan_id": scan_id,
                "status": scan.status,
                "progress": scan.progress,
                "message": "Scan is still in progress. Results are not yet available.",
            },
        )

    # Return structured results
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=result.model_dump(mode="json"),
    )
