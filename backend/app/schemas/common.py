"""
app/schemas/common.py

Shared Pydantic schemas used across multiple API endpoints.
"""

from pydantic import BaseModel


class ErrorResponse(BaseModel):
    """
    Structured error response returned by the API for all failures.

    This model is used by the global exception handlers in app/main.py
    and ensures callers always receive predictable JSON error shapes.
    """

    status: str = "failed"
    error_type: str
    message: str

    model_config = {"json_schema_extra": {"examples": [
        {
            "status": "failed",
            "error_type": "invalid_target",
            "message": "The provided target is not a valid domain or IP address.",
        }
    ]}}
