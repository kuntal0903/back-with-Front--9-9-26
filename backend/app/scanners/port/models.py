"""
app/scanners/port/models.py

Pydantic models representing structured data for the Port Discovery Scanner.
"""

from pydantic import BaseModel, Field


class PortDiscoveryRecord(BaseModel):
    """
    Represents the reachability status of a single network port on a target.
    """

    port: int = Field(..., ge=1, le=65535, description="Network port number.")
    protocol: str = Field(default="tcp", description="Network protocol (e.g., 'tcp', 'udp').")
    state: str = Field(
        ...,
        description="The reachability state: open | closed | filtered | unreachable | open_or_filtered | error.",
    )
    reason: str = Field(
        ...,
        description="Detail behind the state classification (e.g., 'connection_accepted', 'connection_refused', 'timeout', 'host_unreachable').",
    )
    duration_seconds: float = Field(
        ...,
        description="Time taken in seconds to probe this port.",
    )
    method: str = Field(
        default="tcp_connect",
        description="Probing mechanism used (e.g., 'tcp_connect', 'udp_probe').",
    )
    attempt_count: int = Field(
        default=1,
        description="Number of probe attempts made before finalizing state.",
    )
    service_hint: str | None = Field(
        default=None,
        description="Non-binding service suggestion based on standard port association (e.g., 'http', 'https', 'ssh'). Must be verified by Service Identification scanner.",
    )
