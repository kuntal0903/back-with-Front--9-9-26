"""
app/orchestrator/dependency_manager.py

Manages target-type compatibilities and scanner execution dependencies.
"""

from app.core.constants import (
    TARGET_TYPE_DOMAIN,
    TARGET_TYPE_HOSTNAME,
    TARGET_TYPE_IPV4,
    TARGET_TYPE_IPV6,
    TOOL_DNS_SCAN,
    TOOL_PORT_DISCOVERY,
    TOOL_SERVICE_IDENTIFICATION,
    TOOL_HTTP_SCAN,
    TOOL_TECHNOLOGY_DETECTION,
    TOOL_ENDPOINT_DISCOVERY,
    TOOL_JAVASCRIPT_DISCOVERY,
    TOOL_TLS_SCAN,
    TOOL_EMAIL_SECURITY,
    TOOL_CLOUD_CDN_DETECTION,
)


class ScanDependencyManager:
    """
    Validates scan tool compatibilities and evaluates execution dependency chains.
    """

    def __init__(self) -> None:
        # Map target types to compatible base scanning tools
        self._compatibility_map = {
            TARGET_TYPE_DOMAIN: [
                TOOL_DNS_SCAN,
                TOOL_EMAIL_SECURITY,
                TOOL_HTTP_SCAN,
                TOOL_TLS_SCAN,
                TOOL_CLOUD_CDN_DETECTION,
            ],
            TARGET_TYPE_HOSTNAME: [
                TOOL_DNS_SCAN,
                TOOL_HTTP_SCAN,
                TOOL_TLS_SCAN,
                TOOL_CLOUD_CDN_DETECTION,
            ],
            TARGET_TYPE_IPV4: [
                TOOL_PORT_DISCOVERY,
                TOOL_HTTP_SCAN,
                TOOL_TLS_SCAN,
                TOOL_CLOUD_CDN_DETECTION,
            ],
            TARGET_TYPE_IPV6: [
                TOOL_PORT_DISCOVERY,
                TOOL_HTTP_SCAN,
                TOOL_TLS_SCAN,
                TOOL_CLOUD_CDN_DETECTION,
            ],
        }

        # Dependencies: tool -> list of tools that must execute before it
        self._dependencies = {
            TOOL_DNS_SCAN: [],
            TOOL_EMAIL_SECURITY: [],
            TOOL_PORT_DISCOVERY: [],
            TOOL_HTTP_SCAN: [],
            TOOL_TLS_SCAN: [],
            TOOL_CLOUD_CDN_DETECTION: [],
            
            # Service Identification requires Port Discovery to find open ports first
            TOOL_SERVICE_IDENTIFICATION: [TOOL_PORT_DISCOVERY],
            
            # Technology, Endpoint, and JS Discovery scanners require HTTP body details
            TOOL_TECHNOLOGY_DETECTION: [TOOL_HTTP_SCAN],
            TOOL_ENDPOINT_DISCOVERY: [TOOL_HTTP_SCAN],
            TOOL_JAVASCRIPT_DISCOVERY: [TOOL_HTTP_SCAN],
        }

    def get_compatible_tools(self, target_type: str) -> list[str]:
        """
        Get all scan tools compatible with a specific target type.
        """
        return self._compatibility_map.get(target_type, [])

    def is_compatible(self, tool_name: str, target_type: str) -> bool:
        """
        Check if a tool is compatible with a target type.
        
        Compatibility includes both direct compatibility (the tool can run on
        this target type natively) and cascading compatibility (the tool can
        run on sub-assets that other scanners discover from this target type).
        """
        # Direct compatibility check
        if tool_name in self.get_compatible_tools(target_type):
            return True
        
        # Cascading compatibility:
        # Port discovery can cascade onto IPs discovered by DNS from domains/hostnames
        if tool_name == TOOL_PORT_DISCOVERY:
            return TOOL_DNS_SCAN in self.get_compatible_tools(target_type)
        
        # Service identification cascades from port discovery results
        if tool_name == TOOL_SERVICE_IDENTIFICATION:
            return self.is_compatible(TOOL_PORT_DISCOVERY, target_type)
        
        # Technology, Endpoint, and JS discovery cascade from HTTP scan results
        if tool_name in (TOOL_TECHNOLOGY_DETECTION, TOOL_ENDPOINT_DISCOVERY, TOOL_JAVASCRIPT_DISCOVERY):
            return TOOL_HTTP_SCAN in self.get_compatible_tools(target_type)
        
        return False

    def get_dependencies(self, tool_name: str) -> list[str]:
        """
        Get list of parent tools that must run before the specified tool.
        """
        return self._dependencies.get(tool_name, [])

    def resolve_execution_order(self, tools: list[str]) -> list[list[str]]:
        """
        Resolve execution dependencies into chronological stages of parallel execution.
        
        Args:
            tools: List of selected tool names.
            
        Returns:
            list[list[str]]: Chronological stages of tools to execute (e.g. Stage 0, Stage 1).
        """
        resolved = []
        remaining = set(tools)
        completed = set()

        while remaining:
            stage = []
            for tool in sorted(list(remaining)):
                # A tool is ready for this stage if all of its dependencies
                # are either not selected in this scan or have already completed in a prior stage
                deps = self.get_dependencies(tool)
                if all(d not in remaining for d in deps):
                    stage.append(tool)
            
            if not stage:
                # Cyclic dependency or missing selection - break to prevent infinite loop
                # Just add remaining tools as a final fallback stage
                resolved.append(list(remaining))
                break
                
            resolved.append(stage)
            completed.update(stage)
            remaining.difference_update(stage)

        return resolved
