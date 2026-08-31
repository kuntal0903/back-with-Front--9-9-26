"""
scripts/scan.py

Command-line Interface (CLI) for the Attack Surface Engineering Platform.

Usage Examples:
    scan dns google.com
    scan full google.com
    scan tls google.com
    scan port 192.178.158.100
"""

import argparse
import asyncio
import sys
from datetime import datetime, timezone

# Ensure project root is on sys.path
sys.path.insert(0, ".")

from app.core.constants import (
    SCAN_STATUS_QUEUED,
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
from app.models.scan import Scan
from app.orchestrator.db import scan_db
from app.orchestrator.scan_orchestrator import ScanOrchestrator
from app.services.assets.db import asset_db
from app.services.target.processor import TargetProcessor

VALID_TOOLS = [
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
]

# Short convenient aliases mapping to canonical tool identifiers
TOOL_ALIASES = {
    "dns": TOOL_DNS_SCAN,
    "dns_scan": TOOL_DNS_SCAN,
    "port": TOOL_PORT_DISCOVERY,
    "port_discovery": TOOL_PORT_DISCOVERY,
    "service": TOOL_SERVICE_IDENTIFICATION,
    "service_identification": TOOL_SERVICE_IDENTIFICATION,
    "http": TOOL_HTTP_SCAN,
    "http_scan": TOOL_HTTP_SCAN,
    "tech": TOOL_TECHNOLOGY_DETECTION,
    "technology": TOOL_TECHNOLOGY_DETECTION,
    "technology_detection": TOOL_TECHNOLOGY_DETECTION,
    "endpoint": TOOL_ENDPOINT_DISCOVERY,
    "endpoint_discovery": TOOL_ENDPOINT_DISCOVERY,
    "js": TOOL_JAVASCRIPT_DISCOVERY,
    "javascript": TOOL_JAVASCRIPT_DISCOVERY,
    "javascript_discovery": TOOL_JAVASCRIPT_DISCOVERY,
    "tls": TOOL_TLS_SCAN,
    "tls_scan": TOOL_TLS_SCAN,
    "email": TOOL_EMAIL_SECURITY,
    "email_security": TOOL_EMAIL_SECURITY,
    "cloud": TOOL_CLOUD_CDN_DETECTION,
    "cdn": TOOL_CLOUD_CDN_DETECTION,
    "cloud_cdn": TOOL_CLOUD_CDN_DETECTION,
    "cloud_cdn_detection": TOOL_CLOUD_CDN_DETECTION,
}


async def run_cli_scan(tool_or_mode: str, target_str: str):
    # Clear databases
    asset_db.clear()
    scan_db.clear()

    # Process target
    processor = TargetProcessor()
    try:
        target_info = processor.process(target_str)
    except Exception as e:
        print(f"\n[-] Target Error: {e}")
        sys.exit(1)

    normalized_input = tool_or_mode.lower().strip()

    # Determine mode and tools
    if normalized_input in ("full", "all"):
        mode = "full"
        scans = []
        mode_label = "FULL SCAN (All Tools)"
    elif normalized_input in TOOL_ALIASES:
        canonical_tool = TOOL_ALIASES[normalized_input]
        mode = "individual"
        scans = [canonical_tool]
        mode_label = f"SINGLE SCAN [{canonical_tool}]"
    else:
        print(f"\n[-] Invalid Tool or Mode: '{tool_or_mode}'")
        print("Available short tools: dns, port, service, http, tech, endpoint, js, tls, email, cloud")
        print("Use 'full' or 'all' for complete scanning.")
        sys.exit(1)

    print("\n" + "=" * 60)
    print(" ATTACK SURFACE ENGINE CLI")
    print("=" * 60)
    print(f"  Target:     {target_info.original} ({target_info.target_type})")
    print(f"  Mode:       {mode_label}")
    print(f"  Started:    {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("=" * 60 + "\n")

    # Create scan record
    scan = Scan(
        target=target_info,
        status=SCAN_STATUS_QUEUED,
        mode=mode,
        scans=scans,
    )
    scan_db.save_scan(scan)

    # Run orchestrator
    print("[*] Scanning target... please wait...\n")
    orchestrator = ScanOrchestrator()
    await orchestrator.run_scan(scan.scan_id)

    # Fetch result
    updated_scan = scan_db.get_scan(scan.scan_id)
    result = scan_db.get_result(scan.scan_id)

    if not result:
        print("[-] Scan failed or returned no results.")
        sys.exit(1)

    # Print results
    print("=" * 60)
    print(f" SCAN RESULTS (Status: {updated_scan.status.upper()})")
    print("=" * 60)

    # Assets
    print(f"\n[+] DISCOVERED ASSETS ({len(result.assets)} Total):")
    asset_by_type = {}
    for a in result.assets:
        asset_by_type.setdefault(a.asset_type, []).append(a)

    for atype, assets in sorted(asset_by_type.items()):
        print(f"\n  [ {atype.upper()} ] ({len(assets)} items):")
        for a in assets[:10]:
            print(f"     * {a.normalized_value}")
            if a.metadata:
                for k, v in a.metadata.items():
                    if v and str(v).strip():
                        print(f"       +-- {k}: {str(v)[:70]}")
        if len(assets) > 10:
            print(f"     ... and {len(assets) - 10} more")

    # Relationships
    print(f"\n[+] RELATIONSHIPS ({len(result.relationships)} Total):")
    rel_counts = {}
    for r in result.relationships:
        rel_counts[r.relationship_type] = rel_counts.get(r.relationship_type, 0) + 1
    for rtype, count in rel_counts.items():
        print(f"  * {rtype}: {count} links")

    # Errors
    if result.errors:
        print(f"\n[!] ERRORS ({len(result.errors)}):")
        for err in result.errors:
            print(f"  * {err.get('error_type')}: {err.get('message')}")

    print("\n" + "=" * 60)
    print(f" [+] Scan complete! Discovered {len(result.assets)} assets and {len(result.relationships)} relationships.")
    print("=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Attack Surface Engine Command Line Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  scan dns google.com
  scan tls google.com
  scan port 192.178.158.100
  scan full google.com
        """,
    )
    parser.add_argument(
        "tool_or_mode",
        help="Scan tool short name (dns, port, service, http, tech, endpoint, js, tls, email, cloud) or 'full' / 'all'.",
    )
    parser.add_argument(
        "target",
        help="Target domain, hostname, or IP address (e.g. google.com or 192.0.2.1)",
    )

    args = parser.parse_args()
    asyncio.run(run_cli_scan(args.tool_or_mode, args.target))


if __name__ == "__main__":
    main()
