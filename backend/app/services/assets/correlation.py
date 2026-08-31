"""
app/services/assets/correlation.py

Extracts raw assets and directed relationships from various scanner record types.
"""

from typing import Any
from urllib.parse import urlparse

from app.core.constants import (
    TARGET_TYPE_DOMAIN,
    TARGET_TYPE_HOSTNAME,
    TARGET_TYPE_IPV4,
    TARGET_TYPE_IPV6,
)
from app.services.target.classifier import classify_target


def determine_asset_type_for_host(host: str) -> str:
    """
    Classify a target host string into 'ip_address', 'domain', or 'hostname'.
    """
    cleaned = host.strip().rstrip(".")
    if not cleaned:
        return "hostname"
    try:
        t_type = classify_target(cleaned)
        if t_type in (TARGET_TYPE_IPV4, TARGET_TYPE_IPV6):
            return "ip_address"
        elif t_type == TARGET_TYPE_DOMAIN:
            return "domain"
        elif t_type == TARGET_TYPE_HOSTNAME:
            return "hostname"
    except Exception:
        pass
    return "hostname"


def extract_assets_and_relations(
    tool_name: str,
    record: Any,
    target_host: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Extract standardized asset and relationship dictionary definitions from scanner outputs.
    
    Args:
        tool_name: The scanner tool name identifier.
        record: The individual result record from scanner results list.
        target_host: The parent target hostname/IP of the scan.
        
    Returns:
        tuple[list[dict], list[dict]]:
            - list[dict]: Each dict represents an asset: { "type": str, "value": str, "metadata": dict }
            - list[dict]: Each dict represents a directed relationship:
                { "source_type": str, "source_val": str, "type": str, "target_type": str, "target_val": str }
    """
    assets = []
    relations = []
    
    rec_type = type(record).__name__
    t_host_clean = target_host.strip().rstrip(".")
    t_host_type = determine_asset_type_for_host(t_host_clean)

    # 1. DNS Scanner (DnsRecord)
    if rec_type == "DnsRecord":
        target = t_host_clean
        t_type = t_host_type
        assets.append({"type": t_type, "value": target, "metadata": {}})
        
        rtype = record.record_type.upper().strip()
        rdata = record.value.strip()
        
        if rtype in ("A", "AAAA"):
            # resolves_to ip_address
            assets.append({"type": "ip_address", "value": rdata, "metadata": {}})
            relations.append({
                "source_type": t_type, "source_val": target,
                "type": "resolves_to",
                "target_type": "ip_address", "target_val": rdata
            })
        elif rtype == "CNAME":
            # resolves_to CNAME domain/hostname
            c_clean = rdata.rstrip(".")
            c_type = determine_asset_type_for_host(c_clean)
            assets.append({"type": c_type, "value": c_clean, "metadata": {}})
            relations.append({
                "source_type": t_type, "source_val": target,
                "type": "resolves_to",
                "target_type": c_type, "target_val": c_clean
            })
        elif rtype == "MX":
            # mx_for mail_server (MX record has e.g. "10 mail.example.com.")
            parts = rdata.split()
            exchange = parts[1].rstrip(".").lower() if len(parts) >= 2 else rdata.rstrip(".").lower()
            if exchange:
                assets.append({"type": "mail_server", "value": exchange, "metadata": {}})
                relations.append({
                    "source_type": t_type, "source_val": target,
                    "type": "mx_for",
                    "target_type": "mail_server", "target_val": exchange
                })
        elif rtype == "NS":
            # hosts nameserver
            ns_clean = rdata.rstrip(".")
            ns_type = determine_asset_type_for_host(ns_clean)
            assets.append({"type": ns_type, "value": ns_clean, "metadata": {}})
            relations.append({
                "source_type": t_type, "source_val": target,
                "type": "hosts",
                "target_type": ns_type, "target_val": ns_clean
            })

    # 2. Port Scanner (PortDiscoveryRecord)
    elif rec_type == "PortDiscoveryRecord":
        assets.append({"type": t_host_type, "value": t_host_clean, "metadata": {}})
        
        port_val = f"{t_host_clean}:{record.port}"
        assets.append({
            "type": "network_port",
            "value": port_val,
            "metadata": {"port": record.port, "state": record.state, "reason": record.reason}
        })
        relations.append({
            "source_type": t_host_type, "source_val": t_host_clean,
            "type": "exposes",
            "target_type": "network_port", "target_val": port_val
        })

    # 3. Service Scanner (ServiceRecord)
    elif rec_type == "ServiceRecord":
        host = record.host.strip() if hasattr(record, "host") else t_host_clean
        h_type = determine_asset_type_for_host(host)
        
        port_val = f"{host}:{record.port}"
        assets.append({"type": "network_port", "value": port_val, "metadata": {}})
        
        protocol_name = record.protocol or "unknown"
        assets.append({
            "type": "service",
            "value": protocol_name,
            "metadata": {
                "software_name": record.software_name,
                "software_version": record.software_version,
                "is_tls": getattr(record, "is_tls", False),
                "alpn": getattr(record, "alpn", None),
                "confidence": getattr(record, "confidence", "high"),
                "raw_banner": record.raw_banner,
            }
        })
        relations.append({
            "source_type": "network_port", "source_val": port_val,
            "type": "provides",
            "target_type": "service", "target_val": protocol_name
        })

    # 4. HTTP/HTTPS Scanner (HttpRecord)
    elif rec_type == "HttpRecord":
        details = record.details
        url = details.url
        parsed = urlparse(url)
        host = parsed.hostname or t_host_clean
        h_type = determine_asset_type_for_host(host)
        
        assets.append({"type": h_type, "value": host, "metadata": {}})
        assets.append({
            "type": "url",
            "value": url,
            "metadata": {
                "status_code": details.status_code,
                "title": details.title,
            }
        })
        relations.append({
            "source_type": h_type, "source_val": host,
            "type": "serves",
            "target_type": "url", "target_val": url
        })
        
        # Follow redirects history chain
        prev_url = url
        for step in getattr(details, "redirect_chain", []):
            step_url = step.url
            assets.append({"type": "url", "value": step_url, "metadata": {}})
            relations.append({
                "source_type": "url", "source_val": prev_url,
                "type": "redirects_to",
                "target_type": "url", "target_val": step_url
            })
            prev_url = step_url

    # 5. Technology Detection (TechRecord)
    elif rec_type == "TechRecord":
        url = record.url
        assets.append({"type": "url", "value": url, "metadata": {}})
        
        # TechRecord contains list of matched technologies
        for tech in getattr(record, "technologies", []):
            assets.append({
                "type": "technology",
                "value": tech.name,
                "metadata": {
                    "version": tech.version,
                    "confidence": tech.confidence,
                }
            })
            relations.append({
                "source_type": "url", "source_val": url,
                "type": "uses",
                "target_type": "technology", "target_val": tech.name
            })

    # 6. Web Endpoint Discovery (EndpointRecord / crawled link)
    elif rec_type == "EndpointRecord":
        origin = record.parent_url or t_host_clean
        target_link = record.url
        
        assets.append({"type": "url", "value": origin, "metadata": {}})
        # Web endpoint links can be classed as url or endpoint
        t_asset_type = "url" if target_link.startswith(("http://", "https://")) else "endpoint"
        assets.append({"type": t_asset_type, "value": target_link, "metadata": {}})
        relations.append({
            "source_type": "url", "source_val": origin,
            "type": "contains",
            "target_type": t_asset_type, "target_val": target_link
        })

    # 7. JavaScript Discovery (JsRecord)
    elif rec_type == "JsRecord":
        origin = record.origin_url
        assets.append({"type": "url", "value": origin, "metadata": {}})
        
        for script in getattr(record, "scripts", []):
            script_url = script.script_url
            script_type = "javascript_file"
            assets.append({"type": script_type, "value": script_url, "metadata": {}})
            relations.append({
                "source_type": "url", "source_val": origin,
                "type": "contains",
                "target_type": script_type, "target_val": script_url
            })
            
            # Extract paths
            for path in script.discovered_paths:
                assets.append({"type": "endpoint", "value": path, "metadata": {}})
                relations.append({
                    "source_type": script_type, "source_val": script_url,
                    "type": "contains",
                    "target_type": "endpoint", "target_val": path
                })

    # 8. TLS/Certificate Scanner (TlsRecord)
    elif rec_type == "TlsRecord":
        host = record.host.strip()
        h_type = determine_asset_type_for_host(host)
        port_val = f"{host}:{record.port}"
        
        assets.append({"type": h_type, "value": host, "metadata": {}})
        assets.append({"type": "network_port", "value": port_val, "metadata": {}})
        relations.append({
            "source_type": h_type, "source_val": host,
            "type": "exposes",
            "target_type": "network_port", "target_val": port_val
        })

        if record.certificate:
            cert_val = record.certificate.subject.get("commonName") or record.certificate.serial_number
            if cert_val:
                assets.append({
                    "type": "tls_certificate",
                    "value": cert_val,
                    "metadata": {
                        "issuer": record.certificate.issuer,
                        "validity_end": record.certificate.validity_end,
                        "serial_number": record.certificate.serial_number,
                    }
                })
                relations.append({
                    "source_type": "network_port", "source_val": port_val,
                    "type": "uses",
                    "target_type": "tls_certificate", "target_val": cert_val
                })
                
                # Link SAN hosts to the certificate
                for san in record.certificate.subject_alt_names:
                    san_type = determine_asset_type_for_host(san)
                    assets.append({"type": san_type, "value": san, "metadata": {}})
                    relations.append({
                        "source_type": "tls_certificate", "source_val": cert_val,
                        "type": "hosts",
                        "target_type": san_type, "target_val": san
                    })

    # 9. Email Security Scanner (EmailRecord)
    elif rec_type == "EmailRecord":
        domain = record.domain.strip()
        assets.append({"type": "domain", "value": domain, "metadata": {}})
        
        for mx in record.mx_records:
            mx_clean = mx.strip().lower()
            assets.append({"type": "mail_server", "value": mx_clean, "metadata": {}})
            relations.append({
                "source_type": "domain", "source_val": domain,
                "type": "mx_for",
                "target_type": "mail_server", "target_val": mx_clean
            })

    # 10. Cloud/CDN Detection (CloudCdnRecord)
    elif rec_type == "CloudCdnRecord":
        target = record.target.strip()
        t_type = determine_asset_type_for_host(target)
        
        assets.append({"type": t_type, "value": target, "metadata": {}})
        provider = record.provider
        if provider:
            assets.append({
                "type": "infrastructure_indicator",
                "value": provider,
                "metadata": {
                    "is_cloud": record.is_cloud,
                    "is_cdn": record.is_cdn,
                    "detection_method": record.detection_method,
                    "matched_evidence": record.matched_evidence,
                }
            })
            relations.append({
                "source_type": t_type, "source_val": target,
                "type": "infra_hosted_on",
                "target_type": "infrastructure_indicator", "target_val": provider
            })

    return assets, relations
