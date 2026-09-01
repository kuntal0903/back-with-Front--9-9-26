/**
 * src/api/scanApi.js
 *
 * REST API client module connecting the Frontend UI to the Attack Surface Engine Backend.
 * Uses environment variable VITE_API_URL or defaults to localhost in dev / relative origin.
 */

const API_BASE = (import.meta.env.VITE_API_URL || '').replace(/\/$/, '');

/**
 * Health check endpoint probe
 */
export async function checkHealth() {
  try {
    const res = await fetch(`${API_BASE}/api/v1/health`);
    if (!res.ok) throw new Error(`Health check failed: ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('Backend API Health check error:', err);
    return { status: 'offline', error: err.message };
  }
}

/**
 * Submit scan target to backend
 */
export async function submitScan(target, mode = 'full', scans = []) {
  let requestMode = 'full';
  let requestScans = [];

  const TOOL_MAP = {
    'dns': 'dns_scan',
    'dns_scan': 'dns_scan',
    'port': 'port_discovery',
    'port_discovery': 'port_discovery',
    'service': 'service_identification',
    'service_identification': 'service_identification',
    'http': 'http_scan',
    'http_scan': 'http_scan',
    'tech': 'technology_detection',
    'technology_detection': 'technology_detection',
    'endpoint': 'endpoint_discovery',
    'endpoint_discovery': 'endpoint_discovery',
    'js': 'javascript_discovery',
    'javascript_discovery': 'javascript_discovery',
    'tls': 'tls_scan',
    'tls_scan': 'tls_scan',
    'email': 'email_security',
    'email_security': 'email_security',
    'cloud': 'cloud_cdn_detection',
    'cloud_cdn_detection': 'cloud_cdn_detection',
  };

  if (mode === 'full' || mode === 'all') {
    requestMode = 'full';
    requestScans = [];
  } else {
    requestMode = 'selected';
    const canonicalTool = TOOL_MAP[mode] || mode;
    requestScans = [canonicalTool];
  }

  const payload = { target, mode: requestMode };
  if (requestMode === 'selected' || (requestScans && requestScans.length > 0)) {
    payload.scans = requestScans;
  }

  const res = await fetch(`${API_BASE}/api/v1/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.message || `Scan submission failed (${res.status})`);
  }

  return await res.json();
}

/**
 * Get active scan status by scan_id
 */
export async function getScanStatus(scanId) {
  const res = await fetch(`${API_BASE}/api/v1/scans/${scanId}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch scan status (${res.status})`);
  }
  return await res.json();
}

/**
 * Get completed scan results by scan_id
 */
export async function getScanResults(scanId) {
  const res = await fetch(`${API_BASE}/api/v1/scans/${scanId}/results`);
  if (!res.ok) {
    throw new Error(`Failed to fetch scan results (${res.status})`);
  }
  return await res.json();
}
