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
  const payload = { target, mode };
  if (mode === 'selected' || (scans && scans.length > 0)) {
    payload.scans = scans;
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
