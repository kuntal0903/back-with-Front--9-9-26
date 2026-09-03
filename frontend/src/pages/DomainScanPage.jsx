import { useState, useMemo, useCallback } from 'react';
import { useToast } from '../context/ToastContext';
import { submitScan, getScanStatus, getScanResults } from '../api/scanApi';
import {
  Globe, Search, AlertTriangle, ShieldCheck, Server, Lock, Radio, Download,
  Activity, RefreshCw, ExternalLink, Zap, AlertCircle
} from 'lucide-react';

import '../styles/domainScan.css';

export default function DomainScanPage() {
  const { addToast } = useToast();
  const [targetDomain, setTargetDomain] = useState('');
  const [scanType, setScanType] = useState('full');
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [activeTab, setActiveTab] = useState('subdomains');
  const [searchFilter, setSearchFilter] = useState('');
  const [consoleLogs, setConsoleLogs] = useState([]);
  const [scanResult, setScanResult] = useState(null);
  const [scanError, setScanError] = useState(null);

  const handleStartScan = useCallback(async () => {
    if (!targetDomain.trim()) return;

    const cleanedDomain = targetDomain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    
    // Clear previous scan results and errors
    setScanResult(null);
    setScanError(null);
    setIsScanning(true);
    setProgress(10);
    
    addToast(`Submitting scan for ${cleanedDomain} to Backend Engine`, 'info');
    setConsoleLogs([
      { time: new Date().toLocaleTimeString(), text: `Connecting to Attack Surface Engine API...`, type: 'info' },
      { time: new Date().toLocaleTimeString(), text: `Submitting target [${cleanedDomain}] (mode: ${scanType})...`, type: 'info' }
    ]);

    try {
      const createdScan = await submitScan(cleanedDomain, scanType);
      const scanId = createdScan.scan_id;
      setConsoleLogs((prev) => [
        ...prev,
        { time: new Date().toLocaleTimeString(), text: `Scan accepted by backend. Scan ID: ${scanId}`, type: 'success' },
        { time: new Date().toLocaleTimeString(), text: `Orchestrating active scanners against target...`, type: 'info' }
      ]);

      let attempts = 0;
      const pollInterval = setInterval(async () => {
        attempts += 1;
        setProgress((prev) => Math.min(prev + 15, 90));

        try {
          const statusRes = await getScanStatus(scanId);
          if (statusRes.status === 'completed' || statusRes.status === 'failed' || attempts > 35) {
            clearInterval(pollInterval);
            setIsScanning(false);

            if (statusRes.status === 'completed') {
              setProgress(100);
              addToast(`Scan completed for ${cleanedDomain}`, 'success');
              setConsoleLogs((prev) => [
                ...prev,
                { time: new Date().toLocaleTimeString(), text: `Backend scan completed. Fetching results graph...`, type: 'success' }
              ]);

              try {
                const resultsData = await getScanResults(scanId);
                const backendAssets = resultsData.assets || [];
                const backendEvidence = resultsData.evidence || [];
                const backendTarget = resultsData.target || {};

                // 1. Primary IP Address from assets or target
                const ipAssets = backendAssets.filter(a => a.asset_type === 'ip_address');
                const primaryIp = ipAssets[0]?.normalized_value || backendTarget.ip || 'Unresolved';

                // 2. Real DNS Records from evidence
                const dnsEvidenceItems = backendEvidence.filter(e => e.source_tool === 'dns_scan' && e.raw_evidence);
                let dnsRecords = dnsEvidenceItems.map(e => {
                  const ev = e.raw_evidence;
                  return {
                    type: ev.record_type || 'A',
                    name: ev.target_hostname || cleanedDomain,
                    value: ev.value || (ev.mx_exchanges ? ev.mx_exchanges.join(', ') : ''),
                    ttl: ev.ttl || 300,
                    status: ev.extra?.dns_status || 'Active'
                  };
                });

                if (dnsRecords.length === 0) {
                  backendAssets.forEach(a => {
                    if (a.asset_type === 'ip_address') {
                      dnsRecords.push({ type: 'A', name: '@', value: a.normalized_value, ttl: 300, status: 'Active' });
                    } else if (a.asset_type === 'domain' || a.asset_type === 'hostname') {
                      dnsRecords.push({ type: 'NS/CNAME', name: '@', value: a.normalized_value, ttl: 300, status: 'Active' });
                    }
                  });
                }

                // 3. Real SSL / TLS Evidence
                const tlsEvidence = backendEvidence.find(e => e.source_tool === 'tls_scan' && e.raw_evidence);
                const tlsRaw = tlsEvidence?.raw_evidence || {};
                const sslCertAsset = backendAssets.find(a => a.asset_type === 'tls_certificate');

                let sslInfo = null;
                if (tlsEvidence || sslCertAsset) {
                  let sslIssuerName = 'Verified SSL Authority';
                  if (typeof tlsRaw.issuer === 'object' && tlsRaw.issuer !== null) {
                    sslIssuerName = tlsRaw.issuer.commonName || tlsRaw.issuer.organizationName || 'Verified SSL Authority';
                  } else if (typeof tlsRaw.issuer === 'string') {
                    sslIssuerName = tlsRaw.issuer;
                  } else if (sslCertAsset?.metadata?.issuer) {
                    sslIssuerName = String(sslCertAsset.metadata.issuer);
                  }

                  const validEndStr = tlsRaw.validity_end || sslCertAsset?.metadata?.validity_end;
                  const daysLeft = validEndStr ? Math.max(0, Math.floor((new Date(validEndStr) - new Date()) / (86400 * 1000))) : null;

                  sslInfo = {
                    issuer: sslIssuerName,
                    validFrom: tlsRaw.validity_start || sslCertAsset?.metadata?.validity_start || 'Observed Active',
                    validTo: validEndStr || 'Active Certificate',
                    daysLeft: daysLeft,
                    protocol: tlsRaw.negotiated_version || 'TLS',
                    cipher: tlsRaw.negotiated_cipher || 'Standard Cipher',
                    hsts: Boolean(backendEvidence.some(e => e.raw_evidence?.security_headers?.hsts)),
                    ocspStapling: tlsRaw.trust_status === 'valid',
                    fingerprint: tlsRaw.fingerprint_sha256 || sslCertAsset?.metadata?.serial_number || 'N/A'
                  };
                }

                // 4. Real Server & Technologies
                const httpEv = backendEvidence.find(e => e.source_tool === 'http_scan' && e.raw_evidence);
                const serverProduct = httpEv?.raw_evidence?.server_product || 'Unknown';
                const statusCode = httpEv?.raw_evidence?.status_code ? `${httpEv.raw_evidence.status_code}` : 'Unknown';

                const techAssets = backendAssets.filter(a => a.asset_type === 'technology');
                const techList = techAssets.map(a => a.normalized_value).join(', ') || 'Unknown';

                // Build lookup maps from relationships for per-subdomain data
                const relationships = resultsData.relationships || [];

                const hostToIps = {};
                relationships.forEach(r => {
                  if (r.relationship_type === 'resolves_to') {
                    const srcAsset = backendAssets.find(a => a.asset_id === r.source_asset_id);
                    const tgtAsset = backendAssets.find(a => a.asset_id === r.target_asset_id);
                    if (srcAsset && tgtAsset && tgtAsset.asset_type === 'ip_address') {
                      const key = srcAsset.normalized_value;
                      if (!hostToIps[key]) hostToIps[key] = [];
                      hostToIps[key].push(tgtAsset.normalized_value);
                    }
                  }
                });

                const portAssetsList = backendAssets.filter(a => a.asset_type === 'network_port');
                const hostToPorts = {};
                portAssetsList.forEach(a => {
                  const parts = a.normalized_value.split(':');
                  if (parts.length >= 2) {
                    const host = parts.slice(0, -1).join(':');
                    const port = parseInt(parts[parts.length - 1], 10);
                    if (!isNaN(port)) {
                      if (!hostToPorts[host]) hostToPorts[host] = [];
                      if (!hostToPorts[host].includes(port)) hostToPorts[host].push(port);
                    }
                  }
                });

                // 5. Real Subdomains & Hostnames
                const hostAssets = backendAssets.filter(a => a.asset_type === 'domain' || a.asset_type === 'hostname');
                const subdomains = hostAssets.map(a => {
                  const hostname = a.normalized_value;
                  const resolvedIps = hostToIps[hostname];
                  const subIp = resolvedIps && resolvedIps.length > 0 ? resolvedIps[0] : primaryIp;
                  const subPorts = hostToPorts[hostname] || hostToPorts[subIp] || [];
                  const hasRiskyPorts = subPorts.some(p => p !== 80 && p !== 443);
                  return {
                    name: hostname,
                    ip: subIp,
                    ports: subPorts.length > 0 ? subPorts : [],
                    status: statusCode,
                    tech: techList,
                    risk: hasRiskyPorts ? 'Medium' : (subPorts.length > 0 ? 'Safe' : 'Unknown')
                  };
                });

                // 6. Real Network Ports
                const portAssets = backendAssets.filter(a => a.asset_type === 'network_port');
                const portRecords = portAssets.map(a => {
                  const parts = a.normalized_value.split(':');
                  const pNum = parseInt(parts[parts.length - 1] || '80', 10);
                  return {
                    port: pNum,
                    protocol: 'TCP',
                    service: pNum === 443 ? 'HTTPS' : (pNum === 80 ? 'HTTP' : 'Service'),
                    state: a.metadata?.state || 'Open',
                    risk: pNum === 80 || pNum === 443 ? 'Safe' : 'Medium'
                  };
                });

                // Calculate evidence-based posture grade & score
                let score = 95;
                if (sslInfo && !sslInfo.hsts) score -= 5;
                if (sslInfo && (tlsRaw.trust_status === 'expired' || tlsRaw.trust_status === 'self_signed')) score -= 20;
                if (portRecords.some(p => p.risk === 'Critical')) score -= 25;
                const grade = score >= 90 ? 'A' : (score >= 80 ? 'B' : (score >= 70 ? 'C' : 'D'));

                setConsoleLogs((prev) => [
                  ...prev,
                  { time: new Date().toLocaleTimeString(), text: `Scan complete! Discovered ${backendAssets.length} assets, ${backendEvidence.length} evidence items.`, type: 'success' }
                ]);

                setScanResult({
                  domain: cleanedDomain,
                  grade: grade,
                  score: Math.max(50, score),
                  ip: primaryIp,
                  registrar: serverProduct,
                  subdomains: subdomains,
                  dns: dnsRecords,
                  ssl: sslInfo,
                  ports: portRecords,
                  totalAssets: backendAssets.length,
                  totalEvidence: backendEvidence.length,
                });
              } catch (resErr) {
                console.error("Error parsing scan results:", resErr);
                setScanError(`Failed to parse scan results: ${resErr.message}`);
                setScanResult(null);
              }
            } else {
              setScanError(statusRes.message || 'Backend scan failed or timed out.');
              setScanResult(null);
              addToast(`Scan failed or timed out on backend`, 'error');
              setConsoleLogs((prev) => [
                ...prev,
                { time: new Date().toLocaleTimeString(), text: `Scan failed or timed out: ${statusRes.message || 'Error'}`, type: 'error' }
              ]);
            }
          }
        } catch (pollErr) {
          console.warn("Polling status warning:", pollErr);
        }
      }, 1500);

    } catch (err) {
      setIsScanning(false);
      setProgress(0);
      setScanError(`API Error: ${err.message}`);
      setScanResult(null);
      addToast(`API Request Error: ${err.message}`, 'error');
      setConsoleLogs((prev) => [
        ...prev,
        { time: new Date().toLocaleTimeString(), text: `Backend Connection Error: ${err.message}`, type: 'error' }
      ]);
    }
  }, [targetDomain, scanType, addToast]);

  const filteredSubdomains = useMemo(() => {
    if (!scanResult?.subdomains) return [];
    if (!searchFilter.trim()) return scanResult.subdomains;
    const q = searchFilter.toLowerCase();
    return scanResult.subdomains.filter(
      (s) => s.name.toLowerCase().includes(q) || s.ip.includes(q) || s.tech.toLowerCase().includes(q)
    );
  }, [scanResult, searchFilter]);

  const handleExportReport = (format) => {
    if (!scanResult) return;
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(scanResult, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `domain-scan-${scanResult.domain}.${format}`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    addToast(`Exported domain scan report (${format.toUpperCase()})`, 'success');
  };

  return (
    <div className="page-content domain-scan-container">
      <div className="page-header">
        <div className="page-header__left">
          <h1 className="page-header__title">
            Domain <span>Scan</span>
          </h1>
          <p className="page-header__subtitle">
            Perform real-time attack surface discovery, subdomain enumeration, and DNS/SSL vulnerability audits.
          </p>
        </div>
        {scanResult && (
          <div className="flex-gap-md">
            <button className="export-btn" onClick={() => handleExportReport('json')}>
              <Download size={14} /> Export JSON
            </button>
          </div>
        )}
      </div>

      <div className="domain-scan-hero">
        <div className="domain-hero__header">
          <div className="domain-hero__title">
            <Globe size={22} color="var(--neon-blue)" />
            Target Domain Surface Reconnaissance
          </div>
          <p className="domain-hero__subtitle">
            Enter an authorized domain name or IP address to execute real active scans against target infrastructure.
          </p>
        </div>

        <div className="domain-input-group">
          <div className="domain-input-wrapper">
            <Globe size={18} />
            <input
              type="text"
              className="domain-input"
              value={targetDomain}
              onChange={(e) => setTargetDomain(e.target.value)}
              placeholder="Enter target (e.g. google.com or github.com)"
              disabled={isScanning}
              onKeyDown={(e) => e.key === 'Enter' && handleStartScan()}
            />
          </div>

          <select
            className="domain-select"
            value={scanType}
            onChange={(e) => setScanType(e.target.value)}
            disabled={isScanning}
          >
            <option value="dns">1. DNS Scanner</option>
            <option value="port">2. Port Discovery</option>
            <option value="service">3. Service Identification</option>
            <option value="http">4. HTTP / HTTPS Scan</option>
            <option value="tech">5. Technology Detection</option>
            <option value="endpoint">6. Endpoint Discovery</option>
            <option value="js">7. JavaScript Discovery</option>
            <option value="tls">8. TLS / Certificate Scan</option>
            <option value="email">9. Email Security Scan</option>
            <option value="cloud">10. Cloud / CDN Detection</option>
            <option value="full">11. All Scanners Together (Full Scan)</option>
          </select>

          <button
            className="scan-launch-btn"
            onClick={handleStartScan}
            disabled={isScanning || !targetDomain.trim()}
          >
            {isScanning ? (
              <>
                <RefreshCw size={16} className="spin-icon" /> Scanning...
              </>
            ) : (
              <>
                <Zap size={16} /> Launch Scan
              </>
            )}
          </button>
        </div>
      </div>

      {isScanning && (
        <div className="scan-progress-card">
          <div className="progress-header">
            <div className="progress-title">
              <Activity size={18} color="var(--neon-blue)" className="spin-icon" />
              Scanning Target: <span style={{ color: 'var(--neon-blue)', fontFamily: 'monospace' }}>{targetDomain}</span>
            </div>
            <div className="progress-percent">{progress}%</div>
          </div>
          <div className="progress-bar-track">
            <div className="progress-bar-fill" style={{ width: `${progress}%` }} />
          </div>

          <div className="scan-console">
            {consoleLogs.map((log, idx) => (
              <div key={idx} className="console-line">
                <span className="console-time">[{log.time}]</span>
                <span className={`console-msg ${log.type}`}>{log.text}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {scanError && !isScanning && (
        <div style={{
          background: 'rgba(239, 68, 68, 0.1)',
          border: '1px solid rgba(239, 68, 68, 0.3)',
          borderRadius: 'var(--radius-xl)',
          padding: 24,
          display: 'flex',
          alignItems: 'center',
          gap: 16,
          color: '#f87171'
        }}>
          <AlertCircle size={24} />
          <div>
            <h4 style={{ fontWeight: 700, fontSize: 15, marginBottom: 2 }}>Scan Execution Failure</h4>
            <p style={{ fontSize: 13, opacity: 0.9 }}>{scanError}</p>
          </div>
        </div>
      )}

      {!isScanning && !scanResult && !scanError && (
        <div style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-xl)',
          padding: '56px 24px',
          textAlign: 'center',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 16,
        }}>
          <div style={{
            width: 64,
            height: 64,
            borderRadius: '50%',
            background: 'rgba(59, 130, 246, 0.1)',
            border: '1px solid rgba(59, 130, 246, 0.2)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--neon-blue)',
          }}>
            <Radio size={32} />
          </div>
          <h3 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)' }}>No Scan Started</h3>
          <p style={{ fontSize: 13, color: 'var(--text-secondary)', maxWidth: 460, lineHeight: 1.5 }}>
            Enter an authorized target domain or IP address in the field above and click <strong>Launch Scan</strong> to perform live active surface discovery.
          </p>
        </div>
      )}

      {scanResult && !isScanning && (
        <div className="domain-kpi-grid">
          <div className="domain-kpi-card">
            <div className="kpi-header-row">
              <span className="kpi-lbl">Domain Health Grade</span>
              <div className="kpi-icon-box" style={{ background: 'rgba(56,189,248,0.12)', color: 'var(--neon-blue)' }}>
                <ShieldCheck size={20} />
              </div>
            </div>
            <div className="kpi-val" style={{ color: scanResult.score >= 80 ? '#4ade80' : 'var(--high)' }}>
              {scanResult.grade} <span style={{ fontSize: 16, color: 'var(--text-muted)' }}>({scanResult.score}/100)</span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
              Server Info: <strong style={{ color: 'var(--text-primary)' }}>{scanResult.registrar}</strong>
            </div>
          </div>

          <div className="domain-kpi-card">
            <div className="kpi-header-row">
              <span className="kpi-lbl">Discovered Subdomains</span>
              <div className="kpi-icon-box" style={{ background: 'rgba(129,140,248,0.12)', color: '#818cf8' }}>
                <Server size={20} />
              </div>
            </div>
            <div className="kpi-val">{scanResult.subdomains.length}</div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
              Primary IP: <span style={{ fontFamily: 'monospace', color: 'var(--neon-blue)' }}>{scanResult.ip}</span>
            </div>
          </div>

          <div className="domain-kpi-card">
            <div className="kpi-header-row">
              <span className="kpi-lbl">Exposed Ports</span>
              <div className="kpi-icon-box" style={{ background: 'rgba(249,115,22,0.12)', color: 'var(--high)' }}>
                <Radio size={20} />
              </div>
            </div>
            <div className="kpi-val" style={{ color: scanResult.ports.some(p => p.risk === 'Critical') ? 'var(--critical)' : 'var(--text-primary)' }}>
              {scanResult.ports.length} <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Ports</span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
              Critical Open: <strong>{scanResult.ports.filter(p => p.risk === 'Critical' || p.risk === 'High').length}</strong>
            </div>
          </div>

          <div className="domain-kpi-card">
            <div className="kpi-header-row">
              <span className="kpi-lbl">SSL/TLS Certificate</span>
              <div className="kpi-icon-box" style={{ background: 'rgba(34,197,94,0.12)', color: '#4ade80' }}>
                <Lock size={20} />
              </div>
            </div>
            <div className="kpi-val" style={{ fontSize: 18, color: scanResult.ssl ? '#4ade80' : 'var(--text-muted)' }}>
              {scanResult.ssl ? scanResult.ssl.protocol : 'None Discovered'}
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
              {scanResult.ssl ? (
                <>Issuer: <strong style={{ color: 'var(--text-primary)' }}>{scanResult.ssl.issuer}</strong></>
              ) : (
                'No TLS evidence'
              )}
            </div>
          </div>
        </div>
      )}

      {scanResult && !isScanning && (
        <div className="domain-tabs-wrapper">
          <div className="domain-tab-list">
            <button
              className={`domain-tab-btn ${activeTab === 'subdomains' ? 'active' : ''}`}
              onClick={() => setActiveTab('subdomains')}
            >
              <Server size={15} /> Discovered Subdomains
              <span className="tab-badge">{scanResult.subdomains.length}</span>
            </button>

            <button
              className={`domain-tab-btn ${activeTab === 'dns' ? 'active' : ''}`}
              onClick={() => setActiveTab('dns')}
            >
              <Globe size={15} /> DNS & Mail Security
              <span className="tab-badge">{scanResult.dns.length}</span>
            </button>

            <button
              className={`domain-tab-btn ${activeTab === 'ssl' ? 'active' : ''}`}
              onClick={() => setActiveTab('ssl')}
            >
              <Lock size={15} /> SSL/TLS Audit
            </button>

            <button
              className={`domain-tab-btn ${activeTab === 'ports' ? 'active' : ''}`}
              onClick={() => setActiveTab('ports')}
            >
              <Radio size={15} /> Port Matrix
              <span className="tab-badge">{scanResult.ports.length}</span>
            </button>
          </div>

          {activeTab === 'subdomains' && (
            <div>
              {scanResult.subdomains.length === 0 ? (
                <div style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
                  No subdomains discovered for target.
                </div>
              ) : (
                <>
                  <div className="tab-controls">
                    <div className="table-search-box">
                      <Search size={14} color="var(--text-muted)" />
                      <input
                        type="text"
                        placeholder="Filter subdomains, IPs, stack..."
                        value={searchFilter}
                        onChange={(e) => setSearchFilter(e.target.value)}
                      />
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                      Showing {filteredSubdomains.length} of {scanResult.subdomains.length} subdomains
                    </div>
                  </div>

                  <table className="domain-data-table">
                    <thead>
                      <tr>
                        <th>Subdomain FQDN</th>
                        <th>IP Address</th>
                        <th>Open Ports</th>
                        <th>HTTP Status</th>
                        <th>Tech Stack</th>
                        <th>Exposure Risk</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredSubdomains.map((sub, idx) => (
                        <tr key={idx}>
                          <td className="mono-cell" style={{ fontWeight: 600, color: 'var(--neon-blue)' }}>
                            <a href={`https://${sub.name}`} target="_blank" rel="noreferrer" style={{ textDecoration: 'none', color: 'inherit', display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                              {sub.name} <ExternalLink size={12} style={{ opacity: 0.6 }} />
                            </a>
                          </td>
                          <td className="mono-cell">{sub.ip}</td>
                          <td>
                            {sub.ports.map((p) => (
                              <span key={p} className={`port-tag ${p === 8080 || p === 5432 ? 'risk' : ''}`}>
                                :{p}
                              </span>
                            ))}
                          </td>
                          <td>
                            <span style={{ fontSize: 12, fontWeight: 600, color: sub.status.includes('200') ? '#4ade80' : 'var(--high)' }}>
                              {sub.status}
                            </span>
                          </td>
                          <td style={{ color: 'var(--text-secondary)', fontSize: 12 }}>{sub.tech}</td>
                          <td>
                            <span className={`status-badge ${sub.risk.toLowerCase()}`}>
                              {sub.risk === 'Critical' && <AlertTriangle size={12} />}
                              {sub.risk}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </>
              )}
            </div>
          )}

          {activeTab === 'dns' && (
            <div>
              {scanResult.dns.length === 0 ? (
                <div style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
                  No DNS records returned for target.
                </div>
              ) : (
                <table className="domain-data-table">
                  <thead>
                    <tr>
                      <th>Type</th>
                      <th>Hostname</th>
                      <th>Value / Record Data</th>
                      <th>TTL</th>
                      <th>Security Audit</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scanResult.dns.map((rec, idx) => (
                      <tr key={idx}>
                        <td>
                          <span className="port-tag" style={{ fontWeight: 700 }}>
                            {rec.type}
                          </span>
                        </td>
                        <td className="mono-cell">{rec.name}</td>
                        <td className="mono-cell" style={{ fontSize: 12, wordBreak: 'break-all', maxWidth: 400 }}>
                          {rec.value}
                        </td>
                        <td className="mono-cell" style={{ color: 'var(--text-muted)' }}>{rec.ttl}s</td>
                        <td>
                          <span className={`status-badge ${rec.status.includes('Valid') || rec.status.includes('Optimal') || rec.status.includes('Active') ? 'safe' : 'medium'}`}>
                            {rec.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}

          {activeTab === 'ssl' && (
            <div>
              {!scanResult.ssl ? (
                <div style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
                  No TLS certificate evidence detected for target.
                </div>
              ) : (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 20 }}>
                  <div style={{ background: 'var(--bg-card)', padding: 18, borderRadius: 'var(--radius-md)', border: '1px solid var(--border)' }}>
                    <h4 style={{ marginBottom: 12, fontSize: 14, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
                      <Lock size={16} color="var(--neon-blue)" /> Certificate Details
                    </h4>
                    <div style={{ fontSize: 13, display: 'flex', flexDirection: 'column', gap: 10, color: 'var(--text-secondary)' }}>
                      <div>Issuer: <strong style={{ color: 'var(--text-primary)' }}>{scanResult.ssl.issuer}</strong></div>
                      <div>Valid From: <span className="mono-cell">{scanResult.ssl.validFrom}</span></div>
                      <div>Valid To: <span className="mono-cell">{scanResult.ssl.validTo}</span></div>
                      <div>Days Remaining: <span className="mono-cell" style={{ color: scanResult.ssl.daysLeft > 30 ? '#4ade80' : 'var(--high)', fontWeight: 700 }}>{scanResult.ssl.daysLeft !== null ? `${scanResult.ssl.daysLeft} Days` : 'N/A'}</span></div>
                    </div>
                  </div>

                  <div style={{ background: 'var(--bg-card)', padding: 18, borderRadius: 'var(--radius-md)', border: '1px solid var(--border)' }}>
                    <h4 style={{ marginBottom: 12, fontSize: 14, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
                      <ShieldCheck size={16} color="#4ade80" /> Cryptographic Configuration
                    </h4>
                    <div style={{ fontSize: 13, display: 'flex', flexDirection: 'column', gap: 10, color: 'var(--text-secondary)' }}>
                      <div>Protocol Version: <span className="mono-cell" style={{ color: 'var(--neon-blue)' }}>{scanResult.ssl.protocol}</span></div>
                      <div>Cipher Suite: <span className="mono-cell" style={{ fontSize: 11 }}>{scanResult.ssl.cipher}</span></div>
                      <div>HSTS Enabled: <strong style={{ color: scanResult.ssl.hsts ? '#4ade80' : 'var(--critical)' }}>{scanResult.ssl.hsts ? 'YES (Strict-Transport-Security)' : 'NO'}</strong></div>
                      <div>OCSP Stapling: <strong style={{ color: scanResult.ssl.ocspStapling ? '#4ade80' : 'var(--high)' }}>{scanResult.ssl.ocspStapling ? 'Enabled' : 'Disabled'}</strong></div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'ports' && (
            <div>
              {scanResult.ports.length === 0 ? (
                <div style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
                  No open network ports discovered for target.
                </div>
              ) : (
                <table className="domain-data-table">
                  <thead>
                    <tr>
                      <th>Port</th>
                      <th>Protocol</th>
                      <th>Service Name</th>
                      <th>State</th>
                      <th>Risk Rating</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scanResult.ports.map((p, idx) => (
                      <tr key={idx}>
                        <td className="mono-cell" style={{ fontWeight: 700, color: 'var(--neon-blue)' }}>
                          :{p.port}
                        </td>
                        <td className="mono-cell">{p.protocol}</td>
                        <td style={{ fontWeight: 600 }}>{p.service}</td>
                        <td>
                          <span style={{ color: p.state === 'Open' ? '#4ade80' : 'var(--high)', fontWeight: 600, fontSize: 12 }}>
                            {p.state}
                          </span>
                        </td>
                        <td>
                          <span className={`status-badge ${p.risk.toLowerCase()}`}>
                            {p.risk}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}

        </div>
      )}

    </div>
  );
}
