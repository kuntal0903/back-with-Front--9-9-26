import { useState } from 'react';
import { X, Activity, ShieldCheck, Server, RefreshCw, AlertTriangle } from 'lucide-react';
import { useToast } from '../context/ToastContext';
import { useBackendHealth } from '../hooks/useBackendHealth';

export default function SystemStatusModal({ onClose }) {
  const { addToast } = useToast();
  const { status, latency, error, healthData, refetch } = useBackendHealth(30000, 4000);
  const [isRefetching, setIsRefetching] = useState(false);

  const handleRunHealthCheck = async () => {
    setIsRefetching(true);
    addToast('Executing frontend ↔ backend connection probe...', 'info');
    await refetch();
    setIsRefetching(false);
    addToast(
      status === 'connected'
        ? `Backend health check passed (${latency ? latency + 'ms' : 'Active'})`
        : `Backend connectivity check failed: ${error || 'Offline'}`,
      status === 'connected' ? 'success' : 'error'
    );
  };

  const isConnected = status === 'connected';
  const isDisconnected = status === 'disconnected';

  return (
    <>
      <div className="modal-overlay" onClick={onClose} style={{ position: 'fixed', inset: 0, background: 'rgba(3,7,18,0.75)', backdropFilter: 'blur(6px)', zIndex: 300 }} />
      <div role="dialog" aria-label="System Health Status" style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', width: '92%', maxWidth: '460px', background: 'var(--bg-surface)', border: '1px solid var(--border-hover)', borderRadius: 'var(--radius-lg)', zIndex: 301, padding: 24, boxShadow: 'var(--glow-blue)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
          <h3 style={{ fontSize: 16, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Activity size={18} color={isConnected ? "#60a5fa" : (isDisconnected ? "#f87171" : "var(--neon-cyan)")} /> System Health Diagnostics
          </h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}><X size={18} /></button>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, fontSize: 13, background: 'var(--bg-base)', padding: 14, borderRadius: 8, border: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Server size={14} color="var(--neon-blue)" /> Backend Engine API
            </span>
            <span style={{
              color: isConnected ? '#60a5fa' : (isDisconnected ? '#f87171' : 'var(--neon-cyan)'),
              fontWeight: 600,
              background: isConnected ? 'rgba(59,130,246,0.12)' : (isDisconnected ? 'rgba(239,68,68,0.12)' : 'rgba(56,189,248,0.12)'),
              border: isConnected ? '1px solid rgba(59,130,246,0.3)' : (isDisconnected ? '1px solid rgba(239,68,68,0.3)' : '1px solid rgba(56,189,248,0.3)'),
              padding: '2px 8px',
              borderRadius: 4
            }}>
              {isConnected ? '● Operational (BLUE)' : (isDisconnected ? '● Backend Offline (RED)' : '● Checking...')}
            </span>
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Activity size={14} color="var(--accent-blue)" /> HTTP Latency
            </span>
            <span className="mono-cell" style={{ color: isConnected ? 'var(--neon-blue)' : 'var(--text-muted)', fontWeight: 600 }}>
              {latency !== null ? `${latency}ms` : (isConnected ? '< 50ms' : 'N/A')}
            </span>
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <ShieldCheck size={14} color="var(--neon-cyan)" /> Health Probe Target
            </span>
            <span className="mono-cell" style={{ color: 'var(--text-secondary)', fontSize: 11 }}>
              /api/v1/health
            </span>
          </div>

          {healthData && (
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Server size={14} color="var(--text-muted)" /> Engine Version
              </span>
              <span className="mono-cell" style={{ color: 'var(--text-primary)', fontSize: 12 }}>
                v{healthData.version || '0.1.0'} ({healthData.environment || 'production'})
              </span>
            </div>
          )}

          {error && (
            <div style={{ fontSize: 12, color: '#f87171', background: 'rgba(239, 68, 68, 0.08)', padding: 8, borderRadius: 4, display: 'flex', alignItems: 'center', gap: 6, marginTop: 4 }}>
              <AlertTriangle size={14} /> Diagnostic Error: {error}
            </div>
          )}
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, marginTop: 20, paddingTop: 14, borderTop: '1px solid var(--border)' }}>
          <button className="btn btn--outline" onClick={handleRunHealthCheck} disabled={isRefetching} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <RefreshCw size={14} className={isRefetching ? 'spin-icon' : ''} /> {isRefetching ? 'Probing...' : 'Refresh Health'}
          </button>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn--ghost" onClick={onClose}>Close</button>
            <button className="btn btn--primary" onClick={handleRunHealthCheck} disabled={isRefetching}>
              Run Diagnostics
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
