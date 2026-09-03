import { useState, useEffect } from 'react';
import { useTheme } from '../hooks/useTheme';
import { useToast } from '../context/ToastContext';
import { useBackendHealth } from '../hooks/useBackendHealth';
import { Search, Bell, Sun, Moon, Zap, Menu, ShieldCheck, Activity, Clock } from 'lucide-react';

export default function Topbar({
  activePage,
  searchQuery,
  onSearchChange,
  onNavigate,
  onToggleSidebar,
  onToggleMobile,
  onOpenNotifications,
  onOpenStatusModal,
}) {
  const { theme, setTheme } = useTheme();
  const { addToast } = useToast();
  const health = useBackendHealth(20000, 4000);
  const [is24Hour, setIs24Hour] = useState(false);
  const [timeString, setTimeString] = useState('');

  useEffect(() => {
    const updateClock = () => {
      const now = new Date();
      setTimeString(now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: !is24Hour }));
    };
    updateClock();
    const timer = setInterval(updateClock, 1000);
    return () => clearInterval(timer);
  }, [is24Hour]);

  const toggleClockFormat = () => {
    const nextFormat = !is24Hour;
    setIs24Hour(nextFormat);
    addToast(`Clock set to ${nextFormat ? '24-hour (21:02:16)' : '12-hour (09:02:16 PM)'} format`, 'info');
  };

  const toggleTheme = () => {
    let nextTheme = 'dark';
    if (theme === 'dark') nextTheme = 'light';
    else if (theme === 'light') nextTheme = 'blue';
    setTheme(nextTheme);
    addToast(`Switched workspace theme to ${nextTheme.toUpperCase()}`, 'info');
  };

  return (
    <header className="topbar">
      <div className="topbar__left">
        <button
          className="topbar__menu-btn"
          onClick={onToggleMobile}
          aria-label="Open navigation menu"
        >
          <Menu size={20} />
        </button>

        <div className="topbar__search">
          <Search size={16} className="topbar__search-icon" />
          <input
            type="text"
            className="topbar__search-input"
            placeholder="Search assets, CVEs, IPs, domain targets..."
            value={searchQuery || ''}
            onChange={(e) => onSearchChange?.(e.target.value)}
          />
        </div>
      </div>

      <div className="topbar__right">
        <div
          className="topbar__clock-pill clickable-row"
          onClick={toggleClockFormat}
          title={`Click to switch to ${is24Hour ? '12-hour AM/PM' : '24-hour'} format`}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            padding: '5px 12px',
            borderRadius: 20,
            background: 'var(--bg-card)',
            border: '1px solid var(--border)',
            color: 'var(--neon-cyan)',
            fontFamily: 'JetBrains Mono, monospace',
            fontSize: 12,
            fontWeight: 700,
            boxShadow: 'var(--glow-cyan)',
            cursor: 'pointer'
          }}
        >
          <Clock size={14} color="var(--neon-cyan)" />
          <span>{timeString}</span>
          <span style={{ fontSize: 10, color: 'var(--text-muted)', marginLeft: 2, padding: '1px 5px', borderRadius: 4, background: 'var(--bg-raised)' }}>
            {is24Hour ? '24H' : '12H'}
          </span>
        </div>

        <button
          className="status-indicator-btn clickable-row"
          onClick={() => onOpenStatusModal?.(health)}
          title={`Backend Connection: ${health.status.toUpperCase()} (Click for System Status)`}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 8,
            padding: '6px 14px',
            fontSize: 12,
            fontWeight: 700,
            borderRadius: 20,
            background: health.status === 'connected'
              ? 'rgba(59, 130, 246, 0.12)'
              : (health.status === 'disconnected' ? 'rgba(239, 68, 68, 0.12)' : 'rgba(56, 189, 248, 0.12)'),
            color: health.status === 'connected'
              ? '#60a5fa'
              : (health.status === 'disconnected' ? '#f87171' : 'var(--neon-cyan)'),
            border: health.status === 'connected'
              ? '1px solid rgba(59, 130, 246, 0.35)'
              : (health.status === 'disconnected' ? '1px solid rgba(239, 68, 68, 0.35)' : '1px solid rgba(56, 189, 248, 0.35)'),
            boxShadow: health.status === 'connected'
              ? '0 0 15px rgba(59, 130, 246, 0.2)'
              : (health.status === 'disconnected' ? '0 0 15px rgba(239, 68, 68, 0.2)' : '0 0 15px rgba(56, 189, 248, 0.2)'),
            cursor: 'pointer',
            whiteSpace: 'nowrap',
            transition: 'all 0.3s ease'
          }}
        >
          <span style={{
            width: 8,
            height: 8,
            borderRadius: '50%',
            background: health.status === 'connected' ? '#3b82f6' : (health.status === 'disconnected' ? '#ef4444' : '#38bdf8'),
            boxShadow: health.status === 'connected' ? '0 0 10px #3b82f6' : (health.status === 'disconnected' ? '0 0 10px #ef4444' : '0 0 10px #38bdf8')
          }} />
          <span>
            {health.status === 'connected' ? 'Operational' : (health.status === 'disconnected' ? 'Backend Offline' : 'Checking...')}
          </span>
        </button>

        <button
          className="topbar__icon-btn"
          onClick={toggleTheme}
          title={`Current Theme: ${theme.toUpperCase()} (Click to toggle)`}
        >
          {theme === 'light' ? <Sun size={18} /> : <Moon size={18} />}
        </button>

        <button
          className="topbar__icon-btn"
          onClick={onOpenNotifications}
          title="Notifications"
          style={{ position: 'relative' }}
        >
          <Bell size={18} />
          <span className="notif-badge-dot" />
        </button>

        <div className="topbar__profile" onClick={() => onNavigate('settings')} title="View Settings & Profile" style={{ cursor: 'pointer' }}>
          <div className="topbar__avatar">AD</div>
          <div className="topbar__user-info">
            <span className="topbar__user-name">Alex Dawson</span>
            <span className="topbar__user-role">SecOps Lead</span>
          </div>
        </div>
      </div>
    </header>
  );
}
