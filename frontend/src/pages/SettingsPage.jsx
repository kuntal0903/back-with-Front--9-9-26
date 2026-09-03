import { useState } from 'react';
import { useTheme } from '../hooks/useTheme';
import { useToast } from '../context/ToastContext';
import {
  User, Shield, Key, Plug, Calendar, Bell, Palette,
  Users, AlertTriangle, Check, Copy, Plus,
  Trash2, Mail, MessageSquare, Link2, Save, Lock, X
} from 'lucide-react';

import '../styles/settings.css';

const NAV_SECTIONS = [
  {
    group: 'ACCOUNT', items: [
      { id: 'profile', label: 'Profile', icon: User },
      { id: 'security', label: 'Security', icon: Shield },
      { id: 'api-keys', label: 'API Keys', icon: Key },
    ]
  },
  {
    group: 'PLATFORM', items: [
      { id: 'integrations', label: 'Integrations', icon: Plug },
      { id: 'scan', label: 'Scan Schedule', icon: Calendar },
      { id: 'notifications', label: 'Notifications', icon: Bell },
    ]
  },
  {
    group: 'SYSTEM', items: [
      { id: 'appearance', label: 'Appearance', icon: Palette },
      { id: 'team', label: 'Team Access', icon: Users },
      { id: 'danger', label: 'Danger Zone', icon: AlertTriangle },
    ]
  },
];

export default function SettingsPage() {
  const { addToast } = useToast();
  const { theme, setTheme } = useTheme();
  const [activeTab, setActiveTab] = useState('profile');

  // Profile State
  const [profile, setProfile] = useState({
    name: 'Alex Dawson',
    email: 'alex.dawson@enterprise.sec',
    role: 'SecOps Lead & Administrator',
    bio: 'Overseeing enterprise threat surface discovery and automated vulnerability triage.',
    department: 'Cybersecurity Operations',
    timezone: 'UTC-07:00 (Pacific Time)',
  });

  // Security State
  const [security, setSecurity] = useState({
    twoFactor: true,
    sessionTimeout: '30',
    ipRestricted: false,
    allowedIps: '192.168.1.0/24, 10.0.0.0/8',
  });
  const [showPasswordModal, setShowPasswordModal] = useState(false);
  const [passwords, setPasswords] = useState({ current: '', newPass: '', confirm: '' });

  // API Keys State
  const [apiKeys, setApiKeys] = useState([
    { id: '1', name: 'CI/CD Pipeline Key', key: 'asm_live_98a7f6e5d4c3b2a10987654321', created: '2026-08-15', lastUsed: '2 mins ago', scope: 'Read/Write' },
    { id: '2', name: 'SIEM Integration Tool', key: 'asm_live_1a2b3c4d5e6f7a8b9c0d1e2f3a', created: '2026-07-20', lastUsed: '1 hour ago', scope: 'Read Only' },
  ]);
  const [showNewKeyModal, setShowNewKeyModal] = useState(false);
  const [newKeyName, setNewKeyName] = useState('');
  const [copiedKeyId, setCopiedKeyId] = useState(null);

  // Integrations State
  const [integrations, setIntegrations] = useState([
    { id: 'slack', name: 'Slack Alerts', desc: 'Real-time notifications for critical asset changes and high vulnerabilities', connected: true, status: 'connected', color: '#4A154B' },
    { id: 'jira', name: 'Jira Software', desc: 'Auto-create tickets for discovered CVEs and unpatched open ports', connected: true, status: 'connected', color: '#0052CC' },
    { id: 'splunk', name: 'Splunk Enterprise SIEM', desc: 'Stream raw scan telemetry and asset findings directly to your SIEM index', connected: false, status: 'disconnected', color: '#ED5723' },
    { id: 'pagerduty', name: 'PagerDuty', desc: 'Trigger on-call escalation policies for newly exposed SSH/RDP endpoints', connected: true, status: 'connected', color: '#06AC38' },
    { id: 'aws', name: 'AWS Security Hub', desc: 'Sync multi-cloud discovery results with native Security Hub dashboards', connected: false, status: 'disconnected', color: '#FF9900' },
    { id: 'webhook', name: 'Custom Webhook', desc: 'POST JSON payloads on scan completion or asset risk updates', connected: false, status: 'disconnected', color: '#3B82F6' },
  ]);

  // Scan Schedule State
  const [scanSchedule, setScanSchedule] = useState({
    frequency: 'daily',
    concurrency: 5,
    timeout: 10,
    excludedDomains: 'staging.internal, test-dev.corp',
    autoRescan: true,
  });

  // Notifications State
  const [notifications, setNotifications] = useState({
    emailAlerts: true,
    slackAlerts: true,
    digestFrequency: 'daily',
    minSeverity: 'high',
    channels: {
      email: true,
      slack: true,
      webhook: false,
    }
  });

  // Appearance State
  const [compactView, setCompactView] = useState(false);
  const [highContrast, setHighContrast] = useState(false);

  // Team Access State
  const [teamMembers, setTeamMembers] = useState([
    { id: '1', name: 'Alex Dawson', email: 'alex.dawson@enterprise.sec', role: 'Admin', status: 'live', avatar: 'AD', color: 'var(--accent-purple)' },
    { id: '2', name: 'Elena Rostova', email: 'elena.r@enterprise.sec', role: 'Analyst', status: 'live', avatar: 'ER', color: 'var(--accent-blue)' },
    { id: '3', name: 'Marcus Vance', email: 'm.vance@enterprise.sec', role: 'Analyst', status: 'live', avatar: 'MV', color: 'var(--accent-cyan)' },
    { id: '4', name: 'DevOps Automated Bot', email: 'devops-bot@enterprise.sec', role: 'ReadOnly', status: 'live', avatar: 'DB', color: 'var(--accent-emerald)' },
  ]);
  const [showInviteModal, setShowInviteModal] = useState(false);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState('Analyst');

  // Copy helper
  const handleCopy = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedKeyId(id);
    addToast('Copied to clipboard!', 'info');
    setTimeout(() => setCopiedKeyId(null), 2000);
  };

  // Generate API Key
  const handleGenerateKey = () => {
    if (!newKeyName.trim()) return;
    const newKey = {
      id: Date.now().toString(),
      name: newKeyName,
      key: `asm_live_${Math.random().toString(36).substring(2)}${Math.random().toString(36).substring(2)}`,
      created: new Date().toISOString().split('T')[0],
      lastUsed: 'Never',
      scope: 'Read/Write',
    };
    setApiKeys([...apiKeys, newKey]);
    setNewKeyName('');
    setShowNewKeyModal(false);
    addToast('Generated new API key successfully', 'success');
  };

  const handleRevokeKey = (id) => {
    setApiKeys(apiKeys.filter(k => k.id !== id));
    addToast('API key revoked', 'warning');
  };

  const toggleIntegration = (id) => {
    setIntegrations(integrations.map(item => {
      if (item.id === id) {
        const nextState = !item.connected;
        return {
          ...item,
          connected: nextState,
          status: nextState ? 'connected' : 'disconnected'
        };
      }
      return item;
    }));
    addToast('Integration status updated', 'info');
  };

  const handleInviteMember = () => {
    if (!inviteEmail.trim()) return;
    const newMember = {
      id: Date.now().toString(),
      name: inviteEmail.split('@')[0].replace('.', ' '),
      email: inviteEmail,
      role: inviteRole,
      status: 'live',
      avatar: inviteEmail.substring(0, 2).toUpperCase(),
      color: 'var(--accent-blue)',
    };
    setTeamMembers([...teamMembers, newMember]);
    setInviteEmail('');
    setShowInviteModal(false);
    addToast(`Invitation sent to ${inviteEmail}`, 'success');
  };

  return (
    <div className="page-content">
      <div className="page-header">
        <div className="page-header__left">
          <h1 className="page-header__title">
            Platform <span>Settings</span>
          </h1>
          <p className="page-header__subtitle">
            Configure system preferences, API credentials, third-party integrations, and team access.
          </p>
        </div>
      </div>

      <div className="settings-layout">
        {/* Navigation Sidebar */}
        <nav className="settings-nav">
          {NAV_SECTIONS.map((sec) => (
            <div key={sec.group}>
              <div className="settings-nav__group-label">{sec.group}</div>
              {sec.items.map((item) => {
                const Icon = item.icon;
                const isActive = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    className={`settings-nav__item ${isActive ? 'active' : ''}`}
                    onClick={() => setActiveTab(item.id)}
                  >
                    <Icon size={16} />
                    <span>{item.label}</span>
                  </button>
                );
              })}
            </div>
          ))}
        </nav>

        {/* Dynamic Content Pane */}
        <div className="settings-content">

          {/* TAB 1: PROFILE */}
          {activeTab === 'profile' && (
            <div className="settings-section">
              <div className="settings-section__header">
                <div className="settings-section__icon" style={{ background: 'rgba(59, 130, 246, 0.15)', color: 'var(--accent-blue)' }}>
                  <User size={20} />
                </div>
                <div className="settings-section__titles">
                  <h3>User Profile & Account Information</h3>
                  <p>Manage your identity, role permissions, and contact preferences.</p>
                </div>
              </div>
              <div className="settings-section__body">
                <div className="profile-avatar-section">
                  <div className="profile-avatar-large">AD</div>
                  <div className="profile-avatar-info">
                    <h4>{profile.name}</h4>
                    <p>{profile.role} • {profile.department}</p>
                    <button className="btn btn--outline btn--sm" onClick={() => addToast('Avatar update function ready', 'info')}>
                      Change Avatar
                    </button>
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                  <div className="field-row">
                    <label className="field-label">Full Name</label>
                    <input
                      type="text"
                      className="s-input"
                      value={profile.name}
                      onChange={(e) => setProfile({ ...profile, name: e.target.value })}
                    />
                  </div>
                  <div className="field-row">
                    <label className="field-label">Email Address <span>(Primary Login)</span></label>
                    <input
                      type="email"
                      className="s-input"
                      value={profile.email}
                      onChange={(e) => setProfile({ ...profile, email: e.target.value })}
                    />
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                  <div className="field-row">
                    <label className="field-label">Department / Team</label>
                    <input
                      type="text"
                      className="s-input"
                      value={profile.department}
                      onChange={(e) => setProfile({ ...profile, department: e.target.value })}
                    />
                  </div>
                  <div className="field-row">
                    <label className="field-label">Timezone</label>
                    <select
                      className="s-select"
                      value={profile.timezone}
                      onChange={(e) => setProfile({ ...profile, timezone: e.target.value })}
                    >
                      <option>UTC-07:00 (Pacific Time)</option>
                      <option>UTC-05:00 (Eastern Time)</option>
                      <option>UTC+00:00 (London, GMT)</option>
                      <option>UTC+01:00 (Berlin, CET)</option>
                      <option>UTC+05:30 (India, IST)</option>
                      <option>UTC+08:00 (Singapore, SGT)</option>
                    </select>
                  </div>
                </div>

                <div className="field-row">
                  <label className="field-label">Professional Bio / Responsibility Notes</label>
                  <textarea
                    className="s-textarea"
                    value={profile.bio}
                    onChange={(e) => setProfile({ ...profile, bio: e.target.value })}
                  />
                </div>

                <div className="settings-footer">
                  <button className="btn btn--primary" onClick={() => addToast('Profile changes saved successfully', 'success')}>
                    <Save size={14} style={{ marginRight: 6 }} /> Save Profile
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: SECURITY */}
          {activeTab === 'security' && (
            <div className="settings-section">
              <div className="settings-section__header">
                <div className="settings-section__icon" style={{ background: 'rgba(168, 85, 247, 0.15)', color: 'var(--accent-purple)' }}>
                  <Shield size={20} />
                </div>
                <div className="settings-section__titles">
                  <h3>Security & Authentication</h3>
                  <p>Multi-factor authentication, session lifecycle, and IP access rules.</p>
                </div>
              </div>
              <div className="settings-section__body">
                <div className="toggle-row" onClick={() => {
                  setSecurity({ ...security, twoFactor: !security.twoFactor });
                  addToast(`Two-Factor Authentication ${!security.twoFactor ? 'enabled' : 'disabled'}`, 'info');
                }}>
                  <div>
                    <div className="toggle-row__label">Two-Factor Authentication (2FA / TOTP)</div>
                    <div className="toggle-row__desc">Require hardware security key or authenticator app code on login</div>
                  </div>
                  <label className="toggle" onClick={(e) => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={security.twoFactor}
                      onChange={() => {
                        setSecurity({ ...security, twoFactor: !security.twoFactor });
                        addToast(`Two-Factor Authentication ${!security.twoFactor ? 'enabled' : 'disabled'}`, 'info');
                      }}
                    />
                    <span className="toggle__track"></span>
                    <span className="toggle__thumb"></span>
                  </label>
                </div>

                <div className="toggle-row" onClick={() => setSecurity({ ...security, ipRestricted: !security.ipRestricted })}>
                  <div>
                    <div className="toggle-row__label">Enforce IP Whitelisting</div>
                    <div className="toggle-row__desc">Restrict administrative access strictly to designated corporate IP CIDRs</div>
                  </div>
                  <label className="toggle" onClick={(e) => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={security.ipRestricted}
                      onChange={() => setSecurity({ ...security, ipRestricted: !security.ipRestricted })}
                    />
                    <span className="toggle__track"></span>
                    <span className="toggle__thumb"></span>
                  </label>
                </div>

                {security.ipRestricted && (
                  <div className="field-row">
                    <label className="field-label">Whitelisted CIDR Blocks <span>(Comma separated)</span></label>
                    <input
                      type="text"
                      className="s-input"
                      value={security.allowedIps}
                      onChange={(e) => setSecurity({ ...security, allowedIps: e.target.value })}
                    />
                  </div>
                )}

                <div className="field-row">
                  <label className="field-label">Inactivity Session Timeout</label>
                  <select
                    className="s-select"
                    value={security.sessionTimeout}
                    onChange={(e) => setSecurity({ ...security, sessionTimeout: e.target.value })}
                  >
                    <option value="15">15 Minutes</option>
                    <option value="30">30 Minutes (Recommended)</option>
                    <option value="60">1 Hour</option>
                    <option value="480">8 Hours (Full Shift)</option>
                  </select>
                </div>

                <div className="settings-divider"></div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <h4 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>Account Password</h4>
                    <p style={{ fontSize: 12, color: 'var(--text-muted)' }}>Last updated 45 days ago</p>
                  </div>
                  <button className="btn btn--outline btn--sm" onClick={() => setShowPasswordModal(true)}>
                    <Lock size={14} style={{ marginRight: 6 }} /> Update Password
                  </button>
                </div>

                <div className="settings-footer">
                  <button className="btn btn--primary" onClick={() => addToast('Security policies updated', 'success')}>
                    <Save size={14} style={{ marginRight: 6 }} /> Save Security Rules
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: API KEYS */}
          {activeTab === 'api-keys' && (
            <div className="settings-section">
              <div className="settings-section__header">
                <div className="settings-section__icon" style={{ background: 'rgba(6, 182, 212, 0.15)', color: 'var(--accent-cyan)' }}>
                  <Key size={20} />
                </div>
                <div className="settings-section__titles">
                  <h3>API Credentials & Tokens</h3>
                  <p>Generate REST API keys for headless automation, CI/CD, and SIEM ingestion.</p>
                </div>
              </div>
              <div className="settings-section__body">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                  <h4 style={{ fontSize: 14, fontWeight: 700 }}>Active API Keys ({apiKeys.length})</h4>
                  <button className="btn btn--primary btn--sm" onClick={() => setShowNewKeyModal(true)}>
                    <Plus size={14} style={{ marginRight: 6 }} /> Generate New Key
                  </button>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                  {apiKeys.map((item) => (
                    <div key={item.id} className="api-key-row">
                      <div>
                        <div className="api-key-row__name">{item.name}</div>
                        <div className="api-key-row__value">{item.key}</div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                          Created: {item.created} • Last Used: {item.lastUsed} • Scope: {item.scope}
                        </div>
                      </div>
                      <div className="api-key-row__meta">
                        <button
                          className="btn btn--icon btn--ghost"
                          title="Copy Key"
                          onClick={() => handleCopy(item.key, item.id)}
                        >
                          {copiedKeyId === item.id ? <Check size={14} style={{ color: '#4ade80' }} /> : <Copy size={14} />}
                        </button>
                        <button
                          className="btn btn--icon btn--ghost"
                          title="Revoke Key"
                          onClick={() => handleRevokeKey(item.id)}
                          style={{ color: '#f87171' }}
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: INTEGRATIONS */}
          {activeTab === 'integrations' && (
            <div className="settings-section">
              <div className="settings-section__header">
                <div className="settings-section__icon" style={{ background: 'rgba(34, 197, 94, 0.15)', color: 'var(--accent-emerald)' }}>
                  <Plug size={20} />
                </div>
                <div className="settings-section__titles">
                  <h3>Connected Integrations</h3>
                  <p>Connect ASM Shield 3.0 to your alert pipelines, ticket trackers, and SIEM tools.</p>
                </div>
              </div>
              <div className="settings-section__body">
                <div className="integrations-grid">
                  {integrations.map((item) => (
                    <div key={item.id} className="integration-card">
                      <div>
                        <div className="integration-card__header">
                          <div
                            className="integration-card__logo"
                            style={{ background: item.color + '20', color: item.color }}
                          >
                            <Plug size={20} />
                          </div>
                          <span className={`integration-status-badge integration-status-badge--${item.status}`}>
                            {item.status}
                          </span>
                        </div>
                        <div className="integration-card__name" style={{ marginTop: 12 }}>{item.name}</div>
                        <div className="integration-card__desc">{item.desc}</div>
                      </div>
                      <div className="integration-card__action">
                        <button
                          className={`integration-btn ${item.connected ? 'integration-btn--disconnect' : 'integration-btn--connect'}`}
                          onClick={() => toggleIntegration(item.id)}
                        >
                          {item.connected ? 'Disconnect' : 'Connect Integration'}
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: SCAN SCHEDULE */}
          {activeTab === 'scan' && (
            <div className="settings-section">
              <div className="settings-section__header">
                <div className="settings-section__icon" style={{ background: 'rgba(234, 179, 8, 0.15)', color: '#eab308' }}>
                  <Calendar size={20} />
                </div>
                <div className="settings-section__titles">
                  <h3>Scan Schedule & Engine Policies</h3>
                  <p>Configure automated surface recon frequency, timeout limits, and rate throttling.</p>
                </div>
              </div>
              <div className="settings-section__body">
                <div className="field-row">
                  <label className="field-label">Automated Recon Cadence</label>
                  <div className="schedule-grid">
                    {[
                      { id: 'continuous', label: 'Continuous (Real-time)', desc: 'Continuous background asset monitoring' },
                      { id: 'daily', label: 'Daily Recurrent', desc: 'Executes every midnight UTC' },
                      { id: 'weekly', label: 'Weekly Deep Audit', desc: 'Full port & TLS scan every Sunday' },
                      { id: 'manual', label: 'On-Demand Only', desc: 'Trigger scans manually via UI/API' },
                    ].map((sched) => (
                      <div
                        key={sched.id}
                        className={`schedule-card ${scanSchedule.frequency === sched.id ? 'selected' : ''}`}
                        onClick={() => setScanSchedule({ ...scanSchedule, frequency: sched.id })}
                      >
                        <div className="schedule-card__check">
                          {scanSchedule.frequency === sched.id && <Check size={10} style={{ color: 'white' }} />}
                        </div>
                        <div className="schedule-card__freq">{sched.label}</div>
                        <div className="schedule-card__desc">{sched.desc}</div>
                      </div>
                    ))}
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                  <div className="field-row">
                    <label className="field-label">Max Concurrent Target Workers</label>
                    <input
                      type="number"
                      className="s-input"
                      min="1"
                      max="20"
                      value={scanSchedule.concurrency}
                      onChange={(e) => setScanSchedule({ ...scanSchedule, concurrency: parseInt(e.target.value) || 1 })}
                    />
                  </div>
                  <div className="field-row">
                    <label className="field-label">Individual Probe Timeout <span>(Seconds)</span></label>
                    <input
                      type="number"
                      className="s-input"
                      min="1"
                      max="60"
                      value={scanSchedule.timeout}
                      onChange={(e) => setScanSchedule({ ...scanSchedule, timeout: parseInt(e.target.value) || 10 })}
                    />
                  </div>
                </div>

                <div className="field-row">
                  <label className="field-label">Excluded Subdomains / Hosts <span>(Comma separated)</span></label>
                  <input
                    type="text"
                    className="s-input"
                    value={scanSchedule.excludedDomains}
                    onChange={(e) => setScanSchedule({ ...scanSchedule, excludedDomains: e.target.value })}
                  />
                </div>

                <div className="settings-footer">
                  <button className="btn btn--primary" onClick={() => addToast('Scan schedule policy updated', 'success')}>
                    <Save size={14} style={{ marginRight: 6 }} /> Save Schedule Settings
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* TAB 6: NOTIFICATIONS */}
          {activeTab === 'notifications' && (
            <div className="settings-section">
              <div className="settings-section__header">
                <div className="settings-section__icon" style={{ background: 'rgba(239, 68, 68, 0.15)', color: '#f87171' }}>
                  <Bell size={20} />
                </div>
                <div className="settings-section__titles">
                  <h3>Alert Notifications & Severity Thresholds</h3>
                  <p>Control when and where critical security alerts are dispatched.</p>
                </div>
              </div>
              <div className="settings-section__body">
                <div className="field-row">
                  <label className="field-label">Notification Delivery Channels</label>
                  <div className="channel-list">
                    {[
                      { id: 'email', label: 'Email Alerts', icon: Mail },
                      { id: 'slack', label: 'Slack Webhook', icon: MessageSquare },
                      { id: 'webhook', label: 'HTTP REST Webhook', icon: Link2 },
                    ].map((chan) => {
                      const Icon = chan.icon;
                      const isActive = notifications.channels[chan.id];
                      return (
                        <div
                          key={chan.id}
                          className={`channel-pill ${isActive ? 'active' : ''}`}
                          onClick={() => {
                            setNotifications({
                              ...notifications,
                              channels: { ...notifications.channels, [chan.id]: !isActive }
                            });
                          }}
                        >
                          <span className="channel-pill__dot"></span>
                          <Icon size={14} />
                          <span>{chan.label}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>

                <div className="field-row">
                  <label className="field-label">Minimum Severity Trigger</label>
                  <select
                    className="s-select"
                    value={notifications.minSeverity}
                    onChange={(e) => setNotifications({ ...notifications, minSeverity: e.target.value })}
                  >
                    <option value="critical">Critical Only (CVSS 9.0 - 10.0)</option>
                    <option value="high">High and Critical (CVSS 7.0+)</option>
                    <option value="medium">Medium and Above (CVSS 4.0+)</option>
                    <option value="all">All Discovered Findings (Low to Critical)</option>
                  </select>
                </div>

                <div className="toggle-row" onClick={() => setNotifications({ ...notifications, emailAlerts: !notifications.emailAlerts })}>
                  <div>
                    <div className="toggle-row__label">Daily Executive Summary Digest</div>
                    <div className="toggle-row__desc">Receive a 24-hour summary email with security posture score and change diffs</div>
                  </div>
                  <label className="toggle" onClick={(e) => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={notifications.emailAlerts}
                      onChange={() => setNotifications({ ...notifications, emailAlerts: !notifications.emailAlerts })}
                    />
                    <span className="toggle__track"></span>
                    <span className="toggle__thumb"></span>
                  </label>
                </div>

                <div className="settings-footer">
                  <button className="btn btn--primary" onClick={() => addToast('Notification preferences saved', 'success')}>
                    <Save size={14} style={{ marginRight: 6 }} /> Save Alert Rules
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* TAB 7: APPEARANCE */}
          {activeTab === 'appearance' && (
            <div className="settings-section">
              <div className="settings-section__header">
                <div className="settings-section__icon" style={{ background: 'rgba(59, 130, 246, 0.15)', color: 'var(--neon-blue)' }}>
                  <Palette size={20} />
                </div>
                <div className="settings-section__titles">
                  <h3>UI Appearance & Color Themes</h3>
                  <p>Customize your visual workspace layout, high-contrast mode, and color themes.</p>
                </div>
              </div>
              <div className="settings-section__body">
                <div className="field-row">
                  <label className="field-label">Active Workspace Theme <span>Currently: {theme.toUpperCase()}</span></label>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
                    {[
                      { id: 'dark', label: 'Dark Mode', bg: '#0b132b', border: '#1e293b' },
                      { id: 'light', label: 'Light Mode', bg: '#f8fafc', border: '#e2e8f0' },
                      { id: 'blue', label: 'Blue Synthwave', bg: '#0f172a', border: '#3b82f6' },
                    ].map((t) => (
                      <div
                        key={t.id}
                        style={{
                          background: t.bg,
                          border: `2px solid ${theme === t.id ? 'var(--neon-blue)' : t.border}`,
                          borderRadius: 'var(--radius-lg)',
                          padding: 16,
                          cursor: 'pointer',
                          display: 'flex',
                          flexDirection: 'column',
                          alignItems: 'center',
                          gap: 8,
                          boxShadow: theme === t.id ? '0 0 12px rgba(59, 130, 246, 0.3)' : 'none',
                        }}
                        onClick={() => {
                          setTheme(t.id);
                          addToast(`Switched to ${t.label}`, 'info');
                        }}
                      >
                        <Palette size={24} style={{ color: theme === t.id ? 'var(--neon-blue)' : 'var(--text-muted)' }} />
                        <span style={{ fontSize: 13, fontWeight: 700, color: theme === t.id ? 'var(--neon-blue)' : 'var(--text-primary)' }}>
                          {t.label}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="toggle-row" onClick={() => setCompactView(!compactView)}>
                  <div>
                    <div className="toggle-row__label">Compact Table Spacing</div>
                    <div className="toggle-row__desc">Reduce table padding to fit more vulnerability rows on screen</div>
                  </div>
                  <label className="toggle" onClick={(e) => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={compactView}
                      onChange={() => setCompactView(!compactView)}
                    />
                    <span className="toggle__track"></span>
                    <span className="toggle__thumb"></span>
                  </label>
                </div>

                <div className="toggle-row" onClick={() => setHighContrast(!highContrast)}>
                  <div>
                    <div className="toggle-row__label">High Contrast Borders</div>
                    <div className="toggle-row__desc">Increase border opacity and text contrast for low-light SOC monitors</div>
                  </div>
                  <label className="toggle" onClick={(e) => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={highContrast}
                      onChange={() => setHighContrast(!highContrast)}
                    />
                    <span className="toggle__track"></span>
                    <span className="toggle__thumb"></span>
                  </label>
                </div>

                <div className="settings-footer">
                  <button className="btn btn--primary" onClick={() => addToast('Appearance settings saved', 'success')}>
                    <Save size={14} style={{ marginRight: 6 }} /> Save Display Settings
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* TAB 8: TEAM ACCESS */}
          {activeTab === 'team' && (
            <div className="settings-section">
              <div className="settings-section__header">
                <div className="settings-section__icon" style={{ background: 'rgba(168, 85, 247, 0.15)', color: 'var(--accent-purple)' }}>
                  <Users size={20} />
                </div>
                <div className="settings-section__titles">
                  <h3>Team Members & Access Control</h3>
                  <p>Manage analyst permissions, invitation links, and RBAC roles.</p>
                </div>
              </div>
              <div className="settings-section__body">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <h4 style={{ fontSize: 14, fontWeight: 700 }}>Workspace Members ({teamMembers.length})</h4>
                  <button className="btn btn--primary btn--sm" onClick={() => setShowInviteModal(true)}>
                    <Plus size={14} style={{ marginRight: 6 }} /> Invite Member
                  </button>
                </div>

                <table className="team-table">
                  <thead>
                    <tr>
                      <th>User</th>
                      <th>Role</th>
                      <th>Status</th>
                      <th style={{ textAlign: 'right' }}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {teamMembers.map((member) => (
                      <tr key={member.id}>
                        <td>
                          <div className="user-cell">
                            <div className="user-avatar" style={{ background: member.color }}>
                              {member.avatar}
                            </div>
                            <div>
                              <div className="user-name">{member.name}</div>
                              <div className="user-email">{member.email}</div>
                            </div>
                          </div>
                        </td>
                        <td>
                          <span className={`role-badge role-badge--${member.role.toLowerCase()}`}>
                            {member.role}
                          </span>
                        </td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <span className="status-dot status-dot--live"></span>
                            <span style={{ fontSize: 12, textTransform: 'capitalize' }}>{member.status}</span>
                          </div>
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <button
                            className="btn btn--icon btn--ghost"
                            onClick={() => {
                              if (member.id === '1') {
                                addToast('Cannot remove workspace owner', 'error');
                                return;
                              }
                              setTeamMembers(teamMembers.filter(m => m.id !== member.id));
                              addToast(`Removed ${member.name} from workspace`, 'warning');
                            }}
                            style={{ color: '#f87171' }}
                            title="Remove Member"
                          >
                            <Trash2 size={14} />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 9: DANGER ZONE */}
          {activeTab === 'danger' && (
            <div className="settings-section settings-section--danger">
              <div className="settings-section__header" style={{ background: 'rgba(239, 68, 68, 0.08)' }}>
                <div className="settings-section__icon" style={{ background: 'rgba(239, 68, 68, 0.2)', color: '#f87171' }}>
                  <AlertTriangle size={20} />
                </div>
                <div className="settings-section__titles">
                  <h3 style={{ color: '#f87171' }}>Danger Zone</h3>
                  <p>Destructive actions, database wipes, and telemetry resets.</p>
                </div>
              </div>
              <div className="settings-section__body">
                <div className="danger-row">
                  <div className="danger-row__info">
                    <h4>Purge Local Scan History</h4>
                    <p>Permanently remove all previous scan telemetry, logs, and evidence dumps.</p>
                  </div>
                  <button
                    className="btn btn--outline"
                    style={{ borderColor: 'rgba(239, 68, 68, 0.5)', color: '#f87171' }}
                    onClick={() => {
                      if (window.confirm('Are you sure you want to purge all scan history? This action cannot be undone.')) {
                        addToast('Scan history purged successfully', 'warning');
                      }
                    }}
                  >
                    Purge Scans
                  </button>
                </div>

                <div className="danger-row">
                  <div className="danger-row__info">
                    <h4>Reset Discovered Asset Inventory</h4>
                    <p>Clear all discovered subdomains, open ports, and DNS records from the local workspace database.</p>
                  </div>
                  <button
                    className="btn btn--outline"
                    style={{ borderColor: 'rgba(239, 68, 68, 0.5)', color: '#f87171' }}
                    onClick={() => {
                      if (window.confirm('Are you sure you want to reset all asset telemetry?')) {
                        addToast('Asset inventory reset', 'warning');
                      }
                    }}
                  >
                    Reset Assets
                  </button>
                </div>
              </div>
            </div>
          )}

        </div>
      </div>

      {/* MODAL: Generate API Key */}
      {showNewKeyModal && (
        <div style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(4px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000
        }}>
          <div style={{
            background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-xl)',
            padding: 24, width: 420, maxWidth: '90%'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <h3 style={{ fontSize: 16, fontWeight: 700 }}>Generate New API Key</h3>
              <button className="btn btn--icon btn--ghost" onClick={() => setShowNewKeyModal(false)}><X size={16} /></button>
            </div>
            <div className="field-row" style={{ marginBottom: 16 }}>
              <label className="field-label">Key Description / Name</label>
              <input
                type="text"
                className="s-input"
                placeholder="e.g. Jenkins Security Pipeline"
                value={newKeyName}
                onChange={(e) => setNewKeyName(e.target.value)}
              />
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
              <button className="btn btn--outline" onClick={() => setShowNewKeyModal(false)}>Cancel</button>
              <button className="btn btn--primary" onClick={handleGenerateKey}>Generate Key</button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL: Update Password */}
      {showPasswordModal && (
        <div style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(4px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000
        }}>
          <div style={{
            background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-xl)',
            padding: 24, width: 420, maxWidth: '90%'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <h3 style={{ fontSize: 16, fontWeight: 700 }}>Update Password</h3>
              <button className="btn btn--icon btn--ghost" onClick={() => setShowPasswordModal(false)}><X size={16} /></button>
            </div>
            <div className="field-row" style={{ marginBottom: 12 }}>
              <label className="field-label">Current Password</label>
              <input
                type="password"
                className="s-input"
                value={passwords.current}
                onChange={(e) => setPasswords({ ...passwords, current: e.target.value })}
              />
            </div>
            <div className="field-row" style={{ marginBottom: 12 }}>
              <label className="field-label">New Password</label>
              <input
                type="password"
                className="s-input"
                value={passwords.newPass}
                onChange={(e) => setPasswords({ ...passwords, newPass: e.target.value })}
              />
            </div>
            <div className="field-row" style={{ marginBottom: 16 }}>
              <label className="field-label">Confirm New Password</label>
              <input
                type="password"
                className="s-input"
                value={passwords.confirm}
                onChange={(e) => setPasswords({ ...passwords, confirm: e.target.value })}
              />
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
              <button className="btn btn--outline" onClick={() => setShowPasswordModal(false)}>Cancel</button>
              <button className="btn btn--primary" onClick={() => {
                setShowPasswordModal(false);
                addToast('Password updated successfully', 'success');
              }}>Save Password</button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL: Invite Team Member */}
      {showInviteModal && (
        <div style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(4px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000
        }}>
          <div style={{
            background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-xl)',
            padding: 24, width: 420, maxWidth: '90%'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <h3 style={{ fontSize: 16, fontWeight: 700 }}>Invite Team Member</h3>
              <button className="btn btn--icon btn--ghost" onClick={() => setShowInviteModal(false)}><X size={16} /></button>
            </div>
            <div className="field-row" style={{ marginBottom: 12 }}>
              <label className="field-label">Email Address</label>
              <input
                type="email"
                className="s-input"
                placeholder="colleague@enterprise.sec"
                value={inviteEmail}
                onChange={(e) => setInviteEmail(e.target.value)}
              />
            </div>
            <div className="field-row" style={{ marginBottom: 16 }}>
              <label className="field-label">RBAC Role</label>
              <select
                className="s-select"
                value={inviteRole}
                onChange={(e) => setInviteRole(e.target.value)}
              >
                <option value="Analyst">Analyst (Read & Execute Scans)</option>
                <option value="Admin">Admin (Full Access & Settings)</option>
                <option value="ReadOnly">ReadOnly (View Only)</option>
              </select>
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
              <button className="btn btn--outline" onClick={() => setShowInviteModal(false)}>Cancel</button>
              <button className="btn btn--primary" onClick={handleInviteMember}>Send Invite</button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
