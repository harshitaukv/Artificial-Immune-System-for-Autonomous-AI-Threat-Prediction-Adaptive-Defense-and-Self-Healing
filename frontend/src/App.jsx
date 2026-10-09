import React, { useCallback, useEffect, useRef, useState } from 'react'
import { NavLink, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import {
  Bell, BarChart3, ClipboardCheck, Dna, ExternalLink, FileSearch, FlaskConical, FolderOpen,
  Gauge, ListChecks, LogOut, Moon, Radar, Settings as SettingsIcon, ShieldAlert, SlidersHorizontal,
  Sun, TerminalSquare, Waypoints,
} from 'lucide-react'
import { api, authEvents, connectFeed } from './lib/api'
import { ago } from './lib/viz'
import { Banner, SeverityBadge, Spinner } from './components/ui'

import SecurityCenter from './pages/SecurityCenter'
import IncidentsSOC from './pages/IncidentsSOC'
import Alerts from './pages/Alerts'
import Traffic from './pages/Traffic'
import BotPolicy from './pages/BotPolicy'
import Settings from './pages/Settings'
import Memory from './pages/Memory'
import AnalyzerConsole from './pages/AnalyzerConsole'
import Playground from './pages/Playground'
import Analytics from './pages/Analytics'
import About from './pages/About'
import Scan from './pages/Scan'
import Probe from './pages/Probe'
import Audit from './pages/Audit'
import Reports from './pages/Reports'
import Login from './pages/Login'

const NAV = [
  { section: 'Security Center' },
  { to: '/overview', label: 'Overview', icon: Gauge },
  { to: '/incidents', label: 'Incidents', icon: ShieldAlert },
  { to: '/alerts', label: 'Alerts', icon: Bell, badge: 'alerts' },
  { to: '/traffic', label: 'Traffic & files', icon: Waypoints },
  { section: 'AstraBot' },
  { href: '/bot', label: 'Open AstraBot', icon: ExternalLink },
  { to: '/policy', label: 'Bot & policy', icon: SlidersHorizontal },
  { section: 'Assess' },
  { to: '/audit', label: 'Application audit', icon: ClipboardCheck },
  { to: '/scan', label: 'File inspection', icon: FileSearch },
  { to: '/probe', label: 'Endpoint probe', icon: Radar },
  { to: '/reports', label: 'Saved reports', icon: FolderOpen },
  { section: 'Intelligence' },
  { to: '/memory', label: 'Immune memory', icon: Dna },
  { to: '/console', label: 'Analyzer console', icon: TerminalSquare },
  { to: '/lab', label: 'Module trace lab', icon: FlaskConical },
  { to: '/analytics', label: 'Model analytics', icon: BarChart3 },
  { section: 'System' },
  { to: '/settings', label: 'Settings & alerts', icon: SettingsIcon },
  { to: '/about', label: 'System & modules', icon: ListChecks },
]

const TITLES = {
  '/overview': ['Security Center', 'Runtime protection, detection and response for AstraBot and your applications'],
  '/incidents': ['Incidents', 'Every significant security event, with the evidence behind it'],
  '/alerts': ['Alerts', 'What AstraSec told you, and on which channels'],
  '/traffic': ['Traffic & files', 'Every request and upload AstraSec inspected'],
  '/policy': ['Bot & policy', 'Configure AstraBot and how AstraSec responds to risk'],
  '/audit': ['Application audit', 'Pre-deployment review of an application’s code, prompt, settings and live behaviour'],
  '/scan': ['File inspection', 'Inspect any document or dataset for injected instructions and sensitive data'],
  '/probe': ['Endpoint probe', 'Attack a live AI endpoint with a controlled battery'],
  '/reports': ['Saved reports', 'Every audit, scan and probe'],
  '/memory': ['Immune memory', 'What AstraSec has learned, and the rules it proposes'],
  '/console': ['Analyzer console', 'Test any message or reply against the analyzers'],
  '/lab': ['Module trace lab', 'Step through the five-module immune cascade for one input'],
  '/analytics': ['Model analytics', 'Training and evaluation evidence for the detection models'],
  '/settings': ['Settings & alerts', 'Owner access, alert channels and housekeeping'],
  '/about': ['System & modules', 'Runtime configuration and module inventory'],
}

export default function App() {
  const [auth, setAuth] = useState(null)
  const refreshAuth = useCallback(async () => {
    try { setAuth(await api.authStatus()) } catch { setAuth({ error: true }) }
  }, [])
  useEffect(() => { refreshAuth() }, [refreshAuth])
  useEffect(() => {
    const h = () => refreshAuth()
    authEvents.addEventListener('unauthorized', h)
    return () => authEvents.removeEventListener('unauthorized', h)
  }, [refreshAuth])

  if (!auth) return <div className="auth-wrap"><Spinner /></div>
  if (auth.error) {
    return <div className="auth-wrap"><Banner kind="err">The Security Center is unavailable right now.
      Please reload in a moment.</Banner></div>
  }
  if (!auth.authenticated) return <Login status={auth} onDone={refreshAuth} />
  return <Shell auth={auth} onAuthChange={refreshAuth} />
}

function Shell({ auth, onAuthChange }) {
  const location = useLocation()
  const navigate = useNavigate()
  const [theme, setTheme] = useState(() => {
    try { return localStorage.getItem('astrasec-theme') || 'light' } catch { return 'light' }
  })
  const [health, setHealth] = useState(null)
  const [feed, setFeed] = useState('connecting')
  const [liveTick, setLiveTick] = useState(0)
  const [unread, setUnread] = useState(0)
  const [bellOpen, setBellOpen] = useState(false)
  const [bellItems, setBellItems] = useState([])
  const [toasts, setToasts] = useState([])
  const bellRef = useRef(null)

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    try { localStorage.setItem('astrasec-theme', theme) } catch { /* private mode */ }
  }, [theme])

  const refreshUnread = useCallback(() => {
    api.soc.alerts({ limit: 8 }).then((d) => { setUnread(d.unread); setBellItems(d.items) }).catch(() => {})
  }, [])

  useEffect(() => {
    api.health().then(setHealth).catch(() => {})
    refreshUnread()
    const t = setInterval(() => { api.health().then(setHealth).catch(() => {}); refreshUnread() }, 30000)
    return () => clearInterval(t)
  }, [refreshUnread])

  // Live feed: every inspection nudges the open page to refresh; alerts pop a
  // toast and, when permitted, a desktop notification.
  useEffect(() => {
    let tickTimer
    const close = connectFeed((ev) => {
      clearTimeout(tickTimer)
      tickTimer = setTimeout(() => setLiveTick((x) => x + 1), 600)
      if (ev.type === 'alert') {
        setToasts((t) => [...t.slice(-2), ev])
        setTimeout(() => setToasts((t) => t.filter((x) => x.id !== ev.id)), 9000)
        refreshUnread()
        try {
          if (typeof Notification !== 'undefined' && Notification.permission === 'granted') {
            const n = new Notification(ev.title, { body: ev.message, tag: ev.id })
            n.onclick = () => { window.focus(); navigate(`/incidents?id=${ev.incident_id}`) }
          }
        } catch { /* notifications unavailable */ }
      }
    }, setFeed)
    return () => { clearTimeout(tickTimer); close() }
  }, [navigate, refreshUnread])

  useEffect(() => {
    const onDoc = (e) => { if (bellRef.current && !bellRef.current.contains(e.target)) setBellOpen(false) }
    document.addEventListener('mousedown', onDoc)
    return () => document.removeEventListener('mousedown', onDoc)
  }, [])

  const logout = async () => { await api.authLogout(); onAuthChange() }
  const [title, subtitle] = TITLES[location.pathname] || ['AstraSec', '']
  const ready = health?.models_loaded

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <div>
            <div className="brand-name">AstraSec</div>
            <div className="brand-sub">AI &amp; application security</div>
          </div>
        </div>
        <nav>
          {NAV.map((item, i) => {
            if (item.section) return <div className="nav-section" key={`s-${i}`}>{item.section}</div>
            if (item.href) {
              return (
                <a key={item.href} className="nav-item" href={item.href} target="_blank" rel="noreferrer">
                  <item.icon size={15} strokeWidth={1.75} className="nav-icon" />{item.label}
                </a>
              )
            }
            return (
              <NavLink key={item.to} to={item.to}
                       className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                <item.icon size={15} strokeWidth={1.75} className="nav-icon" />
                {item.label}
                {item.badge === 'alerts' && unread > 0 && (
                  <span className="badge" style={{ marginLeft: 'auto', padding: '0 7px', color: 'var(--status-critical)',
                                                   borderColor: 'var(--status-critical)' }}>{unread}</span>
                )}
              </NavLink>
            )
          })}
        </nav>
        <div className="sidebar-footer">
          <div className="status-line">
            <span className="status-dot" style={{ background: !health ? 'var(--text-muted)' : ready ? 'var(--status-good)' : 'var(--status-critical)' }} />
            {!health ? 'Checking protection…' : ready ? 'Protection active' : 'Protection unavailable'}
          </div>
        </div>
      </aside>

      <div className="main">
        <header className="topbar">
          <div>
            <h1>{title}</h1>
            {subtitle && <div className="sub">{subtitle}</div>}
          </div>
          <div className="spacer" />
          <div className="bell" ref={bellRef}>
            <button className="btn btn-icon" type="button" aria-label={`${unread} unread alerts`}
                    onClick={() => { setBellOpen((o) => !o); refreshUnread() }}>
              <Bell size={15} />
            </button>
            {unread > 0 && <span className="bell-count">{unread > 99 ? '99+' : unread}</span>}
            {bellOpen && (
              <div className="popover">
                <div className="popover-head">Alerts<span className="spacer" />
                  <button className="btn btn-sm btn-ghost" type="button"
                          onClick={async () => { await api.soc.readAlerts(); refreshUnread() }}>Mark all read</button>
                </div>
                {!bellItems.length ? <div className="empty">No alerts yet.</div> : bellItems.map((a) => (
                  <div key={a.id} className={`alert-item ${a.read ? '' : 'unread'}`}
                       onClick={async () => {
                         setBellOpen(false)
                         if (!a.read) await api.soc.readAlerts(a.id)
                         refreshUnread()
                         navigate(`/incidents?id=${a.incident_id}`)
                       }}>
                    <div className="alert-title">{a.title}</div>
                    <div className="alert-meta">{ago(a.ts)} · {a.incident_id}</div>
                  </div>
                ))}
                <div style={{ padding: 10, textAlign: 'center' }}>
                  <button className="btn btn-sm" type="button" onClick={() => { setBellOpen(false); navigate('/alerts') }}>
                    All alerts</button>
                </div>
              </div>
            )}
          </div>
          <button className="btn btn-icon" type="button" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
                  aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}>
            {theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}
          </button>
          {auth.configured && (
            <button className="btn btn-icon" type="button" onClick={logout} aria-label="Sign out" title="Sign out">
              <LogOut size={15} />
            </button>
          )}
        </header>

        <main className="content">
          {!auth.configured && (
            <div style={{ marginBottom: 14 }}>
              <Banner kind="warn">No owner password is set, so this Security Center only opens on this
                computer. <a href="#/settings">Set a password</a> before exposing AstraBot to other people.</Banner>
            </div>
          )}
          {health && !ready && (
            <div style={{ marginBottom: 14 }}>
              <Banner kind="err">The protection engine is unavailable, so AstraBot is not accepting
                messages. Restart AstraSec to restore it.</Banner>
            </div>
          )}
          <Routes>
            <Route path="/" element={<Navigate to="/overview" replace />} />
            <Route path="/overview" element={<SecurityCenter liveTick={liveTick} />} />
            <Route path="/incidents" element={<IncidentsSOC liveTick={liveTick} />} />
            <Route path="/alerts" element={<Alerts liveTick={liveTick} onRead={refreshUnread} />} />
            <Route path="/traffic" element={<Traffic liveTick={liveTick} />} />
            <Route path="/policy" element={<BotPolicy />} />
            <Route path="/settings" element={<Settings onLogout={logout} />} />
            <Route path="/memory" element={<Memory liveTick={liveTick} />} />
            <Route path="/console" element={<AnalyzerConsole />} />
            <Route path="/lab" element={<Playground />} />
            <Route path="/scan" element={<Scan />} />
            <Route path="/probe" element={<Probe />} />
            <Route path="/audit" element={<Audit />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/analytics" element={<Analytics />} />
            <Route path="/about" element={<About health={health} />} />
            <Route path="*" element={<Navigate to="/overview" replace />} />
          </Routes>
        </main>
      </div>

      <div className="toast-wrap" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className="toast" onClick={() => navigate(`/incidents?id=${t.incident_id}`)}>
            <div className="row" style={{ gap: 8 }}><SeverityBadge value={t.severity} />
              <span className="alert-meta" style={{ marginTop: 0 }}>just now</span></div>
            <div className="alert-title" style={{ marginTop: 5 }}>{t.title}</div>
            <div className="alert-msg">{t.message}</div>
          </div>
        ))}
      </div>
    </div>
  )
}
