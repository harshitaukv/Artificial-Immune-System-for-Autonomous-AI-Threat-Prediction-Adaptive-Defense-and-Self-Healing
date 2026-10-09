import React, { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../lib/api'
import { datetime, num } from '../lib/viz'
import { Banner, Card, Empty, SeverityBadge, Spinner } from '../components/ui'
import IncidentDrawer from '../components/IncidentDrawer'

const CHANNEL_LABEL = { in_app: 'Dashboard', email: 'Email', webhook: 'Webhook' }

function ChannelChip({ name, state }) {
  if (!state || state === 'off') return null
  const ok = state === 'sent'
  const color = ok ? 'var(--status-good)' : state === 'pending' ? 'var(--text-muted)' : 'var(--status-critical)'
  return <span className="badge" title={state} style={{ color, borderColor: color }}>
    {CHANNEL_LABEL[name] || name}: {ok ? 'sent' : state === 'pending' ? 'sending' : 'failed'}</span>
}

export default function Alerts({ liveTick, onRead }) {
  const [items, setItems] = useState([])
  const [unread, setUnread] = useState(0)
  const [onlyUnread, setOnlyUnread] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [open, setOpen] = useState(null)
  const [perm, setPerm] = useState(typeof Notification !== 'undefined' ? Notification.permission : 'unsupported')

  const load = useCallback(async () => {
    try {
      const d = await api.soc.alerts({ unread: onlyUnread, limit: 200 })
      setItems(d.items); setUnread(d.unread); setError('')
    } catch (e) { setError(e.message) } finally { setLoading(false) }
  }, [onlyUnread])
  useEffect(() => { load() }, [load, liveTick])

  const markAll = async () => { await api.soc.readAlerts(); load(); onRead?.() }
  const openAlert = async (a) => {
    if (!a.read) { await api.soc.readAlerts(a.id); onRead?.() }
    if (a.incident_id) setOpen(a.incident_id)
    load()
  }
  const askPermission = async () => {
    try { setPerm(await Notification.requestPermission()) } catch { /* unsupported */ }
  }

  return (
    <div className="stack">
      {error && <Banner kind="err">{error}</Banner>}
      {perm === 'default' && (
        <Banner kind="info">
          Get a desktop notification the moment AstraSec raises an alert, even when this tab is in the
          background.{' '}<button className="btn btn-sm" type="button" onClick={askPermission}>Enable notifications</button>
        </Banner>
      )}
      <Card title={`${num(unread)} unread alert${unread === 1 ? '' : 's'}`}
            sub="Alerts never contain the offending message or file content — only what happened and where to look."
            actions={<div className="row" style={{ gap: 8 }}>
              <label className="switch" style={{ padding: 0 }}>
                <input type="checkbox" checked={onlyUnread} onChange={(e) => setOnlyUnread(e.target.checked)} />
                <span>Unread only</span></label>
              <button className="btn btn-sm" type="button" onClick={markAll} disabled={!unread}>Mark all read</button>
              <Link className="btn btn-sm" to="/settings">Email &amp; webhook</Link>
            </div>}>
        {loading ? <div className="row"><Spinner /> Loading…</div> : !items.length ? (
          <Empty>No alerts{onlyUnread ? ' left to read' : ''}.</Empty>
        ) : (
          <div className="stack-sm">
            {items.map((a) => (
              <div key={a.id} className={`alert-item ${a.read ? '' : 'unread'}`}
                   style={{ border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)' }}
                   onClick={() => openAlert(a)}>
                <div className="row" style={{ gap: 8 }}>
                  <SeverityBadge value={a.severity} />
                  <div className="alert-title">{a.title}</div>
                  <span className="spacer" />
                  {Object.entries(a.channels || {}).map(([k, v]) => <ChannelChip key={k} name={k} state={v} />)}
                  <span className="alert-meta" style={{ marginTop: 0 }}>{datetime(a.ts)}</span>
                </div>
                <div className="alert-msg">{a.message}</div>
              </div>
            ))}
          </div>
        )}
      </Card>
      {open && <IncidentDrawer id={open} onClose={() => setOpen(null)} onChanged={load} />}
    </div>
  )
}
