import React, { useCallback, useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ExternalLink, RefreshCw } from 'lucide-react'
import { api } from '../lib/api'
import {
  BAND_COLOR, SEVERITY_COLOR, SOURCE_LABEL, THREAT_LABEL, ago, num, pct, titleCase,
} from '../lib/viz'
import { ActionBadge, Banner, Card, Empty, SeverityBadge, Spinner } from '../components/ui'
import {
  ActionLadder, DefenceTrend, Kpi, RiskHistogram, RiskLine, RiskScore, StatusBadge, ThreatBarList,
} from '../components/soc'
import { ScoreRing } from '../components/charts'
import IncidentDrawer from '../components/IncidentDrawer'

const HEALTH_LABEL = { optimal: 'Excellent', healthy: 'Healthy', moderate: 'Fair', high: 'At risk', critical: 'Critical' }
const RANGES = [['24h', 'Last 24 hours'], ['7d', 'Last 7 days'], ['30d', 'Last 30 days']]

export default function SecurityCenter({ liveTick }) {
  const [range, setRange] = useState('24h')
  const [data, setData] = useState(null)
  const [incidents, setIncidents] = useState([])
  const [alerts, setAlerts] = useState([])
  const [error, setError] = useState('')
  const [open, setOpen] = useState(null)
  const [refreshing, setRefreshing] = useState(false)
  const navigate = useNavigate()

  const load = useCallback(async () => {
    setRefreshing(true)
    try {
      const [o, inc, al] = await Promise.all([
        api.soc.overview(range),
        api.soc.incidents({ limit: 8 }),
        api.soc.alerts({ limit: 6 }),
      ])
      setData(o); setIncidents(inc.items); setAlerts(al.items); setError('')
    } catch (e) { setError(e.message) } finally { setRefreshing(false) }
  }, [range])

  useEffect(() => { load() }, [load, liveTick])
  useEffect(() => { const t = setInterval(load, 20000); return () => clearInterval(t) }, [load])

  if (!data) {
    return error ? <Banner kind="err">{error}</Banner>
      : <div className="row"><Spinner /> <span className="muted">Loading the Security Center…</span></div>
  }
  const k = data.kpis
  const spark = (key) => data.trend.map((b) => b[key])
  const h = data.health
  const m = data.memory || {}
  const rangeLabel = RANGES.find((r) => r[0] === range)[1].toLowerCase()

  return (
    <div className="stack">
      {error && <Banner kind="err">{error}</Banner>}

      <div className="row" style={{ justifyContent: 'space-between' }}>
        <div className="estate">
          <span><strong>{num(k.applications)}</strong>applications</span>
          <span><strong>{num(k.ai_bots)}</strong>AI bot{k.ai_bots === 1 ? '' : 's'} protected</span>
          <span><strong>{num(k.audits)}</strong>application audits</span>
          <span><strong>{num(k.files)}</strong>files inspected</span>
          <span><strong>{num(data.bot?.active_sessions || 0)}</strong>live conversations</span>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <div className="seg-tabs" role="group" aria-label="Time range">
            {RANGES.map(([v, l]) => (
              <button key={v} type="button" className={range === v ? 'active' : ''}
                      onClick={() => setRange(v)}>{l}</button>
            ))}
          </div>
          <button className="btn btn-sm" type="button" onClick={load} disabled={refreshing}
                  aria-label="Refresh"><RefreshCw size={13} className={refreshing ? 'spin' : ''} /></button>
          <a className="btn btn-sm" href="/bot" target="_blank" rel="noreferrer">
            Open AstraBot <ExternalLink size={13} />
          </a>
        </div>
      </div>

      <div className="grid grid-4" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))' }}>
        <Kpi label="Requests analysed" value={num(k.requests)}
             sub={`${num(k.prompts)} messages · ${num(k.files)} files · ${num(k.responses_checked)} replies checked`}
             definition="Every message and file AstraBot received, all inspected before the model."
             spark={spark('total')} sparkColor="var(--series-1)" />
        <Kpi label="Threats detected" value={num(k.threats_detected)}
             tone={k.threats_detected ? 'serious' : undefined}
             sub={k.requests ? `${pct(k.threats_detected / Math.max(1, k.requests), 1)} of requests` : 'No traffic yet'}
             definition="Inputs or replies the framework acted on: monitored, sanitised, masked or refused."
             spark={data.trend.map((b) => b.flagged + b.blocked)} sparkColor="var(--status-serious)"
             onClick={() => navigate('/traffic?flagged=1')} />
        <Kpi label="Threats blocked" value={num(k.threats_blocked)}
             tone={k.threats_blocked ? 'critical' : undefined}
             sub={k.block_rate != null ? `${pct(k.block_rate)} of detected threats stopped outright` : '—'}
             definition="Never reached the model: rate-limited, blocked, quarantined, or reply withheld."
             spark={spark('blocked')} sparkColor="var(--status-critical)" />
        <Kpi label="Active incidents" value={num(k.active_incidents)}
             tone={k.open_critical ? 'critical' : k.active_incidents ? 'warning' : 'good'}
             sub={k.open_critical ? `${k.open_critical} critical still open` : 'No critical incidents open'}
             definition="Open or under investigation. Resolve or mark false positives on the Incidents page."
             onClick={() => navigate('/incidents')} />
      </div>

      <div className="grid grid-2-1">
        <Card title="Traffic and defence" sub={`Every request in the ${rangeLabel}, by what AstraSec did with it`}>
          <DefenceTrend trend={data.trend} />
          <div className="section-title" style={{ fontSize: 13, marginTop: 16 }}>Average risk of answered messages</div>
          <div className="field-hint" style={{ marginTop: 0, marginBottom: 6 }}>
            0–100 risk index; ordinary conversation sits under 20.
          </div>
          <RiskLine trend={data.trend} />
        </Card>

        <Card title="Security health" sub="A single index of how the protected estate is doing"
              actions={<span className="badge" style={{ color: BAND_COLOR[h.band], borderColor: BAND_COLOR[h.band] }}>
                {HEALTH_LABEL[h.band] || titleCase(h.band)}</span>}>
          <div style={{ display: 'grid', placeItems: 'center', marginBottom: 12 }}>
            <ScoreRing value={h.score} label={String(Math.round(h.score))} color={BAND_COLOR[h.band]}
                       caption="out of 100" />
          </div>
          <div className="stack-sm">
            {h.components.map((c) => (
              <div key={c.key} className="rb-row" style={{ gridTemplateColumns: '1fr 90px 34px' }}>
                <div className="rb-label">{c.label}
                  <div className="field-hint" style={{ marginTop: 0 }}>{c.detail} · weight {pct(c.weight)}</div></div>
                <div className="barlist-track"><div className="barlist-fill"
                  style={{ width: `${Math.max(2, c.value)}%`, background: 'var(--series-1)' }} /></div>
                <div className="barlist-value tnum">{Math.round(c.value)}</div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <div className="grid grid-3">
        <Card title="Threat analytics" sub={`Incidents by type, ${rangeLabel}`}>
          <ThreatBarList distribution={data.threat_classes}
                         onSelect={(t) => navigate(`/incidents?q=${t}`)} />
        </Card>
        <Card title="Defence decisions" sub="How far up the escalation ladder each request went">
          <ActionLadder distribution={data.actions} />
          <div className="field-hint">Darker = stronger response. Allow → Monitor → Sanitise → Rate limit → Block → Quarantine.</div>
        </Card>
        <Card title="Where threats came from" sub="Each input channel, and what was stopped">
          <div className="table-wrap"><table className="table">
            <thead><tr><th>Channel</th><th className="num">Total</th><th className="num">Flagged</th><th className="num">Blocked</th></tr></thead>
            <tbody>
              {['prompt', 'file', 'response'].map((s) => {
                const r = data.sources[s] || { total: 0, flagged: 0, blocked: 0 }
                return (
                  <tr key={s}><td>{SOURCE_LABEL[s]}</td><td className="num">{num(r.total)}</td>
                    <td className="num">{num(r.flagged)}</td><td className="num">{num(r.blocked)}</td></tr>
                )
              })}
            </tbody>
          </table></div>
          <div className="section-title" style={{ fontSize: 13, marginTop: 14 }}>Risk of every scored message</div>
          <RiskHistogram hist={data.risk_histogram} height={120} />
        </Card>
      </div>

      <div className="grid grid-2-1">
        <Card title="Recent incidents" sub="Newest first — select one for the full evidence"
              actions={<Link className="btn btn-sm" to="/incidents">All incidents</Link>}>
          {!incidents.length ? <Empty>No incidents. Try a prompt-injection message in AstraBot.</Empty> : (
            <div className="table-wrap"><table className="table">
              <thead><tr><th>Incident</th><th>Threat</th><th>Risk</th><th>Action</th><th>Status</th></tr></thead>
              <tbody>{incidents.map((i) => (
                <tr key={i.id} className="clickable" onClick={() => setOpen(i.id)}>
                  <td className="nowrap"><span className="mono">{i.id}</span>
                    <div className="muted" style={{ fontSize: 11.5 }}>{ago(i.ts)}</div></td>
                  <td>{THREAT_LABEL[i.threat_class] || titleCase(i.threat_class)}
                    <div className="muted" style={{ fontSize: 11.5 }}>{({ prompt: 'Chat message', file: 'Uploaded file', response: 'Model reply' })[i.source]}</div></td>
                  <td><RiskScore value={i.risk} severity={i.severity} /></td>
                  <td><ActionBadge value={i.action} /></td>
                  <td><StatusBadge value={i.status} /></td>
                </tr>
              ))}</tbody>
            </table></div>
          )}
        </Card>
        <Card title="Owner alerts" sub={`${num(k.unread_alerts)} unread`}
              actions={<Link className="btn btn-sm" to="/alerts">All alerts</Link>}>
          {!alerts.length ? <Empty>No alerts yet.</Empty> : (
            <div>
              {alerts.map((a) => (
                <div key={a.id} className={`alert-line ${a.read ? '' : 'unread'}`}
                     onClick={() => a.incident_id && setOpen(a.incident_id)} title={a.message}>
                  <span className="sev-dot" style={{ background: SEVERITY_COLOR[a.severity] }} />
                  <span className="t">{a.title.replace(/^.*?—\s*/, '')}
                    <span className="muted" style={{ fontWeight: 400 }}> · {titleCase(a.severity)}</span></span>
                  <span className="muted nowrap" style={{ fontSize: 12 }}>{ago(a.ts)}</span>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      <div className="grid grid-2">
        <Card title="Artificial immune memory" sub="What the system has learned from attacks it has seen"
              actions={<Link className="btn btn-sm" to="/memory">Open</Link>}>
          <div className="kv-grid">
            <div><span>Known attack patterns</span><b>{num(m.known_patterns)}</b></div>
            <div><span>Patterns seen again</span><b>{num(m.repeated_patterns)}</b></div>
            <div><span>Repeat encounters</span><b>{num(m.repeat_encounters)}</b></div>
            <div><span>New patterns ({range})</span><b>{num(m.new_patterns)}</b></div>
            <div><span>Defence success</span><b>{m.defence_success_rate == null ? '—' : pct(m.defence_success_rate)}</b></div>
            <div><span>Recall rate</span><b>{pct(m.recall_rate || 0)}</b></div>
            <div><span>Rules awaiting approval</span><b>{num(m.rules_pending)}</b></div>
            <div><span>Rules enforcing</span><b>{num(m.rules_active)}</b></div>
          </div>
          <div className="field-hint">Defence success = incidents the framework acted on that the owner
            did not later mark as a false positive.</div>
        </Card>
        <Card title="Clients to watch" sub="Who sent the riskiest traffic in this period">
          {!data.top_clients.length ? <Empty>No client activity yet.</Empty> : (
            <div className="table-wrap"><table className="table">
              <thead><tr><th>Client</th><th className="num">Requests</th><th className="num">Flagged</th><th>Highest risk</th><th>State</th><th /></tr></thead>
              <tbody>{data.top_clients.map((c) => (
                <tr key={c.client}><td className="mono">{c.client}</td><td className="num">{num(c.requests)}</td>
                  <td className="num">{num(c.flagged)}</td>
                  <td><RiskScore value={c.max_risk} severity={c.max_risk > 80 ? 'critical' : c.max_risk > 60 ? 'high' : c.max_risk > 40 ? 'medium' : 'low'} /></td>
                  <td>{c.state === 'active' ? <span className="muted">Active</span>
                    : <ActionBadge value={c.state === 'quarantined' ? 'quarantine' : 'rate_limit'} />}</td>
                  <td style={{ textAlign: 'right' }}>{c.state !== 'active' && (
                    <button className="btn btn-sm" type="button"
                            onClick={async () => { await api.soc.release(c.client); load() }}>Release</button>)}</td></tr>
              ))}</tbody>
            </table></div>
          )}
          <div className="kv-grid" style={{ marginTop: 12 }}>
            <div><span>Median decision time</span><b>{k.p50_latency_ms == null ? '—' : `${k.p50_latency_ms} ms`}</b></div>
            <div><span>95th percentile</span><b>{k.p95_latency_ms == null ? '—' : `${k.p95_latency_ms} ms`}</b></div>
            <div><span>Median time to triage</span><b>{k.median_triage_minutes == null ? '—' : `${k.median_triage_minutes} min`}</b></div>
            <div><span>False-positive rate</span><b>{k.false_positive_rate == null ? '—' : pct(k.false_positive_rate, 1)}</b></div>
          </div>
        </Card>
      </div>

      {open && <IncidentDrawer id={open} onClose={() => setOpen(null)} onChanged={load} />}
    </div>
  )
}
