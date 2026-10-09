import React, { useCallback, useEffect, useState } from 'react'
import { useLocation } from 'react-router-dom'
import { api } from '../lib/api'
import { SOURCE_LABEL, THREAT_LABEL, datetime, num, titleCase } from '../lib/viz'
import { ActionBadge, Banner, Card, Empty, SeverityBadge, Spinner } from '../components/ui'
import { RiskScore, StatusBadge } from '../components/soc'
import IncidentDrawer from '../components/IncidentDrawer'

const STATUS_TABS = [
  ['active', 'Active'], ['', 'All'], ['resolved', 'Resolved'], ['false_positive', 'False positives'],
]
const PAGE = 25

export default function IncidentsSOC({ liveTick }) {
  const loc = useLocation()
  const params = new URLSearchParams(loc.search)
  const [status, setStatus] = useState(params.get('status') ?? 'active')
  const [severity, setSeverity] = useState('')
  const [source, setSource] = useState('')
  const [q, setQ] = useState(params.get('q') || '')
  const [page, setPage] = useState(0)
  const [data, setData] = useState({ items: [], total: 0 })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [open, setOpen] = useState(params.get('id'))

  const load = useCallback(async () => {
    try {
      setData(await api.soc.incidents({ status, severity, source, q: q.trim(), limit: PAGE, offset: page * PAGE }))
      setError('')
    } catch (e) { setError(e.message) } finally { setLoading(false) }
  }, [status, severity, source, q, page])

  useEffect(() => { load() }, [load, liveTick])
  useEffect(() => { setPage(0) }, [status, severity, source, q])

  const pages = Math.max(1, Math.ceil(data.total / PAGE))
  return (
    <div className="stack">
      {error && <Banner kind="err">{error}</Banner>}
      <Card>
        <div className="filters">
          <div className="seg-tabs" role="group" aria-label="Status">
            {STATUS_TABS.map(([v, l]) => (
              <button key={l} type="button" className={status === v ? 'active' : ''} onClick={() => setStatus(v)}>{l}</button>
            ))}
          </div>
          <select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severity">
            <option value="">Any severity</option>
            {['critical', 'high', 'medium', 'low'].map((s) => <option key={s} value={s}>{titleCase(s)}</option>)}
          </select>
          <select value={source} onChange={(e) => setSource(e.target.value)} aria-label="Channel">
            <option value="">Any channel</option>
            {Object.entries(SOURCE_LABEL).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
          </select>
          <input type="text" value={q} onChange={(e) => setQ(e.target.value)}
                 placeholder="Search ID, threat, file or text" aria-label="Search" />
          <span className="spacer" />
          <span className="muted" style={{ fontSize: 12.5 }}>{num(data.total)} incident{data.total === 1 ? '' : 's'}</span>
        </div>
        {loading ? <div className="row"><Spinner /> Loading…</div> : !data.items.length ? (
          <Empty>No incidents match these filters.</Empty>
        ) : (
          <div className="table-wrap"><table className="table">
            <thead><tr><th>Incident</th><th>Detected</th><th>Channel</th><th>Summary</th><th>Severity</th>
              <th>Risk</th><th>Action</th><th>Status</th></tr></thead>
            <tbody>{data.items.map((i) => (
              <tr key={i.id} className="clickable" onClick={() => setOpen(i.id)}>
                <td className="mono nowrap">{i.id}</td>
                <td className="nowrap">{datetime(i.ts)}</td>
                <td className="nowrap">{SOURCE_LABEL[i.source] || i.source}</td>
                <td style={{ maxWidth: 420 }}>
                  <div style={{ color: 'var(--text-primary)' }}>{THREAT_LABEL[i.threat_class] || titleCase(i.threat_class)}
                    {i.file_name && <span className="muted"> · {i.file_name}</span>}</div>
                  <div className="truncate muted" style={{ fontSize: 12 }}>{i.excerpt}</div>
                </td>
                <td><SeverityBadge value={i.severity} /></td>
                <td><RiskScore value={i.risk} severity={i.severity} /></td>
                <td><ActionBadge value={i.action} /></td>
                <td><StatusBadge value={i.status} /></td>
              </tr>
            ))}</tbody>
          </table></div>
        )}
        {data.total > PAGE && (
          <div className="pager">
            <button className="btn btn-sm" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
            <span>Page {page + 1} of {pages}</span>
            <button className="btn btn-sm" disabled={page + 1 >= pages} onClick={() => setPage(page + 1)}>Next</button>
          </div>
        )}
      </Card>
      {open && <IncidentDrawer id={open} onClose={() => setOpen(null)} onChanged={load} />}
    </div>
  )
}
