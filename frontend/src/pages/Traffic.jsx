import React, { useCallback, useEffect, useState } from 'react'
import { useLocation } from 'react-router-dom'
import { api } from '../lib/api'
import { SOURCE_LABEL, THREAT_LABEL, datetime, num, titleCase } from '../lib/viz'
import { ActionBadge, Banner, Card, Empty, Spinner } from '../components/ui'
import { RiskScore } from '../components/soc'
import IncidentDrawer from '../components/IncidentDrawer'

const PAGE = 50
const OUTCOME = {
  answered: 'Answered', sanitized: 'Answered (cleaned)', masked: 'Reply masked', blocked: 'Reply withheld',
  refused: 'Refused', rejected: 'Rejected', accepted: 'Accepted',
}

export default function Traffic({ liveTick }) {
  const loc = useLocation()
  const [source, setSource] = useState('')
  const [flagged, setFlagged] = useState(new URLSearchParams(loc.search).get('flagged') === '1')
  const [page, setPage] = useState(0)
  const [rows, setRows] = useState([])
  const [files, setFiles] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [open, setOpen] = useState(null)

  const load = useCallback(async () => {
    try {
      const [r, f] = await Promise.all([
        api.soc.requests({ source, flagged, limit: PAGE, offset: page * PAGE }),
        api.soc.files(),
      ])
      setRows(r); setFiles(f); setError('')
    } catch (e) { setError(e.message) } finally { setLoading(false) }
  }, [source, flagged, page])
  useEffect(() => { load() }, [load, liveTick])
  useEffect(() => { setPage(0) }, [source, flagged])

  return (
    <div className="stack">
      {error && <Banner kind="err">{error}</Banner>}
      <Card title="Request log" sub="Every message, file and model reply AstraSec inspected. Text is shown redacted.">
        <div className="filters">
          <div className="seg-tabs" role="group" aria-label="Channel">
            {[['', 'All'], ['prompt', 'Messages'], ['file', 'Files'], ['response', 'Replies']].map(([v, l]) => (
              <button key={l} type="button" className={source === v ? 'active' : ''} onClick={() => setSource(v)}>{l}</button>
            ))}
          </div>
          <label className="switch" style={{ padding: 0 }}>
            <input type="checkbox" checked={flagged} onChange={(e) => setFlagged(e.target.checked)} />
            <span>Only requests AstraSec acted on</span>
          </label>
        </div>
        {loading ? <div className="row"><Spinner /> Loading…</div> : !rows.length ? (
          <Empty>Nothing logged yet{flagged ? ' that was flagged' : ''}.</Empty>
        ) : (
          <div className="table-wrap"><table className="table">
            <thead><tr><th>Time</th><th>Channel</th><th>Client</th><th>Content</th><th>Assessment</th>
              <th>Risk</th><th>Decision</th><th>Outcome</th><th className="num">Latency</th></tr></thead>
            <tbody>{rows.map((r) => (
              <tr key={r.id} className={r.incident_id ? 'clickable' : ''}
                  onClick={() => r.incident_id && setOpen(r.incident_id)}>
                <td className="nowrap">{datetime(r.ts)}</td>
                <td className="nowrap">{SOURCE_LABEL[r.source]?.replace(/s$/, '') || r.source}</td>
                <td className="mono nowrap">{r.client}</td>
                <td style={{ maxWidth: 360 }}><div className="truncate">{r.excerpt || <span className="muted">—</span>}</div></td>
                <td className="nowrap">{r.threat_class === 'benign' ? <span className="muted">No threat</span>
                  : (THREAT_LABEL[r.threat_class] || titleCase(r.threat_class))}</td>
                <td><RiskScore value={r.risk} severity={r.severity} /></td>
                <td>{['reject'].includes(r.action) ? <span className="muted">Too long</span> : <ActionBadge value={r.action} />}</td>
                <td className="nowrap">{OUTCOME[r.outcome] || titleCase(r.outcome)}</td>
                <td className="num nowrap">{r.latency_ms == null ? '—' : `${num(r.latency_ms, 0)} ms`}</td>
              </tr>
            ))}</tbody>
          </table></div>
        )}
        <div className="pager">
          <button className="btn btn-sm" disabled={page === 0} onClick={() => setPage(page - 1)}>Newer</button>
          <span>Page {page + 1}</span>
          <button className="btn btn-sm" disabled={rows.length < PAGE} onClick={() => setPage(page + 1)}>Older</button>
        </div>
      </Card>

      <Card title="Uploaded files" sub="Everything attached in AstraBot and what the file guard decided">
        {!files.length ? <Empty>No files uploaded yet.</Empty> : (
          <div className="table-wrap"><table className="table">
            <thead><tr><th>Time</th><th>File</th><th>Type</th><th className="num">Size</th><th>Decision</th>
              <th>Risk</th><th>Findings</th></tr></thead>
            <tbody>{files.map((f) => {
              const s = f.summary || {}
              const findings = [
                s.injections?.length ? `${s.injections.length} injected instruction(s)` : null,
                s.sensitive?.length ? `${s.sensitive.length} sensitive value(s)` : null,
                s.links?.length ? `${s.links.length} suspicious link(s)` : null,
              ].filter(Boolean).join(' · ') || s.reason || 'Clean'
              const action = { accepted: 'allow', sanitized: 'sanitize', blocked: 'block',
                               quarantined: 'quarantine' }[f.status]
              return (
                <tr key={f.id} className={f.incident_id ? 'clickable' : ''}
                    onClick={() => f.incident_id && setOpen(f.incident_id)}>
                  <td className="nowrap">{datetime(f.ts)}</td>
                  <td>{f.name}</td>
                  <td className="nowrap">{(f.kind || '').toUpperCase()}</td>
                  <td className="num nowrap">{f.size ? `${num(f.size / 1024, 1)} KB` : '—'}</td>
                  <td>{action ? <ActionBadge value={action} /> : <span className="muted">{titleCase(f.status)}</span>}</td>
                  <td><RiskScore value={f.risk} severity={f.risk > 80 ? 'critical' : f.risk > 60 ? 'high' : f.risk > 40 ? 'medium' : 'low'} /></td>
                  <td>{findings}</td>
                </tr>
              )
            })}</tbody>
          </table></div>
        )}
      </Card>
      {open && <IncidentDrawer id={open} onClose={() => setOpen(null)} onChanged={load} />}
    </div>
  )
}
