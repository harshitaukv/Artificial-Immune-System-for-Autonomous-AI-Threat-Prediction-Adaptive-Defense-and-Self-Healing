import React, { useEffect, useState } from 'react'
import { X } from 'lucide-react'
import { api } from '../lib/api'
import { SOURCE_LABEL, THREAT_LABEL, datetime, num, titleCase } from '../lib/viz'
import { ActionBadge, Banner, Card, SeverityBadge, Spinner } from './ui'
import { RiskBreakdown, StatusBadge } from './soc'

const STATUSES = [
  ['open', 'Open'], ['investigating', 'Investigating'],
  ['resolved', 'Resolved'], ['false_positive', 'False positive'],
]

export default function IncidentDrawer({ id, onClose, onChanged }) {
  const [inc, setInc] = useState(null)
  const [error, setError] = useState('')
  const [status, setStatus] = useState('')
  const [note, setNote] = useState('')
  const [saving, setSaving] = useState(false)
  const [feedback, setFeedback] = useState(null)

  useEffect(() => {
    let live = true
    setInc(null); setError(''); setFeedback(null)
    api.soc.incident(id).then((d) => { if (live) { setInc(d); setStatus(d.status) } })
      .catch((e) => live && setError(e.message))
    return () => { live = false }
  }, [id])

  useEffect(() => {
    const onKey = (e) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const save = async () => {
    setSaving(true); setError('')
    try {
      const d = await api.soc.updateIncident(id, { status, note })
      setInc(d); setNote(''); setFeedback(d.feedback)
      onChanged?.()
    } catch (e) { setError(e.message) } finally { setSaving(false) }
  }

  const d = inc?.detail || {}
  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <aside className="drawer" onClick={(e) => e.stopPropagation()} aria-label={`Incident ${id}`}>
        <div className="drawer-head">
          <div>
            <div className="muted mono" style={{ fontSize: 12 }}>{id}</div>
            <h2 style={{ fontSize: 18, marginTop: 2 }}>{inc?.title || 'Incident'}</h2>
          </div>
          <div className="spacer" />
          <button className="btn btn-icon btn-ghost" onClick={onClose} aria-label="Close"><X size={16} /></button>
        </div>
        {error && <Banner kind="err">{error}</Banner>}
        {!inc ? <div className="row"><Spinner /> Loading…</div> : (
          <div className="stack">
            <div className="row" style={{ gap: 8 }}>
              <SeverityBadge value={inc.severity} />
              <ActionBadge value={inc.action} />
              <StatusBadge value={inc.status} />
              <span className="badge">{SOURCE_LABEL[inc.source] || titleCase(inc.source)}</span>
            </div>

            <Card>
              <div className="kv-grid">
                <div><span>Detected</span><b>{datetime(inc.ts)}</b></div>
                <div><span>Threat</span><b>{THREAT_LABEL[inc.threat_class] || titleCase(inc.threat_class)}</b></div>
                <div><span>Risk</span><b>{Math.round(inc.risk)}/100</b></div>
                <div><span>Application</span><b>{inc.app_id}</b></div>
                <div><span>Client</span><b className="mono">{inc.client || '—'}</b></div>
                {inc.file_name && <div><span>File</span><b>{inc.file_name}</b></div>}
                {inc.ml_confidence != null && <div><span>ML confidence</span><b>{num(inc.ml_confidence * 100, 1)}%</b></div>}
                <div><span>Defence</span><b className="mono" style={{ fontSize: 12 }}>{(inc.defense || []).join(', ') || '—'}</b></div>
              </div>
            </Card>

            {d.breakdown && (d.breakdown.threat !== undefined) && (
              <Card title="Why this was flagged" sub="Each layer of the framework, 0–100">
                <RiskBreakdown b={d.breakdown} />
              </Card>
            )}

            {(d.redacted_text || d.redacted_response) && (
              <Card title={inc.source === 'response' ? 'Model response (redacted)' : 'Message (redacted)'}
                    sub={d.forwarded_to_model === false ? 'This message never reached the model.' :
                      d.forwarded_to_model ? 'A cleaned version was forwarded to the model.' : undefined}>
                <div className="prompt-box blocked">{d.redacted_text || d.redacted_response}</div>
                {d.sanitized_text && (
                  <>
                    <div className="section-title" style={{ fontSize: 13 }}>What the model received</div>
                    <div className="prompt-box clean">{d.sanitized_text}</div>
                  </>
                )}
                {d.multi_turn && <Banner kind="warn">This message completed an attack started in the
                  previous message; the two were analysed together.</Banner>}
              </Card>
            )}

            {d.reasons?.length > 0 && (
              <Card title="Response analyzer">
                <ul className="notes">{d.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
              </Card>
            )}

            {d.injections?.length > 0 && (
              <Card title="Instructions found in the file" sub="Treated as indirect prompt injection">
                <div className="table-wrap"><table className="table">
                  <thead><tr><th>Where</th><th>Threat</th><th className="num">Risk</th><th>Excerpt (redacted)</th></tr></thead>
                  <tbody>{d.injections.map((f, i) => (
                    <tr key={i}><td className="nowrap">{f.locator}</td>
                      <td>{THREAT_LABEL[f.threat_class] || titleCase(f.threat_class)}</td>
                      <td className="num">{Math.round(f.risk)}</td><td className="mono">{f.excerpt}</td></tr>
                  ))}</tbody>
                </table></div>
              </Card>
            )}

            {(d.sensitive?.length > 0 || d.findings?.length > 0) && (
              <Card title="Sensitive data" sub="Values are never stored — only the type, location and a masked preview">
                <div className="table-wrap"><table className="table">
                  <thead><tr><th>Type</th><th>Where</th><th>Severity</th><th>Preview</th></tr></thead>
                  <tbody>{(d.sensitive || d.findings).map((f, i) => (
                    <tr key={i}><td>{f.label}</td><td className="nowrap">{f.locator || (f.line ? `line ${f.line}` : '—')}</td>
                      <td><SeverityBadge value={f.severity} /></td><td className="mono">{f.preview}</td></tr>
                  ))}</tbody>
                </table></div>
              </Card>
            )}

            {d.links?.length > 0 && (
              <Card title="Suspicious links">
                <ul className="notes">{d.links.map((l, i) => (
                  <li key={i}><span className="mono">{l.url_preview}</span> — {l.reasons.join('; ')}</li>))}</ul>
              </Card>
            )}

            {d.signatures?.length > 0 && (
              <Card title="Signatures that fired">
                <div className="table-wrap"><table className="table">
                  <thead><tr><th>ID</th><th>Description</th><th>OWASP</th><th>Matched</th></tr></thead>
                  <tbody>{d.signatures.map((s) => (
                    <tr key={s.id}><td className="mono">{s.id}</td><td>{s.description}</td>
                      <td>{s.owasp}</td><td className="mono">{s.match}</td></tr>
                  ))}</tbody>
                </table></div>
              </Card>
            )}

            {d.narrative && (
              <Card title="Five-module trace">
                <div className="prompt-box" style={{ fontFamily: 'var(--font-ui)', fontSize: 13 }}>{d.narrative}</div>
              </Card>
            )}

            {d.recommendations?.length > 0 && (
              <Card title="Recommended actions" sub="From Module 5 — Security Intelligence">
                <ul className="notes">{d.recommendations.map((r) => (
                  <li key={r.recommendation_id || r.title}><strong>{r.title}</strong> — {r.detail}</li>))}</ul>
              </Card>
            )}

            <Card title="Triage" sub="Marking a false positive removes the pattern from immune memory and adds the text to the benign set every new rule is tested against.">
              <div className="row" style={{ gap: 8, marginBottom: 10 }}>
                {STATUSES.map(([v, l]) => (
                  <button key={v} type="button" className={`btn btn-sm ${status === v ? 'btn-primary' : ''}`}
                          onClick={() => setStatus(v)}>{l}</button>
                ))}
              </div>
              <label className="field">
                <span>Note</span>
                <textarea rows={2} value={note} onChange={(e) => setNote(e.target.value)}
                          placeholder="What you checked, what you decided" />
              </label>
              <button className="btn btn-primary" type="button" onClick={save}
                      disabled={saving || (status === inc.status && !note.trim())}>
                {saving ? <><Spinner size={13} /> Saving…</> : 'Save'}
              </button>
              {feedback && (
                <Banner kind="ok">
                  Learned from your decision: {feedback.memory_cells_removed} memory cell(s) removed,
                  {' '}{feedback.candidate_rules_withdrawn} pending rule(s) withdrawn
                  {feedback.holdout_added ? ', text added to the benign test set' : ''}.
                </Banner>
              )}
              {inc.notes?.length > 0 && (
                <div className="stack-sm" style={{ marginTop: 14 }}>
                  {inc.notes.slice().reverse().map((n, i) => (
                    <div key={i} style={{ fontSize: 12.5 }}>
                      <span className="muted">{datetime(n.ts)}</span> · <StatusBadge value={n.status} />
                      {n.note && <div className="secondary" style={{ marginTop: 3 }}>{n.note}</div>}
                    </div>
                  ))}
                </div>
              )}
            </Card>
          </div>
        )}
      </aside>
    </div>
  )
}
