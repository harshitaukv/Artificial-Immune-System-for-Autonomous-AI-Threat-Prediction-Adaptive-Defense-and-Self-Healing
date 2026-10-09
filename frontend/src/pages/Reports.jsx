import React, { useCallback, useEffect, useState } from 'react'
import {
  ArrowLeft, Download, FileSearch, RefreshCw, Trash2,
} from 'lucide-react'
import { api } from '../lib/api'
import {
  Banner, Card, Empty, GradeBadge, Spinner, ToggleGroup, VerdictPill,
} from '../components/ui'
import ScanReport from '../components/ScanReport'
import {
  REPORT_KIND_COLOR, REPORT_KIND_LABEL, SECTION_ACCENT, datetime, num, titleCase,
} from '../lib/viz'

/**
 * Every scan, probe and audit is written to the store as it runs, so the
 * evidence for a project report survives a page reload and a restart. This
 * page is the index of that store.
 *
 * Only scans re-open inline: a probe or audit report is re-read here as a
 * summary row plus its raw payload, because re-rendering a probe means
 * replaying attack prompts and replies that belong with the run that made them.
 */
export default function Reports() {
  const [kind, setKind] = useState('')
  const [rows, setRows] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [open, setOpen] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setRows(await api.savedReports(kind || undefined, 100))
      setError('')
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [kind])

  useEffect(() => { load() }, [load])

  const view = async (id) => {
    setError('')
    try {
      setOpen(await api.savedReport(id))
    } catch (e) {
      setError(e.message)
    }
  }

  const remove = async (id) => {
    try {
      await api.deleteSavedReport(id)
      if (open && (open.scan_id || open.probe_id || open.audit_id) === id) setOpen(null)
      load()
    } catch (e) {
      setError(e.message)
    }
  }

  if (open?.scan_id) {
    return (
      <div className="stack">
        <div className="row">
          <button className="btn" type="button" onClick={() => setOpen(null)}>
            <ArrowLeft size={15} /> Back to all reports
          </button>
        </div>
        <ScanReport report={open} />
      </div>
    )
  }

  return (
    <div className="stack">
      {error && <Banner kind="err">{error}</Banner>}

      <Card
        title="Saved reports"
        sub="Every scan, probe and audit is written to the store as it runs — evidence that survives a restart"
        actions={
          <div className="row" style={{ gap: 10 }}>
            <ToggleGroup
              value={kind}
              onChange={setKind}
              options={[
                { value: '', label: 'All' },
                { value: 'scan', label: 'Scans' },
                { value: 'probe', label: 'Probes' },
                { value: 'audit', label: 'Audits' },
              ]}
            />
            <button className="btn btn-sm" onClick={load} type="button">
              <RefreshCw size={14} /> Refresh
            </button>
          </div>
        }
      >
        {loading ? (
          <div className="row"><Spinner /> <span className="muted">Loading…</span></div>
        ) : !rows.length ? (
          <Empty icon={FileSearch}>
            Nothing saved yet. Scan a file, probe an endpoint or audit an application
            and the report will appear here.
          </Empty>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Kind</th><th>Subject</th><th>Result</th>
                  <th className="num">Items</th><th className="num">Findings</th>
                  <th className="num">Score</th><th>When</th><th />
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.report_id}>
                    <td>
                      <span className="badge" style={{ borderColor: REPORT_KIND_COLOR[r.kind] }}>
                        <span className="dot" style={{ background: REPORT_KIND_COLOR[r.kind] }} />
                        {REPORT_KIND_LABEL[r.kind] || titleCase(r.kind)}
                      </span>
                    </td>
                    <td>
                      <div className="truncate" style={{ maxWidth: 320, fontWeight: 600 }}>{r.title}</div>
                      <div className="muted" style={{ fontSize: 12 }}>{r.subtitle}</div>
                    </td>
                    <td>
                      {r.kind === 'scan'
                        ? <VerdictPill value={r.verdict} />
                        : <GradeBadge grade={r.verdict} size="sm" />}
                    </td>
                    <td className="num tnum">{num(r.items)}</td>
                    <td className="num tnum">{num(r.findings)}</td>
                    <td className="num tnum">{r.score == null ? '—' : r.score.toFixed(1)}</td>
                    <td className="nowrap muted" style={{ fontSize: 12.5 }}>{datetime(r.created_at)}</td>
                    <td>
                      <div className="row" style={{ gap: 6, flexWrap: 'nowrap' }}>
                        {r.kind === 'scan' && (
                          <>
                            <button className="btn btn-sm" type="button" onClick={() => view(r.report_id)}>
                              Open
                            </button>
                            <a className="btn btn-sm" href={api.exportCsvUrl(r.report_id)}
                               download={`${r.report_id}.csv`} title="Download findings as CSV">
                              <Download size={13} />
                            </a>
                          </>
                        )}
                        <button className="btn btn-sm btn-ghost" type="button"
                                onClick={() => remove(r.report_id)} title="Delete this report">
                          <Trash2 size={13} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  )
}
