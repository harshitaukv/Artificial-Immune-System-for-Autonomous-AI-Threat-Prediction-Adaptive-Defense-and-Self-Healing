import React, { useMemo, useState } from 'react'
import {
  Download, Filter, ListChecks, ShieldCheck, Signature, Target, Timer,
} from 'lucide-react'
import {
  Card, Empty, FindingCard, StatTile, ToggleGroup, VerdictPill,
} from './ui'
import { ClassBars, FindingMap, ScoreRing, SeverityBars } from './charts'
import {
  SCAN_VERDICT_COLOR, SCAN_VERDICT_LABEL, THREAT_LABEL, VERDICT_TONE,
  bytes, num, pct, titleCase,
} from '../lib/viz'
import { api } from '../lib/api'

/**
 * The report a scan produces, rendered the same way whether it has just run
 * or has been reopened from the saved-report store.
 *
 * The central editorial decision here: *hostile* items drive the headline,
 * *defensive* items are shown but never counted. Scanning real material — a
 * repo's own prompt templates, a policy PDF, a support transcript quoting the
 * rules — surfaces protective phrasing constantly, and letting it inflate the
 * risk score would make the number meaningless on exactly the material this
 * tool exists to read.
 */
export default function ScanReport({ report }) {
  const [filter, setFilter] = useState('hostile')
  const [threat, setThreat] = useState('')
  const [open, setOpen] = useState(() => new Set())

  const findings = report?.findings || []

  const flaggedSeverity = useMemo(() => {
    const out = {}
    for (const f of findings) out[f.severity] = (out[f.severity] || 0) + 1
    return out
  }, [findings])

  const visible = useMemo(() => {
    let rows = findings
    if (filter === 'hostile') rows = rows.filter((f) => !f.likely_defensive)
    if (filter === 'defensive') rows = rows.filter((f) => f.likely_defensive)
    if (threat) rows = rows.filter((f) => f.threat_class === threat)
    return rows
  }, [findings, filter, threat])

  if (!report) return null

  const verdictColor = SCAN_VERDICT_COLOR[report.verdict] || 'var(--text-muted)'
  const classes = Object.keys(report.class_distribution || {}).filter((c) => c !== 'benign')

  const toggle = (i) => setOpen((prev) => {
    const next = new Set(prev)
    next.has(i) ? next.delete(i) : next.add(i)
    return next
  })

  return (
    <div className="stack">
      {/* ---------------------------------------------------- headline */}
      <Card
        title={report.source_name}
        sub={`${titleCase(report.source_kind)} · ${report.scan_id} · scanned in ${report.duration_seconds}s`}
        actions={
          <div className="row" style={{ gap: 10 }}>
            <VerdictPill value={report.verdict} />
            <a
              className="btn btn-sm"
              href={api.exportCsvUrl(report.scan_id)}
              download={`${report.scan_id}.csv`}
            >
              <Download size={14} /> CSV
            </a>
          </div>
        }
      >
        <div className="grid grid-1-2" style={{ alignItems: 'center' }}>
          <ScoreRing
            value={report.risk_score}
            label={String(report.risk_score)}
            color={verdictColor}
            caption={SCAN_VERDICT_LABEL[report.verdict]}
            suffix=""
          />
          <div className="stack-sm">
            <div className="section-title">What this means</div>
            <p className="secondary" style={{ fontSize: 14.5, lineHeight: 1.65, margin: 0 }}>
              {report.hostile_items === 0 ? (
                <>
                  Nothing in this material reads as an attack on an AI application.
                  {report.defensive_items > 0 && (
                    <> {num(report.defensive_items)} item{report.defensive_items === 1 ? '' : 's'} matched
                    threat vocabulary but state a protection rather than request one, so they are
                    listed below and excluded from the score.</>
                  )}
                </>
              ) : (
                <>
                  <strong>{num(report.hostile_items)}</strong> of {num(report.items_scanned)} items
                  carry hostile intent — {pct(report.detection_rate, 1)} of the material. The risk
                  score is weighted by severity rather than count, so a single critical finding in a
                  large export still reads as critical.
                  {report.defensive_items > 0 && (
                    <> A further {num(report.defensive_items)} item{report.defensive_items === 1 ? '' : 's'} use
                    protective phrasing and are excluded from the score.</>
                  )}
                </>
              )}
            </p>
            <dl className="kv" style={{ marginTop: 6 }}>
              <dt>Items scanned</dt><dd>{num(report.items_scanned)}</dd>
              <dt>Clean</dt><dd>{num(report.clean_items)}</dd>
              <dt>Hostile</dt><dd>{num(report.hostile_items)}</dd>
              <dt>Defensive phrasing</dt><dd>{num(report.defensive_items)}</dd>
              <dt>Mean inspection latency</dt><dd>{report.mean_latency_ms} ms</dd>
              {report.file_size_bytes ? (<><dt>File size</dt><dd>{bytes(report.file_size_bytes)}</dd></>) : null}
              <dt>Committed to immune memory</dt><dd>{report.persisted ? 'Yes' : 'No — analysis only'}</dd>
            </dl>
          </div>
        </div>
      </Card>

      {/* ------------------------------------------------------- tiles */}
      <div className="grid grid-4">
        <StatTile label="Risk score" value={report.risk_score} icon={Target}
                  tone={VERDICT_TONE[report.verdict]} meter={report.risk_score}
                  foot="Severity-weighted, 0–100" />
        <StatTile label="Hostile items" value={num(report.hostile_items)} icon={ShieldCheck}
                  tone={report.hostile_items ? 'critical' : 'good'}
                  foot={`${pct(report.detection_rate, 1)} of the material`} />
        <StatTile label="Items scanned" value={num(report.items_scanned)} icon={ListChecks}
                  foot={`${titleCase(report.source_kind)} source`} />
        <StatTile label="Scan time" value={`${report.duration_seconds}s`} icon={Timer}
                  foot={`${report.mean_latency_ms} ms per item`} />
      </div>

      {/* ------------------------------------------------------ charts */}
      <div className="grid grid-2">
        <Card title="Threat classes found" sub="Benign items are excluded so the distribution is readable">
          <ClassBars distribution={report.class_distribution} />
        </Card>
        <Card title="Severity of the flagged items" sub="Flagged items only — benign items all carry severity 'none' and would swamp the scale">
          <SeverityBars distribution={flaggedSeverity} height={240} />
        </Card>
      </div>

      <div className="grid grid-2-1">
        <Card title="Where the findings sit" sub="Clustered hits read very differently from evenly scattered ones">
          <FindingMap findings={findings} total={report.items_scanned} />
        </Card>
        <Card title="Signatures that fired" sub="Innate detection layer" >
          {report.top_signatures?.length ? (
            <div className="stack-sm">
              {report.top_signatures.map((s) => (
                <div className="row" key={s.id} style={{ gap: 10 }}>
                  <Signature size={14} className="muted" />
                  <span className="chip">{s.id}</span>
                  <div className="spacer" />
                  <span className="tnum secondary">{num(s.count)}</span>
                </div>
              ))}
            </div>
          ) : (
            <Empty>No innate signature matched — any findings came from the learned model.</Empty>
          )}
        </Card>
      </div>

      {/* ----------------------------------------------- recommendations */}
      {!!report.recommendations?.length && (
        <Card title="Recommended actions"
              sub="De-duplicated across every finding, ordered by priority">
          <div className="stack-sm">
            {report.recommendations.map((r) => (
              <div className="finding" key={r.title}
                   style={{ '--f-accent': `var(--status-${r.priority === 'critical' ? 'critical'
                     : r.priority === 'high' ? 'serious' : r.priority === 'medium' ? 'warning' : 'good'})` }}>
                <div className="row" style={{ gap: 10, marginBottom: 6 }}>
                  <strong style={{ fontFamily: 'var(--font-display)', fontSize: 16 }}>{r.title}</strong>
                  <span className="chip">{titleCase(r.priority)}</span>
                  <span className="chip">{titleCase(r.category)}</span>
                  <div className="spacer" />
                  <span className="muted tnum" style={{ fontSize: 12.5 }}>
                    {r.occurrences}× across findings
                  </span>
                </div>
                <div className="secondary" style={{ fontSize: 14, lineHeight: 1.6 }}>{r.detail}</div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* --------------------------------------------------- findings */}
      <Card
        title={`Findings (${num(visible.length)})`}
        sub="Every finding points back at a line, row, page or cell in the original"
        actions={
          <div className="row" style={{ gap: 10 }}>
            <ToggleGroup
              value={filter}
              onChange={setFilter}
              options={[
                { value: 'hostile', label: `Hostile ${report.hostile_items}` },
                { value: 'defensive', label: `Defensive ${report.defensive_items}` },
                { value: 'all', label: `All ${report.flagged_items}` },
              ]}
            />
            {classes.length > 1 && (
              <select value={threat} onChange={(e) => setThreat(e.target.value)}
                      style={{ width: 'auto', minWidth: 190 }} aria-label="Filter by threat class">
                <option value="">All threat classes</option>
                {classes.map((c) => (
                  <option key={c} value={c}>{THREAT_LABEL[c] || titleCase(c)}</option>
                ))}
              </select>
            )}
          </div>
        }
      >
        {visible.length === 0 ? (
          <Empty icon={Filter}>
            {report.flagged_items === 0
              ? 'Nothing was flagged in this material.'
              : 'No findings match the current filter.'}
          </Empty>
        ) : (
          <div className="stack-sm">
            {visible.map((f) => (
              <FindingCard
                key={`${f.index}-${f.locator}`}
                finding={f}
                expanded={open.has(f.index)}
                onToggle={() => toggle(f.index)}
              />
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}
