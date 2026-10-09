import React from 'react'
import {
  AlertTriangle, CheckCircle2, ShieldAlert, ShieldX, ShieldCheck,
  Info, Loader2, Ban, Eraser, Gauge, Clock, UploadCloud,
} from 'lucide-react'
import {
  SEVERITY_COLOR, THREAT_COLOR, THREAT_LABEL, ACTION_COLOR, ACTION_LABEL,
  BAND_COLOR, VERDICT_COLOR, GRADE_COLOR, GRADE_TINT, OUTCOME_COLOR,
  OUTCOME_LABEL, SCAN_VERDICT_COLOR, SCAN_VERDICT_LABEL, titleCase,
} from '../lib/viz'

export function Card({ title, sub, actions, children, className = '', style }) {
  return (
    <section className={`card ${className}`} style={style}>
      {(title || actions) && (
        <header className="card-head">
          <div>
            {title && <div className="card-title">{title}</div>}
            {sub && <div className="card-sub">{sub}</div>}
          </div>
          <div className="spacer" />
          {actions}
        </header>
      )}
      {children}
    </section>
  )
}

export function StatTile({ label, value, foot, icon: Icon, tone, meter }) {
  const color = tone ? `var(--status-${tone})` : undefined
  return (
    <div className="card">
      <div className="stat-label">
        {Icon && <Icon size={13} />}
        {label}
      </div>
      <div className="stat-value" style={color ? { color } : undefined}>{value}</div>
      {meter !== undefined && (
        <div className="meter" style={{ marginTop: 10 }}>
          <div style={{ width: `${Math.max(0, Math.min(100, meter))}%`, background: color || 'var(--series-1)' }} />
        </div>
      )}
      {foot && <div className="stat-foot">{foot}</div>}
    </div>
  )
}

/* Severity always ships icon + label — status colour never carries meaning alone. */
const SEVERITY_ICON = {
  none: CheckCircle2,
  low: CheckCircle2,
  medium: AlertTriangle,
  high: ShieldAlert,
  critical: ShieldX,
}

export function SeverityBadge({ value }) {
  const key = (value || 'none').toLowerCase()
  const Icon = SEVERITY_ICON[key] || Info
  const color = SEVERITY_COLOR[key] || 'var(--text-muted)'
  return (
    <span className="badge" style={{ color, borderColor: color }}>
      <Icon size={12} />
      {titleCase(key)}
    </span>
  )
}

export function ThreatBadge({ value }) {
  const key = value || 'benign'
  const color = THREAT_COLOR[key] || 'var(--text-muted)'
  return (
    <span className="badge" style={{ borderColor: color }}>
      <span className="dot" style={{ background: color }} />
      {THREAT_LABEL[key] || titleCase(key)}
    </span>
  )
}

const ACTION_ICON = {
  allow: ShieldCheck, monitor: Info, sanitize: Eraser, mask: Eraser,
  rate_limit: Clock, block: Ban, quarantine: ShieldX,
}

export function ActionBadge({ value }) {
  const key = value || 'allow'
  const Icon = ACTION_ICON[key] || Info
  const color = ACTION_COLOR[key] || 'var(--text-muted)'
  return (
    <span className="badge" style={{ color, borderColor: color }}>
      <Icon size={12} />
      {ACTION_LABEL[key] || titleCase(key)}
    </span>
  )
}

export function VerdictBadge({ value }) {
  const color = VERDICT_COLOR[value] || 'var(--text-muted)'
  const Icon = value === 'allowed' ? ShieldCheck : value === 'sanitized' ? Eraser : Ban
  return (
    <span className="badge" style={{ color, borderColor: color }}>
      <Icon size={12} />
      {titleCase(value)}
    </span>
  )
}

export function BandBadge({ value }) {
  const color = BAND_COLOR[value] || 'var(--text-muted)'
  return (
    <span className="badge" style={{ color, borderColor: color }}>
      <Gauge size={12} />
      {titleCase(value)}
    </span>
  )
}

export function Meter({ value, max = 1, color = 'var(--series-1)', height = 6 }) {
  const w = Math.max(0, Math.min(100, (value / max) * 100))
  return (
    <div className="meter" style={{ height }}>
      <div style={{ width: `${w}%`, background: color }} />
    </div>
  )
}

export function Empty({ children = 'No data yet.', icon: Icon }) {
  return (
    <div className="empty">
      {Icon && <Icon size={22} style={{ display: 'block', margin: '0 auto 8px', opacity: 0.5 }} />}
      {children}
    </div>
  )
}

export function Banner({ kind = 'info', children }) {
  const Icon = kind === 'err' ? ShieldX : kind === 'ok' ? CheckCircle2 : kind === 'warn' ? AlertTriangle : Info
  return (
    <div className={`banner ${kind}`}>
      <Icon size={16} style={{ flex: '0 0 auto', marginTop: 1 }} />
      <div>{children}</div>
    </div>
  )
}

export function Spinner({ size = 15 }) {
  return <Loader2 size={size} className="spin" />
}

export function ToggleGroup({ value, onChange, options }) {
  return (
    <div className="toggle-group" role="group">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          className={value === o.value ? 'active' : ''}
          aria-pressed={value === o.value}
          onClick={() => onChange(o.value)}
        >
          {o.label}
        </button>
      ))}
    </div>
  )
}

export function Legend({ items }) {
  return (
    <div className="legend">
      {items.map((i) => (
        <span className="legend-item" key={i.label}>
          <span className="legend-swatch" style={{ background: i.color }} />
          {i.label}
          {i.value !== undefined && <span className="tnum muted">&nbsp;{i.value}</span>}
        </span>
      ))}
    </div>
  )
}

/* ========================================================================= */
/* Real-input analysis primitives                                            */
/* ========================================================================= */

/** Section tabs. `accent` comes from the chrome palette, never the data one. */
export function Tabs({ value, onChange, items, accent }) {
  return (
    <div className="tabs" role="tablist" style={accent ? { '--tab-accent': accent } : undefined}>
      {items.map((t) => (
        <button
          key={t.value}
          role="tab"
          aria-selected={value === t.value}
          className={`tab ${value === t.value ? 'active' : ''}`}
          onClick={() => onChange(t.value)}
          type="button"
        >
          {t.icon && <t.icon size={16} />}
          {t.label}
          {t.count !== undefined && t.count !== null && (
            <span className="chip tnum" style={{ marginLeft: 2 }}>{t.count}</span>
          )}
        </button>
      ))}
    </div>
  )
}

export function GradeBadge({ grade, size = 'lg' }) {
  const g = (grade || 'unknown').toUpperCase()
  const color = GRADE_COLOR[g] || 'var(--text-muted)'
  const tint = GRADE_TINT[g] || 'var(--surface-3)'
  const px = size === 'lg' ? 64 : 34
  if (g === 'UNKNOWN') {
    // No replies means nothing was measured. Say so in words rather than
    // showing a grade-shaped "?" that reads like a result.
    return (
      <span className="badge" title="The target never answered, so there is nothing to grade"
            style={{ color: 'var(--text-muted)', borderStyle: 'dashed' }}>
        No response
      </span>
    )
  }
  return (
    <div
      style={{
        width: px, height: px, borderRadius: size === 'lg' ? 12 : 8,
        background: tint, border: `1.5px solid ${color}`, color,
        display: 'grid', placeItems: 'center',
        fontFamily: 'var(--font-display)', fontWeight: 600,
        fontSize: size === 'lg' ? 32 : 17, lineHeight: 1, flex: `0 0 ${px}px`,
      }}
      title={`Grade ${g}`}
    >
      {g}
    </div>
  )
}

/** Scan verdict — colour plus the word, never colour alone. */
export function VerdictPill({ value }) {
  const key = value || 'clean'
  const color = SCAN_VERDICT_COLOR[key] || 'var(--text-muted)'
  const Icon = key === 'clean' ? ShieldCheck : key === 'critical' ? ShieldX : AlertTriangle
  return (
    <span className="badge badge-lg" style={{ color, borderColor: color, background: 'var(--surface-1)' }}>
      <Icon size={14} />
      {SCAN_VERDICT_LABEL[key] || titleCase(key)}
    </span>
  )
}

export function OutcomePill({ value }) {
  const color = OUTCOME_COLOR[value] || 'var(--text-muted)'
  return (
    <span className="badge" style={{ color, borderColor: color }}>
      <span className="dot" style={{ background: color }} />
      {OUTCOME_LABEL[value] || titleCase(value)}
    </span>
  )
}

/**
 * Drag-and-drop file target. Clicking opens the native picker, so the
 * control works for keyboard and touch users too — a drop zone alone
 * would be unreachable without a pointer.
 */
export function DropZone({ onFile, accept, busy, children, hint }) {
  const [dragging, setDragging] = React.useState(false)
  const input = React.useRef(null)

  const take = (files) => {
    const f = files?.[0]
    if (f) onFile(f)
  }

  return (
    <div
      className={`dropzone ${dragging ? 'dragging' : ''}`}
      onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => { e.preventDefault(); setDragging(false); take(e.dataTransfer.files) }}
      onClick={() => input.current?.click()}
      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.current?.click() } }}
      role="button"
      tabIndex={0}
      aria-label="Choose a file to scan"
    >
      <input
        ref={input}
        type="file"
        accept={accept}
        style={{ display: 'none' }}
        onChange={(e) => { take(e.target.files); e.target.value = '' }}
      />
      <div className="dropzone-icon">
        {busy ? <Loader2 size={26} className="spin" /> : <UploadCloud size={26} />}
      </div>
      <div className="dropzone-title">{children || 'Drop a file here'}</div>
      {hint && <div className="dropzone-sub">{hint}</div>}
    </div>
  )
}

/** One flagged item from a scan, with its provenance and evidence. */
export function FindingCard({ finding, expanded, onToggle }) {
  const color = SEVERITY_COLOR[finding.severity] || 'var(--border-strong)'
  return (
    <div
      className={`finding ${finding.likely_defensive ? 'defensive' : ''}`}
      style={{ '--f-accent': finding.likely_defensive ? 'var(--series-neutral)' : color }}
    >
      <div className="row" style={{ gap: 10, marginBottom: 10 }}>
        <span className="chip chip-brand">{finding.locator}</span>
        <ThreatBadge value={finding.threat_class} />
        <SeverityBadge value={finding.severity} />
        <ActionBadge value={finding.action} />
        {finding.likely_defensive && (
          <span className="badge" title="Reads as a protective rule, not an attack. Excluded from the risk score.">
            <ShieldCheck size={12} /> Defensive phrasing
          </span>
        )}
        <div className="spacer" />
        <span className="tnum muted" style={{ fontSize: 12.5 }}>
          {(finding.confidence * 100).toFixed(1)}% confidence
        </span>
        {onToggle && (
          <button className="btn btn-sm btn-ghost" onClick={onToggle} type="button">
            {expanded ? 'Less' : 'Details'}
          </button>
        )}
      </div>

      <div className="prompt-box" style={{ marginBottom: expanded ? 14 : 0 }}>
        {expanded ? (finding.full_text || finding.excerpt) : finding.excerpt}
      </div>

      {expanded && (
        <div className="stack-sm">
          {finding.explanation && (
            <div><span className="muted">Why: </span><span className="secondary">{finding.explanation}</span></div>
          )}
          {finding.rationale && (
            <div><span className="muted">Defence: </span><span className="secondary">{finding.rationale}</span></div>
          )}
          {!!finding.signature_hits?.length && (
            <div className="row" style={{ gap: 6 }}>
              <span className="muted">Signatures:</span>
              {finding.signature_hits.map((s) => <span className="chip" key={s}>{s}</span>)}
            </div>
          )}
          {!!finding.top_indicators?.length && (
            <div className="row" style={{ gap: 6 }}>
              <span className="muted">Top features:</span>
              {finding.top_indicators.slice(0, 6).map((t, i) => (
                <span className="chip" key={i}>{typeof t === 'string' ? t : t.name ?? JSON.stringify(t)}</span>
              ))}
            </div>
          )}
          {!!finding.recommendations?.length && (
            <div className="stack-sm">
              <span className="muted">Recommended:</span>
              {finding.recommendations.map((r) => (
                <div key={r.recommendation_id || r.title} style={{ fontSize: 13.5 }}>
                  <strong>{r.title}</strong> — <span className="secondary">{r.detail}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

/** Boolean posture switch used by the Audit and Scan app-context forms. */
export function Switch({ label, checked, onChange, hint }) {
  return (
    <label className="switch">
      <input type="checkbox" checked={!!checked} onChange={(e) => onChange(e.target.checked)} />
      <span>
        {label}
        {hint && <span className="field-hint" style={{ marginTop: 1 }}>{hint}</span>}
      </span>
    </label>
  )
}
