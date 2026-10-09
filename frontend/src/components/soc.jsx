/* Building blocks for the Security Center.
 *
 * Chart rules (see the dataviz method): one axis per chart, thin marks with a
 * 2px surface gap, a legend whenever there are two or more series, a hover
 * layer on every plot, recessive solid hairline grids, and text in ink colours
 * — never in a series colour.
 */
import React, { useState } from 'react'
import {
  Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import {
  ACTION_LABEL, ACTION_ORDER, ACTION_RAMP, SEVERITY_COLOR, THREAT_COLOR, THREAT_LABEL,
  num, titleCase,
} from '../lib/viz'
import { Empty } from './ui'

const AXIS = { fill: 'var(--text-muted)', fontSize: 11 }

function Tip({ active, payload, label, labels, unit = '' }) {
  if (!active || !payload?.length) return null
  return (
    <div className="tooltip-card">
      <div className="t-label">{label}</div>
      {payload.filter((p) => p.value !== null && p.value !== undefined).map((p) => (
        <div className="t-row" key={p.dataKey}>
          <span className="legend-swatch" style={{ background: p.color || p.fill }} />
          <span>{labels?.[p.dataKey] || titleCase(p.dataKey)}</span>
          <span className="t-val">{num(p.value, p.value % 1 ? 1 : 0)}{unit}</span>
        </div>
      ))}
    </div>
  )
}

/* ------------------------------------------------------------ sparkline */
export function Sparkline({ values, color = 'var(--series-1)', height = 28, width = 110 }) {
  const v = (values || []).map((x) => x ?? 0)
  if (v.length < 2 || v.every((x) => x === 0)) {
    return <svg width={width} height={height} aria-hidden="true">
      <line x1="0" x2={width} y1={height - 2} y2={height - 2} stroke="var(--grid)" strokeWidth="2" />
    </svg>
  }
  const max = Math.max(...v, 1)
  const pts = v.map((x, i) => [i * (width / (v.length - 1)), height - 3 - (x / max) * (height - 6)])
  const d = pts.map((p, i) => `${i ? 'L' : 'M'}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(' ')
  const last = pts[pts.length - 1]
  return (
    <svg width={width} height={height} aria-hidden="true">
      <path d={d} fill="none" stroke={color} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={last[0]} cy={last[1]} r="3" fill={color} stroke="var(--surface-1)" strokeWidth="2" />
    </svg>
  )
}

/* ------------------------------------------------------------ KPI tile */
export function Kpi({ label, value, sub, definition, spark, sparkColor, tone, onClick }) {
  const color = tone ? `var(--status-${tone})` : undefined
  return (
    <div className={`card kpi ${onClick ? 'clickable' : ''}`} onClick={onClick}
         role={onClick ? 'button' : undefined} tabIndex={onClick ? 0 : undefined}>
      <div className="stat-label">{label}</div>
      <div className="row" style={{ justifyContent: 'space-between', alignItems: 'flex-end', gap: 8 }}>
        <div className="stat-value" style={color ? { color } : undefined}>{value}</div>
        {spark && <Sparkline values={spark} color={sparkColor} />}
      </div>
      {sub && <div className="stat-foot">{sub}</div>}
      {definition && <div className="kpi-def">{definition}</div>}
    </div>
  )
}

/* ------------------------------------------------ traffic & defence trend */
const OUTCOME_SERIES = [
  ['allowed', 'Answered normally', 'var(--series-neutral)'],
  ['flagged', 'Monitored or sanitised', 'var(--status-warning)'],
  ['blocked', 'Blocked or refused', 'var(--status-critical)'],
]

export function DefenceTrend({ trend, height = 230 }) {
  const any = (trend || []).some((b) => b.allowed + b.flagged + b.blocked > 0)
  if (!any) return <Empty>No traffic in this period yet. Open AstraBot and send a message.</Empty>
  const labels = Object.fromEntries(OUTCOME_SERIES.map(([k, l]) => [k, l]))
  return (
    <>
      <div style={{ height }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={trend} margin={{ top: 6, right: 6, left: -16, bottom: 0 }} barCategoryGap={2}>
            <CartesianGrid stroke="var(--grid)" vertical={false} />
            <XAxis dataKey="label" tick={AXIS} tickLine={false} axisLine={{ stroke: 'var(--axis)' }}
                   interval="preserveStartEnd" minTickGap={24} />
            <YAxis allowDecimals={false} tick={AXIS} tickLine={false} axisLine={false} />
            <Tooltip content={<Tip labels={labels} />} cursor={{ fill: 'var(--hover)' }} />
            {OUTCOME_SERIES.map(([k, , c], i) => (
              <Bar key={k} dataKey={k} stackId="o" fill={c} isAnimationActive={false}
                   stroke="var(--surface-1)" strokeWidth={1}
                   radius={i === OUTCOME_SERIES.length - 1 ? [3, 3, 0, 0] : 0} maxBarSize={22} />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
      <div className="legend" style={{ marginTop: 8 }}>
        {OUTCOME_SERIES.map(([k, l, c]) => (
          <span className="legend-item" key={k}><span className="legend-swatch" style={{ background: c }} />{l}</span>
        ))}
      </div>
    </>
  )
}

export function RiskLine({ trend, height = 120 }) {
  const data = (trend || []).map((b) => ({ label: b.label, mean_risk: b.mean_risk }))
  if (!data.some((d) => d.mean_risk !== null && d.mean_risk !== undefined)) {
    return <Empty>No answered messages to average yet.</Empty>
  }
  return (
    <div style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ top: 6, right: 6, left: -16, bottom: 0 }}>
          <CartesianGrid stroke="var(--grid)" vertical={false} />
          <XAxis dataKey="label" tick={AXIS} tickLine={false} axisLine={{ stroke: 'var(--axis)' }}
                 interval="preserveStartEnd" minTickGap={24} />
          <YAxis domain={[0, 100]} ticks={[0, 20, 40, 60, 80, 100]} tick={AXIS} tickLine={false} axisLine={false} />
          <Tooltip content={<Tip labels={{ mean_risk: 'Average risk' }} unit="/100" />}
                   cursor={{ stroke: 'var(--axis)', strokeWidth: 1 }} />
          <Line dataKey="mean_risk" stroke="var(--series-1)" strokeWidth={2} dot={false}
                activeDot={{ r: 4, strokeWidth: 2, stroke: 'var(--surface-1)' }}
                connectNulls isAnimationActive={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}

/* ------------------------------------------------ horizontal bar list (HTML) */
export function BarList({ rows, max, format = (v) => num(v), empty = 'Nothing yet.', onSelect }) {
  const data = (rows || []).filter((r) => r.value > 0)
  if (!data.length) return <Empty>{empty}</Empty>
  const top = max || Math.max(...data.map((r) => r.value))
  return (
    <div className="barlist">
      {data.map((r) => (
        <div key={r.key} className={`barlist-row ${onSelect ? 'clickable' : ''}`}
             onClick={onSelect ? () => onSelect(r.key) : undefined} title={`${r.label}: ${format(r.value)}`}>
          <div className="barlist-label">
            {r.swatch !== false && <span className="legend-swatch" style={{ background: r.color }} />}
            <span className="truncate">{r.label}</span>
          </div>
          <div className="barlist-track">
            <div className="barlist-fill" style={{ width: `${Math.max(2, (r.value / top) * 100)}%`, background: r.color }} />
          </div>
          <div className="barlist-value tnum">{format(r.value)}</div>
        </div>
      ))}
    </div>
  )
}

export function ThreatBarList({ distribution, onSelect }) {
  const rows = Object.entries(distribution || {})
    .filter(([k]) => k !== 'benign')
    .map(([k, v]) => ({ key: k, label: THREAT_LABEL[k] || titleCase(k), value: v,
                        color: THREAT_COLOR[k] || 'var(--series-neutral)' }))
    .sort((a, b) => b.value - a.value)
  return <BarList rows={rows} onSelect={onSelect} empty="No threats detected in this period." />
}

export function ActionLadder({ distribution }) {
  const rows = ACTION_ORDER.map((k) => ({
    key: k, label: ACTION_LABEL[k], value: (distribution || {})[k] || 0, color: ACTION_RAMP[k],
  }))
  if (!rows.some((r) => r.value)) return <Empty>No decisions in this period.</Empty>
  const top = Math.max(...rows.map((r) => r.value))
  return (
    <div className="barlist">
      {rows.map((r) => (
        <div key={r.key} className="barlist-row" title={`${r.label}: ${num(r.value)}`}>
          <div className="barlist-label"><span className="legend-swatch" style={{ background: r.color }} />{r.label}</div>
          <div className="barlist-track">
            {r.value > 0 && <div className="barlist-fill" style={{ width: `${Math.max(2, (r.value / top) * 100)}%`, background: r.color }} />}
          </div>
          <div className="barlist-value tnum">{num(r.value)}</div>
        </div>
      ))}
    </div>
  )
}

/* ------------------------------------------------------------ risk histogram */
export function RiskHistogram({ hist, height = 150, bands }) {
  const data = (hist || []).map((v, i) => ({ label: `${i * 10}–${i * 10 + 9}`, messages: v }))
  if (!data.some((d) => d.messages)) return <Empty>No scored messages yet.</Empty>
  return (
    <div style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 6, right: 6, left: -18, bottom: 0 }} barCategoryGap={2}>
          <CartesianGrid stroke="var(--grid)" vertical={false} />
          <XAxis dataKey="label" tick={AXIS} tickLine={false} axisLine={{ stroke: 'var(--axis)' }} interval={1} />
          <YAxis allowDecimals={false} tick={AXIS} tickLine={false} axisLine={false} scale="sqrt" />
          <Tooltip content={<Tip labels={{ messages: 'Messages' }} />} cursor={{ fill: 'var(--hover)' }} />
          <Bar dataKey="messages" fill="var(--series-1)" radius={[3, 3, 0, 0]} isAnimationActive={false} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}

/* ------------------------------------------------------------ risk breakdown */
const LAYERS = [
  ['threat', 'ML threat model', 'Module 3 — probability the text is an attack (TF-IDF + RF/LogReg)'],
  ['signature', 'Known attack patterns', 'Module 3 innate layer — curated signatures that fired'],
  ['similarity', 'Immune memory match', 'Module 5 — similarity to an attack seen before'],
  ['behavior', 'Behaviour anomaly', 'Module 1 — how unusual this client is (Isolation Forest)'],
  ['application', 'Application risk', 'Module 2 — configuration risk of the protected app'],
]

export function RiskBreakdown({ b }) {
  if (!b) return null
  return (
    <div className="stack-sm">
      {LAYERS.map(([k, label, hint]) => b[k] !== undefined && b[k] !== null && (
        <div key={k} className="rb-row" title={hint}>
          <div className="rb-label">{label}<div className="field-hint" style={{ marginTop: 0 }}>{hint}</div></div>
          <div className="barlist-track"><div className="barlist-fill"
            style={{ width: `${Math.max(1, b[k])}%`, background: 'var(--series-1)' }} /></div>
          <div className="barlist-value tnum">{Math.round(b[k])}</div>
        </div>
      ))}
      <div className="rb-row rb-total">
        <div className="rb-label"><strong>Overall risk</strong>
          <div className="field-hint" style={{ marginTop: 0 }}>Primary evidence, raised by corroborating layers</div></div>
        <div className="barlist-track"><div className="barlist-fill"
          style={{ width: `${Math.max(1, b.overall)}%`, background: SEVERITY_COLOR[b.severity] || 'var(--series-1)' }} /></div>
        <div className="barlist-value tnum"><strong>{Math.round(b.overall)}</strong></div>
      </div>
      {b.notes?.length > 0 && (
        <ul className="notes">{b.notes.map((n) => <li key={n}>{n}</li>)}</ul>
      )}
    </div>
  )
}

/* ------------------------------------------------------------ risk pill */
export function RiskScore({ value, severity }) {
  if (value === null || value === undefined) return <span className="muted">—</span>
  const color = SEVERITY_COLOR[severity] || 'var(--series-1)'
  return (
    <span className="risk-score" title={`${Math.round(value)}/100`}>
      <span className="risk-track"><span style={{ width: `${Math.max(3, value)}%`, background: color }} /></span>
      <span className="tnum">{Math.round(value)}</span>
    </span>
  )
}

export function StatusBadge({ value }) {
  const map = {
    open: ['var(--status-critical)', 'Open'],
    investigating: ['var(--status-warning)', 'Investigating'],
    resolved: ['var(--status-good)', 'Resolved'],
    false_positive: ['var(--text-muted)', 'False positive'],
  }
  const [c, l] = map[value] || ['var(--text-muted)', titleCase(value)]
  return <span className="badge" style={{ color: c, borderColor: c }}><span className="dot" style={{ background: c }} />{l}</span>
}

export function useToggle(initial = false) {
  const [v, setV] = useState(initial)
  return [v, () => setV((x) => !x), setV]
}
