import React, { useState } from 'react'
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Legend as RLegend,
  Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis, LabelList,
} from 'recharts'
import { Table2, ChartPie } from 'lucide-react'
import {
  THREAT_COLOR, THREAT_LABEL, THREAT_ORDER, SEVERITY_COLOR, SEVERITY_ORDER,
  ACTION_COLOR, ACTION_LABEL, BAND_COLOR, PROBE_CATEGORY_LABEL,
  SURFACE_COLOR, SURFACE_LABEL, num, pct, titleCase,
} from '../lib/viz'
import { Card, Empty, Legend, ToggleGroup } from './ui'

const AXIS = { fill: 'var(--text-muted)', fontSize: 11 }

/* Shared tooltip: every chart gets a hover layer by default. */
function VizTooltip({ active, payload, label, unit = '', labelMap }) {
  if (!active || !payload?.length) return null
  return (
    <div className="tooltip-card">
      {label !== undefined && <div className="t-label">{label}</div>}
      {payload.map((p) => (
        <div className="t-row" key={p.dataKey ?? p.name}>
          <span className="legend-swatch" style={{ background: p.color || p.payload?.fill }} />
          <span>{labelMap?.[p.dataKey ?? p.name] || titleCase(p.name)}</span>
          <span className="t-val">{num(p.value)}{unit}</span>
        </div>
      ))}
    </div>
  )
}

/* ------------------------------------------------------------------------ */
/* Traffic composition — donut + table view.
 * Three light-mode slots sit below 3:1 on the light surface, so the relief
 * rule applies: this chart always ships direct labels and a table toggle.   */
export function ThreatDonut({ distribution, title = 'Traffic composition' }) {
  const [view, setView] = useState('chart')
  const entries = THREAT_ORDER
    .map((k) => ({ key: k, name: THREAT_LABEL[k], value: distribution?.[k] || 0, fill: THREAT_COLOR[k] }))
    .filter((e) => e.value > 0)
  const total = entries.reduce((s, e) => s + e.value, 0)

  return (
    <Card
      title={title}
      sub={total ? `${num(total)} requests inspected` : undefined}
      actions={
        <ToggleGroup
          value={view}
          onChange={setView}
          options={[{ value: 'chart', label: 'Chart' }, { value: 'table', label: 'Table' }]}
        />
      }
    >
      {!total ? (
        <Empty icon={ChartPie}>No traffic inspected yet — run a simulation or send a prompt.</Empty>
      ) : view === 'table' ? (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr><th>Class</th><th className="num">Requests</th><th className="num">Share</th></tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr key={e.key}>
                  <td>
                    <span className="legend-item">
                      <span className="legend-swatch" style={{ background: e.fill }} />
                      {e.name}
                    </span>
                  </td>
                  <td className="num tnum">{num(e.value)}</td>
                  <td className="num tnum">{pct(e.value / total, 1)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <>
          <div style={{ height: 224 }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={entries}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={58}
                  outerRadius={88}
                  paddingAngle={2}
                  stroke="var(--surface-1)"
                  strokeWidth={2}
                  isAnimationActive={false}
                >
                  {entries.map((e) => <Cell key={e.key} fill={e.fill} />)}
                </Pie>
                <Tooltip content={<VizTooltip />} />
              </PieChart>
            </ResponsiveContainer>
          </div>
          {/* Direct labels satisfy the relief rule for the sub-3:1 light slots. */}
          <div className="legend" style={{ marginTop: 6 }}>
            {entries.map((e) => (
              <span className="legend-item" key={e.key}>
                <span className="legend-swatch" style={{ background: e.fill }} />
                {e.name}
                <span className="tnum muted">&nbsp;{num(e.value)} · {pct(e.value / total)}</span>
              </span>
            ))}
          </div>
        </>
      )}
    </Card>
  )
}

/* ------------------------------------------------------------------------ */
/* Verdict timeline — stacked area with a 2px surface gap between segments.  */
export function TimelineChart({ data, height = 230 }) {
  if (!data?.length) return <Empty>No timeline data yet.</Empty>
  return (
    <>
      <div style={{ height }}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 6, right: 8, left: 0, bottom: 0 }}>
            <CartesianGrid stroke="var(--grid)" strokeDasharray="0" vertical={false} />
            <XAxis dataKey="bucket" tick={AXIS} tickLine={false} axisLine={{ stroke: 'var(--axis)' }} minTickGap={28} />
            <YAxis tick={AXIS} tickLine={false} axisLine={false} allowDecimals={false} width={48} />
            <Tooltip
              content={<VizTooltip labelMap={{ allowed: 'Allowed', sanitized: 'Sanitised', blocked: 'Blocked' }} />}
              cursor={{ stroke: 'var(--text-muted)', strokeWidth: 1 }}
            />
            <Area type="monotone" dataKey="allowed" stackId="1" stroke="var(--status-good)"
                  fill="var(--status-good)" fillOpacity={0.28} strokeWidth={2} isAnimationActive={false} />
            <Area type="monotone" dataKey="sanitized" stackId="1" stroke="var(--status-warning)"
                  fill="var(--status-warning)" fillOpacity={0.28} strokeWidth={2} isAnimationActive={false} />
            <Area type="monotone" dataKey="blocked" stackId="1" stroke="var(--status-critical)"
                  fill="var(--status-critical)" fillOpacity={0.30} strokeWidth={2} isAnimationActive={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <Legend
        items={[
          { label: 'Allowed', color: 'var(--status-good)' },
          { label: 'Sanitised', color: 'var(--status-warning)' },
          { label: 'Blocked', color: 'var(--status-critical)' },
        ]}
      />
    </>
  )
}

/* ------------------------------------------------------------------------ */
export function SeverityBars({ distribution, height = 190 }) {
  const data = SEVERITY_ORDER
    .map((k) => ({ key: k, name: titleCase(k), value: distribution?.[k] || 0, fill: SEVERITY_COLOR[k] }))
    .filter((d) => d.value > 0)
  if (!data.length) return <Empty>No severity data yet.</Empty>
  return (
    <div style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ top: 2, right: 40, left: 6, bottom: 2 }}>
          <CartesianGrid stroke="var(--grid)" horizontal={false} />
          <XAxis type="number" tick={AXIS} tickLine={false} axisLine={false} allowDecimals={false} />
          <YAxis type="category" dataKey="name" tick={AXIS} tickLine={false}
                 axisLine={{ stroke: 'var(--axis)' }} width={62} />
          <Tooltip content={<VizTooltip />} cursor={{ fill: 'var(--hover)' }} />
          <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={16} isAnimationActive={false}>
            {data.map((d) => <Cell key={d.key} fill={d.fill} />)}
            <LabelList dataKey="value" position="right" fill="var(--text-secondary)" fontSize={11} />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}

/* ------------------------------------------------------------------------ */
export function ActionBars({ distribution, height = 200 }) {
  const data = Object.entries(distribution || {})
    .map(([k, v]) => ({ key: k, name: ACTION_LABEL[k] || titleCase(k), value: v, fill: ACTION_COLOR[k] || 'var(--series-1)' }))
    .sort((a, b) => b.value - a.value)
  if (!data.length) return <Empty>No defence actions recorded yet.</Empty>
  return (
    <div style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 14, right: 6, left: 0, bottom: 2 }}>
          <CartesianGrid stroke="var(--grid)" vertical={false} />
          <XAxis dataKey="name" tick={AXIS} tickLine={false} axisLine={{ stroke: 'var(--axis)' }}
                 interval={0} angle={-18} textAnchor="end" height={54} />
          <YAxis tick={AXIS} tickLine={false} axisLine={false} allowDecimals={false} width={48} />
          <Tooltip content={<VizTooltip />} cursor={{ fill: 'var(--hover)' }} />
          <Bar dataKey="value" radius={[4, 4, 0, 0]} barSize={30} isAnimationActive={false}>
            {data.map((d) => <Cell key={d.key} fill={d.fill} />)}
            <LabelList dataKey="value" position="top" fill="var(--text-secondary)" fontSize={11} />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}

/* ------------------------------------------------------------------------ */
/* AI Health Score — a single headline number, so it is a gauge, not a chart. */
export function HealthGauge({ score = 100, band = 'optimal', size = 168 }) {
  const clamped = Math.max(0, Math.min(100, score))
  const color = BAND_COLOR[band] || 'var(--status-good)'
  const r = size / 2 - 13
  const c = 2 * Math.PI * r
  // 270° sweep, starting bottom-left.
  const sweep = 0.75
  const dash = c * sweep
  const filled = dash * (clamped / 100)

  return (
    <div style={{ position: 'relative', width: size, height: size, margin: '0 auto' }}>
      <svg width={size} height={size} style={{ transform: 'rotate(135deg)' }} role="img"
           aria-label={`AI Health Score ${clamped.toFixed(0)} out of 100, ${band}`}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--grid)"
                strokeWidth={11} strokeDasharray={`${dash} ${c}`} strokeLinecap="round" />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color}
                strokeWidth={11} strokeDasharray={`${filled} ${c}`} strokeLinecap="round" />
      </svg>
      <div style={{
        position: 'absolute', inset: 0, display: 'grid', placeContent: 'center',
        textAlign: 'center', gap: 2,
      }}>
        <div style={{ fontSize: 40, fontWeight: 670, letterSpacing: '-.03em', lineHeight: 1, color }}>
          {clamped.toFixed(0)}
        </div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '.07em', fontWeight: 600 }}>
          {band}
        </div>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------------ */
export function HealthHistory({ history, height = 150 }) {
  const data = (history || []).map((h, i) => ({
    i, score: h.score, rolling: h.rolling,
    t: new Date(h.t * 1000).toLocaleTimeString(undefined, { hour12: false }),
  }))
  if (data.length < 2) return <Empty>Not enough history yet.</Empty>
  return (
    <>
      <div style={{ height }}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 6, right: 8, left: 0, bottom: 0 }}>
            <CartesianGrid stroke="var(--grid)" vertical={false} />
            <XAxis dataKey="t" tick={AXIS} tickLine={false} axisLine={{ stroke: 'var(--axis)' }} minTickGap={40} />
            <YAxis domain={[0, 100]} tick={AXIS} tickLine={false} axisLine={false} width={42} />
            <Tooltip content={<VizTooltip labelMap={{ score: 'Instant score', rolling: 'Rolling score' }} />}
                     cursor={{ stroke: 'var(--text-muted)', strokeWidth: 1 }} />
            <Area type="monotone" dataKey="score" stroke="var(--series-1)" fill="var(--series-1)"
                  fillOpacity={0.16} strokeWidth={2} isAnimationActive={false} />
            <Area type="monotone" dataKey="rolling" stroke="var(--status-warning)" fill="none"
                  strokeWidth={2} isAnimationActive={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <Legend items={[
        { label: 'Instant score', color: 'var(--series-1)' },
        { label: 'Rolling score', color: 'var(--status-warning)' },
      ]} />
    </>
  )
}

/* ------------------------------------------------------------------------ */
/* Class-probability bars for a single prediction. One series, so no legend —
 * the card title names it; the predicted class is direct-labelled.          */
export function ProbabilityBars({ probabilities, predicted }) {
  const data = Object.entries(probabilities || {})
    .map(([k, v]) => ({ key: k, name: THREAT_LABEL[k] || titleCase(k), value: v }))
    .sort((a, b) => b.value - a.value)
  if (!data.length) return null
  return (
    <div className="stack" style={{ gap: 8 }}>
      {data.map((d) => (
        <div key={d.key}>
          <div className="row" style={{ justifyContent: 'space-between', marginBottom: 3, gap: 6 }}>
            <span style={{
              fontSize: 12.5,
              fontWeight: d.key === predicted ? 650 : 450,
              color: d.key === predicted ? 'var(--text-primary)' : 'var(--text-secondary)',
            }}>
              {d.name}
            </span>
            <span className="tnum" style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
              {pct(d.value, 1)}
            </span>
          </div>
          <div className="meter">
            <div style={{
              width: `${Math.max(1.5, d.value * 100)}%`,
              background: THREAT_COLOR[d.key] || 'var(--series-1)',
              opacity: d.key === predicted ? 1 : 0.42,
            }} />
          </div>
        </div>
      ))}
    </div>
  )
}

/* ------------------------------------------------------------------------ */
/* Confusion matrix — sequential blue ramp, one hue, light to dark.          */
export function ConfusionMatrix({ matrix, labels, normalise = true }) {
  if (!matrix?.length) return <Empty>No confusion matrix available.</Empty>
  const rowSums = matrix.map((r) => r.reduce((a, b) => a + b, 0))
  const steps = ['var(--seq-100)', 'var(--seq-250)', 'var(--seq-400)', 'var(--seq-550)', 'var(--seq-700)']
  const colorFor = (v) => {
    if (v <= 0) return 'var(--surface-2)'
    const i = Math.min(steps.length - 1, Math.floor(v * steps.length))
    return steps[i]
  }
  // A six-class matrix needs compact headers or the right-hand columns fall
  // off the card. Full names stay in the per-class table below it.
  const SHORT = {
    benign: 'Benign',
    prompt_injection: 'Prompt inj.',
    jailbreak: 'Jailbreak',
    adversarial_obfuscation: 'Adversarial',
    data_exfiltration: 'Data exfil.',
    model_extraction: 'Model extr.',
  }
  const short = (l) => SHORT[l] || THREAT_LABEL[l] || titleCase(l)
  return (
    <div className="table-wrap">
      <table className="table" style={{ fontSize: 12 }}>
        <thead>
          <tr>
            <th style={{ minWidth: 128 }}>True \ Predicted</th>
            {labels.map((l) => <th key={l} className="num" style={{ minWidth: 86 }}>{short(l)}</th>)}
          </tr>
        </thead>
        <tbody>
          {matrix.map((row, i) => (
            <tr key={labels[i]}>
              <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{short(labels[i])}</td>
              {row.map((v, j) => {
                const frac = rowSums[i] ? v / rowSums[i] : 0
                const dark = frac > 0.5
                return (
                  <td key={j} className="num tnum" title={`${v} (${pct(frac, 1)})`}
                      style={{
                        background: colorFor(frac),
                        color: v === 0 ? 'var(--text-muted)' : dark ? '#fff' : '#0b0b0b',
                        fontWeight: i === j ? 650 : 450,
                        textAlign: 'center',
                      }}>
                    {normalise ? (frac ? pct(frac, 0) : '—') : v}
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
      <div className="muted" style={{ fontSize: 11.5, marginTop: 8 }}>
        Cells show row-normalised recall; hover for raw counts. Diagonal = correct classifications.
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------------ */
export function PerClassBars({ perClass, labels, metric = 'f1-score', height = 210 }) {
  const data = (labels || [])
    .filter((l) => perClass?.[l])
    .map((l) => ({
      key: l,
      name: THREAT_LABEL[l] || titleCase(l),
      value: perClass[l][metric] ?? 0,
      fill: THREAT_COLOR[l] || 'var(--series-1)',
    }))
  if (!data.length) return <Empty>No per-class metrics.</Empty>
  return (
    <div style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ top: 2, right: 48, left: 8, bottom: 2 }}>
          <CartesianGrid stroke="var(--grid)" horizontal={false} />
          <XAxis type="number" domain={[0, 1]} tick={AXIS} tickLine={false} axisLine={false}
                 tickFormatter={(v) => v.toFixed(1)} />
          <YAxis type="category" dataKey="name" tick={AXIS} tickLine={false}
                 axisLine={{ stroke: 'var(--axis)' }} width={150} />
          <Tooltip content={<VizTooltip />} cursor={{ fill: 'var(--hover)' }} />
          <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={16} isAnimationActive={false}>
            {data.map((d) => <Cell key={d.key} fill={d.fill} />)}
            <LabelList dataKey="value" position="right" fill="var(--text-secondary)"
                       fontSize={11} formatter={(v) => v.toFixed(3)} />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}

/* ========================================================================= */
/* Real-input analysis charts — scan, probe, audit                           */
/* ========================================================================= */

/* Threat classes found in a scanned corpus. Horizontal bars rather than a
 * donut: a scan is usually dominated by one class, and a donut of 96%/4% is
 * unreadable while a bar chart of the same data is not. */
export function ClassBars({ distribution, height = 240, hideBenign = true }) {
  const data = THREAT_ORDER
    .filter((k) => !(hideBenign && k === 'benign'))
    .map((k) => ({ key: k, name: THREAT_LABEL[k], value: distribution?.[k] || 0, fill: THREAT_COLOR[k] }))
    .filter((d) => d.value > 0)
    .sort((a, b) => b.value - a.value)
  if (!data.length) return <Empty icon={ChartPie}>No threat classes detected in this material.</Empty>
  return (
    <div style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ top: 4, right: 48, left: 8, bottom: 4 }}>
          <CartesianGrid stroke="var(--grid)" horizontal={false} />
          <XAxis type="number" tick={AXIS} tickLine={false} axisLine={false} allowDecimals={false} />
          <YAxis type="category" dataKey="name" tick={AXIS} tickLine={false}
                 axisLine={{ stroke: 'var(--axis)' }} width={152} />
          <Tooltip content={<VizTooltip />} cursor={{ fill: 'var(--hover)' }} />
          <Bar dataKey="value" radius={[0, 5, 5, 0]} barSize={22} isAnimationActive={false}>
            {data.map((d) => <Cell key={d.key} fill={d.fill} />)}
            {/* Direct labels: three of these slots sit below 3:1 on white. */}
            <LabelList dataKey="value" position="right" fill="var(--text-secondary)" fontSize={12} />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}

/* ------------------------------------------------------------------------ */
/* Where the findings sit in the file. A scan's provenance is its whole
 * value, so the report shows *position*, not just totals: a cluster of hits
 * in one region of a transcript reads very differently from hits scattered
 * evenly through it. */
export function FindingMap({ findings, total, height = 150 }) {
  if (!findings?.length || !total) return <Empty>Nothing flagged — no positions to plot.</Empty>
  // One bucket per item while the source is small, so the axis reads as real
  // item numbers; only bin once there are more items than bars worth drawing.
  const buckets = Math.max(1, Math.min(60, total))
  const size = total / buckets
  const rows = Array.from({ length: buckets }, (_, i) => {
    const from = Math.floor(i * size) + 1
    const to = Math.min(total, Math.floor((i + 1) * size))
    return {
      bucket: i,
      from,
      label: to > from ? `${from}–${to}` : String(from),
      hostile: 0,
      defensive: 0,
    }
  })
  for (const f of findings) {
    const b = Math.min(buckets - 1, Math.floor((f.index || 0) / size))
    rows[b][f.likely_defensive ? 'defensive' : 'hostile'] += 1
  }
  return (
    <>
      <div style={{ height }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={rows} margin={{ top: 6, right: 8, left: 0, bottom: 2 }}>
            <CartesianGrid stroke="var(--grid)" vertical={false} />
            <XAxis dataKey="label" tick={AXIS} tickLine={false}
                   axisLine={{ stroke: 'var(--axis)' }} minTickGap={22} />
            <YAxis tick={AXIS} tickLine={false} axisLine={false} allowDecimals={false} width={44} />
            <Tooltip
              content={<VizTooltip labelMap={{ hostile: 'Hostile', defensive: 'Defensive phrasing' }} />}
              cursor={{ fill: 'var(--hover)' }}
            />
            <Bar dataKey="hostile" stackId="f" fill="var(--status-critical)" isAnimationActive={false} />
            <Bar dataKey="defensive" stackId="f" fill="var(--series-neutral)"
                 radius={[3, 3, 0, 0]} isAnimationActive={false} />
          </BarChart>
        </ResponsiveContainer>
      </div>
      <Legend items={[
        { label: 'Hostile input', color: 'var(--status-critical)' },
        { label: 'Defensive phrasing', color: 'var(--series-neutral)' },
      ]} />
      <div className="field-hint">Item position in the source, left to right.</div>
    </>
  )
}

/* ------------------------------------------------------------------------ */
/* Probe: attacks per category, split by what actually happened at the live
 * endpoint. Grouped, not stacked — the comparison that matters is "how many
 * of this category leaked", which a stack forces the eye to estimate. */
export function ProbeCategoryBars({ byCategory, height = 260 }) {
  const data = Object.entries(byCategory || {}).map(([k, v]) => ({
    key: k,
    name: PROBE_CATEGORY_LABEL[k] || titleCase(k),
    leaked: v.vulnerable || 0,
    held: Math.max(0, (v.total || 0) - (v.vulnerable || 0)),
    blocked: v.blocked || 0,
  }))
  if (!data.length) return <Empty>No attack categories were run.</Empty>
  return (
    <>
      <div style={{ height }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 16, right: 8, left: 0, bottom: 4 }} barGap={4}>
            <CartesianGrid stroke="var(--grid)" vertical={false} />
            <XAxis dataKey="name" tick={AXIS} tickLine={false} axisLine={{ stroke: 'var(--axis)' }}
                   interval={0} angle={-16} textAnchor="end" height={70} />
            <YAxis tick={AXIS} tickLine={false} axisLine={false} allowDecimals={false} width={44} />
            <Tooltip content={<VizTooltip labelMap={{
              leaked: 'Leaked at the endpoint',
              held: 'Held / refused',
              blocked: 'Blocked by AstraSec first',
            }} />} cursor={{ fill: 'var(--hover)' }} />
            <Bar dataKey="held" fill="var(--status-good)" radius={[4, 4, 0, 0]} barSize={20} isAnimationActive={false}>
              <LabelList dataKey="held" position="top" fill="var(--text-secondary)" fontSize={11} />
            </Bar>
            <Bar dataKey="leaked" fill="var(--status-critical)" radius={[4, 4, 0, 0]} barSize={20} isAnimationActive={false}>
              <LabelList dataKey="leaked" position="top" fill="var(--text-secondary)" fontSize={11} />
            </Bar>
            <Bar dataKey="blocked" fill="var(--series-1)" radius={[4, 4, 0, 0]} barSize={20} isAnimationActive={false}>
              <LabelList dataKey="blocked" position="top" fill="var(--text-secondary)" fontSize={11} />
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
      <Legend items={[
        { label: 'Held or refused', color: 'var(--status-good)' },
        { label: 'Leaked at the endpoint', color: 'var(--status-critical)' },
        { label: 'Blocked by AstraSec first', color: 'var(--series-1)' },
      ]} />
    </>
  )
}

/* ------------------------------------------------------------------------ */
/* Audit: risk contribution per surface, drawn against the weight each
 * surface actually carries in the posture score (0.50 / 0.32 / 0.18). The
 * bar is the risk; the ghost bar behind it is the weight, so a reader can
 * see that a fully-compromised dependency surface still cannot sink the
 * score on its own. */
export function SurfaceRiskBars({ surfaceScores, weights, height }) {
  const WEIGHT = weights || { system_prompt: 0.5, configuration: 0.32, dependency: 0.18 }
  height = height || 60 + 40 * Object.keys(surfaceScores || {}).length
  const data = Object.entries(surfaceScores || {}).map(([k, v]) => ({
    key: k,
    name: SURFACE_LABEL[k] || titleCase(k),
    risk: Math.round((v || 0) * 100),
    contribution: Math.round((v || 0) * (WEIGHT[k] || 0) * 100),
    fill: SURFACE_COLOR[k] || 'var(--series-1)',
  }))
  if (!data.length) return <Empty>Surface scores unavailable.</Empty>
  return (
    <>
      <div style={{ height }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} layout="vertical" margin={{ top: 4, right: 52, left: 8, bottom: 4 }}>
            <CartesianGrid stroke="var(--grid)" horizontal={false} />
            <XAxis type="number" domain={[0, 100]} tick={AXIS} tickLine={false}
                   axisLine={false} unit="%" />
            <YAxis type="category" dataKey="name" tick={AXIS} tickLine={false}
                   axisLine={{ stroke: 'var(--axis)' }} width={124} />
            <Tooltip content={<VizTooltip unit="%" labelMap={{
              risk: 'Risk on this surface',
              contribution: 'Points it costs the score',
            }} />} cursor={{ fill: 'var(--hover)' }} />
            <Bar dataKey="risk" radius={[0, 5, 5, 0]} barSize={20} isAnimationActive={false}>
              {data.map((d) => <Cell key={d.key} fill={d.fill} />)}
              <LabelList dataKey="risk" position="right" formatter={(v) => `${v}%`}
                         fill="var(--text-secondary)" fontSize={12} />
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
      <div className="field-hint">
        Weighted into the posture score at{' '}
        {data.map((d, i) => `${i ? (i === data.length - 1 ? ' and ' : ', ') : ''}${Math.round((WEIGHT[d.key] || 0) * 100)}% ${d.name.toLowerCase()}`).join('')}.
      </div>
    </>
  )
}

/* ------------------------------------------------------------------------ */
/* Severity mix for audit findings — reuses the reserved status palette and
 * always pairs colour with a written label. */
export function SeverityStrip({ counts }) {
  const order = ['critical', 'high', 'medium', 'low']
  const rows = order.map((k) => ({ k, n: counts?.[k] || 0 })).filter((r) => r.n > 0)
  const total = rows.reduce((s, r) => s + r.n, 0)
  if (!total) return <Empty>No findings — every check passed.</Empty>
  return (
    <div className="stack-sm">
      <div style={{ display: 'flex', height: 14, borderRadius: 999, overflow: 'hidden', gap: 2 }}>
        {rows.map((r) => (
          <div key={r.k} style={{ flex: r.n, background: SEVERITY_COLOR[r.k] }} title={`${titleCase(r.k)}: ${r.n}`} />
        ))}
      </div>
      <Legend items={rows.map((r) => ({
        label: titleCase(r.k), color: SEVERITY_COLOR[r.k], value: r.n,
      }))} />
    </div>
  )
}

/* ------------------------------------------------------------------------ */
/* Score ring — one number, so a gauge and not a chart. Used for the scan
 * risk score, the probe grade and the audit posture score alike. */
export function ScoreRing({ value = 0, label = '', color = 'var(--brand-600)',
                            size = 176, caption = '', suffix = '' }) {
  const clamped = Math.max(0, Math.min(100, value))
  const r = size / 2 - 15
  const c = 2 * Math.PI * r
  const sweep = 0.75
  return (
    <div style={{ display: 'grid', placeItems: 'center', gap: 8 }}>
      <div style={{ position: 'relative', width: size, height: size }}>
        <svg width={size} height={size} style={{ transform: 'rotate(135deg)' }}>
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--surface-3)"
                  strokeWidth={13} strokeDasharray={`${c * sweep} ${c}`} strokeLinecap="round" />
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color}
                  strokeWidth={13} strokeDasharray={`${c * sweep * (clamped / 100)} ${c}`}
                  strokeLinecap="round" style={{ transition: 'stroke-dasharray .5s ease' }} />
        </svg>
        <div style={{
          position: 'absolute', inset: 0, display: 'grid', placeItems: 'center',
          textAlign: 'center', paddingTop: 6,
        }}>
          <div>
            <div style={{
              fontFamily: 'var(--font-display)', fontSize: 44, fontWeight: 700,
              lineHeight: 1, color, letterSpacing: '-.02em',
            }}>
              {label || `${Math.round(clamped)}${suffix}`}
            </div>
            {caption && <div className="muted" style={{ fontSize: 12.5, marginTop: 6 }}>{caption}</div>}
          </div>
        </div>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------------ */
/* Activity over the last N days: how much was tested, and how much of it
 * came back with findings. Kinds get their own three hues here — the chrome
 * uses a single accent, so these never collide with navigation colour.     */
const KIND_SERIES = [
  ['scan', 'Scans', '#1d5fd1'],
  ['probe', 'Endpoint probes', '#0f8a7e'],
  ['audit', 'App audits', '#8a94a6'],
]

export function ActivityChart({ reports, days = 14, height = 220 }) {
  const today = new Date(); today.setHours(0, 0, 0, 0)
  const buckets = []
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(today); d.setDate(d.getDate() - i)
    buckets.push({ t: d.getTime(), name: d.toLocaleDateString(undefined, { day: 'numeric', month: 'short' }),
                   scan: 0, probe: 0, audit: 0, withFindings: 0 })
  }
  const start = buckets[0].t
  for (const r of reports || []) {
    const ts = (r.created_at || 0) * 1000
    if (ts < start) continue
    const idx = Math.min(days - 1, Math.floor((ts - start) / 86400000))
    const b = buckets[idx]
    if (!b || !(r.kind in b)) continue
    b[r.kind] += 1
    if (r.findings > 0) b.withFindings += 1
  }
  const total = buckets.reduce((s, b) => s + b.scan + b.probe + b.audit, 0)
  const flagged = buckets.reduce((s, b) => s + b.withFindings, 0)
  if (!total) return <Empty>Nothing run in the last {days} days.</Empty>
  return (
    <>
      <div style={{ height }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={buckets} margin={{ top: 6, right: 8, left: -18, bottom: 0 }}>
            <CartesianGrid stroke="var(--grid)" vertical={false} />
            <XAxis dataKey="name" tick={AXIS} tickLine={false} axisLine={{ stroke: 'var(--axis)' }}
                   interval="preserveStartEnd" minTickGap={18} />
            <YAxis allowDecimals={false} tick={AXIS} tickLine={false} axisLine={false} />
            <Tooltip content={<VizTooltip labelMap={Object.fromEntries(KIND_SERIES.map(([k, l]) => [k, l]))} />}
                     cursor={{ fill: 'var(--hover)' }} />
            {KIND_SERIES.map(([k, , c], i) => (
              <Bar key={k} dataKey={k} stackId="a" fill={c} isAnimationActive={false}
                   radius={i === KIND_SERIES.length - 1 ? [3, 3, 0, 0] : 0} maxBarSize={28} />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
      <div className="row" style={{ justifyContent: 'space-between', marginTop: 8 }}>
        <div className="legend">
          {KIND_SERIES.map(([k, l, c]) => (
            <span className="legend-item" key={k}><span className="legend-swatch" style={{ background: c }} />{l}</span>
          ))}
        </div>
        <span className="muted" style={{ fontSize: 12 }}>
          {num(total)} run · {num(flagged)} ({pct(flagged / total, 0)}) came back with findings
        </span>
      </div>
    </>
  )
}
