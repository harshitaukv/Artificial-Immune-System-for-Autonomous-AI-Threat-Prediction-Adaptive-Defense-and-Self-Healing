import React, { useEffect, useState } from 'react'
import { Activity, Brain, HeartPulse, ShieldHalf, Dna, Cpu, Server } from 'lucide-react'
import { api, API_BASE } from '../lib/api'
import { Banner, Card, Spinner } from '../components/ui'
import { num, pct } from '../lib/viz'

const ICONS = [Activity, HeartPulse, Brain, ShieldHalf, Dna]

const BIOLOGY = [
  'Self / non-self discrimination — learns what "self" looks like from benign traffic alone.',
  'Homeostasis monitoring — a continuous health signal, not just a pathogen alarm.',
  'Antigen recognition — names the pathogen and attaches a confidence to the call.',
  'Effector response — a proportionate reaction, from neutralise to isolate.',
  'Adaptive immunity — memory cells, clonal selection, affinity maturation, apoptosis.',
]

export default function About({ health }) {
  const [config, setConfig] = useState(null)
  const [stats, setStats] = useState(null)
  const [err, setErr] = useState('')

  useEffect(() => {
    (async () => {
      try {
        setConfig(await api.config())
        setStats(await api.stats())
      } catch (e) { setErr(e.message) }
    })()
  }, [])

  if (err) return <Banner kind="err">{err}</Banner>
  if (!config) return <div className="row"><Spinner /> <span className="muted">Loading…</span></div>

  return (
    <div className="stack">
      <Card title="AstraSec" sub={config.tagline}>
        <p className="secondary" style={{ marginTop: 0, maxWidth: 820, lineHeight: 1.65 }}>
          AstraSec protects AI applications the way a vertebrate immune system protects an organism:
          an <strong>innate</strong> layer of fixed, high-precision signatures gives instant,
          explainable detection, while an <strong>adaptive</strong> layer of machine-learned models
          generalises to attacks nobody has written a rule for. What ties them together is
          <strong> memory</strong> — every incident leaves a receptor behind, so the second encounter
          with an attack is faster and more certain than the first, and the system writes new defensive
          policies for itself without any model being retrained.
        </p>
        <div className="row" style={{ marginTop: 12 }}>
          <span className="chip">v{config.version}</span>
          <span className="chip">{num(config.signature_count)} innate signatures</span>
          <span className="chip">{config.modules.length} modules</span>
          {health && <span className="chip">uptime {num(health.uptime_seconds, 0)}s</span>}
        </div>
      </Card>

      <Card title="Module inventory" sub="Each module maps to a mechanism in the biological analogy">
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th style={{ width: 40 }}>#</th><th>Module</th><th>Algorithm</th><th>Immunological analogue</th></tr></thead>
            <tbody>
              {config.modules.map((m, i) => {
                const Icon = ICONS[i] || Cpu
                return (
                  <tr key={m.id}>
                    <td><span className="module-num">{m.id}</span></td>
                    <td style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                      <span className="row" style={{ gap: 7 }}>
                        <Icon size={14} style={{ color: 'var(--series-1)' }} />{m.name}
                      </span>
                    </td>
                    <td><span className="chip">{m.algorithm}</span></td>
                    <td>{BIOLOGY[i]}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </Card>

      <div className="grid grid-3">
        <Card title="AI Health Score weights" sub="Must sum to 1.0 — validated at startup">
          <div className="stack" style={{ gap: 9 }}>
            {Object.entries(config.health_weights).map(([k, v]) => (
              <div key={k}>
                <div className="row" style={{ justifyContent: 'space-between', marginBottom: 3 }}>
                  <span style={{ fontSize: 12.5 }}>{k.replace('_risk', '').replace('_', ' ')}</span>
                  <span className="tnum muted" style={{ fontSize: 12 }}>{pct(v, 0)}</span>
                </div>
                <div className="meter"><div style={{ width: `${v * 100}%`, background: 'var(--series-1)' }} /></div>
              </div>
            ))}
          </div>
        </Card>

        <Card title="Decision thresholds">
          <dl className="kv">
            <dt>Block</dt><dd>{config.thresholds.block}</dd>
            <dt>Sanitise</dt><dd>{config.thresholds.sanitize}</dd>
            <dt>Monitor</dt><dd>{config.thresholds.monitor}</dd>
            <dt>Prediction floor</dt><dd>{config.thresholds.prediction}</dd>
            <dt>Memory affinity</dt><dd>{config.thresholds.memory_affinity}</dd>
            <dt>Rate limit</dt>
            <dd>{config.rate_limit.requests} / {config.rate_limit.window_seconds}s</dd>
          </dl>

        </Card>

        <Card title="Recommendation engine (Module 5)">
          <dl className="kv">
            <dt>Engine</dt><dd>{config.llm.available ? `${config.llm.model} (generative)` : 'Case-based knowledge base'}</dd>
            <dt>Recommendations issued</dt><dd>{num(config.llm.calls)}</dd>
          </dl>
          <div className="muted" style={{ fontSize: 11.5, marginTop: 10, lineHeight: 1.55 }}>
            Recommendations are built from the incident evidence and the immune memory's record of
            what defended similar attacks before. When a Llama 3.1 model is available they are
            written by the model; the evidence they draw on is the same either way.
          </div>
        </Card>
      </div>

      {stats && (
        <div className="grid grid-2">
          <Card title="Runtime counters" sub="Since the service started">
            <dl className="kv">
              <dt>Uptime</dt><dd>{num(stats.uptime_seconds, 1)} s</dd>
              <dt>Persisted incidents</dt><dd>{num(stats.persisted_incidents)}</dd>
              <dt>Tenants profiled</dt><dd>{num(stats.behavior?.tenants_profiled)}</dd>
              <dt>Behaviour training size</dt><dd>{num(stats.behavior?.training_size)}</dd>
              <dt>Classifier training size</dt><dd>{num(stats.prediction?.training_size)}</dd>
              <dt>Classes</dt><dd>{(stats.prediction?.classes || []).length}</dd>
              <dt>Memory cells</dt><dd>{num(stats.memory?.cells)}</dd>
              <dt>Recall rate</dt><dd>{pct(stats.memory?.recall_rate, 1)}</dd>
              <dt>Active rules</dt><dd>{num(stats.defense?.active_self_healing_rules)}</dd>
              <dt>Quarantined</dt><dd>{num(stats.defense?.quarantined)}</dd>
            </dl>
          </Card>

          <Card title="Demo applications" sub="Postures used by the traffic simulator">
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>Application</th><th>Model</th><th>Notable posture</th></tr></thead>
                <tbody>
                  {config.demo_apps.map((a) => {
                    const flags = []
                    if (a.tool_calling_enabled) flags.push('tool calling')
                    if (a.retrieval_enabled) flags.push('RAG')
                    if (!a.sandbox_enabled) flags.push('no sandbox')
                    if (!a.output_filtering_enabled) flags.push('no output filter')
                    if (!a.authentication_required) flags.push('unauthenticated')
                    if (!a.pii_redaction_enabled) flags.push('no PII redaction')
                    if (a.known_vulnerable_dependencies?.length) flags.push(`${a.known_vulnerable_dependencies.length} vulnerable deps`)
                    return (
                      <tr key={a.app_id}>
                        <td style={{ color: 'var(--text-primary)' }}>
                          {a.app_name}<div className="muted mono" style={{ fontSize: 11 }}>{a.app_id}</div>
                        </td>
                        <td className="mono">{a.model_name}</td>
                        <td>
                          <div className="row" style={{ gap: 5 }}>
                            {flags.length
                              ? flags.map((f) => <span className="chip" key={f}>{f}</span>)
                              : <span className="muted">hardened</span>}
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
      )}

      <Card title="Project">
        <div className="grid grid-2" style={{ gap: 22 }}>
          <dl className="kv">
            <dt>Title</dt><dd>Artificial Immune System for Autonomous AI Threat Prediction, Adaptive Defense and Self-Healing</dd>
            <dt>Department</dt><dd>Computer Science and Engineering</dd>
            <dt>Institution</dt><dd>Sri Manakula Vinayagar Engineering College (Autonomous)</dd>
            <dt>Guide</dt><dd>Mr. B. Thiyagarajan, Assistant Professor</dd>
          </dl>
          <dl className="kv">
            <dt>Harshita U</dt><dd>23UCS062 — Team Leader</dd>
            <dt>Harini S</dt><dd>23UCS059</dd>
            <dt>Mahalakshmi S</dt><dd>23UCS095</dd>
            <dt>API docs</dt>
            <dd><a href={`${API_BASE}/docs`} target="_blank" rel="noreferrer" style={{ color: 'var(--series-1)' }}>
              <Server size={11} style={{ verticalAlign: -1 }} /> OpenAPI / Swagger
            </a></dd>
          </dl>
        </div>
      </Card>
    </div>
  )
}
