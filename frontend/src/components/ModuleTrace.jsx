import React from 'react'
import { Activity, Brain, HeartPulse, ShieldHalf, Dna } from 'lucide-react'
import { Card, SeverityBadge, ThreatBadge, ActionBadge, BandBadge, Meter } from './ui'
import { ProbabilityBars } from './charts'
import { ms, num, pct, titleCase } from '../lib/viz'

const MODULES = [
  { n: 1, name: 'Behavior Learning Engine', algo: 'Isolation Forest', icon: Activity },
  { n: 2, name: 'AI Health & Risk Analyzer', algo: 'Weighted Risk Scoring', icon: HeartPulse },
  { n: 3, name: 'Threat Prediction Engine', algo: 'TF-IDF + RF / LogReg ensemble', icon: Brain },
  { n: 4, name: 'Adaptive Defense Engine', algo: 'Rule-Based Decision Engine', icon: ShieldHalf },
  { n: 5, name: 'Self-Healing & Immune Memory', algo: 'Case-Based Immune Memory', icon: Dna },
]

function Step({ mod, latency, children }) {
  const Icon = mod.icon
  return (
    <div className="module-step">
      <div className="module-num">{mod.n}</div>
      <div>
        <div className="row" style={{ gap: 8, marginBottom: 2 }}>
          <Icon size={14} style={{ color: 'var(--series-1)' }} />
          <span className="module-name">{mod.name}</span>
          <span className="chip">{mod.algo}</span>
          <div className="spacer" />
          {latency !== undefined && <span className="muted tnum" style={{ fontSize: 11.5 }}>{ms(latency)}</span>}
        </div>
        <div className="module-body">{children}</div>
      </div>
    </div>
  )
}

export default function ModuleTrace({ result }) {
  if (!result) return null
  const { behavior, health, prediction, defense, memory, latency_ms: lat } = result

  return (
    <Card
      title="Immune response trace"
      sub={`Incident ${result.incident_id} · total ${ms(result.total_latency_ms)}`}
    >
      {/* ------------------------------------------------ Module 1 */}
      <Step mod={MODULES[0]} latency={lat?.module1_behavior_ms}>
        <div className="row" style={{ marginBottom: 6 }}>
          <span className="badge" style={{
            color: behavior.is_anomalous ? 'var(--status-serious)' : 'var(--status-good)',
            borderColor: behavior.is_anomalous ? 'var(--status-serious)' : 'var(--status-good)',
          }}>
            {behavior.is_anomalous ? 'Anomalous' : 'Within baseline'}
          </span>
          <span className="chip">anomaly {behavior.anomaly_score.toFixed(3)}</span>
          <span className="chip">baseline: {titleCase(behavior.baseline_source)}</span>
          <span className="chip">{num(behavior.observations_seen)} observations</span>
        </div>
        <Meter value={behavior.anomaly_score}
               color={behavior.is_anomalous ? 'var(--status-serious)' : 'var(--status-good)'} />
        <p style={{ margin: '8px 0 0' }}>{behavior.explanation}</p>
        {behavior.deviating_features?.length > 0 && (
          <div className="row" style={{ marginTop: 7, gap: 6 }}>
            {behavior.deviating_features.slice(0, 4).map((d) => (
              <span className="chip" key={d.feature}>
                {d.feature} {d.direction === 'above' ? '↑' : '↓'} {Math.abs(d.deviation_sigma)}σ
              </span>
            ))}
          </div>
        )}
      </Step>

      {/* ------------------------------------------------ Module 2 */}
      <Step mod={MODULES[1]} latency={lat?.module2_health_ms}>
        <div className="row" style={{ marginBottom: 6 }}>
          <span style={{ fontSize: 22, fontWeight: 660, letterSpacing: '-.02em' }}>
            {health.health_score.toFixed(0)}<span className="muted" style={{ fontSize: 13, fontWeight: 400 }}>/100</span>
          </span>
          <BandBadge value={health.band} />
          <SeverityBadge value={health.risk_level} />
        </div>
        <div className="grid grid-4" style={{ gap: 10, marginBottom: 8 }}>
          {Object.entries(health.surface_scores || {}).map(([k, v]) => (
            <div key={k}>
              <div className="muted" style={{ fontSize: 11 }}>{titleCase(k.replace('_risk', ''))}</div>
              <div className="tnum" style={{ fontSize: 13, fontWeight: 600, marginBottom: 3 }}>{pct(v, 0)}</div>
              <Meter value={v} height={4}
                     color={v > 0.6 ? 'var(--status-critical)' : v > 0.3 ? 'var(--status-warning)' : 'var(--status-good)'} />
            </div>
          ))}
        </div>
        <p style={{ margin: '0 0 6px' }}>{health.explanation}</p>
        {health.findings?.length > 0 && (
          <details>
            <summary style={{ cursor: 'pointer', fontSize: 12.5, color: 'var(--text-muted)' }}>
              {health.findings.length} risk finding{health.findings.length === 1 ? '' : 's'}
            </summary>
            <div className="table-wrap" style={{ marginTop: 8 }}>
              <table className="table">
                <thead><tr><th>Code</th><th>Finding</th><th>Severity</th><th>Remediation</th></tr></thead>
                <tbody>
                  {health.findings.map((f) => (
                    <tr key={f.code + f.title}>
                      <td><span className="chip">{f.code}</span></td>
                      <td style={{ color: 'var(--text-primary)' }}>{f.title}</td>
                      <td><SeverityBadge value={f.severity} /></td>
                      <td style={{ maxWidth: 380 }}>{f.remediation}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </details>
        )}
      </Step>

      {/* ------------------------------------------------ Module 3 */}
      <Step mod={MODULES[2]} latency={lat?.module3_prediction_ms}>
        <div className="row" style={{ marginBottom: 8 }}>
          <ThreatBadge value={prediction.threat_class} />
          <SeverityBadge value={prediction.severity} />
          <span className="chip">confidence {pct(prediction.confidence, 1)}</span>
          {prediction.memory_assisted && <span className="chip">memory-assisted</span>}
        </div>
        <div className="grid grid-2" style={{ gap: 16 }}>
          <ProbabilityBars probabilities={prediction.probabilities} predicted={prediction.threat_class} />
          <div>
            {prediction.signature_detail?.length > 0 && (
              <>
                <div className="muted" style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '.05em', fontWeight: 600, marginBottom: 6 }}>
                  Innate signature hits
                </div>
                <div className="stack" style={{ gap: 6, marginBottom: 12 }}>
                  {prediction.signature_detail.map((s) => (
                    <div key={s.id} style={{ fontSize: 12.5 }}>
                      <span className="chip">{s.id}</span>{' '}
                      {s.owasp && <span className="chip">{s.owasp}</span>}{' '}
                      <span className="secondary">{s.description}</span>
                    </div>
                  ))}
                </div>
              </>
            )}
            {prediction.top_indicators?.length > 0 && (
              <>
                <div className="muted" style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '.05em', fontWeight: 600, marginBottom: 6 }}>
                  Top lexical contributions
                </div>
                <div className="row" style={{ gap: 6 }}>
                  {prediction.top_indicators.map((t) => (
                    <span className="chip" key={t.term}
                          style={{ color: t.direction === 'supports' ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                      {t.term} {t.contribution > 0 ? '+' : ''}{t.contribution.toFixed(2)}
                    </span>
                  ))}
                </div>
              </>
            )}
          </div>
        </div>
        <p style={{ margin: '10px 0 0' }}>{prediction.explanation}</p>
      </Step>

      {/* ------------------------------------------------ Module 4 */}
      <Step mod={MODULES[3]} latency={lat?.module4_defense_ms}>
        <div className="row" style={{ marginBottom: 6 }}>
          <ActionBadge value={defense.action} />
          <span className="badge" style={{
            color: defense.allowed ? 'var(--status-good)' : 'var(--status-critical)',
            borderColor: defense.allowed ? 'var(--status-good)' : 'var(--status-critical)',
          }}>
            {defense.allowed ? 'Forwarded to model' : 'Model never called'}
          </span>
          {defense.policy_ids?.map((p) => <span className="chip" key={p}>{p}</span>)}
        </div>
        <p style={{ margin: '0 0 8px' }}>{defense.rationale}</p>
        {defense.sanitized_prompt && (
          <>
            <div className="muted" style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '.05em', fontWeight: 600, marginBottom: 5 }}>
              Sanitised prompt (forwarded)
            </div>
            <div className={`prompt-box ${defense.revalidated_clean ? 'clean' : 'blocked'}`}>
              {defense.sanitized_prompt}
            </div>
            <div className="row" style={{ marginTop: 6, gap: 6 }}>
              <span className="chip">residual risk {pct(defense.residual_risk, 0)}</span>
              <span className="chip">
                re-validation {defense.revalidated_clean ? 'passed' : 'FAILED → blocked'}
              </span>
            </div>
          </>
        )}
        {defense.sanitization_steps?.length > 0 && (
          <details style={{ marginTop: 8 }}>
            <summary style={{ cursor: 'pointer', fontSize: 12.5, color: 'var(--text-muted)' }}>
              {defense.sanitization_steps.length} sanitisation step{defense.sanitization_steps.length === 1 ? '' : 's'}
            </summary>
            <ul style={{ margin: '8px 0 0', paddingLeft: 18, fontSize: 12.5 }}>
              {defense.sanitization_steps.map((s, i) => (
                <li key={i} style={{ marginBottom: 4 }}>
                  <span className="chip">{s.rule_id}</span> {s.description}
                  {s.span && <> — <span className="mono">{s.span}</span></>}
                </li>
              ))}
            </ul>
          </details>
        )}
      </Step>

      {/* ------------------------------------------------ Module 5 */}
      <Step mod={MODULES[4]} latency={lat?.module5_memory_ms}>
        <div className="row" style={{ marginBottom: 6 }}>
          <span className="badge" style={{
            color: memory.recall_hit ? 'var(--series-1)' : 'var(--text-muted)',
            borderColor: memory.recall_hit ? 'var(--series-1)' : 'var(--border-strong)',
          }}>
            {memory.primary_response ? 'Primary response' : 'Secondary response (recall)'}
          </span>
          {memory.matched_cell_id && <span className="chip">cell {memory.matched_cell_id}</span>}
          <span className="chip">affinity {pct(memory.matched_affinity, 1)}</span>
          <span className="chip">{num(memory.cells_total)} cells</span>
          {memory.clones_created > 0 && <span className="chip">+{memory.clones_created} clones</span>}
          {memory.cells_pruned > 0 && <span className="chip">−{memory.cells_pruned} pruned</span>}
        </div>
        <p style={{ margin: '0 0 8px' }}>{memory.explanation}</p>

        {memory.rules_synthesized?.length > 0 && (
          <div style={{ marginBottom: 10 }}>
            <div className="muted" style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '.05em', fontWeight: 600, marginBottom: 5 }}>
              Self-healing rules synthesised
            </div>
            {memory.rules_synthesized.map((r) => (
              <div key={r.rule_id} style={{ fontSize: 12.5, marginBottom: 4 }}>
                <span className="chip">{r.rule_id}</span>{' '}
                <span className="mono">{r.pattern}</span>{' '}
                <span className="badge" style={{
                  color: r.active ? 'var(--status-good)' : 'var(--text-muted)',
                  borderColor: r.active ? 'var(--status-good)' : 'var(--border-strong)',
                }}>
                  {r.active ? 'promoted & enforcing' : 'candidate'}
                </span>{' '}
                <span className="muted">conf {pct(r.confidence, 0)} · support {r.support}</span>
              </div>
            ))}
          </div>
        )}

        {memory.recommendations?.length > 0 && (
          <div>
            <div className="muted" style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '.05em', fontWeight: 600, marginBottom: 6 }}>
              Security recommendations
            </div>
            <div className="stack" style={{ gap: 9 }}>
              {memory.recommendations.map((r) => (
                <div key={r.recommendation_id} style={{
                  borderLeft: '2px solid var(--border-strong)', paddingLeft: 11,
                }}>
                  <div className="row" style={{ gap: 7, marginBottom: 2 }}>
                    <SeverityBadge value={r.priority} />
                    <strong style={{ fontSize: 13 }}>{r.title}</strong>
                    <span className="chip">{r.source === 'llm' ? 'AI-generated' : 'Knowledge base'}</span>
                  </div>
                  <div style={{ fontSize: 12.5 }}>{r.detail}</div>
                  {r.references?.length > 0 && (
                    <div className="row" style={{ gap: 5, marginTop: 4 }}>
                      {r.references.map((ref) => <span className="chip" key={ref}>{ref}</span>)}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </Step>
    </Card>
  )
}
