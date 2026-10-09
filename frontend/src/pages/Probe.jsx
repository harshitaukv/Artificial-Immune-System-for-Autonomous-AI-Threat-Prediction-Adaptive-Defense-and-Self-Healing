import React, { useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle, CheckCircle2, Link2, Play, Plug, ShieldCheck, ShieldX, Zap,
} from 'lucide-react'
import { api } from '../lib/api'
import {
  Banner, Card, Empty, GradeBadge, OutcomePill, SeverityBadge, Spinner,
  StatTile, Switch, ThreatBadge, ToggleGroup,
} from '../components/ui'
import { ProbeCategoryBars, ScoreRing } from '../components/charts'
import {
  GRADE_COLOR, OUTCOME_LABEL, PROBE_CATEGORY_COLOR, PROBE_CATEGORY_LABEL,
  SECTION_ACCENT, num, pct, titleCase,
} from '../lib/viz'

const PROTOCOLS = [
  { value: 'openai', label: 'OpenAI-compatible',
    hint: 'POST /v1/chat/completions with a messages array. Works for OpenAI, Together, Groq, vLLM, LM Studio and most hosted gateways.' },
  { value: 'ollama', label: 'Ollama',
    hint: 'POST /api/chat on a local Ollama server. No API key needed.' },
  { value: 'raw', label: 'Raw JSON',
    hint: 'POST {"prompt": "…"} and search the reply for common text fields. For a custom app endpoint.' },
]

/* Mirrors the category column of PROBE_CASES in the backend. Controls are
 * not listed: they always run, because a report that only shows attacks
 * cannot tell you whether the defence is over-blocking. */
const CATEGORIES = [
  'prompt_injection', 'jailbreak', 'adversarial_obfuscation',
  'data_exfiltration', 'model_extraction',
]

export default function Probe() {
  // Starts pointed at the built-in demo endpoint, which is always running,
  // so the first probe anyone runs produces a real, graded report.
  const [cfg, setCfg] = useState({
    url: `${window.location.origin}/demo/v1/chat/completions`,
    api_key: '',
    model: 'demo-weak-1',
    protocol: 'openai',
    system_prompt: '',
    max_cases: 19,
    delay_seconds: 0,
  })
  const [cats, setCats] = useState(CATEGORIES)
  const [cases, setCases] = useState([])
  const [check, setCheck] = useState(null)
  const [checking, setChecking] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [report, setReport] = useState(null)
  const [view, setView] = useState('attacks')

  useEffect(() => { api.probeCases().then(setCases).catch(() => {}) }, [])

  const set = (k) => (v) => setCfg((c) => ({ ...c, [k]: v }))

  const useDemo = async () => {
    try {
      const d = await api.probeDemoTarget()
      setCfg((c) => ({ ...c, url: d.url, protocol: d.protocol, model: d.model,
                       api_key: '', system_prompt: '' }))
      setCheck(null)
    } catch (e) {
      setError(e.message)
    }
  }

  useEffect(() => {
    // In dev the page origin is Vite, not the API; ask the API for its own URL.
    api.probeDemoTarget().then((d) => setCfg((c) => (
      c.model === 'demo-weak-1' ? { ...c, url: d.url } : c))).catch(() => {})
  }, [])

  const planned = useMemo(
    () => cases.filter((c) => cats.includes(c.category) || c.category === 'control'),
    [cases, cats]
  )

  const runCheck = async () => {
    setChecking(true); setCheck(null); setError('')
    try {
      setCheck(await api.probeCheck({ ...cfg, categories: cats }))
    } catch (e) {
      setError(e.message)
    } finally {
      setChecking(false)
    }
  }

  const run = async () => {
    setBusy(true); setError(''); setReport(null)
    try {
      setReport(await api.probeRun({ ...cfg, categories: cats }))
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  const proto = PROTOCOLS.find((p) => p.value === cfg.protocol)

  return (
    <div className="stack">
      <Banner kind="info">
        The probe sends real attack prompts to a real endpoint and reads what comes
        back. Only point it at a model you are authorised to test. Every case runs
        through AstraSec first, so the report can separate <em>what the endpoint did</em> from
        <em> what AstraSec would have stopped before it got there</em>.
      </Banner>

      {error && <Banner kind="err">{error}</Banner>}

      <div className="grid grid-2-1">
        {/* ------------------------------------------------- configuration */}
        <Card title="Target endpoint" sub="Where the attack battery will be sent">
          <div className="grid grid-2" style={{ gap: 0, columnGap: 18 }}>
            <label className="field">
              <span>Endpoint URL</span>
              <input type="url" value={cfg.url} onChange={(e) => set('url')(e.target.value)}
                     placeholder="https://api.example.com/v1/chat/completions" />
            </label>
            <label className="field">
              <span>Model name</span>
              <input type="text" value={cfg.model} onChange={(e) => set('model')(e.target.value)}
                     placeholder="gpt-4o-mini, llama3.1, …" />
            </label>
            <label className="field">
              <span>Protocol</span>
              <select value={cfg.protocol} onChange={(e) => set('protocol')(e.target.value)}>
                {PROTOCOLS.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
              </select>
              <div className="field-hint">{proto.hint}</div>
            </label>
            <label className="field">
              <span>API key <span className="muted">(sent as a bearer token; leave blank if not needed)</span></span>
              <input type="password" value={cfg.api_key} onChange={(e) => set('api_key')(e.target.value)}
                     placeholder="sk-…" autoComplete="off" />
              <div className="field-hint">
                Used for this request only — it is never written to the report or the audit log.
              </div>
            </label>
          </div>

          <label className="field">
            <span>System prompt the target runs with <span className="muted">(optional)</span></span>
            <textarea rows={4} value={cfg.system_prompt}
                      onChange={(e) => set('system_prompt')(e.target.value)}
                      placeholder="Paste the system prompt your application sends, so the probe tests the model as it is actually deployed." />
            <div className="field-hint">
              Without it you are testing the bare model. With it you are testing your
              application — which is the result that matters.
            </div>
          </label>

          <div className="row" style={{ gap: 10, marginBottom: 14 }}>
            <span className="muted" style={{ fontSize: 12.5 }}>No endpoint to hand?</span>
            <button className="btn btn-sm" type="button" onClick={useDemo}>
              <Link2 size={14} /> Use the built-in demo endpoint
            </button>
            <span className="field-hint" style={{ marginTop: 0 }}>
              A deliberately weak chatbot served by AstraSec itself — nothing else to start.
            </span>
          </div>

          <div className="row" style={{ gap: 10 }}>
            <button className="btn" onClick={runCheck} disabled={checking || busy} type="button">
              {checking ? <><Spinner size={15} /> Checking…</> : <><Plug size={15} /> Test connection</>}
            </button>
            <button className="btn btn-primary btn-lg" onClick={run} disabled={busy} type="button">
              {busy ? <><Spinner size={17} /> Running {planned.length} cases…</>
                    : <><Play size={17} /> Run the attack battery</>}
            </button>
          </div>

          {check && (
            <div style={{ marginTop: 16 }}>
              {check.reachable ? (
                <Banner kind="ok">
                  Reached the endpoint in {check.latency_ms} ms (HTTP {check.status_code}).
                  {check.warning
                    ? <> <strong>{check.warning}</strong></>
                    : <> Sample reply: <span className="mono">“{(check.sample_reply || '').slice(0, 160)}”</span></>}
                </Banner>
              ) : (
                <Banner kind="err">
                  Could not reach the endpoint: <span className="mono">{check.error}</span>
                </Banner>
              )}
            </div>
          )}
        </Card>

        {/* ------------------------------------------------------ battery */}
        <div className="stack">
          <Card title="Attack categories" sub="Benign controls always run, to catch over-blocking">
            <div className="stack-sm">
              {CATEGORIES.map((c) => (
                <Switch
                  key={c}
                  label={
                    <span className="row" style={{ gap: 8 }}>
                      <span className="legend-swatch" style={{ background: PROBE_CATEGORY_COLOR[c] }} />
                      {PROBE_CATEGORY_LABEL[c]}
                      <span className="muted tnum" style={{ fontSize: 12 }}>
                        {cases.filter((x) => x.category === c).length} cases
                      </span>
                    </span>
                  }
                  checked={cats.includes(c)}
                  onChange={(on) => setCats((p) => on ? [...new Set([...p, c])] : p.filter((x) => x !== c))}
                />
              ))}
            </div>
            <div className="field-hint" style={{ marginTop: 12 }}>
              {planned.length} cases will run
              {cfg.delay_seconds ? `, ${cfg.delay_seconds}s apart` : ''}.
            </div>
            <label className="field" style={{ marginTop: 14, marginBottom: 0 }}>
              <span>Delay between cases (seconds)</span>
              <input type="number" min={0} max={5} step={0.5} value={cfg.delay_seconds}
                     onChange={(e) => set('delay_seconds')(Number(e.target.value))} />
              <div className="field-hint">Raise this if the target rate-limits.</div>
            </label>
          </Card>

          <Card title="What each case asks" sub="Three questions per case">
            <ol className="stack-sm" style={{ paddingLeft: 20, fontSize: 14, lineHeight: 1.6 }}>
              <li className="secondary">Would AstraSec have blocked this before it reached the model?</li>
              <li className="secondary">What did the real endpoint actually reply?</li>
              <li className="secondary">Did that reply leak anything it shouldn't have?</li>
            </ol>
            <div className="field-hint" style={{ marginTop: 12 }}>
              A case only counts as a leak when the reply <em>complies</em> or trips an
              output-side signature. A refusal is not a leak, and a control case is
              never one — it is supposed to be answered.
            </div>
          </Card>
        </div>
      </div>

      {report && <ProbeResults report={report} view={view} setView={setView} />}
    </div>
  )
}

/* -------------------------------------------------------------------------- */
function ProbeResults({ report, view, setView }) {
  const [open, setOpen] = useState(null)
  const gradeColor = GRADE_COLOR[report.grade] || 'var(--text-muted)'
  const rows = report.cases.filter((c) =>
    view === 'attacks' ? c.category !== 'control'
      : view === 'controls' ? c.category === 'control' : true)

  return (
    <div className="stack">
      <Card
        title="Endpoint security report"
        sub={`${report.endpoint} · ${report.model || report.protocol} · ${report.probe_id}`}
        actions={
          report.used_system_prompt
            ? <span className="badge"><ShieldCheck size={12} /> Tested with your system prompt</span>
            : <span className="badge"><AlertTriangle size={12} /> Bare model — no system prompt</span>
        }
      >
        {!report.conclusive && (
          <div style={{ marginBottom: 18 }}>
            <Banner kind="err">
              <strong>No result.</strong> Every one of the {num(report.attacks_run)} attack
              requests failed before the endpoint answered, so there is nothing to grade —
              this is <em>not</em> a clean bill of health.
              {report.error_summary && <div className="evidence-line" style={{ margin: '8px 0' }}>{report.error_summary}</div>}
              Check the URL, protocol and API key with <strong>Test connection</strong>, or use
              the built-in demo endpoint, then run the battery again.
            </Banner>
          </div>
        )}
        {report.conclusive && report.errors > 0 && (
          <div style={{ marginBottom: 18 }}>
            <Banner kind="warn">
              {num(report.errors)} request{report.errors === 1 ? '' : 's'} failed and
              {report.errors === 1 ? ' is' : ' are'} excluded from the grade, which covers
              the {num(report.attacks_answered)} attack{report.attacks_answered === 1 ? '' : 's'} the
              endpoint actually answered.
            </Banner>
          </div>
        )}

        <div className="grid grid-1-2" style={{ alignItems: 'center' }}>
          <div style={{ display: 'grid', placeItems: 'center', gap: 14 }}>
            <GradeBadge grade={report.grade} />
            <div className="muted" style={{ fontSize: 13, textAlign: 'center' }}>
              {report.conclusive
                ? `${pct(1 - report.vulnerability_rate, 0)} of answered attacks held`
                : 'Endpoint never answered'}
            </div>
          </div>
          <div className="stack-sm">
            <div className="section-title">What happened</div>
            <p className="secondary" style={{ fontSize: 14.5, lineHeight: 1.65, margin: 0 }}>
              {!report.conclusive ? (
                <>
                  The battery ran, but none of it reached a model. Every request failed with
                  a transport or HTTP error, so the endpoint's security posture is unknown.
                  AstraSec's own verdicts below are still valid — they are computed before the
                  endpoint is called — but nothing here says what your model would have done.
                </>
              ) : report.vulnerable === 0 ? (
                <>The endpoint refused or deflected all {num(report.attacks_run)} attack prompts.
                  {report.false_positives > 0 && (
                    <> However, AstraSec blocked {report.false_positives} benign control
                    case{report.false_positives === 1 ? '' : 's'} — worth reviewing, since
                    over-blocking costs real users.</>
                  )}</>
              ) : (
                <>
                  <strong>{num(report.vulnerable)}</strong> of {num(report.attacks_run)} attack
                  prompts got a compliant or leaking reply out of the live endpoint.
                  {report.prevented_leaks > 0 && (
                    <> AstraSec would have blocked <strong>{num(report.prevented_leaks)}</strong> of
                    them — {pct(report.prevention_rate, 0)} of the successful attacks — before
                    the model ever saw the prompt.</>
                  )}
                  {report.prevented_leaks === 0 && report.vulnerable > 0 && (
                    <> None of them were caught by AstraSec either, which is the honest
                    result: these are the cases the detection layer needs to learn.</>
                  )}
                </>
              )}
            </p>
            <div className="row" style={{ gap: 8, marginTop: 6 }}>
              <span className="chip">{num(report.cases_run)} cases in {report.duration_seconds}s</span>
              {report.errors > 0 && <span className="chip">{num(report.errors)} request errors</span>}
              <span className="chip">{num(report.controls_answered)}/{num(report.controls_run)} controls answered</span>
            </div>
          </div>
        </div>
      </Card>

      <div className="grid grid-4">
        <StatTile label="Leaked at the endpoint" value={num(report.vulnerable)} icon={ShieldX}
                  tone={report.vulnerable ? 'critical' : 'good'}
                  meter={report.vulnerability_rate * 100}
                  foot={`${pct(report.vulnerability_rate, 1)} of attacks`} />
        <StatTile label="Prevented by AstraSec" value={num(report.prevented_leaks)} icon={ShieldCheck}
                  tone={report.prevented_leaks ? 'good' : undefined}
                  meter={(report.prevention_rate ?? 0) * 100}
                  foot={report.prevention_rate === null
                    ? 'Nothing leaked, so nothing to prevent'
                    : `${pct(report.prevention_rate, 0)} of the successful attacks`} />
        <StatTile label="Model refused" value={num(report.refused)} icon={CheckCircle2}
                  meter={report.refusal_rate * 100}
                  foot={report.errors
                    ? `${pct(report.refusal_rate, 1)} of answered · ${num(report.errors)} request errors`
                    : `${pct(report.refusal_rate, 1)} refusal rate`} />
        <StatTile label="False positives" value={num(report.false_positives)} icon={AlertTriangle}
                  tone={report.false_positives ? 'warning' : 'good'}
                  foot={`Benign controls AstraSec blocked, of ${num(report.controls_run)}`} />
      </div>

      <Card title="Outcome by attack category"
            sub="Grouped rather than stacked — the comparison that matters is how many of each category got through">
        <ProbeCategoryBars byCategory={report.by_category} />
      </Card>

      <Card
        title="Every case"
        sub="Click a row to read the prompt sent and the reply that came back"
        actions={
          <ToggleGroup
            value={view}
            onChange={setView}
            options={[
              { value: 'attacks', label: `Attacks ${report.attacks_run}` },
              { value: 'controls', label: `Controls ${report.controls_run}` },
              { value: 'all', label: `All ${report.cases_run}` },
            ]}
          />
        }
      >
        {!rows.length ? <Empty>No cases in this view.</Empty> : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Case</th><th>Category</th><th>Objective</th>
                  <th>AstraSec</th><th>Endpoint</th><th>Leak signatures</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((c) => (
                  <React.Fragment key={c.case_id}>
                    <tr className="clickable" onClick={() => setOpen(open === c.case_id ? null : c.case_id)}>
                      <td className="mono nowrap">{c.case_id}</td>
                      <td>
                        <span className="legend-item">
                          <span className="legend-swatch"
                                style={{ background: PROBE_CATEGORY_COLOR[c.category] }} />
                          {PROBE_CATEGORY_LABEL[c.category] || titleCase(c.category)}
                        </span>
                      </td>
                      <td className="secondary">{c.objective}</td>
                      <td>
                        {c.astrasec_action ? (
                          <span className="badge" style={{
                            color: c.astrasec_blocked ? 'var(--status-good)' : 'var(--text-muted)',
                            borderColor: c.astrasec_blocked ? 'var(--status-good)' : 'var(--border-strong)',
                          }}>
                            {c.astrasec_blocked ? <ShieldCheck size={12} /> : <Zap size={12} />}
                            {c.astrasec_blocked ? 'Blocked' : titleCase(c.astrasec_action)}
                          </span>
                        ) : <span className="muted">—</span>}
                      </td>
                      <td><OutcomePill value={c.outcome} /></td>
                      <td>
                        {c.leak_signatures?.length
                          ? c.leak_signatures.map((s) => <span className="chip" key={s}>{s}</span>)
                          : <span className="muted">—</span>}
                      </td>
                    </tr>
                    {open === c.case_id && (
                      <tr>
                        <td colSpan={6} style={{ background: 'var(--surface-2)' }}>
                          <div className="stack-sm" style={{ padding: '10px 2px' }}>
                            <div>
                              <div className="section-title">Prompt sent</div>
                              <div className="prompt-box">{c.prompt}</div>
                            </div>
                            <div>
                              <div className="section-title">Reply from the endpoint</div>
                              <div className={`prompt-box ${c.outcome === 'vulnerable' ? 'blocked'
                                : c.outcome === 'refused' ? 'clean' : ''}`}>
                                {c.error
                                  ? <span className="muted">{c.error}</span>
                                  : (c.reply || <span className="muted">(empty reply)</span>)}
                              </div>
                            </div>
                            {!!c.leak_detail?.length && (
                              <div>
                                <div className="section-title">What leaked</div>
                                <div className="stack-sm">
                                  {c.leak_detail.map((d) => (
                                    <div className="row" key={d.id} style={{ gap: 10 }}>
                                      <span className="chip">{d.id}</span>
                                      <SeverityBadge value={d.severity} />
                                      <span className="secondary">{d.description}</span>
                                      {d.owasp && <span className="chip chip-brand">{d.owasp}</span>}
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                            {c.astrasec_class && (
                              <div className="row" style={{ gap: 10 }}>
                                <span className="muted">AstraSec read this as</span>
                                <ThreatBadge value={c.astrasec_class} />
                                <SeverityBadge value={c.astrasec_severity} />
                                <span className="tnum muted" style={{ fontSize: 12.5 }}>
                                  {(c.astrasec_confidence * 100).toFixed(1)}% confidence
                                </span>
                                {c.astrasec_signatures?.map((s) => <span className="chip" key={s}>{s}</span>)}
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  )
}
