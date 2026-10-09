import React, { useMemo, useRef, useState } from 'react'
import { Download, FileCode2, Play, Upload } from 'lucide-react'
import { api } from '../lib/api'
import {
  BandBadge, Banner, Card, Empty, GradeBadge, OutcomePill, SeverityBadge, Spinner,
  StatTile, Switch,
} from '../components/ui'
import { ScoreRing, SeverityStrip, SurfaceRiskBars } from '../components/charts'
import {
  GRADE_COLOR, SURFACE_COLOR, SURFACE_LABEL, num, pct, titleCase,
} from '../lib/viz'

/* Each switch: [key, label, what it means]. The import fills these from the
 * app's own code and shows the line that justified each one. */
const POSTURE = [
  ['system_prompt_protected', 'System prompt is isolated from user input',
   'Sent as its own system message, never formatted together with what the user typed.'],
  ['output_filtering_enabled', 'Replies are filtered before they reach the user',
   'Catches a leak even after the model has been talked into producing one.'],
  ['pii_redaction_enabled', 'Personal data is redacted', ''],
  ['authentication_required', 'Callers must authenticate', ''],
  ['rate_limiting_enabled', 'Requests are rate limited',
   'Model-extraction attacks need volume; a rate limit is the cheapest defence against them.'],
  ['logging_enabled', 'Requests and replies are logged', ''],
  ['sandbox_enabled', 'Tool or code execution is sandboxed', ''],
  ['tool_calling_enabled', 'The app can call tools / functions',
   'Raises the stakes: a successful injection can now act, not just talk.'],
  ['retrieval_enabled', 'The app retrieves documents (RAG)',
   'Raises the stakes: retrieved text is untrusted input the user never typed.'],
]

const DEFAULT_APP = {
  app_id: 'my-app',
  app_name: 'My AI application',
  model_name: '',
  system_prompt_protected: true,
  output_filtering_enabled: false,
  tool_calling_enabled: false,
  retrieval_enabled: false,
  pii_redaction_enabled: false,
  authentication_required: true,
  logging_enabled: true,
  rate_limiting_enabled: false,
  sandbox_enabled: true,
  dependencies: [],
  known_vulnerable_dependencies: [],
  last_security_review_days: 30,
}

const PROTOCOLS = [
  ['openai', 'OpenAI-compatible (/v1/chat/completions)'],
  ['ollama', 'Ollama (/api/chat)'],
  ['raw', 'Raw JSON {"prompt": …}'],
]

const list = (s) => s.split(/[,\n]/).map((x) => x.trim()).filter(Boolean)

export default function Audit() {
  const [prompt, setPrompt] = useState('')
  const [sample, setSample] = useState('')
  const [app, setApp] = useState(DEFAULT_APP)
  const [deps, setDeps] = useState('')
  const [vulnDeps, setVulnDeps] = useState('')
  const [source, setSource] = useState(null)
  const [importing, setImporting] = useState(false)
  const [liveOn, setLiveOn] = useState(false)
  const [endpoint, setEndpoint] = useState({ url: '', protocol: 'openai', model: '', api_key: '' })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [report, setReport] = useState(null)
  const fileRef = useRef(null)
  const resultRef = useRef(null)

  const set = (k) => (v) => setApp((a) => ({ ...a, [k]: v }))
  const setEp = (k) => (v) => setEndpoint((e) => ({ ...e, [k]: v }))

  const applyImport = (imp) => {
    setSource(imp)
    const best = imp.prompts?.[0]
    if (best) setPrompt(best.text)
    setApp((a) => ({
      ...a,
      ...imp.suggested_app,
      app_id: (imp.app_name || 'imported-app').toLowerCase().replace(/[^a-z0-9]+/g, '-'),
      app_name: imp.app_name || a.app_name,
      model_name: imp.model_name || a.model_name,
    }))
    setDeps((imp.suggested_app.dependencies || []).join(', '))
    setVulnDeps((imp.suggested_app.known_vulnerable_dependencies || []).join(', '))
    setReport(null)
  }

  const onFile = async (file) => {
    if (!file) return
    setImporting(true); setError('')
    try {
      applyImport(await api.auditImport(file))
    } catch (e) {
      setError(`Could not import ${file.name}: ${e.message}`)
    } finally {
      setImporting(false)
      if (fileRef.current) fileRef.current.value = ''
    }
  }

  const loadSample = async () => {
    setImporting(true); setError('')
    try { applyImport(await api.auditSampleApp()) } catch (e) { setError(e.message) }
    finally { setImporting(false) }
  }

  const loadDemo = async () => {
    setError('')
    try {
      const d = await api.auditDemoApp()
      setSource(null)
      setPrompt(d.system_prompt)
      setApp(d.app)
      setDeps(''); setVulnDeps('')
      setEndpoint(d.endpoint)
      setLiveOn(true)
      setReport(null)
    } catch (e) { setError(e.message) }
  }

  const run = async () => {
    if (liveOn && !endpoint.url.trim()) {
      setError('Enter the endpoint URL, or switch off the live test.')
      return
    }
    setBusy(true); setError(''); setReport(null)
    try {
      const r = await api.audit({
        system_prompt: prompt,
        sample_response: sample,
        source,
        endpoint: liveOn ? endpoint : null,
        app: { ...app, dependencies: list(deps), known_vulnerable_dependencies: list(vulnDeps) },
      })
      setReport(r)
      setTimeout(() => resultRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 50)
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  const words = prompt.trim() ? prompt.trim().split(/\s+/).length : 0

  return (
    <div className="stack">
      {error && <Banner kind="err">{error}</Banner>}

      <div className="steps">
        <div className={`step ${source ? 'done' : ''}`}>
          <div className="step-n">STEP 1 · RECOMMENDED</div>
          <div className="step-title">Import the app's source</div>
          <div className="step-body">
            Upload a zip of the project, or one file. AstraSec finds the system prompt,
            hard-coded secrets, dependencies and security controls in the code itself.
          </div>
          <div className="row" style={{ marginTop: 10, gap: 8 }}>
            <input ref={fileRef} type="file" hidden
                   accept=".zip,.py,.js,.ts,.tsx,.jsx,.mjs,.java,.go,.rb,.php,.cs,.ipynb,.json,.yaml,.yml,.toml,.txt,.md,.env"
                   onChange={(e) => onFile(e.target.files?.[0])} />
            <button className="btn btn-sm btn-primary" type="button" disabled={importing}
                    onClick={() => fileRef.current?.click()}>
              {importing ? <><Spinner size={13} /> Reading…</> : <><Upload size={14} /> Upload source</>}
            </button>
            <button className="btn btn-sm" type="button" disabled={importing} onClick={loadSample}>
              Try the sample app
            </button>
          </div>
        </div>
        <div className={`step ${prompt ? 'done' : ''}`}>
          <div className="step-n">STEP 2</div>
          <div className="step-title">Confirm prompt and settings</div>
          <div className="step-body">
            Check the prompt and switches below match what is deployed. Imported switches
            show the line of code behind them; anything not found is left off for you to confirm.
          </div>
        </div>
        <div className={`step ${liveOn && endpoint.url ? 'done' : ''}`}>
          <div className="step-n">STEP 3 · OPTIONAL</div>
          <div className="step-title">Attack the running app</div>
          <div className="step-body">
            Give the app's chat endpoint and the audit also sends the 19-case attack
            battery and scores what it actually did.
          </div>
          <div className="row" style={{ marginTop: 10 }}>
            <button className="btn btn-sm" type="button" onClick={loadDemo}>
              Audit the built-in demo app
            </button>
          </div>
        </div>
      </div>

      {source && <ImportSummary source={source} onPick={setPrompt} current={prompt} />}

      <div className="grid grid-2-1">
        <div className="stack">
          <Card title="System prompt"
                sub="What the model is told before every conversation — the surface a user reaches directly">
            <label className="field">
              <textarea rows={12} value={prompt} onChange={(e) => setPrompt(e.target.value)}
                        placeholder="Paste the system prompt, or import the app's source above." />
              <div className="field-hint">
                {num(prompt.length)} characters · {num(words)} words · ≈{num(Math.round(prompt.length / 4))} tokens
              </div>
            </label>
            <label className="field" style={{ marginBottom: 0 }}>
              <span>A real reply from the app <span className="muted">(optional)</span></span>
              <textarea rows={3} value={sample} onChange={(e) => setSample(e.target.value)}
                        placeholder="Paste a response you suspect says too much." />
            </label>
          </Card>

          <Card title="Live test"
                sub="Sends real attack prompts to the app — only use it on an app you are allowed to test"
                actions={<Switch label="Include" checked={liveOn} onChange={setLiveOn} />}>
            <div className="grid grid-2" style={{ opacity: liveOn ? 1 : 0.55 }}>
              <label className="field" style={{ gridColumn: '1 / -1' }}>
                <span>Endpoint URL</span>
                <input type="url" value={endpoint.url} disabled={!liveOn}
                       onChange={(e) => setEp('url')(e.target.value)}
                       placeholder="http://localhost:8000/v1/chat/completions" />
              </label>
              <label className="field">
                <span>Protocol</span>
                <select value={endpoint.protocol} disabled={!liveOn}
                        onChange={(e) => setEp('protocol')(e.target.value)}>
                  {PROTOCOLS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                </select>
              </label>
              <label className="field">
                <span>Model</span>
                <input type="text" value={endpoint.model} disabled={!liveOn}
                       onChange={(e) => setEp('model')(e.target.value)} placeholder="gpt-4o-mini" />
              </label>
              <label className="field" style={{ gridColumn: '1 / -1', marginBottom: 0 }}>
                <span>API key <span className="muted">(sent only to that endpoint, never stored)</span></span>
                <input type="password" value={endpoint.api_key} disabled={!liveOn}
                       onChange={(e) => setEp('api_key')(e.target.value)} />
              </label>
            </div>
          </Card>

          <div className="row">
            <button className="btn btn-primary btn-lg" onClick={run} disabled={busy} type="button">
              {busy
                ? <><Spinner size={16} /> {liveOn ? 'Auditing and attacking…' : 'Auditing…'}</>
                : <><Play size={16} /> Run the audit</>}
            </button>
            <span className="muted" style={{ fontSize: 12.5 }}>
              {[source && 'source code', 'prompt', 'settings', 'dependencies', liveOn && 'live behaviour']
                .filter(Boolean).join(' · ')}
            </span>
          </div>
        </div>

        <div className="stack">
          <Card title="Application">
            <label className="field">
              <span>Name</span>
              <input type="text" value={app.app_name} onChange={(e) => set('app_name')(e.target.value)} />
            </label>
            <label className="field" style={{ marginBottom: 0 }}>
              <span>Model</span>
              <input type="text" value={app.model_name} onChange={(e) => set('model_name')(e.target.value)} />
            </label>
          </Card>

          <Card title="Deployment settings" sub="Set these to what is actually deployed">
            <div className="stack-sm">
              {POSTURE.map(([key, label, hint]) => {
                const ev = source?.posture?.[key]
                return (
                  <div key={key}>
                    <Switch label={label} hint={hint} checked={app[key]} onChange={set(key)} />
                    {source && key !== 'system_prompt_protected' && (
                      <div className="field-hint" style={{ marginLeft: 27, marginTop: 0 }}>
                        {ev?.detected
                          ? <>Found at <span className="mono">{ev.evidence.location}</span></>
                          : 'Not found in the code — confirm by hand'}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
            <label className="field" style={{ marginTop: 14 }}>
              <span>Days since the last security review</span>
              <input type="number" min={0} max={3650} value={app.last_security_review_days}
                     onChange={(e) => set('last_security_review_days')(Number(e.target.value))} />
            </label>
            <label className="field">
              <span>Dependencies</span>
              <textarea rows={2} value={deps} onChange={(e) => setDeps(e.target.value)}
                        placeholder="openai==1.40.0, langchain==0.2.1" />
            </label>
            <label className="field" style={{ marginBottom: 0 }}>
              <span>Known vulnerable</span>
              <textarea rows={2} value={vulnDeps} onChange={(e) => setVulnDeps(e.target.value)}
                        placeholder="Filled in from the advisory list on import" />
            </label>
          </Card>
        </div>
      </div>

      <div ref={resultRef}>{report && <AuditResults report={report} />}</div>
    </div>
  )
}

/* -------------------------------------------------------------------------- */
function ImportSummary({ source, onPick, current }) {
  const vulnerable = source.dependencies.filter((d) => d.advisories.some((a) => a.certain))
  return (
    <Card title={`Imported ${source.filename}`}
          sub={`${num(source.files_scanned)} file${source.files_scanned === 1 ? '' : 's'} read · nothing was executed`}
          actions={source.filename === 'acme_travel_bot.zip' && (
            <a className="btn btn-sm" href={api.auditSampleZipUrl()}>
              <Download size={14} /> Download sample
            </a>
          )}>
      <div className="grid grid-4" style={{ marginBottom: 14 }}>
        <Mini label="System prompts found" value={source.prompts.length} />
        <Mini label="Hard-coded secrets" value={source.secrets.length}
              tone={source.secrets.length ? 'critical' : 'good'} />
        <Mini label="Dependencies" value={source.dependencies.length}
              sub={vulnerable.length ? `${vulnerable.length} with a known advisory` : 'none with a known advisory'}
              tone={vulnerable.length ? 'serious' : undefined} />
        <Mini label="Code, API & AI issues" value={source.code_risks.length + (source.code_findings || []).length}
              tone={source.code_risks.length + (source.code_findings || []).length ? 'serious' : 'good'} />
      </div>

      {source.prompts.length > 1 && (
        <div style={{ marginBottom: 12 }}>
          <div className="card-sub" style={{ marginBottom: 6 }}>
            Several prompts were found. The most likely one is loaded — pick another if it is wrong.
          </div>
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Location</th><th>Found in</th><th className="num">Words</th><th /></tr></thead>
              <tbody>
                {source.prompts.map((p) => (
                  <tr key={p.location}>
                    <td className="mono">{p.location}</td>
                    <td>{p.source}</td>
                    <td className="num">{p.words}</td>
                    <td style={{ textAlign: 'right' }}>
                      {p.text === current
                        ? <span className="badge">In use</span>
                        : <button className="btn btn-sm" type="button" onClick={() => onPick(p.text)}>Use</button>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {(source.secrets.length > 0 || source.code_risks.length > 0 || (source.code_findings || []).length > 0) && (
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Found</th><th>Where</th><th>Detail</th></tr></thead>
            <tbody>
              {source.secrets.map((s) => (
                <tr key={s.location + s.preview}>
                  <td><SeverityBadge value="critical" /> {s.kind}</td>
                  <td className="mono">{s.location}</td>
                  <td className="mono">{s.preview}</td>
                </tr>
              ))}
              {source.code_risks.map((r) => (
                <tr key={r.location + r.kind}>
                  <td><SeverityBadge value={r.kind === 'user_input_in_system_prompt' ? 'critical' : 'high'} />{' '}
                    {r.kind === 'user_input_in_system_prompt' ? 'User input inside the system prompt' : 'Code / shell execution'}</td>
                  <td className="mono">{r.location}</td>
                  <td className="mono">{r.line}</td>
                </tr>
              ))}
              {(source.code_findings || []).map((r) => (
                <tr key={r.code + r.location}>
                  <td><SeverityBadge value={r.severity} /> {r.title}</td>
                  <td className="mono">{r.location || '—'}</td>
                  <td className="mono">{r.line || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {source.prompts.length === 0 && (
        <Banner kind="warn">
          No system prompt was found in the code. If it is loaded from a database or a
          remote config, paste it into the box below.
        </Banner>
      )}
    </Card>
  )
}

function Mini({ label, value, sub, tone }) {
  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '10px 12px' }}>
      <div className="stat-label">{label}</div>
      <div className="stat-value" style={{ fontSize: 22, color: tone ? `var(--status-${tone})` : undefined }}>
        {num(value)}
      </div>
      {sub && <div className="stat-foot" style={{ marginTop: 2 }}>{sub}</div>}
    </div>
  )
}

/* -------------------------------------------------------------------------- */
function AuditResults({ report }) {
  const [surface, setSurface] = useState('')
  const [open, setOpen] = useState(null)
  const gradeColor = GRADE_COLOR[report.grade] || 'var(--text-muted)'

  const bySurface = useMemo(() => {
    const m = {}
    for (const f of report.findings) m[f.surface] = (m[f.surface] || 0) + 1
    return m
  }, [report])

  const visible = surface ? report.findings.filter((f) => f.surface === surface) : report.findings
  const live = report.live
  const worst = Object.entries(report.surface_scores)
    .sort((a, b) => b[1] * (report.surface_weights?.[b[0]] || 0) - a[1] * (report.surface_weights?.[a[0]] || 0))[0]

  return (
    <div className="stack">
      <Card title={`${report.app_name} — audit result`}
            sub={`${report.model_name || 'model not set'} · ${report.audit_id} · ${report.duration_seconds}s · saved to Reports`}
            actions={<BandBadge value={report.band} />}>
        <div className="grid grid-1-2" style={{ alignItems: 'center' }}>
          <div style={{ display: 'grid', placeItems: 'center', gap: 12 }}>
            <ScoreRing value={report.posture_score} label={String(report.posture_score)}
                       color={gradeColor} caption="Posture score / 100" />
            <GradeBadge grade={report.grade} size="sm" />
          </div>
          <div className="stack-sm">
            <p className="secondary" style={{ fontSize: 14, lineHeight: 1.6, margin: 0 }}>
              {report.counts.total === 0
                ? 'Every check passed on every surface that was assessed.'
                : <>
                    {num(report.counts.total)} issue{report.counts.total === 1 ? '' : 's'}
                    {report.counts.critical > 0 && <>, <strong>{report.counts.critical} critical</strong></>}.
                    {worst && <> The largest share of the risk is in the <strong>{(SURFACE_LABEL[worst[0]] || worst[0]).toLowerCase()}</strong>.</>}
                    {live?.conclusive && <> Under a live attack the app gave way on{' '}
                      <strong>{live.vulnerable} of {live.attacks_answered}</strong> attempts.</>}
                  </>}
            </p>
            <SeverityStrip counts={report.counts} />
            <dl className="kv" style={{ marginTop: 6 }}>
              <dt>Surfaces assessed</dt>
              <dd>{Object.keys(report.surface_scores).map((k) => SURFACE_LABEL[k] || titleCase(k)).join(', ')}</dd>
              {report.source && <><dt>Source</dt>
                <dd>{report.source.filename} · {num(report.source.files_scanned)} files</dd></>}
              {live && <><dt>Live endpoint</dt>
                <dd className="mono truncate">{live.endpoint}</dd></>}
            </dl>
          </div>
        </div>
      </Card>

      {report.category_scores && (
        <Card title="Security report card" sub="Each area scored out of 100 — every finding takes a share of what is left">
          <div className="stack-sm">
            {report.category_scores.map((c) => (
              <div key={c.key} className="rb-row" style={{ gridTemplateColumns: 'minmax(160px, 26%) 1fr 48px 150px' }}>
                <div className="rb-label" style={{ color: 'var(--text-primary)' }}>{c.label}</div>
                <div className="barlist-track">{c.assessed && <div className="barlist-fill"
                  style={{ width: `${Math.max(2, c.score)}%`,
                           background: c.score >= 78 ? 'var(--status-good)' : c.score >= 62 ? 'var(--status-warning)'
                             : c.score >= 45 ? 'var(--status-serious)' : 'var(--status-critical)' }} />}</div>
                <div className="barlist-value tnum">{c.assessed ? Math.round(c.score) : '—'}</div>
                <div className="muted" style={{ fontSize: 12.5 }}>
                  {!c.assessed ? 'Import source to assess' : c.findings
                    ? <>{c.findings} finding{c.findings === 1 ? '' : 's'} · worst <SeverityBadge value={c.worst} /></>
                    : 'No findings'}
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      <div className="grid grid-4">
        <StatTile label="Posture score" value={report.posture_score}
                  tone={report.posture_score >= 78 ? 'good' : report.posture_score >= 62 ? 'warning' : 'critical'}
                  foot="100 means no risk found on any assessed surface" />
        <StatTile label="Critical and high" value={num(report.counts.critical + report.counts.high)}
                  tone={(report.counts.critical + report.counts.high) ? 'critical' : 'good'}
                  foot="Fix these before the app goes live" />
        <StatTile label="Live attacks that worked"
                  value={live ? (live.conclusive ? `${live.vulnerable}/${live.attacks_answered}` : 'No response') : 'Not run'}
                  tone={live?.conclusive ? (live.vulnerable ? 'critical' : 'good') : undefined}
                  foot={live?.conclusive
                    ? `${pct(live.vulnerability_rate, 0)} of answered attacks leaked or complied`
                    : live ? 'The endpoint never answered — left out of the score' : 'Add an endpoint to include live behaviour'} />
        <StatTile label="Blocked by AstraSec"
                  value={live?.conclusive && live.vulnerable ? `${live.prevented_leaks}/${live.vulnerable}` : '—'}
                  foot="Of the attacks that worked, how many the gateway would have stopped first" />
      </div>

      <div className="grid grid-2">
        <Card title="Risk by surface" sub="Bar length is the risk on that surface">
          <SurfaceRiskBars surfaceScores={report.surface_scores} weights={report.surface_weights} />
        </Card>
        <Card title="Findings by surface" sub="Select one to filter the table">
          <div className="stack-sm">
            {Object.entries(bySurface).map(([k, n]) => (
              <button key={k} type="button"
                      className={`btn ${surface === k ? 'btn-primary' : ''}`}
                      style={{ justifyContent: 'flex-start', width: '100%' }}
                      onClick={() => setSurface(surface === k ? '' : k)}>
                <span className="legend-swatch" style={{ background: SURFACE_COLOR[k] }} />
                {SURFACE_LABEL[k] || titleCase(k)}
                <span className="spacer" />
                <span className="tnum">{n}</span>
              </button>
            ))}
          </div>
        </Card>
      </div>

      <Card title={`Findings (${visible.length})`} sub="Most severe first. Select a row for the evidence and the fix.">
        {!visible.length ? <Empty>Nothing found{surface ? ' on this surface' : ''}.</Empty> : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr><th>Severity</th><th>Check</th><th>Finding</th><th>Surface</th></tr>
              </thead>
              <tbody>
                {visible.map((f, i) => {
                  const key = `${f.code}-${i}`
                  return (
                    <React.Fragment key={key}>
                      <tr className="clickable" onClick={() => setOpen(open === key ? null : key)}>
                        <td><SeverityBadge value={f.severity} /></td>
                        <td className="mono nowrap">{f.code}</td>
                        <td style={{ color: 'var(--text-primary)' }}>{f.title}</td>
                        <td className="nowrap">
                          <span className="legend-swatch" style={{ background: SURFACE_COLOR[f.surface], display: 'inline-block', marginRight: 6, verticalAlign: -1 }} />
                          {SURFACE_LABEL[f.surface] || titleCase(f.surface)}
                        </td>
                      </tr>
                      {open === key && (
                        <tr>
                          <td colSpan={4} style={{ background: 'var(--surface-2)' }}>
                            <div className="stack-sm" style={{ padding: '4px 0' }}>
                              <div><span className="muted">Evidence</span>
                                <div className="evidence-line" style={{ marginTop: 4 }}>{f.evidence}</div></div>
                              <div><span className="muted">Fix</span>
                                <div style={{ marginTop: 4 }}>{f.remediation}</div></div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {report.live_cases && live?.conclusive && (
        <Card title="Live attack transcript"
              sub={`${live.attacks_run} attacks and ${report.live_cases.length - live.attacks_run} normal requests sent to ${live.endpoint}`}>
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Case</th><th>Attack</th><th>Outcome</th><th>AstraSec</th><th>Reply (start)</th></tr></thead>
              <tbody>
                {report.live_cases.map((c) => (
                  <tr key={c.case_id}>
                    <td className="mono">{c.case_id}</td>
                    <td>{c.objective}</td>
                    <td><OutcomePill value={c.outcome} /></td>
                    <td className="nowrap">{c.astrasec_blocked ? 'Would block' : 'Would allow'}</td>
                    <td className="mono" style={{ maxWidth: 360 }}>
                      <div className="truncate">{c.error || c.reply}</div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  )
}
