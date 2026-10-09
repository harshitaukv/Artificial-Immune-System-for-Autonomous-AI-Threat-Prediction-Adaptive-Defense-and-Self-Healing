import React, { useEffect, useState } from 'react'
import { ExternalLink } from 'lucide-react'
import { api } from '../lib/api'
import { ACTION_LABEL, ACTION_ORDER, ACTION_RAMP } from '../lib/viz'
import { Banner, Card, Spinner, Switch } from '../components/ui'

const PROVIDERS = [
  ['auto', 'Automatic (recommended)'],
  ['ollama', 'Local model through Ollama (e.g. Llama 3.1)'],
  ['openai_compatible', 'Hosted API (OpenAI, Groq, Together…)'],
  ['offline', 'AstraBot assistant only'],
]
const BAND_KEYS = ['allow', 'monitor', 'sanitize', 'rate_limit', 'block']

export default function BotPolicy() {
  const [cfg, setCfg] = useState(null)
  const [pol, setPol] = useState(null)
  const [apiKey, setApiKey] = useState('')
  const [msg, setMsg] = useState(null)
  const [busy, setBusy] = useState('')

  useEffect(() => {
    Promise.all([api.soc.botConfig(), api.soc.policy()])
      .then(([c, p]) => { setCfg(c); setPol(p) })
      .catch((e) => setMsg({ kind: 'err', text: e.message }))
  }, [])

  if (!cfg || !pol) return msg ? <Banner kind={msg.kind}>{msg.text}</Banner> : <div className="row"><Spinner /> Loading…</div>

  const setC = (k) => (v) => setCfg((c) => ({ ...c, [k]: v }))
  const setP = (k) => (v) => setPol((p) => ({ ...p, [k]: v }))
  const setBand = (k, v) => setPol((p) => ({ ...p, bands: { ...p.bands, [k]: v } }))

  const saveBot = async () => {
    setBusy('bot'); setMsg(null)
    try {
      const body = { ...cfg }
      if (apiKey) body.api_key = apiKey
      const d = await api.soc.saveBotConfig(body)
      setCfg(d); setApiKey('')
      setMsg({ kind: 'ok', text: `AstraBot saved. Answering with ${d.resolved_label}.` })
    } catch (e) { setMsg({ kind: 'err', text: e.message }) } finally { setBusy('') }
  }
  const clearKey = async () => {
    setBusy('bot')
    try { setCfg(await api.soc.saveBotConfig({ clear_api_key: true })) } finally { setBusy('') }
  }
  const savePolicy = async () => {
    setBusy('pol'); setMsg(null)
    try {
      const body = { ...pol, allowed_public_values: typeof pol.allowed_public_values === 'string'
        ? pol.allowed_public_values.split(/[\n,]/).map((s) => s.trim()).filter(Boolean) : pol.allowed_public_values }
      setPol(await api.soc.savePolicy(body))
      setMsg({ kind: 'ok', text: 'Security policy saved. It applies to the next request.' })
    } catch (e) { setMsg({ kind: 'err', text: e.message }) } finally { setBusy('') }
  }

  const b = pol.bands
  const bounds = [0, ...BAND_KEYS.map((k) => b[k]), 100]
  const allowed = Array.isArray(pol.allowed_public_values) ? pol.allowed_public_values.join(', ') : pol.allowed_public_values

  return (
    <div className="stack">
      {msg && <Banner kind={msg.kind}>{msg.text}</Banner>}
      <div className="grid grid-2">
        <Card title="AstraBot" sub="The chatbot AstraSec protects"
              actions={<a className="btn btn-sm" href="/bot" target="_blank" rel="noreferrer">Open <ExternalLink size={13} /></a>}>
          <div className="kv-grid">
            <div><span>Answering with</span><b>{cfg.resolved_label}</b></div>
          </div>
          <div className="grid grid-2" style={{ marginTop: 14 }}>
            <label className="field"><span>Name</span>
              <input type="text" value={cfg.name} onChange={(e) => setC('name')(e.target.value)} /></label>
            <label className="field"><span>Tagline</span>
              <input type="text" value={cfg.tagline} onChange={(e) => setC('tagline')(e.target.value)} /></label>
          </div>
          <label className="field"><span>Greeting</span>
            <textarea rows={2} value={cfg.greeting} onChange={(e) => setC('greeting')(e.target.value)} /></label>
          <label className="field"><span>System prompt</span>
            <textarea rows={9} value={cfg.system_prompt} onChange={(e) => setC('system_prompt')(e.target.value)} />
            <span className="field-hint">The response analyzer blocks any reply that repeats this text, and a hidden
              canary marker is appended to it automatically.</span></label>
          <label className="field"><span>Model provider</span>
            <select value={cfg.provider} onChange={(e) => setC('provider')(e.target.value)}>
              {PROVIDERS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select></label>
          <div className="grid grid-2">
            <label className="field"><span>Model</span>
              <input type="text" value={cfg.model} onChange={(e) => setC('model')(e.target.value)} placeholder="llama3.1" /></label>
            <label className="field"><span>Server URL</span>
              <input type="url" value={cfg.base_url} onChange={(e) => setC('base_url')(e.target.value)}
                     placeholder="http://localhost:11434" /></label>
            <label className="field"><span>API key {cfg.api_key_set && <span className="muted">(saved — leave blank to keep)</span>}</span>
              <input type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)}
                     placeholder={cfg.api_key_set ? '••••••••' : 'Only for hosted APIs'} autoComplete="off" /></label>
            <label className="field"><span>Temperature</span>
              <input type="number" step="0.1" min="0" max="1.5" value={cfg.temperature}
                     onChange={(e) => setC('temperature')(Number(e.target.value))} /></label>
          </div>
          <div className="field-hint" style={{ marginBottom: 12 }}>
            To answer with Llama 3.1, install Ollama and pull the model; Automatic picks it up.</div>
          <div className="row">
            <button className="btn btn-primary" onClick={saveBot} disabled={busy === 'bot'}>
              {busy === 'bot' ? <><Spinner size={13} /> Saving…</> : 'Save AstraBot'}</button>
            {cfg.api_key_set && <button className="btn" onClick={clearKey}>Remove API key</button>}
          </div>
        </Card>

        <Card title="Security policy" sub="How AstraSec responds to risk. Changes apply immediately.">
          <div className="section-title" style={{ fontSize: 13 }}>Risk bands</div>
          <div className="band-bar" aria-hidden="true">
            {[...BAND_KEYS, 'quarantine'].map((k, i) => (
              <span key={k} style={{ width: `${bounds[i + 1] - bounds[i]}%`, background: ACTION_RAMP[k] }}
                    title={`${ACTION_LABEL[k]}: ${bounds[i] + (i ? 1 : 0)}–${bounds[i + 1]}`} />
            ))}
          </div>
          <div className="band-scale"><span>0</span><span>50</span><span>100</span></div>
          <div className="grid" style={{ gridTemplateColumns: 'repeat(5, 1fr)', gap: 8, marginTop: 10 }}>
            {BAND_KEYS.map((k) => (
              <label className="field" key={k} style={{ marginBottom: 6 }}>
                <span>{ACTION_LABEL[k]} up to</span>
                <input type="number" min={0} max={100} value={b[k]} onChange={(e) => setBand(k, Number(e.target.value))} />
              </label>
            ))}
          </div>
          <div className="field-hint">Above the Block limit a client is quarantined. Rate limit refuses the
            message and makes the client wait; block refuses it outright.</div>

          <div className="section-title" style={{ fontSize: 13, marginTop: 16 }}>Enforcement</div>
          <div className="grid grid-2">
            <label className="field"><span>Rate-limit wait (seconds)</span>
              <input type="number" value={pol.rate_limit_cooldown_seconds} onChange={(e) => setP('rate_limit_cooldown_seconds')(Number(e.target.value))} /></label>
            <label className="field"><span>Quarantine length (minutes)</span>
              <input type="number" value={pol.quarantine_minutes} onChange={(e) => setP('quarantine_minutes')(Number(e.target.value))} /></label>
            <label className="field"><span>Longest message (characters)</span>
              <input type="number" value={pol.max_message_chars} onChange={(e) => setP('max_message_chars')(Number(e.target.value))} /></label>
            <label className="field"><span>Largest file (MB)</span>
              <input type="number" value={pol.max_file_mb} onChange={(e) => setP('max_file_mb')(Number(e.target.value))} /></label>
            <label className="field"><span>Files per conversation</span>
              <input type="number" value={pol.max_files_per_session} onChange={(e) => setP('max_files_per_session')(Number(e.target.value))} /></label>
            <label className="field"><span>Uploads per minute</span>
              <input type="number" value={pol.uploads_per_minute} onChange={(e) => setP('uploads_per_minute')(Number(e.target.value))} /></label>
          </div>

          <div className="section-title" style={{ fontSize: 13 }}>Alerts to you</div>
          <div className="grid grid-2">
            <label className="field"><span>Alert when a threat is at least</span>
              <select value={pol.alert_min_action} onChange={(e) => setP('alert_min_action')(e.target.value)}>
                {ACTION_ORDER.slice(1).map((a) => <option key={a} value={a}>{ACTION_LABEL[a]}</option>)}
              </select></label>
            <label className="field"><span>…or a file finding is at least</span>
              <select value={pol.alert_min_file_severity} onChange={(e) => setP('alert_min_file_severity')(e.target.value)}>
                {['low', 'medium', 'high', 'critical'].map((s) => <option key={s} value={s}>{s[0].toUpperCase() + s.slice(1)}</option>)}
              </select></label>
          </div>
          <Switch label="Alert when a model reply leaks the system prompt or a secret" checked={pol.alert_on_response_leak}
                  onChange={setP('alert_on_response_leak')} />

          <div className="section-title" style={{ fontSize: 13, marginTop: 12 }}>Response analyzer</div>
          <Switch label="Block replies that reveal the system prompt" checked={pol.block_system_prompt_leaks}
                  onChange={setP('block_system_prompt_leaks')} />
          <Switch label="Mask personal data (emails, phone numbers, cards) in replies" checked={pol.mask_pii_in_responses}
                  onChange={setP('mask_pii_in_responses')} />
          <label className="field" style={{ marginTop: 8 }}><span>Public values the bot may say (comma separated)</span>
            <input type="text" value={allowed} onChange={(e) => setP('allowed_public_values')(e.target.value)}
                   placeholder="support@yourcompany.com" /></label>
          <Switch label="Keep redacted excerpts of messages in the log" checked={pol.store_message_excerpts}
                  onChange={setP('store_message_excerpts')} />

          <div className="row" style={{ marginTop: 12 }}>
            <button className="btn btn-primary" onClick={savePolicy} disabled={busy === 'pol'}>
              {busy === 'pol' ? <><Spinner size={13} /> Saving…</> : 'Save policy'}</button>
          </div>
        </Card>
      </div>
    </div>
  )
}
