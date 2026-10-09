import React, { useEffect, useState } from 'react'
import { api } from '../lib/api'
import { Banner, Card, Spinner, Switch } from '../components/ui'

export default function Settings({ onLogout }) {
  const [ch, setCh] = useState(null)
  const [emailPw, setEmailPw] = useState('')
  const [pw, setPw] = useState({ current: '', next: '', confirm: '' })
  const [msg, setMsg] = useState(null)
  const [busy, setBusy] = useState('')
  const [test, setTest] = useState(null)
  const [auth, setAuth] = useState(null)

  useEffect(() => {
    api.soc.channels().then(setCh).catch((e) => setMsg({ kind: 'err', text: e.message }))
    api.authStatus().then(setAuth).catch(() => {})
  }, [])

  const setE = (k) => (v) => setCh((c) => ({ ...c, email: { ...c.email, [k]: v } }))
  const setW = (k) => (v) => setCh((c) => ({ ...c, webhook: { ...c.webhook, [k]: v } }))

  const saveChannels = async () => {
    setBusy('ch'); setMsg(null)
    try {
      const body = { email: { ...ch.email }, webhook: ch.webhook }
      if (emailPw) body.email.password = emailPw
      setCh(await api.soc.saveChannels(body)); setEmailPw('')
      setMsg({ kind: 'ok', text: 'Alert channels saved.' })
    } catch (e) { setMsg({ kind: 'err', text: e.message }) } finally { setBusy('') }
  }
  const runTest = async () => {
    setBusy('test'); setTest(null)
    try { setTest(await api.soc.testChannels()) } catch (e) { setMsg({ kind: 'err', text: e.message }) }
    finally { setBusy('') }
  }
  const changePassword = async (e) => {
    e.preventDefault()
    if (pw.next !== pw.confirm) { setMsg({ kind: 'err', text: 'The new passwords do not match.' }); return }
    setBusy('pw'); setMsg(null)
    try {
      if (auth && !auth.configured) await api.authSetup(pw.next)
      else await api.authChange(pw.current, pw.next)
      setPw({ current: '', next: '', confirm: '' })
      setAuth(await api.authStatus())
      setMsg({ kind: 'ok', text: 'Owner password saved. Other signed-in sessions have been signed out.' })
    } catch (e2) { setMsg({ kind: 'err', text: e2.message }) } finally { setBusy('') }
  }
  const purge = async () => {
    if (!window.confirm('Delete every logged request, incident, alert and file record? Configuration is kept.')) return
    setBusy('purge')
    try { await api.soc.purge(); setMsg({ kind: 'ok', text: 'Activity cleared.' }) }
    catch (e) { setMsg({ kind: 'err', text: e.message }) } finally { setBusy('') }
  }

  return (
    <div className="stack">
      {msg && <Banner kind={msg.kind}>{msg.text}</Banner>}
      <div className="grid grid-2">
        <Card title="Owner password" sub="Protects this Security Center. AstraBot itself stays public.">
          <form onSubmit={changePassword}>
            {auth?.configured ? (
              <label className="field"><span>Current password</span>
                <input type="password" autoComplete="current-password" value={pw.current}
                       onChange={(e) => setPw({ ...pw, current: e.target.value })} /></label>
            ) : <Banner kind="warn">No password yet — the Security Center is only reachable from this computer
                until you set one.</Banner>}
            <label className="field"><span>New password (8+ characters)</span>
              <input type="password" autoComplete="new-password" value={pw.next}
                     onChange={(e) => setPw({ ...pw, next: e.target.value })} /></label>
            <label className="field"><span>Confirm</span>
              <input type="password" autoComplete="new-password" value={pw.confirm}
                     onChange={(e) => setPw({ ...pw, confirm: e.target.value })} /></label>
            <div className="row">
              <button className="btn btn-primary" type="submit" disabled={busy === 'pw' || !pw.next}>
                {busy === 'pw' ? <><Spinner size={13} /> Saving…</> : 'Save password'}</button>
              {auth?.configured && <button className="btn" type="button" onClick={onLogout}>Sign out</button>}
            </div>
          </form>
        </Card>

        <Card title="Alert channels" sub="Every alert appears here and as a desktop notification. Add email or a chat webhook to get them anywhere.">
          {!ch ? <Spinner /> : (
            <>
              <Switch label="Email alerts (SMTP)" checked={ch.email.enabled} onChange={setE('enabled')} />
              {ch.email.enabled && (
                <div className="grid grid-2" style={{ marginTop: 8 }}>
                  <label className="field"><span>SMTP server</span>
                    <input type="text" value={ch.email.smtp_host} onChange={(e) => setE('smtp_host')(e.target.value)} placeholder="smtp.gmail.com" /></label>
                  <label className="field"><span>Port</span>
                    <input type="number" value={ch.email.smtp_port} onChange={(e) => setE('smtp_port')(Number(e.target.value))} /></label>
                  <label className="field"><span>Username</span>
                    <input type="text" value={ch.email.username} onChange={(e) => setE('username')(e.target.value)} /></label>
                  <label className="field"><span>Password / app password {ch.email.password_set && <span className="muted">(saved)</span>}</span>
                    <input type="password" value={emailPw} onChange={(e) => setEmailPw(e.target.value)} autoComplete="off" /></label>
                  <label className="field"><span>From</span>
                    <input type="text" value={ch.email.sender} onChange={(e) => setE('sender')(e.target.value)} /></label>
                  <label className="field"><span>Send alerts to</span>
                    <input type="text" value={ch.email.recipient} onChange={(e) => setE('recipient')(e.target.value)} /></label>
                  <div style={{ gridColumn: '1 / -1' }}>
                    <Switch label="Use STARTTLS" checked={ch.email.use_tls} onChange={setE('use_tls')} />
                    <div className="field-hint">For Gmail use smtp.gmail.com, port 587 and an app password.</div>
                  </div>
                </div>
              )}
              <div style={{ height: 8 }} />
              <Switch label="Webhook (Slack, Discord or any HTTPS endpoint)" checked={ch.webhook.enabled} onChange={setW('enabled')} />
              {ch.webhook.enabled && (
                <div className="grid grid-2" style={{ marginTop: 8 }}>
                  <label className="field" style={{ gridColumn: '1 / -1' }}><span>Webhook URL</span>
                    <input type="url" value={ch.webhook.url} onChange={(e) => setW('url')(e.target.value)} placeholder="https://hooks.slack.com/services/…" /></label>
                  <label className="field"><span>Format</span>
                    <select value={ch.webhook.format} onChange={(e) => setW('format')(e.target.value)}>
                      <option value="generic">Generic JSON</option><option value="slack">Slack</option><option value="discord">Discord</option>
                    </select></label>
                </div>
              )}
              <div className="row" style={{ marginTop: 12 }}>
                <button className="btn btn-primary" onClick={saveChannels} disabled={busy === 'ch'}>Save channels</button>
                <button className="btn" onClick={runTest} disabled={busy === 'test'}>
                  {busy === 'test' ? <><Spinner size={13} /> Sending…</> : 'Send a test alert'}</button>
              </div>
              {test && (
                <div className="field-hint" style={{ marginTop: 8 }}>
                  Dashboard: {test.in_app} · Email: {test.email} · Webhook: {test.webhook}
                </div>
              )}
            </>
          )}
        </Card>
      </div>
      <Card title="Housekeeping">
        <div className="row">
          <button className="btn btn-danger" onClick={purge} disabled={busy === 'purge'}>Clear activity log</button>
          <span className="muted" style={{ fontSize: 12.5 }}>Deletes requests, incidents, alerts and file records.
            Keeps the policy, bot settings, password and immune memory.</span>
        </div>
      </Card>
    </div>
  )
}
