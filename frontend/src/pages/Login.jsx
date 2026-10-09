import React, { useState } from 'react'
import { api } from '../lib/api'
import { Banner, Card, Spinner } from '../components/ui'

export default function Login({ status, onDone }) {
  const setup = !status.configured
  const [pw, setPw] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    if (setup && pw !== confirm) { setError('The passwords do not match.'); return }
    setBusy(true)
    try {
      if (setup) await api.authSetup(pw)
      else await api.authLogin(pw)
      onDone()
    } catch (err) { setError(err.message) } finally { setBusy(false) }
  }

  return (
    <div className="auth-wrap">
      <div className="auth-card">
        <div style={{ marginBottom: 14 }}>
          <div className="brand-name" style={{ fontSize: 22 }}>AstraSec</div>
          <div className="muted" style={{ fontSize: 13 }}>Security Center</div>
        </div>
        <Card title={setup ? 'Create the owner password' : 'Sign in'}
              sub={setup ? 'Only the application owner can see incidents, alerts and settings.'
                         : 'Owner access to incidents, alerts and settings.'}>
          {setup && !status.setup_allowed ? (
            <Banner kind="warn">For security, the owner password can only be created on the computer
              that runs AstraSec. Open the Security Center there to finish setting up.</Banner>
          ) : (
            <form onSubmit={submit}>
              {error && <div style={{ marginBottom: 12 }}><Banner kind="err">{error}</Banner></div>}
              <label className="field"><span>Password</span>
                <input type="password" autoFocus autoComplete={setup ? 'new-password' : 'current-password'}
                       value={pw} onChange={(e) => setPw(e.target.value)} /></label>
              {setup && (
                <label className="field"><span>Confirm password</span>
                  <input type="password" autoComplete="new-password" value={confirm}
                         onChange={(e) => setConfirm(e.target.value)} /></label>
              )}
              <button className="btn btn-primary" type="submit" disabled={busy || !pw} style={{ width: '100%' }}>
                {busy ? <><Spinner size={13} /> Please wait…</> : setup ? 'Create and continue' : 'Sign in'}
              </button>
              {setup && <div className="field-hint">At least 8 characters. You can change it later in Settings.</div>}
            </form>
          )}
        </Card>
        <div className="muted" style={{ fontSize: 12, marginTop: 12, textAlign: 'center' }}>
          Looking for the chatbot? <a href="/bot">Open AstraBot</a>
        </div>
      </div>
    </div>
  )
}
