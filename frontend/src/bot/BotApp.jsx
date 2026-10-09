import React, { useCallback, useEffect, useRef, useState } from 'react'
import { ArrowUp, FileText, Paperclip, RotateCcw, ShieldCheck, ShieldAlert, X, Loader2 } from 'lucide-react'

/* AstraBot — the protected chatbot.
 *
 * Deliberately knows nothing about security internals: it shows what a user
 * of a real product would see. Every message and file goes to the AstraSec
 * gateway first; this UI only renders the outcome. Replies are rendered as
 * React elements from a small, safe markdown subset — never as HTML. */

const SESSION_KEY = 'astrabot-session'

async function call(path, options = {}) {
  const res = await fetch(path, { ...options, credentials: 'same-origin' })
  let body = null
  try { body = await res.json() } catch { /* not JSON */ }
  if (!res.ok) {
    const detail = body?.detail
    throw Object.assign(new Error(typeof detail === 'string' ? detail : `Request failed (${res.status})`),
                        { status: res.status })
  }
  return body
}

async function newSession() {
  const d = await call('/api/bot/session', { method: 'POST' })
  try { sessionStorage.setItem(SESSION_KEY, d.session_id) } catch { /* private mode */ }
  return d.session_id
}

/* ------------------------------------------------------------ safe markdown */
function inline(text, keyBase) {
  const out = []
  const re = /(\*\*[^*]+\*\*|`[^`]+`|_[^_]+_)/g
  let last = 0
  let m
  let i = 0
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index))
    const tok = m[0]
    if (tok.startsWith('**')) out.push(<strong key={`${keyBase}-${i++}`}>{tok.slice(2, -2)}</strong>)
    else if (tok.startsWith('`')) out.push(<code key={`${keyBase}-${i++}`}>{tok.slice(1, -1)}</code>)
    else out.push(<em key={`${keyBase}-${i++}`}>{tok.slice(1, -1)}</em>)
    last = m.index + tok.length
  }
  if (last < text.length) out.push(text.slice(last))
  return out
}

function Markdown({ text }) {
  const blocks = []
  const parts = String(text || '').split(/```/)
  parts.forEach((part, pi) => {
    if (pi % 2 === 1) {
      const body = part.replace(/^[a-zA-Z0-9]*\n/, '')
      blocks.push(<pre key={`c${pi}`}><code>{body.replace(/\n$/, '')}</code></pre>)
      return
    }
    const lines = part.split('\n')
    let list = null
    let para = []
    const flushPara = () => {
      if (para.length) {
        blocks.push(<p key={`p${pi}-${blocks.length}`}>{inline(para.join(' '), `p${pi}-${blocks.length}`)}</p>)
        para = []
      }
    }
    const flushList = () => {
      if (list) {
        const Tag = list.ordered ? 'ol' : 'ul'
        blocks.push(<Tag key={`l${pi}-${blocks.length}`}>{list.items.map((it, j) =>
          <li key={j}>{inline(it, `li${pi}-${j}`)}</li>)}</Tag>)
        list = null
      }
    }
    lines.forEach((line) => {
      const ul = line.match(/^\s*[-*•]\s+(.*)$/)
      const ol = line.match(/^\s*\d+[.)]\s+(.*)$/)
      if (ul || ol) {
        flushPara()
        const ordered = Boolean(ol)
        if (!list || list.ordered !== ordered) { flushList(); list = { ordered, items: [] } }
        list.items.push((ul || ol)[1])
      } else if (!line.trim()) {
        flushPara(); flushList()
      } else {
        flushList(); para.push(line.trim())
      }
    })
    flushPara(); flushList()
  })
  return <div className="md">{blocks}</div>
}

/* ------------------------------------------------------------------ app */
const FILE_STATE = {
  reading: ['Checking…', 'pending'],
  accepted: ['Ready', 'ok'],
  sanitized: ['Ready · cleaned', 'ok'],
  blocked: ['Blocked', 'bad'],
  quarantined: ['Held for review', 'bad'],
  rejected: ['Not accepted', 'bad'],
  refused: ['Not accepted', 'bad'],
}

export default function BotApp() {
  const [info, setInfo] = useState(null)
  const [sid, setSid] = useState(null)
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [files, setFiles] = useState([])
  const [dragging, setDragging] = useState(false)
  const [fatal, setFatal] = useState('')
  const listRef = useRef(null)
  const fileRef = useRef(null)
  const taRef = useRef(null)

  const start = useCallback(async (fresh = false) => {
    try {
      const i = await call('/api/bot/info')
      setInfo(i)
      let s = null
      try { s = fresh ? null : sessionStorage.getItem(SESSION_KEY) } catch { /* private mode */ }
      if (!s || !/^[a-f0-9]{32}$/.test(s)) s = await newSession()
      setSid(s)
      setMessages([{ role: 'assistant', text: i.greeting, id: 'greet' }])
      setFiles([])
      setFatal('')
    } catch (e) {
      setFatal(e.status === 503 ? 'AstraBot is starting up. Please try again in a moment.'
        : 'AstraBot is unavailable right now. Please try again shortly.')
    }
  }, [])
  useEffect(() => { start() }, [start])

  useEffect(() => {
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight, behavior: 'smooth' })
  }, [messages, busy])

  useEffect(() => {
    const ta = taRef.current
    if (!ta) return
    ta.style.height = 'auto'
    ta.style.height = `${Math.min(200, ta.scrollHeight)}px`
  }, [input])

  const reset = async () => {
    if (sid) { try { await call('/api/bot/reset', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ session_id: sid }) }) } catch { /* ignore */ } }
    start(true)
  }

  const send = async () => {
    const text = input.trim()
    if (!text || busy || !sid) return
    if (info && text.length > info.max_message_chars) {
      setMessages((m) => [...m, { role: 'system', tone: 'warn', id: Date.now(),
        text: `That message is too long — the limit is ${info.max_message_chars.toLocaleString()} characters.` }])
      return
    }
    setInput('')
    setMessages((m) => [...m, { role: 'user', text, id: Date.now() }])
    setBusy(true)
    try {
      const d = await call('/api/bot/chat', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sid, message: text }),
      })
      if (d.status === 'refused' || d.status === 'rejected' || d.status === 'response_blocked') {
        setMessages((m) => [...m, { role: 'system', tone: 'bad', text: d.reply, id: Date.now() + 1 }])
      } else {
        setMessages((m) => [...m, { role: 'assistant', text: d.reply, notice: d.notice, model: d.model, id: Date.now() + 1 }])
      }
    } catch (e) {
      if (e.status === 400) { const s = await newSession(); setSid(s) }
      setMessages((m) => [...m, { role: 'system', tone: 'warn', id: Date.now() + 1,
        text: 'Something went wrong sending that message. Please try again.' }])
    } finally {
      setBusy(false)
      taRef.current?.focus()
    }
  }

  const upload = async (file) => {
    if (!file || !sid) return
    const tempId = `tmp-${Date.now()}`
    if (info && file.size > info.max_file_mb * 1024 * 1024) {
      setFiles((f) => [...f, { id: tempId, name: file.name, status: 'rejected',
        notice: `Larger than the ${info.max_file_mb} MB limit.` }])
      return
    }
    setFiles((f) => [...f, { id: tempId, name: file.name, status: 'reading' }])
    const fd = new FormData()
    fd.append('session_id', sid)
    fd.append('file', file)
    try {
      const d = await call('/api/bot/upload', { method: 'POST', body: fd })
      setFiles((f) => f.map((x) => x.id === tempId
        ? { id: d.file_id || tempId, name: d.name || file.name, status: d.status, notice: d.notice,
            attached: d.attached }
        : x))
      setMessages((m) => [...m, {
        role: d.attached ? 'assistant' : 'system', tone: d.attached ? undefined : 'bad',
        text: d.notice, id: Date.now(), file: d.name || file.name,
      }])
    } catch (e) {
      setFiles((f) => f.map((x) => x.id === tempId ? { ...x, status: 'rejected', notice: e.message } : x))
    }
  }

  const removeFile = async (f) => {
    setFiles((all) => all.filter((x) => x.id !== f.id))
    if (f.attached && sid) {
      try { await call(`/api/bot/files/${encodeURIComponent(f.id)}?session_id=${sid}`, { method: 'DELETE' }) } catch { /* ignore */ }
    }
  }

  const onDrop = (e) => {
    e.preventDefault(); setDragging(false)
    Array.from(e.dataTransfer.files || []).slice(0, 3).forEach(upload)
  }

  if (fatal) {
    return <div className="bot-shell"><div className="bot-fatal">{fatal}
      <button className="bot-btn" onClick={() => start()}>Retry</button></div></div>
  }

  return (
    <div className="bot-shell"
         onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
         onDragLeave={(e) => { if (e.currentTarget === e.target) setDragging(false) }}
         onDrop={onDrop}>
      <header className="bot-header">
        <div>
          <div className="bot-name">{info?.name || 'AstraBot'}</div>
          <div className="bot-tagline">{info?.tagline}</div>
        </div>
        <button className="bot-btn ghost" onClick={reset} title="Start a new conversation">
          <RotateCcw size={14} /> New chat
        </button>
      </header>

      <main className="bot-list" ref={listRef} aria-live="polite">
        <div className="bot-col">
          {messages.map((m) => (
            <div key={m.id} className={`msg ${m.role} ${m.tone || ''}`}>
              {m.role === 'system' ? (
                <div className="sys">
                  <ShieldAlert size={15} />
                  <div>{m.file && <div className="sys-file"><FileText size={13} /> {m.file}</div>}
                    <div style={{ whiteSpace: 'pre-line' }}>{m.text}</div></div>
                </div>
              ) : m.role === 'user' ? (
                <div className="bubble">{m.text}</div>
              ) : (
                <div className="answer">
                  {m.file && <div className="sys-file"><FileText size={13} /> {m.file}</div>}
                  <Markdown text={m.text} />
                  {m.notice && <div className="notice"><ShieldCheck size={13} /> {m.notice}</div>}
                </div>
              )}
            </div>
          ))}
          {busy && <div className="msg assistant"><div className="answer typing"><span /><span /><span /></div></div>}
        </div>
      </main>

      <footer className="bot-composer">
        <div className="bot-col">
          {files.length > 0 && (
            <div className="chips">
              {files.map((f) => {
                const [label, tone] = FILE_STATE[f.status] || [f.status, 'pending']
                return (
                  <div key={f.id} className={`chip-file ${tone}`} title={f.notice || ''}>
                    {f.status === 'reading' ? <Loader2 size={13} className="spin" /> : <FileText size={13} />}
                    <span className="chip-name">{f.name}</span>
                    <span className="chip-state">{label}</span>
                    {f.status !== 'reading' && (
                      <button onClick={() => removeFile(f)} aria-label={`Remove ${f.name}`}><X size={12} /></button>
                    )}
                  </div>
                )
              })}
            </div>
          )}
          <div className="composer">
            <input ref={fileRef} type="file" hidden accept={(info?.accepted_files || []).join(',')}
                   onChange={(e) => { Array.from(e.target.files || []).forEach(upload); e.target.value = '' }} multiple />
            <button className="icon-btn" onClick={() => fileRef.current?.click()} title="Attach a file"
                    aria-label="Attach a file" disabled={!sid}><Paperclip size={17} /></button>
            <textarea ref={taRef} rows={1} value={input} placeholder={`Message ${info?.name || 'AstraBot'}…`}
                      onChange={(e) => setInput(e.target.value)}
                      onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send() } }} />
            <button className="send-btn" onClick={send} disabled={busy || !input.trim()} aria-label="Send">
              <ArrowUp size={17} />
            </button>
          </div>
          <div className="fineprint">
            <ShieldCheck size={12} /> Protected by AstraSec — messages and files are checked before the AI sees them.

          </div>
        </div>
      </footer>
      {dragging && <div className="drop-overlay">Drop a PDF, Word, TXT, CSV or JSON file</div>}
    </div>
  )
}
