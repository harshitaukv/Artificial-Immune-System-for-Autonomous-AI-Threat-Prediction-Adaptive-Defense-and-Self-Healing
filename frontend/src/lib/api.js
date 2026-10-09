/* Thin fetch wrapper around the AstraSec REST API. */

const BASE = import.meta.env.VITE_API_BASE || ''

/* A 401 from any owner endpoint means the session ended; the shell listens
 * for this and shows the sign-in screen instead of a page of errors. */
export const authEvents = new EventTarget()

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    ...options,
  })
  if (res.status === 401 && !path.startsWith('/api/auth/')) {
    authEvents.dispatchEvent(new Event('unauthorized'))
  }
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`
    try {
      const body = await res.json()
      if (body?.detail) detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)
    } catch { /* body was not JSON — keep the status line */ }
    throw new Error(detail)
  }
  return res.status === 204 ? null : res.json()
}

const get = (p) => request(p)
const post = (p, body) => request(p, { method: 'POST', body: JSON.stringify(body ?? {}) })
const put = (p, body) => request(p, { method: 'PUT', body: JSON.stringify(body ?? {}) })
const patch = (p, body) => request(p, { method: 'PATCH', body: JSON.stringify(body ?? {}) })
const qs = (params = {}) => {
  const q = new URLSearchParams(
    Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== '' && v !== false)
  ).toString()
  return q ? `?${q}` : ''
}

/* Multipart uploads must NOT carry an explicit Content-Type: the browser has
 * to append its own multipart boundary, and setting the header by hand strips
 * it, which FastAPI rejects as a malformed body. */
async function upload(path, formData) {
  const res = await fetch(`${BASE}${path}`, { method: 'POST', body: formData, credentials: 'same-origin' })
  if (res.status === 401) authEvents.dispatchEvent(new Event('unauthorized'))
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`
    try {
      const body = await res.json()
      if (body?.detail) detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)
    } catch { /* body was not JSON — keep the status line */ }
    throw new Error(detail)
  }
  return res.json()
}

export const API_BASE = BASE

export const api = {
  health: () => get('/api/health'),
  config: () => get('/api/config'),
  stats: () => get('/api/stats'),

  inspect: (payload) => post('/api/inspect', payload),
  gateway: (payload) => post('/api/gateway/chat', payload),

  summary: (appId) => get(`/api/dashboard/summary${appId ? `?app_id=${encodeURIComponent(appId)}` : ''}`),
  feed: (limit = 50) => get(`/api/dashboard/feed?limit=${limit}`),

  incidents: (params = {}) => {
    const q = new URLSearchParams(
      Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== '')
    ).toString()
    return get(`/api/incidents${q ? `?${q}` : ''}`)
  },
  incident: (id) => get(`/api/incidents/${id}`),

  memoryStats: () => get('/api/memory/stats'),
  memoryCells: (limit = 60, threatClass) =>
    get(`/api/memory/cells?limit=${limit}${threatClass ? `&threat_class=${threatClass}` : ''}`),
  memoryRecall: (prompt) => post('/api/memory/recall', { prompt }),

  rules: () => get('/api/rules'),
  activateRule: (id) => post(`/api/rules/${id}/activate`),
  deactivateRule: (id) => post(`/api/rules/${id}/deactivate`),
  signatures: () => get('/api/signatures'),

  tenants: () => get('/api/tenants'),
  releaseTenant: (id) => post(`/api/tenants/${id}/release`),

  simulate: (count = 200, seed = 7) => post('/api/simulate/traffic', { count, seed }),
  redteam: () => post('/api/simulate/redteam'),
  reset: (purge = false) => post(`/api/reset?purge_store=${purge}`),

  reports: () => get('/api/reports'),
  report: (name) => get(`/api/report/${name}`),

  // ---- real-input analysis -------------------------------------------
  scanText: (payload) => post('/api/scan/text', payload),
  scanFormats: () => get('/api/scan/formats'),

  /** Peek at a CSV's headers so the analyst picks columns before scanning. */
  inspectColumns: (file) => {
    const fd = new FormData()
    fd.append('file', file)
    return upload('/api/scan/inspect-columns', fd)
  },

  scanFile: (file, opts = {}) => {
    const fd = new FormData()
    fd.append('file', file)
    fd.append('columns', (opts.columns || []).join(','))
    fd.append('split', opts.split || 'line')
    fd.append('learn', opts.learn ? 'true' : 'false')
    fd.append('app_id', opts.appId || 'uploaded-file')
    fd.append('app_name', opts.appName || '')
    return upload('/api/scan/file', fd)
  },

  probeCheck: (payload) => post('/api/probe/check', payload),
  probeRun: (payload) => post('/api/probe/run', payload),
  probeCases: () => get('/api/probe/cases'),

  probeDemoTarget: () => get('/api/probe/demo-target'),

  audit: (payload) => post('/api/audit', payload),
  auditImport: (file) => {
    const fd = new FormData()
    fd.append('file', file)
    return upload('/api/audit/import', fd)
  },
  auditSampleApp: () => get('/api/audit/sample-app'),
  auditSampleZipUrl: () => `${BASE}/api/audit/sample-app.zip`,
  auditDemoApp: () => get('/api/audit/demo-app'),

  reportsSummary: () => get('/api/reports/summary'),
  savedReports: (kind, limit = 50) =>
    get(`/api/reports/saved?${kind ? `kind=${kind}&` : ''}limit=${limit}`),
  savedReport: (id) => get(`/api/reports/saved/${id}`),
  deleteSavedReport: (id) => request(`/api/reports/saved/${id}`, { method: 'DELETE' }),
  exportCsvUrl: (id) => `${BASE}/api/reports/saved/${id}/export.csv`,

  // ---- owner auth -------------------------------------------------------
  authStatus: () => get('/api/auth/status'),
  authSetup: (password) => post('/api/auth/setup', { password }),
  authLogin: (password) => post('/api/auth/login', { password }),
  authLogout: () => post('/api/auth/logout'),
  authChange: (current, next) => post('/api/auth/change', { current, new: next }),

  // ---- security center ----------------------------------------------------
  soc: {
    overview: (range = '24h') => get(`/api/soc/overview?range=${range}`),
    incidents: (params) => get(`/api/soc/incidents${qs(params)}`),
    incident: (id) => get(`/api/soc/incidents/${encodeURIComponent(id)}`),
    updateIncident: (id, body) => patch(`/api/soc/incidents/${encodeURIComponent(id)}`, body),
    alerts: (params) => get(`/api/soc/alerts${qs(params)}`),
    readAlerts: (id) => post('/api/soc/alerts/read', { id: id || null }),
    requests: (params) => get(`/api/soc/requests${qs(params)}`),
    files: () => get('/api/soc/files'),
    clients: () => get('/api/soc/clients'),
    release: (client) => post(`/api/soc/clients/${encodeURIComponent(client)}/release`),
    policy: () => get('/api/soc/policy'),
    savePolicy: (body) => put('/api/soc/policy', body),
    botConfig: () => get('/api/soc/bot-config'),
    saveBotConfig: (body) => put('/api/soc/bot-config', body),
    channels: () => get('/api/soc/alert-channels'),
    saveChannels: (body) => put('/api/soc/alert-channels', body),
    testChannels: () => post('/api/soc/alert-channels/test'),
    analyze: (text, kind = 'prompt') => post('/api/soc/analyze', { text, kind }),
    memory: () => get('/api/soc/memory'),
    rules: () => get('/api/soc/rules'),
    validateRule: (id) => post(`/api/soc/rules/${id}/validate`),
    approveRule: (id) => post(`/api/soc/rules/${id}/approve`),
    rejectRule: (id) => post(`/api/soc/rules/${id}/reject`),
    disableRule: (id) => post(`/api/soc/rules/${id}/disable`),
    purge: () => post('/api/soc/purge'),
  },
}

/** Live incident stream. Returns a close() handle. */
export function connectFeed(onEvent, onStatus) {
  // With a split deployment (dashboard on a static host, API on a container
  // host) the WebSocket must follow VITE_API_BASE, not the page origin —
  // otherwise the browser opens the socket against the static host, which has
  // no /ws/feed route and the live feed silently never connects.
  let url
  if (BASE) {
    url = `${BASE.replace(/^http/, 'ws').replace(/\/$/, '')}/ws/feed`
  } else {
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    url = `${proto}://${window.location.host}/ws/feed`
  }
  let ws
  let closed = false
  let retry

  const open = () => {
    if (closed) return
    try {
      ws = new WebSocket(url)
    } catch {
      onStatus?.('error')
      return
    }
    ws.onopen = () => onStatus?.('connected')
    ws.onmessage = (e) => {
      try { onEvent(JSON.parse(e.data)) } catch { /* ignore malformed frame */ }
    }
    ws.onclose = () => {
      onStatus?.('disconnected')
      // Reconnect with a fixed backoff; the dashboard is long-lived and the
      // backend may restart during a demo.
      if (!closed) retry = setTimeout(open, 3000)
    }
    ws.onerror = () => onStatus?.('error')
  }
  open()

  return () => {
    closed = true
    clearTimeout(retry)
    try { ws?.close() } catch { /* already closed */ }
  }
}
