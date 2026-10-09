/* Colour roles, formatting and label helpers shared by every chart.
 *
 * Colour follows the entity, never its rank: THREAT_COLOR is a fixed map, so
 * filtering the series list never repaints the survivors. The five threat
 * classes take validated categorical slots 1-5; `benign` wears neutral ink
 * because it is the absence of a threat, not a sixth category.
 */

export const THREAT_ORDER = [
  'prompt_injection',
  'jailbreak',
  'adversarial_obfuscation',
  'data_exfiltration',
  'model_extraction',
  'sensitive_data',
  'suspicious_link',
  'benign',
]

/* The defence ladder is ordered, so it wears an ordinal ramp (one hue, light
 * to dark) rather than status colours: "sanitised" is not a warning state,
 * it is a rung. */
export const ACTION_ORDER = ['allow', 'monitor', 'sanitize', 'rate_limit', 'block', 'quarantine']
export const ACTION_RAMP = {
  allow: 'var(--ord-1)', monitor: 'var(--ord-2)', sanitize: 'var(--ord-3)', mask: 'var(--ord-3)',
  rate_limit: 'var(--ord-4)', block: 'var(--ord-5)', quarantine: 'var(--ord-6)',
}
export const SOURCE_LABEL = { prompt: 'Chat messages', file: 'Uploaded files', response: 'Model responses' }
export const STATUS_LABEL = {
  open: 'Open', investigating: 'Investigating', resolved: 'Resolved', false_positive: 'False positive',
}

export const THREAT_COLOR = {
  prompt_injection: 'var(--series-1)',
  jailbreak: 'var(--series-2)',
  adversarial_obfuscation: 'var(--series-3)',
  data_exfiltration: 'var(--series-4)',
  model_extraction: 'var(--series-5)',
  sensitive_data: 'var(--series-7)',
  suspicious_link: 'var(--series-neutral)',
  benign: 'var(--series-neutral)',
}

export const THREAT_LABEL = {
  prompt_injection: 'Prompt injection',
  jailbreak: 'Jailbreak',
  adversarial_obfuscation: 'Adversarial / obfuscation',
  data_exfiltration: 'Data exfiltration',
  model_extraction: 'Model extraction',
  sensitive_data: 'Sensitive data',
  suspicious_link: 'Suspicious link',
  benign: 'Benign',
}

/* Reserved status palette — always paired with a label, never colour alone. */
export const SEVERITY_COLOR = {
  none: 'var(--series-neutral)',
  low: 'var(--status-good)',
  medium: 'var(--status-warning)',
  high: 'var(--status-serious)',
  critical: 'var(--status-critical)',
}

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'none']

export const ACTION_COLOR = {
  allow: 'var(--status-good)',
  monitor: 'var(--series-1)',
  sanitize: 'var(--status-warning)',
  mask: 'var(--status-warning)',
  rate_limit: 'var(--status-serious)',
  block: 'var(--status-critical)',
  quarantine: 'var(--status-critical)',
}

export const ACTION_LABEL = {
  allow: 'Allowed',
  monitor: 'Monitored',
  sanitize: 'Sanitised',
  mask: 'Masked',
  rate_limit: 'Rate limited',
  block: 'Blocked',
  quarantine: 'Quarantined',
}

export const BAND_COLOR = {
  optimal: 'var(--status-good)',
  healthy: 'var(--status-good)',
  moderate: 'var(--status-warning)',
  high: 'var(--status-serious)',
  critical: 'var(--status-critical)',
}

export const VERDICT_COLOR = {
  allowed: 'var(--status-good)',
  sanitized: 'var(--status-warning)',
  blocked: 'var(--status-critical)',
  quarantined: 'var(--status-critical)',
}

/* ------------------------------------------------------------ formatting */
export const pct = (v, digits = 0) =>
  v === null || v === undefined || Number.isNaN(v) ? '—' : `${(v * 100).toFixed(digits)}%`

export const num = (v, digits = 0) =>
  v === null || v === undefined || Number.isNaN(v)
    ? '—'
    : Number(v).toLocaleString(undefined, {
        minimumFractionDigits: digits,
        maximumFractionDigits: digits,
      })

export const ms = (v) => (v == null ? '—' : `${Number(v).toFixed(1)} ms`)

export const clock = (ts) =>
  ts ? new Date(ts * 1000).toLocaleTimeString(undefined, { hour12: false }) : '—'

export const datetime = (ts) =>
  ts ? new Date(ts * 1000).toLocaleString(undefined, { hour12: false }) : '—'

export const ago = (ts) => {
  if (!ts) return '—'
  const s = Math.max(0, Date.now() / 1000 - ts)
  if (s < 60) return `${Math.round(s)}s ago`
  if (s < 3600) return `${Math.round(s / 60)}m ago`
  if (s < 86400) return `${Math.round(s / 3600)}h ago`
  return `${Math.round(s / 86400)}d ago`
}

export const titleCase = (s) =>
  (s || '').replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase())

/** Resolve a CSS custom property to a concrete hex, for canvas/SVG contexts. */
export function resolveVar(name) {
  if (typeof window === 'undefined') return '#888'
  const raw = name.startsWith('var(') ? name.slice(4, -1) : name
  const v = getComputedStyle(document.documentElement).getPropertyValue(raw.trim())
  return v.trim() || '#888'
}

/* ------------------------------------------------------- chrome accents */
/* Deliberately separate from the data palette above. These colour the shell
 * — section headers, tabs, stat rails — and never appear inside a chart, so
 * a reader never has to ask whether a colour is decoration or a category. */
export const SECTION_ACCENT = {
  analyse: 'var(--accent-analyse)',
  evidence: 'var(--accent-evidence)',
  immune: 'var(--accent-immune)',
  system: 'var(--accent-system)',
}

/* ------------------------------------------------------- scan verdicts */
export const VERDICT_TONE = {
  clean: 'good',
  low: 'good',
  medium: 'warning',
  high: 'serious',
  critical: 'critical',
}

export const SCAN_VERDICT_COLOR = {
  clean: 'var(--status-good)',
  low: 'var(--status-good)',
  medium: 'var(--status-warning)',
  high: 'var(--status-serious)',
  critical: 'var(--status-critical)',
}

export const SCAN_VERDICT_LABEL = {
  clean: 'Clean',
  low: 'Low risk',
  medium: 'Medium risk',
  high: 'High risk',
  critical: 'Critical risk',
}

/* ------------------------------------------------- grades (probe, audit) */
/* A and B share the good slot on purpose: the meaningful break is
 * "nothing got through" vs "something did", not each letter step. */
export const GRADE_COLOR = {
  A: 'var(--status-good)',
  B: 'var(--status-good)',
  C: 'var(--status-warning)',
  D: 'var(--status-serious)',
  F: 'var(--status-critical)',
  unknown: 'var(--text-muted)',
}

export const GRADE_TINT = {
  A: 'var(--good-tint)',
  B: 'var(--good-tint)',
  C: 'var(--warning-tint)',
  D: 'var(--serious-tint)',
  F: 'var(--critical-tint)',
  unknown: 'var(--surface-3)',
}

/* ------------------------------------------------------- probe outcomes */
export const OUTCOME_COLOR = {
  vulnerable: 'var(--status-critical)',
  refused: 'var(--status-good)',
  deflected: 'var(--series-1)',
  answered: 'var(--status-good)',
  false_positive: 'var(--status-warning)',
  empty: 'var(--series-neutral)',
  error: 'var(--text-muted)',
}

export const OUTCOME_LABEL = {
  vulnerable: 'Leaked',
  refused: 'Refused',
  deflected: 'Deflected',
  answered: 'Answered',
  false_positive: 'False positive',
  empty: 'Empty reply',
  error: 'Request error',
}

export const PROBE_CATEGORY_LABEL = {
  prompt_injection: 'Prompt injection',
  jailbreak: 'Jailbreak',
  adversarial_obfuscation: 'Adversarial / obfuscation',
  data_exfiltration: 'Data exfiltration',
  model_extraction: 'Model extraction',
  control: 'Benign control',
}

export const PROBE_CATEGORY_COLOR = {
  prompt_injection: 'var(--series-1)',
  jailbreak: 'var(--series-2)',
  adversarial_obfuscation: 'var(--series-3)',
  data_exfiltration: 'var(--series-4)',
  model_extraction: 'var(--series-5)',
  control: 'var(--series-neutral)',
}

/* -------------------------------------------------------- audit surfaces */
export const SURFACE_LABEL = {
  system_prompt: 'System prompt',
  configuration: 'Configuration',
  dependency: 'Dependencies',
  response: 'Sample response',
  source_code: 'Source code',
  live_endpoint: 'Live behaviour',
}

export const SURFACE_COLOR = {
  system_prompt: 'var(--series-1)',
  configuration: 'var(--series-4)',
  dependency: 'var(--series-3)',
  response: 'var(--series-5)',
  source_code: 'var(--series-2)',
  live_endpoint: 'var(--status-critical)',
}

/* ------------------------------------------------------- report kinds */
export const REPORT_KIND_LABEL = { scan: 'Scan', probe: 'Endpoint probe', audit: 'App audit' }
export const REPORT_KIND_COLOR = {
  scan: 'var(--accent-analyse)',
  probe: 'var(--accent-evidence)',
  audit: 'var(--accent-immune)',
}

/** Human file size, for upload cards. */
export const bytes = (n) => {
  if (n == null) return '—'
  if (n < 1024) return `${n} B`
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 ** 2).toFixed(2)} MB`
}
