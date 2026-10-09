import React, { useCallback, useEffect, useState } from 'react'
import { api } from '../lib/api'
import { THREAT_LABEL, ago, num, pct, titleCase } from '../lib/viz'
import { ActionBadge, Banner, Card, Empty, Spinner } from '../components/ui'
import { Kpi, ThreatBarList } from '../components/soc'

/* Artificial Immune Memory and controlled self-healing.
 *
 * The memory learns every attack it sees. From recurring attacks it proposes
 * new defence rules — but a rule only goes live after the owner runs its
 * security test (zero benign matches, at least one real attack matched) and
 * approves it. Nothing rewrites the defences on its own. */
export default function Memory({ liveTick }) {
  const [mem, setMem] = useState(null)
  const [rules, setRules] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')

  const load = useCallback(async () => {
    try {
      const [m, r] = await Promise.all([api.soc.memory(), api.soc.rules()])
      setMem(m); setRules(r); setError('')
    } catch (e) { setError(e.message) }
  }, [])
  useEffect(() => { load() }, [load, liveTick])

  const act = async (fn, id) => {
    setBusy(id); setError('')
    try { await fn(id); await load() } catch (e) { setError(e.message) } finally { setBusy('') }
  }

  if (!mem || !rules) return error ? <Banner kind="err">{error}</Banner> : <div className="row"><Spinner /> Loading…</div>
  const s = mem.stats
  return (
    <div className="stack">
      {error && <Banner kind="err">{error}</Banner>}
      <div className="grid grid-4">
        <Kpi label="Attack patterns remembered" value={num(s.primary_cells)}
             definition="Distinct attacks held as memory cells (Module 5)." />
        <Kpi label="Recall rate" value={pct(s.recall_rate || 0)}
             definition="Share of attacks recognised from memory — the secondary immune response." />
        <Kpi label="Clonal variants" value={num(s.clones)}
             definition="Mutated copies generated so rewordings of a known attack are caught." />
        <Kpi label="Immunity strength" value={pct(s.immunity_strength || 0)}
             definition="Blend of recall coverage and memory diversity." />
      </div>

      <div className="grid grid-2-1">
        <Card title="Remembered attacks" sub="Most frequently seen first · examples are redacted">
          {!mem.patterns.length ? <Empty>No attacks remembered yet.</Empty> : (
            <div className="table-wrap"><table className="table">
              <thead><tr><th>Threat</th><th>Example</th><th className="num">Seen</th><th className="num">Clones</th><th>Last seen</th></tr></thead>
              <tbody>{mem.patterns.map((p) => (
                <tr key={p.cell_id}>
                  <td className="nowrap">{THREAT_LABEL[p.threat_class] || titleCase(p.threat_class)}</td>
                  <td className="mono" style={{ maxWidth: 420 }}><div className="truncate">{p.exemplar}</div></td>
                  <td className="num">{num(p.encounters)}</td>
                  <td className="num">{num(p.clones)}</td>
                  <td className="nowrap">{ago(p.last_seen)}</td>
                </tr>
              ))}</tbody>
            </table></div>
          )}
        </Card>
        <Card title="Memory by threat type">
          <ThreatBarList distribution={s.by_class} />
        </Card>
      </div>

      <Card title="Suggested defence rules" sub="Proposed by the immune memory from recurring attacks. Test, then approve — nothing goes live on its own.">
        {!rules.pending.length ? <Empty>No suggestions yet. Rules appear once the same attack phrasing recurs several times.</Empty> : (
          <div className="table-wrap"><table className="table">
            <thead><tr><th>Rule</th><th>Pattern</th><th>Threat</th><th className="num">Support</th><th>Security test</th><th /></tr></thead>
            <tbody>{rules.pending.map((r) => {
              const v = r.validation
              return (
                <tr key={r.rule_id}>
                  <td className="mono nowrap">{r.rule_id}</td>
                  <td className="mono" style={{ maxWidth: 280 }}><div className="truncate" title={r.pattern}>{r.pattern}</div></td>
                  <td className="nowrap">{THREAT_LABEL[r.threat_class] || r.threat_class} → <ActionBadge value={r.action} /></td>
                  <td className="num">{num(r.support)}</td>
                  <td style={{ fontSize: 12.5 }}>
                    {!v ? <span className="muted">Not tested</span> : v.passed ? (
                      <span style={{ color: 'var(--status-good)' }}>Passed — {v.attack_hits} attacks, 0 of {num(v.benign_tested)} benign</span>
                    ) : (
                      <span style={{ color: 'var(--status-critical)' }}>
                        Failed — {v.benign_hits} benign match{v.benign_hits === 1 ? '' : 'es'}, {v.attack_hits} attacks</span>
                    )}
                  </td>
                  <td className="nowrap" style={{ textAlign: 'right' }}>
                    <button className="btn btn-sm" disabled={busy === r.rule_id}
                            onClick={() => act(api.soc.validateRule, r.rule_id)}>Test</button>{' '}
                    <button className="btn btn-sm btn-primary" disabled={!v?.passed || busy === r.rule_id}
                            onClick={() => act(api.soc.approveRule, r.rule_id)}>Approve</button>{' '}
                    <button className="btn btn-sm btn-ghost" disabled={busy === r.rule_id}
                            onClick={() => act(api.soc.rejectRule, r.rule_id)}>Reject</button>
                  </td>
                </tr>
              )
            })}</tbody>
          </table></div>
        )}
      </Card>

      <Card title="Rules enforcing now" sub="Approved self-healing rules, applied by Module 4 alongside the built-in signatures">
        {!rules.active.length ? <Empty>No self-healing rules are active.</Empty> : (
          <div className="table-wrap"><table className="table">
            <thead><tr><th>Rule</th><th>Pattern</th><th>Threat</th><th>Approved</th><th /></tr></thead>
            <tbody>{rules.active.map((r) => (
              <tr key={r.rule_id}>
                <td className="mono">{r.rule_id}</td>
                <td className="mono"><div className="truncate" title={r.pattern}>{r.pattern}</div></td>
                <td>{THREAT_LABEL[r.threat_class] || r.threat_class} → <ActionBadge value={r.action} /></td>
                <td>{r.approved_at ? ago(r.approved_at) : 'at training'}</td>
                <td style={{ textAlign: 'right' }}>
                  <button className="btn btn-sm" onClick={() => act(api.soc.disableRule, r.rule_id)}>Disable</button>
                </td>
              </tr>
            ))}</tbody>
          </table></div>
        )}
      </Card>
    </div>
  )
}
