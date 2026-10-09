import React, { useCallback, useEffect, useState } from 'react'
import { Swords, RefreshCw, FileText, Target, AlertTriangle } from 'lucide-react'
import { api } from '../lib/api'
import { Banner, Card, Empty, Spinner, StatTile, ThreatBadge, VerdictBadge, ToggleGroup } from '../components/ui'
import { ConfusionMatrix, PerClassBars } from '../components/charts'
import { num, pct, titleCase } from '../lib/viz'

export default function Analytics() {
  const [training, setTraining] = useState(null)
  const [redteam, setRedteam] = useState(null)
  const [view, setView] = useState('fused')
  const [metric, setMetric] = useState('f1-score')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  const load = useCallback(async () => {
    try {
      setTraining(await api.report('training_report'))
      setErr('')
    } catch (e) {
      setErr(e.message)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const runRedteam = async () => {
    setBusy(true); setErr('')
    try { setRedteam(await api.redteam()) } catch (e) { setErr(e.message) } finally { setBusy(false) }
  }

  const block = training?.[view === 'fused' ? 'module3_fused' : 'module3_ml_only']

  return (
    <div className="stack">
      {err && (
        <Banner kind="warn">
          The model evaluation report is not available yet.
        </Banner>
      )}

      {training && (
        <>
          <Banner kind="info">
            Metrics below use a <strong>template-disjoint</strong> split: whole phrasing templates are
            held out, so the test set contains attack formulations the model has never seen. This is a
            deliberately harsh protocol — a conventional random split on a template-generated corpus
            leaks near-duplicates and reports inflated numbers. The cross-validation figure is exactly
            that optimistic in-distribution bound, and is shown only as a stability check.
          </Banner>

          <div className="grid grid-4">
            <StatTile label="Accuracy" value={pct(block?.accuracy, 2)} icon={Target}
                      foot={`${view === 'fused' ? 'ML + innate signatures' : 'ML ensemble only'}`}
                      meter={(block?.accuracy || 0) * 100} />
            <StatTile label="Macro F1" value={(block?.macro_f1 ?? 0).toFixed(4)}
                      foot="Unweighted mean across all six classes"
                      meter={(block?.macro_f1 || 0) * 100} />
            <StatTile label="Behaviour ROC-AUC" value={(training.module1_behavior?.test_auc ?? 0).toFixed(4)}
                      foot="Module 1, trained on benign traffic only"
                      meter={(training.module1_behavior?.test_auc || 0) * 100} />
            <StatTile label="Benign flag rate" value={pct(training.module1_behavior?.flag_rate_on_benign, 2)}
                      foot="Module 1 false-positive rate on clean traffic" />
          </div>

          <div className="grid grid-2">
            <Card title="Training run">
              <dl className="kv">
                <dt>Corpus size</dt><dd>{num(training.dataset_size)} prompts</dd>
                <dt>Train / test</dt><dd>{num(training.train_size)} / {num(training.test_size)}</dd>
                <dt>Split protocol</dt><dd>{training.split_protocol} (template-disjoint)</dd>
                <dt>Templates</dt><dd>{num(training.dataset?.n_templates)} phrasing templates</dd>
                <dt>Corpus checksum</dt><dd className="mono">{training.dataset?.checksum}</dd>
                <dt>TF-IDF features</dt><dd>{num(training.module3_training?.n_features)}</dd>
                <dt>SVD components</dt><dd>
                  {num(training.module3_training?.svd_components)}
                  {' '}({pct(training.module3_training?.svd_explained_variance, 1)} variance)
                </dd>
                <dt>Isolation Forest</dt><dd>{num(training.module1_behavior?.training_size)} benign prompts</dd>
                <dt>Duration</dt><dd>{num(training.duration_seconds, 1)} s</dd>
                <dt>Random seed</dt><dd>{training.settings?.random_seed}</dd>
              </dl>
            </Card>

            <Card title="Signature fusion contribution"
                  sub="What the innate layer adds on top of the ML ensemble">
              <div className="table-wrap">
                <table className="table">
                  <thead><tr><th>Configuration</th><th className="num">Accuracy</th><th className="num">Macro F1</th><th className="num">Weighted F1</th></tr></thead>
                  <tbody>
                    <tr>
                      <td>ML ensemble only</td>
                      <td className="num tnum">{(training.module3_ml_only?.accuracy ?? 0).toFixed(4)}</td>
                      <td className="num tnum">{(training.module3_ml_only?.macro_f1 ?? 0).toFixed(4)}</td>
                      <td className="num tnum">{(training.module3_ml_only?.weighted_f1 ?? 0).toFixed(4)}</td>
                    </tr>
                    <tr>
                      <td style={{ color: 'var(--text-primary)', fontWeight: 600 }}>ML + innate signatures</td>
                      <td className="num tnum">{(training.module3_fused?.accuracy ?? 0).toFixed(4)}</td>
                      <td className="num tnum">{(training.module3_fused?.macro_f1 ?? 0).toFixed(4)}</td>
                      <td className="num tnum">{(training.module3_fused?.weighted_f1 ?? 0).toFixed(4)}</td>
                    </tr>
                    <tr>
                      <td className="muted">Delta</td>
                      <td className="num tnum" style={{ color: 'var(--status-good)' }}>
                        +{(((training.module3_fused?.accuracy ?? 0) - (training.module3_ml_only?.accuracy ?? 0))).toFixed(4)}
                      </td>
                      <td className="num tnum" style={{ color: 'var(--status-good)' }}>
                        +{(((training.module3_fused?.macro_f1 ?? 0) - (training.module3_ml_only?.macro_f1 ?? 0))).toFixed(4)}
                      </td>
                      <td className="num tnum" style={{ color: 'var(--status-good)' }}>
                        +{(((training.module3_fused?.weighted_f1 ?? 0) - (training.module3_ml_only?.weighted_f1 ?? 0))).toFixed(4)}
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
              {training.cv_macro_f1?.length > 0 && (
                <div className="muted" style={{ fontSize: 12, marginTop: 12, lineHeight: 1.55 }}>
                  <strong>Cross-validation (in-distribution):</strong>{' '}
                  {training.cv_macro_f1.map((s) => s.toFixed(4)).join(', ')} — mean{' '}
                  {training.cv_mean?.toFixed(4)} ± {training.cv_std?.toFixed(4)}. Folds are random
                  within the training split, so templates appear on both sides; this measures
                  ensemble stability, <em>not</em> generalisation to new phrasings.
                </div>
              )}
            </Card>
          </div>

          <Card
            title="Confusion matrix"
            sub="Row-normalised recall on held-out phrasings"
            actions={
              <ToggleGroup
                value={view}
                onChange={setView}
                options={[{ value: 'fused', label: 'ML + innate' }, { value: 'ml', label: 'ML only' }]}
              />
            }
          >
            <ConfusionMatrix matrix={block?.confusion_matrix} labels={block?.labels || []} />
          </Card>

          <Card
            title="Per-class performance"
              actions={
                <ToggleGroup
                  value={metric}
                  onChange={setMetric}
                  options={[
                    { value: 'f1-score', label: 'F1' },
                    { value: 'precision', label: 'Precision' },
                    { value: 'recall', label: 'Recall' },
                  ]}
                />
              }
            >
              <PerClassBars perClass={block?.per_class} labels={block?.labels} metric={metric} />
              <div className="table-wrap" style={{ marginTop: 10 }}>
                <table className="table">
                  <thead><tr><th>Class</th><th className="num">Precision</th><th className="num">Recall</th><th className="num">F1</th><th className="num">Support</th></tr></thead>
                  <tbody>
                    {(block?.labels || []).map((l) => {
                      const d = block.per_class?.[l] || {}
                      return (
                        <tr key={l}>
                          <td><ThreatBadge value={l} /></td>
                          <td className="num tnum">{(d.precision ?? 0).toFixed(4)}</td>
                          <td className="num tnum">{(d.recall ?? 0).toFixed(4)}</td>
                          <td className="num tnum">{(d['f1-score'] ?? 0).toFixed(4)}</td>
                          <td className="num tnum">{num(d.support)}</td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
          </Card>
        </>
      )}

      <Card
        title="Red-team battery"
        sub="Curated attacks, benign controls and evasive rewordings replayed end to end"
        actions={
          <button className="btn btn-primary btn-sm" onClick={runRedteam} disabled={busy}>
            {busy ? <Spinner size={13} /> : <Swords size={13} />} Run battery
          </button>
        }
      >
        {!redteam ? (
          <Empty icon={Target}>
            Run the battery to evaluate the full pipeline — not just the classifier — against
            hand-written attacks and false-positive controls.
          </Empty>
        ) : (
          <div className="stack">
            <div className="grid grid-4">
              <StatTile label="Attacks detected" value={`${redteam.attacks_detected}/${redteam.attacks_total}`}
                        foot={pct(redteam.detection_rate, 1)} meter={redteam.detection_rate * 100} />
              <StatTile label="Exact class match" value={pct(redteam.exact_class_rate, 1)}
                        foot="Correct threat family, not just 'malicious'" meter={redteam.exact_class_rate * 100} />
              <StatTile label="False positives" value={`${redteam.false_positives}/${redteam.benign_total}`}
                        tone={redteam.false_positives ? 'critical' : 'good'}
                        foot={`${pct(redteam.false_positive_rate, 1)} of benign controls blocked`} />
              <StatTile label="Evasive variants caught"
                        value={redteam.evasive?.total ? `${redteam.evasive.detected}/${redteam.evasive.total}` : '—'}
                        foot={`memory recall ${pct(redteam.evasive?.memory_recall_rate, 0)}`}
                        meter={(redteam.evasive?.detection_rate || 0) * 100} />
            </div>

            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Case</th><th>Kind</th><th>Expected</th><th>Predicted</th>
                    <th>Verdict</th><th className="num">Conf.</th><th>Signatures</th><th>Result</th>
                  </tr>
                </thead>
                <tbody>
                  {redteam.cases.map((c) => {
                    const ok = c.kind === 'benign' ? !c.blocked_false_positive : c.detected
                    return (
                      <tr key={c.case_id}>
                        <td className="mono">{c.case_id}</td>
                        <td>{titleCase(c.kind)}</td>
                        <td className="muted">{titleCase(c.expected)}</td>
                        <td><ThreatBadge value={c.predicted} /></td>
                        <td><VerdictBadge value={c.verdict} /></td>
                        <td className="num tnum">{pct(c.confidence, 0)}</td>
                        <td className="mono truncate" style={{ maxWidth: 180 }}>
                          {c.signature_hits?.join(', ') || '—'}
                        </td>
                        <td>
                          <span className="badge" style={{
                            color: ok ? 'var(--status-good)' : 'var(--status-critical)',
                            borderColor: ok ? 'var(--status-good)' : 'var(--status-critical)',
                          }}>
                            {ok ? 'Pass' : 'Fail'}
                          </span>
                          {c.memory_recall && <span className="chip" style={{ marginLeft: 5 }}>recall</span>}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </Card>
    </div>
  )
}
