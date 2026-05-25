import React, { useMemo, useState } from 'react'
import { formatForDisplay, formatNumber } from '@/utils/format'
import { Panel, Alert, Button, LoadingSpinner, Table, Modal } from '@/components/ui/Common'
import { useSteppedNumber } from '@/hooks/useAnimatedNumber'
import blueboxLogo from '../../../images/logo_white_nobg.png'

export const StatusOverview = ({ status = null, anomaly = null }) => {
  const trusted = status?.trusted_readiness?.trusted || false
  const statusColor = status?.status === 'verified' ? 'verified' : status?.status === 'failed' ? 'failed' : 'pending'
  const flaggedCount = anomaly
    ? anomaly.anomalies ?? 0
    : null
  const liveCounterActive = Boolean(status?.live_traffic?.active)
  const totalEntries = useSteppedNumber(status?.total_entries || 0, {
    enabled: liveCounterActive,
    intervalMs: 28,
  })
  const flaggedEntries = useSteppedNumber(trusted ? flaggedCount ?? 0 : 0, {
    enabled: liveCounterActive && flaggedCount !== null,
    intervalMs: 55,
  })
  const verifiedEntries = useSteppedNumber(status?.checked_entries || 0, {
    enabled: liveCounterActive,
    intervalMs: 28,
  })

  if (!status) return <LoadingSpinner />

  return (
    <div className="grid grid-cols-4 gap-4 mb-6">
      <div className="card-panel">
        <p className="text-eyebrow">Total Entries</p>
        <p className="text-3xl font-black text-bluebox-cyan">{totalEntries}</p>
        {/* <p className="text-xs text-bluebox-muted">append-only rows</p> */}
      </div>

      <div className="card-panel">
        <p className="text-eyebrow">Flagged Entries</p>
        <p className={`text-3xl font-black ${(flaggedCount || 0) > 0 ? 'text-bluebox-red' : 'text-bluebox-green'}`}>
          {trusted ? flaggedEntries : '-'}
        </p>
        {/* <p className="text-xs text-bluebox-muted">detected anomalies</p> */}
      </div>

      <div className="card-panel">
        <p className="text-eyebrow">Verified Entries</p>
        <p className="text-3xl font-black text-bluebox-green">{verifiedEntries}</p>
        {/* <p className="text-xs text-bluebox-muted">rows checked</p> */}
      </div>

      <div className="card-panel">
        <p className="text-eyebrow">Chain Status</p>
        <p className={`text-2xl font-black ${statusColor === 'verified' ? 'text-bluebox-green' : statusColor === 'failed' ? 'text-bluebox-red' : 'text-bluebox-yellow'}`}>
          {status.status?.toUpperCase() || 'UNKNOWN'}
        </p>
        {/* <p className="text-xs text-bluebox-muted">{trusted ? 'trusted' : 'not trusted'}</p> */}
      </div>
    </div>
  )
}

export const ChainStatusPanel = ({ status = null, onVerifyChain = null, busy = false }) => {
  if (!status) return <LoadingSpinner />

  const head = status.head || {}
  const trusted = status.trusted_readiness?.trusted || false
  const chainFailed = status.status === 'failed' || status.trusted_readiness?.checks?.chain_verified === false
  const health = chainFailed
    ? { label: 'Failed', color: '#FF6478', background: 'rgba(255, 100, 120, 0.12)' }
    : trusted
      ? { label: 'Verified', color: '#49E38F', background: 'rgba(73, 227, 143, 0.12)' }
      : { label: 'Untrusted', color: '#FFD166', background: 'rgba(255, 209, 102, 0.12)' }

  return (
    <Panel
      title="DB Storage"
      subtitle="Chain Integrity"
      headerAction={onVerifyChain && (
        <Button
          variant="success"
          onClick={onVerifyChain}
          disabled={busy}
          className="logger-chain-verify-button"
        >
          Verify Chain
        </Button>
      )}
    >
      <div className="space-y-4">
        <div className="chain-health-card">
          <div
            className="chain-health-dial"
            style={{
              '--chain-health-color': health.color,
              '--chain-logo-mask': `url(${blueboxLogo})`,
            }}
          >
            <div className="chain-health-inner">
              <span className="chain-health-logo" aria-hidden="true" />
            </div>
          </div>
          <div>
            <p className="text-eyebrow">Current Sequence</p>
            <p className="text-4xl font-black text-bluebox-cyan">{head.sequence || '0'}</p>
            <p className="chain-health-status-text" style={{ color: health.color }}>{health.label} Chain</p>
          </div>
        </div>
      </div>
    </Panel>
  )
}

export const TrustedReadinessChecks = ({ status = null, layout = 'grid' }) => {
  if (!status || !status.trusted_readiness) return null

  const checks = status.trusted_readiness.checks || {}
  const checkCopy = {
    chain_verified: {
      label: 'Integrity Chain',
    },
    recovery_ledger_verified: {
      label: 'Recovery Ledger',
    },
    ai_evidence_ledger_verified: {
      label: 'AI Evidence Ledger',
    },
    ai_checkpoints_verified: {
      label: 'Merkle Checkpoints',
    },
  }
  const checkItems = [
    'chain_verified',
    'recovery_ledger_verified',
    'ai_evidence_ledger_verified',
    'ai_checkpoints_verified',
  ]
    .filter(key => Object.prototype.hasOwnProperty.call(checks, key))
    .map(key => [key, checks[key]])

  return (
    <Panel title="Integrity Checks Detail" subtitle="Trusted Evidence Gate">
      <div className={`logger-checklist ${layout === 'linear' ? 'linear' : ''}`}>
        {checkItems.map(([key, value]) => {
          const passed = value === true
          const item = checkCopy[key] || {
            label: key.replace(/_/g, ' '),
          }
          return (
            <div key={key} className={`logger-check-row ${passed ? 'pass' : 'fail'}`}>
              <div>
                <strong>{item.label}</strong>
              </div>
              <span>{passed ? 'Pass' : 'Fail'}</span>
            </div>
          )
        })}
      </div>
    </Panel>
  )
}

export const EntriesViewer = ({ entries = [], onEntryClick = null, loading = false }) => {
  const [selectedEntry, setSelectedEntry] = useState(null)

  if (loading) return <LoadingSpinner />

  const columns = [
    { key: 'sequence', label: 'Seq', render: (val) => <span className="font-mono">{val}</span> },
    { key: 'event_type', label: 'Type', render: (val) => <span className="px-2 py-1 rounded text-xs bg-cyan-900 bg-opacity-30">{val}</span> },
    { key: 'source_offset', label: 'Offset', render: (val) => <span className="font-mono">{val}</span> },
    { key: 'mode', label: 'Mode', render: (val) => <span>{val}</span> },
    { key: 'source_file', label: 'Source', render: (val) => <span className="text-xs">{val || '-'}</span> },
  ]

  return (
    <Panel title="Log Entries" subtitle={`${entries.length} records`}>
      <div className="overflow-auto max-h-96">
        <Table
          columns={columns}
          rows={entries}
          onRowClick={(row) => {
            setSelectedEntry(row)
            onEntryClick?.(row)
          }}
        />
      </div>

      {selectedEntry && (
        <Modal
          title="Entry Detail"
          isOpen={!!selectedEntry}
          onClose={() => setSelectedEntry(null)}
        >
          <pre className="text-xs bg-bluebox-dark p-3 rounded overflow-auto max-h-64">
            {formatForDisplay(selectedEntry)}
          </pre>
        </Modal>
      )}
    </Panel>
  )
}

const SEVERITY_ORDER = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  NONE: 0,
  NORMAL: 0,
}

const SCORE_BUCKET_SIZE = 0.005

const severityRank = (severity = '') => SEVERITY_ORDER[String(severity || '').toUpperCase()] ?? 0

const scoreBucket = (score = 0) => {
  const value = Number(score || 0)
  return Math.round(value / SCORE_BUCKET_SIZE) * SCORE_BUCKET_SIZE
}

const normalizedText = (value = '') => String(value || '').trim().toLowerCase()

const anomalySignature = (item = {}) => {
  const anomalyType = normalizedText(item.anomaly_type)
  if (anomalyType && anomalyType !== 'none') return anomalyType.replace(/_/g, ' ')

  const features = Array.isArray(item.top_features) ? item.top_features.filter(Boolean).join(' / ') : ''
  if (features) return features.replace(/_/g, ' ')

  const explanation = normalizedText(item.explanation)
  if (explanation) return explanation.split('.')[0]

  return [
    item.data_format,
    item.domain,
    item.protocol || item.label_octal,
    item.port ? `port ${item.port}` : '',
  ].filter(Boolean).join(' / ') || 'model threshold'
}

const groupAnomalies = (anomalies = []) => {
  const flagged = anomalies.filter(a => Number(a.predicted_anomaly || 0) === 1)
  const groups = new Map()

  flagged.forEach((item) => {
    const bucket = scoreBucket(item.anomaly_score)
    const signature = anomalySignature(item)
    const key = [
      String(item.severity || 'ANOMALY').toUpperCase(),
      bucket.toFixed(3),
      normalizedText(signature),
      normalizedText(item.domain),
      normalizedText(item.protocol || item.label_octal),
    ].join('|')

    if (!groups.has(key)) {
      groups.set(key, {
        key,
        severity: String(item.severity || 'ANOMALY').toUpperCase(),
        scoreBucket: bucket,
        signature,
        domain: item.domain,
        protocol: item.protocol,
        label: item.label_octal,
        port: item.port,
        top_features: item.top_features || [],
        explanation: item.explanation || '',
        items: [],
        minScore: Number(item.anomaly_score || 0),
        maxScore: Number(item.anomaly_score || 0),
      })
    }

    const group = groups.get(key)
    const score = Number(item.anomaly_score || 0)
    group.items.push(item)
    group.minScore = Math.min(group.minScore, score)
    group.maxScore = Math.max(group.maxScore, score)
    if (!group.explanation && item.explanation) group.explanation = item.explanation
    if (!group.top_features?.length && item.top_features?.length) group.top_features = item.top_features
  })

  return Array.from(groups.values())
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.minScore - b.minScore || b.items.length - a.items.length)
}

export const AnomalyList = ({ anomalies = [], securityEvents = [], gateMessage = '' }) => {
  const [expandedGroup, setExpandedGroup] = useState(null)
  const groupedAnomalies = useMemo(() => groupAnomalies(anomalies), [anomalies])

  if (!anomalies.length && !securityEvents.length) {
    return (
      <Alert variant="info" className="text-center py-6">
        {gateMessage || 'No anomalies or security events detected'}
      </Alert>
    )
  }

  return (
    <Panel title="Flagged Anomalies" subtitle={`${groupedAnomalies.length} Grouped Anomalies`}>
      <div className="space-y-2 max-h-96 overflow-y-auto">
        {groupedAnomalies.map((group, idx) => {
          const expanded = expandedGroup === group.key
          const scoreLabel = Math.abs(group.maxScore - group.minScore) < 0.0005
            ? formatNumber(group.minScore, 3)
            : `${formatNumber(group.minScore, 3)} to ${formatNumber(group.maxScore, 3)}`
          const sequences = group.items
            .map(item => item.sequence || item.evidence_id)
            .filter(Boolean)
            .sort((a, b) => Number(a) - Number(b))

          return (
            <div key={group.key || idx} className="alert-card critical">
              <button
                type="button"
                className="w-full text-left"
                onClick={() => setExpandedGroup(expanded ? null : group.key)}
              >
                <div className="flex gap-3 items-start">
                  <div className="text-2xl font-black text-bluebox-red min-w-20">
                    {scoreLabel}
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center justify-between gap-3">
                      <strong className="text-bluebox-red">{group.severity}</strong>
                      <span className="text-xs font-bold text-bluebox-cyan">
                        {group.items.length} entries {expanded ? 'hide' : 'show'}
                      </span>
                    </div>
                    <p className="text-xs text-bluebox-muted">
                      {group.signature}
                    </p>
                    <p className="text-xs text-bluebox-muted">
                      {[group.domain, group.protocol || group.label, group.port ? `port ${group.port}` : '']
                        .filter(Boolean)
                        .join(' / ') || 'source unavailable'}
                    </p>
                    <p className="text-xs mt-1">{group.explanation || 'Model verdict exceeded anomaly threshold'}</p>
                    <p className="text-xs text-bluebox-cyan mt-1">
                      SHAP: {group.top_features?.join(' / ') || 'N/A'}
                    </p>
                  </div>
                </div>
              </button>

              {expanded && (
                <div className="mt-3 pt-3 border-t border-slate-700">
                  <p className="text-eyebrow mb-2">Sequences in this pattern</p>
                  <div className="flex flex-wrap gap-2">
                    {sequences.map(sequence => (
                      <span
                        key={`${group.key}-${sequence}`}
                        className="px-2 py-1 rounded bg-bluebox-dark text-xs font-mono text-bluebox-text border border-slate-700"
                      >
                        #{sequence}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )
        })}

        {securityEvents.slice(0, 10).map((item, idx) => (
          <div key={`sec-${idx}`} className="alert-card warning">
            <div className="flex gap-3">
              <div className="text-2xl font-black text-bluebox-yellow min-w-12">SEC</div>
              <div className="flex-1">
                <strong className="text-bluebox-yellow">SECURITY EVENT</strong>
                <p className="text-xs text-bluebox-muted">Seq #{item.sequence}</p>
                <p className="text-xs mt-1">
                  {item.details?.operation ? `${item.details.operation} attempt on #${item.details.target_sequence}` : item.event}
                </p>
              </div>
            </div>
          </div>
        ))}
      </div>
    </Panel>
  )
}
