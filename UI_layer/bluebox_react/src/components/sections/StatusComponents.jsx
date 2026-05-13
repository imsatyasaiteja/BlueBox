import React, { useState } from 'react'
import { formatForDisplay, formatNumber } from '@/utils/format'
import { Panel, Alert, LoadingSpinner, Table, Modal } from '@/components/ui/Common'

export const StatusOverview = ({ status = null, anomaly = null }) => {
  if (!status) return <LoadingSpinner />

  const trusted = status.trusted_readiness?.trusted || false
  const statusColor = status.status === 'verified' ? 'verified' : status.status === 'failed' ? 'failed' : 'pending'
  const flaggedCount = anomaly
    ? anomaly.total_alerts ?? ((anomaly.anomalies || 0) + (anomaly.security_events_count || 0))
    : null

  return (
    <div className="grid grid-cols-4 gap-4 mb-6">
      <div className="card-panel">
        <p className="text-eyebrow">Total Entries</p>
        <p className="text-3xl font-black text-bluebox-cyan">{status.total_entries || 0}</p>
        {/* <p className="text-xs text-bluebox-muted">append-only rows</p> */}
      </div>

      <div className="card-panel">
        <p className="text-eyebrow">Flagged Entries</p>
        <p className={`text-3xl font-black ${(flaggedCount || 0) > 0 ? 'text-bluebox-red' : 'text-bluebox-green'}`}>
          {trusted ? flaggedCount ?? '-' : '-'}
        </p>
        {/* <p className="text-xs text-bluebox-muted">detected anomalies</p> */}
      </div>

      <div className="card-panel">
        <p className="text-eyebrow">Verified Entries</p>
        <p className="text-3xl font-black text-bluebox-green">{status.checked_entries || 0}</p>
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

export const ChainStatusPanel = ({ status = null }) => {
  if (!status) return <LoadingSpinner />

  const head = status.head || {}
  const trusted = status.trusted_readiness?.trusted || false
  const chainFailed = status.status === 'failed' || status.trusted_readiness?.checks?.chain_verified === false
  const health = chainFailed
    ? { label: 'Failed', color: '#FF6478', background: 'rgba(255, 100, 120, 0.12)' }
    : trusted
      ? { label: 'Good', color: '#49E38F', background: 'rgba(73, 227, 143, 0.12)' }
      : { label: 'Untrusted', color: '#FFD166', background: 'rgba(255, 209, 102, 0.12)' }

  return (
    <Panel title="Protected Storage" subtitle="Chain Head">
      <div className="space-y-4">
        <div className="chain-health-card">
          <div
            className="chain-health-dial"
            style={{
              '--chain-health-color': health.color,
              background: `conic-gradient(${health.color} 0 78%, rgba(139,203,255,0.12) 78% 100%)`,
            }}
          >
            <div className="chain-health-inner" style={{ backgroundColor: health.background }}>
              <strong style={{ color: health.color }}>{health.label}</strong>
              <span>Chain</span>
            </div>
          </div>
          <div>
            <p className="text-eyebrow">Current Sequence</p>
            <p className="text-4xl font-black text-bluebox-cyan">{head.sequence || '0'}</p>
            <p className="text-xs text-bluebox-muted">latest protected entry</p>
          </div>
        </div>

        <div className="space-y-2 text-sm">
          <div className="flex justify-between">
            <span className="text-bluebox-muted">Entry Count:</span>
            <span className="font-semibold text-bluebox-text">{head.entry_count || status.total_entries || 0}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-bluebox-muted">Status:</span>
            <span className="font-semibold" style={{ color: health.color }}>{health.label}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-bluebox-muted">Trusted:</span>
            <span className={`font-semibold ${status.trusted_readiness?.trusted ? 'text-bluebox-green' : 'text-bluebox-red'}`}>
              {trusted ? 'YES' : 'NO'}
            </span>
          </div>
        </div>

        {status.first_failure && (
          <Alert variant="critical">
            <strong>Latest Failure:</strong>
            <pre className="text-xs mt-2 overflow-auto">{formatForDisplay(status.first_failure)}</pre>
          </Alert>
        )}
      </div>
    </Panel>
  )
}

export const TrustedReadinessChecks = ({ status = null }) => {
  if (!status || !status.trusted_readiness) return null

  const checks = status.trusted_readiness.checks || {}
  const checkItems = Object.entries(checks)

  return (
    <Panel title="Trust Readiness" subtitle="5-Check Verification">
      <div className="space-y-2">
        {checkItems.map(([key, value]) => {
          const passed = value === true
          return (
            <div key={key} className="flex items-center justify-between p-2 rounded bg-opacity-20" style={{ backgroundColor: passed ? 'rgba(73, 227, 143, 0.1)' : 'rgba(255, 100, 120, 0.1)' }}>
              <span className="text-sm font-mono">{key.replace(/_/g, ' ')}</span>
              <span className={`font-bold text-sm ${passed ? 'text-bluebox-green' : 'text-bluebox-red'}`}>
                {passed ? 'PASS' : 'FAIL'}
              </span>
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

export const AnomalyList = ({ anomalies = [], securityEvents = [], gateMessage = '' }) => {
  if (!anomalies.length && !securityEvents.length) {
    return (
      <Alert variant="info" className="text-center py-6">
        {gateMessage || 'No anomalies or security events detected'}
      </Alert>
    )
  }

  return (
    <Panel title="Flagged Anomalies" subtitle="Ranked Alerts">
      <div className="space-y-2 max-h-96 overflow-y-auto">
        {anomalies
          .filter(a => a.predicted_anomaly === 1 || a.predicted_anomaly === '1')
          .slice(0, 20)
          .map((item, idx) => (
            <div key={idx} className="alert-card critical">
              <div className="flex gap-3">
                <div className="text-3xl font-black text-bluebox-red min-w-12">
                  {formatNumber(item.anomaly_score, 2)}
                </div>
                <div className="flex-1">
                  <strong className="text-bluebox-red">{item.severity?.toUpperCase() || 'ANOMALY'}</strong>
                  <p className="text-xs text-bluebox-muted">Seq #{item.sequence}</p>
                  <p className="text-xs mt-1">{item.explanation || 'Model verdict exceeded anomaly threshold'}</p>
                  <p className="text-xs text-bluebox-cyan mt-1">
                    SHAP: {item.top_features?.join(' / ') || 'N/A'}
                  </p>
                </div>
              </div>
            </div>
          ))}

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
