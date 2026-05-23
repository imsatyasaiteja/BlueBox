import React, { useMemo, useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { useAutoRefresh, useRunAction } from '@/hooks/useApi'
import { Header, AppLayout } from '@/components/layout/Layout'
import { ChainStatusPanel, TrustedReadinessChecks, StatusOverview } from '@/components/sections/StatusComponents'
import { Panel, Button, LoadingSpinner, Alert } from '@/components/ui/Common'
import { api } from '@/api/client'
import { formatDateTime } from '@/utils/format'
import { DEFAULT_DASHBOARD_TIME_ZONE, getTimeZoneOption } from '@/utils/timeZones'

const basename = (value = '') => {
  const text = String(value || '')
  return text.split(/[\\/]/).pop() || text || 'Unknown'
}

const titleCase = (value = '') =>
  String(value || '')
    .replace(/_/g, ' ')
    .toLowerCase()
    .replace(/\b[a-z]/g, char => char.toUpperCase())

const sourceTypeLabel = (source = {}) => {
  const type = String(source.source_type || '').toUpperCase()
  const file = String(source.source_file || '').toLowerCase()
  if (type === 'PCAP' || file.endsWith('.pcap')) return 'PCAP'
  if (file.endsWith('_labels.csv')) return 'CSV Labels'
  if (type === 'CSV' || file.endsWith('.csv')) return 'CSV'
  if (type === 'DEMO_MANIFEST') return 'Manifest'
  if (type === 'SECURITY_EVENT') return 'Security'
  return type || 'Source'
}

const sourceSortRank = (source = {}) => {
  const label = sourceTypeLabel(source)
  if (label === 'PCAP') return 0
  if (label === 'CSV') return 1
  if (label === 'CSV Labels') return 2
  return 3
}

const stateClass = (state) => {
  const text = String(state || '').toLowerCase()
  if (text.includes('critical') || text.includes('high') || text.includes('fail') || text.includes('missing') || text.includes('not trusted')) return 'fail'
  if (text.includes('warning') || text.includes('medium') || text.includes('ready') || text.includes('mismatch') || text.includes('unanchored')) return 'warn'
  if (text.includes('low') || text.includes('info') || text.includes('verified') || text.includes('performed') || text.includes('pass')) return 'pass'
  return 'neutral'
}

const StatusBadge = ({ children, state = children }) => (
  <span className={`logger-state-badge ${stateClass(state)}`}>{children}</span>
)

const DetailValue = ({ label, value, state = null, className = '' }) => (
  <div className={`logger-detail-tile ${className}`}>
    <span>{label}</span>
    <strong>{state ? <StatusBadge state={state}>{value}</StatusBadge> : value}</strong>
  </div>
)

const formatLoggerTimestamp = (value, timeZoneOption = DEFAULT_DASHBOARD_TIME_ZONE) => {
  if (!value) return null
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return null

  return {
    date: new Intl.DateTimeFormat([], {
      timeZone: timeZoneOption.timeZone,
      day: '2-digit',
      month: 'short',
      year: 'numeric',
    }).format(date),
    time: new Intl.DateTimeFormat([], {
      timeZone: timeZoneOption.timeZone,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    }).format(date),
    zone: timeZoneOption.label,
  }
}

const TimestampValue = ({ value, timeZoneOption, fallback = '-' }) => {
  const timestamp = formatLoggerTimestamp(value, timeZoneOption)
  if (!timestamp) return <span className="logger-timestamp-empty">{fallback}</span>

  return (
    <div className="logger-timestamp-value">
      <span className="logger-timestamp-time">
        {timestamp.time} <em>{timestamp.zone}</em>
      </span>
      <span className="logger-timestamp-date">{timestamp.date}</span>
    </div>
  )
}

const VerificationTimeline = ({ status, selectedTimeZone = DEFAULT_DASHBOARD_TIME_ZONE.timeZone, compact = false }) => {
  const timeZoneOption = getTimeZoneOption(selectedTimeZone)
  const failure = status.first_failure
  const failureText = failure
    ? failure.sequence != null ? `Failed At #${failure.sequence}` : 'Failed At Anchor'
    : 'No Failure Recorded'

  return (
    <Panel
      title="Verification Timeline"
      subtitle={`Evidence Clock - ${timeZoneOption.label}`}
      className={compact ? 'logger-evidence-clock compact' : 'logger-evidence-clock'}
    >
      <div className={`logger-timeline-grid ${compact ? 'compact' : ''}`}>
        <DetailValue
          label="Last Verified"
          value={status.verified_at ? <TimestampValue value={status.verified_at} timeZoneOption={timeZoneOption} /> : 'Not Verified'}
        />
        <DetailValue label="First Seen" value={<TimestampValue value={status.first_seen} timeZoneOption={timeZoneOption} />} />
        <DetailValue label="Last Seen" value={<TimestampValue value={status.last_seen} timeZoneOption={timeZoneOption} />} />
        <DetailValue label="Latest Failure" value={failureText} />
      </div>
    </Panel>
  )
}

const ActivityTimestamp = ({ value, timeZoneOption }) => {
  const timestamp = formatLoggerTimestamp(value, timeZoneOption)
  if (!timestamp) return <span>-</span>
  return (
    <span className="logger-table-time">
      <strong>{timestamp.time} {timestamp.zone}</strong>
      <em>{timestamp.date}</em>
    </span>
  )
}

const activityKindLabel = (item) => {
  if (item.kind_label) return item.kind_label
  if (item.kind === 'ai_evidence' || item.kind === 'ai_checkpoint') return 'AI'
  if (item.kind === 'mutation_attempt') return 'Attempt'
  return 'Log'
}

const activityRecordLabel = (item) => {
  if (item.record_label) return item.record_label
  if (item.kind === 'ai_evidence') return `AI #${item.evidence_id || item.record_id || '-'}`
  if (item.kind === 'ai_checkpoint') return `AI Checkpoint #${item.checkpoint_id || item.record_id || '-'}`
  if (item.kind === 'mutation_attempt') return `Attempt #${item.attempt_id || item.record_id || '-'}`
  return `Log #${item.sequence || '-'}`
}

const activityClassification = (item) => {
  const text = String(item.classification || '').toLowerCase()
  return text === 'critical' ? 'Critical' : 'Normal'
}

const activityMatchesQuery = (item, query) => {
  if (!query) return true
  const haystack = [
    activityKindLabel(item),
    activityRecordLabel(item),
    item.activity,
    item.source_file,
    item.source_type,
    item.source_offset,
    item.context,
    item.classification,
    item.sequence,
    item.evidence_id,
    item.attempt_id,
  ].join(' ').toLowerCase()
  return haystack.includes(query)
}

const buildActivityBatches = (items = []) => {
  const groups = new Map()

  items.forEach(item => {
    const key = item.batch_key || `${activityKindLabel(item)}:${item.activity}:${item.source_file}:${activityClassification(item)}`
    const recordedAt = item.recorded_at ? new Date(item.recorded_at).getTime() : 0
    const existing = groups.get(key)
    const classification = activityClassification(item)

    if (!existing) {
      groups.set(key, {
        key,
        kindLabel: activityKindLabel(item),
        title: item.activity || 'Append-only activity',
        source: basename(item.source_file),
        classification,
        latestAt: recordedAt,
        latestValue: item.recorded_at,
        items: [item],
      })
      return
    }

    existing.items.push(item)
    if (classification === 'Critical') existing.classification = 'Critical'
    if (recordedAt > existing.latestAt) {
      existing.latestAt = recordedAt
      existing.latestValue = item.recorded_at
    }
  })

  return Array.from(groups.values())
    .map(batch => ({
      ...batch,
      items: batch.items.sort((a, b) => (
        String(b.recorded_at || '').localeCompare(String(a.recorded_at || ''))
      )),
    }))
    .sort((a, b) => b.latestAt - a.latestAt)
}

const AppendOnlyActivity = ({ activity = [], selectedTimeZone = DEFAULT_DASHBOARD_TIME_ZONE.timeZone }) => {
  const timeZoneOption = getTimeZoneOption(selectedTimeZone)
  const [query, setQuery] = useState('')
  const [expandedBatchKey, setExpandedBatchKey] = useState(null)
  const normalizedQuery = query.trim().toLowerCase()
  const filteredActivity = useMemo(
    () => activity.filter(item => activityMatchesQuery(item, normalizedQuery)),
    [activity, normalizedQuery],
  )
  const batches = useMemo(() => buildActivityBatches(filteredActivity), [filteredActivity])
  const hasActivity = activity.length > 0

  return (
    <Panel
      title="Append-Only Activity"
      subtitle="DB Writes and Mutation Attempts"
      className="logger-activity-panel"
      headerAction={(
        <input
          aria-label="Search append-only activity"
          className="input-field logger-activity-search"
          placeholder="Search Activity"
          value={query}
          onChange={event => setQuery(event.target.value)}
          disabled={!hasActivity}
        />
      )}
    >
      {hasActivity ? (
        <div className="logger-activity-feed" role="list" aria-label="Append-only activity feed">
          {batches.length ? batches.map(batch => {
            const expanded = batch.key === expandedBatchKey
            const className = batch.classification.toLowerCase()

            return (
              <section key={batch.key} className="logger-activity-batch" role="listitem">
                <button
                  type="button"
                  className="logger-activity-batch-header"
                  aria-expanded={expanded}
                  onClick={() => setExpandedBatchKey(expanded ? null : batch.key)}
                >
                  <span className={`logger-activity-kind ${batch.kindLabel.toLowerCase()}`}>{batch.kindLabel}</span>
                  <div className="logger-activity-batch-title">
                    <strong>{batch.title}</strong>
                    <span>{batch.source}</span>
                  </div>
                  <span className={`logger-activity-classification ${className}`}>{batch.classification}</span>
                  <strong className="logger-activity-count">{batch.items.length} records</strong>
                  <ActivityTimestamp value={batch.latestValue} timeZoneOption={timeZoneOption} />
                  <span className="logger-activity-toggle-label">{expanded ? 'Hide' : 'Show'}</span>
                </button>

                {expanded && (
                  <div className="logger-activity-record-list">
                    {batch.items.map(item => {
                      const itemClassName = activityClassification(item).toLowerCase()
                      return (
                        <article key={`${item.kind}-${item.record_id}`} className="logger-activity-record-row">
                          <span className="logger-activity-record">{activityRecordLabel(item)}</span>
                          <div className="logger-activity-record-detail">
                            <strong>{item.activity}</strong>
                            <span>{item.context || basename(item.source_file) || item.source_type}</span>
                          </div>
                          <span className={`logger-activity-classification ${itemClassName}`}>
                            {activityClassification(item)}
                          </span>
                          <ActivityTimestamp value={item.recorded_at} timeZoneOption={timeZoneOption} />
                        </article>
                      )
                    })}
                  </div>
                )}
              </section>
            )
          }) : (
            <div className="logger-empty-state">No append-only activity matches this search.</div>
          )}
        </div>
      ) : (
        <div className="logger-empty-state">No append-only database activity recorded yet.</div>
      )}
    </Panel>
  )
}

const RecoveryReadiness = ({ status, events, busy, onVerify, onRestore, wide = false }) => {
  const recovery = status.recovery_ledger || {}
  const restoreEvent = events.find(event => String(event.event || '').includes('restore'))
  const restoreEventLabel = restoreEvent ? formatDateTime(restoreEvent.created_at) : 'No Restore Event'
  const ledgerMatches = recovery.db_head_matches_ledger
    ? 'Matches Current Head'
    : recovery.status === 'verified_db_mismatch'
      ? 'DB Mismatch'
      : 'Unavailable'

  return (
    <Panel
      title="Recovery Ledger"
      subtitle="Backup Status"
      className={wide ? 'logger-recovery-panel wide' : 'logger-recovery-panel'}
      headerAction={(
        <div className="logger-recovery-header-actions">
          <Button variant="success" onClick={onVerify} disabled={busy}>
            Verify Ledger
          </Button>
          <Button variant="danger" onClick={onRestore} disabled={busy}>
            Restore
          </Button>
        </div>
      )}
    >
      <div className={`logger-readiness-list ${wide ? 'wide' : ''}`}>
        <DetailValue label="Recovery Ledger" value={titleCase(recovery.status || 'unknown')} />
        <DetailValue label="Backup Records" value={recovery.records_checked ?? 0} />
        <DetailValue label="DB Head" value={ledgerMatches} />
        <DetailValue label="Last Restore Event" value={restoreEventLabel} />
      </div>
    </Panel>
  )
}

const EvidenceIntakeSummary = ({ sources = [] }) => {
  const orderedSources = useMemo(() => (
    [...sources].sort((a, b) => (
      sourceSortRank(a) - sourceSortRank(b)
      || String(b.last_seen || '').localeCompare(String(a.last_seen || ''))
      || basename(a.source_file).localeCompare(basename(b.source_file))
    ))
  ), [sources])
  const sourceStats = useMemo(() => (
    orderedSources.reduce((stats, source) => {
      const count = Number(source.records || 0)
      if (sourceTypeLabel(source) === 'PCAP') {
        stats.pcapChunks += count
      } else {
        stats.records += count
      }
      return stats
    }, { records: 0, pcapChunks: 0 })
  ), [orderedSources])

  return (
    <Panel
      title="Evidence Intake Summary"
      subtitle="Ingested Sources"
      className="logger-source-panel"
    >
      {orderedSources.length ? (
        <div className="logger-source-panel-body">
          <div className="logger-source-summary">
            <div>
              <span>Sources</span>
              <strong>{orderedSources.length}</strong>
            </div>
            <div>
              <span>Records</span>
              <strong>{sourceStats.records}</strong>
            </div>
            <div>
              <span>PCAP Chunks</span>
              <strong>{sourceStats.pcapChunks}</strong>
            </div>
          </div>
          <div className="logger-source-list" aria-label="Ingested source entries">
            {orderedSources.map(source => {
              const label = sourceTypeLabel(source)
              const unit = label === 'PCAP' ? 'chunks' : 'records'
              return (
                <div key={`${source.source_file}-${source.source_type}`} className="logger-source-row">
                  <div className="logger-source-main">
                    <strong>{basename(source.source_file)}</strong>
                    <span>Seq {source.first_sequence || '-'} to {source.last_sequence || '-'}</span>
                  </div>
                  <div>
                    <strong>{source.records || 0} {unit}</strong>
                    <span>{formatDateTime(source.last_seen)}</span>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      ) : (
        <div className="logger-empty-state">No ingested sources have been recorded.</div>
      )}
    </Panel>
  )
}

const ChainGrowthAnchorHistory = ({ status }) => {
  const head = status.head || {}
  const anchors = status.anchor_history || []
  const sources = status.source_summary || []
  const entries = status.sequence_entries || []
  const sequenceRows = useMemo(() => {
    const entryRows = entries.map(entry => ({
      key: `entry-${entry.sequence}`,
      type: sourceTypeLabel(entry),
      title: `Sequence #${entry.sequence}`,
      detail: basename(entry.source_file) || entry.source_type || 'Log entry',
      sequenceLabel: `${entry.offset_label || 'Offset'} ${entry.source_offset ?? '-'}`,
      time: entry.created_at,
      rank: Number(entry.sequence || 0),
    }))

    if (entryRows.length) {
      return entryRows
        .filter(row => row.rank > 0)
        .sort((a, b) => b.rank - a.rank || String(b.time || '').localeCompare(String(a.time || '')))
    }

    const sourceRows = sources.map(source => ({
      key: `source-${source.source_file}-${source.source_type}-${source.first_sequence}`,
      type: sourceTypeLabel(source),
      title: basename(source.source_file),
      detail: `${source.records || 0} ${sourceTypeLabel(source) === 'PCAP' ? 'chunks' : 'records'} written`,
      sequenceLabel: `Seq ${source.first_sequence || '-'} to ${source.last_sequence || '-'}`,
      time: source.last_seen,
      rank: Number(source.first_sequence || 0),
    }))

    const anchorRows = anchors.map((anchor, index) => ({
      key: `anchor-${anchor.created_at}-${anchor.sequence}-${index}`,
      type: 'Anchor',
      title: `Signed Anchor ${index + 1}`,
      detail: `${anchor.entry_count || 0} entries covered`,
      sequenceLabel: `Seq ${anchor.sequence || '-'}`,
      time: anchor.created_at,
      rank: Number(anchor.sequence || anchor.entry_count || 0),
    }))

    const headRow = Number(head.sequence || 0) > 0
      ? [{
          key: `head-${head.sequence}`,
          type: 'Head',
          title: 'Current Chain Head',
          detail: `${head.entry_count || 0} total entries`,
          sequenceLabel: `Seq ${head.sequence}`,
          time: status.last_seen,
          rank: Number(head.sequence || 0) + 0.1,
        }]
      : []

    return [...sourceRows, ...anchorRows, ...headRow]
      .filter(row => row.rank > 0)
      .sort((a, b) => b.rank - a.rank || String(b.time || '').localeCompare(String(a.time || '')))
  }, [anchors, entries, head.entry_count, head.sequence, sources, status.last_seen])

  return (
    <Panel title="Chain Growth" subtitle="Sequence Progression" className="chain-growth-card">
      <div className="chain-growth-panel">
        <div className="chain-growth-summary">
          <div>
            <span>Current Head</span>
            <strong>Seq #{head.sequence || 0}</strong>
          </div>
          <div>
            <span>Anchors Checked</span>
            <strong>{status.anchor?.anchors_checked ?? anchors.length ?? 0}</strong>
          </div>
          <div>
            <span>Entries Listed</span>
            <strong>{sequenceRows.length}</strong>
          </div>
        </div>
        {sequenceRows.length ? (
          <div className="chain-sequence-list" aria-label="Sequence progression entries">
            {sequenceRows.map(row => (
              <div key={row.key} className="chain-sequence-row">
                <span className={`chain-sequence-type ${row.type.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`}>{row.type}</span>
                <div className="chain-sequence-main">
                  <strong>{row.title}</strong>
                  <span>{row.detail}</span>
                </div>
                <div className="chain-sequence-meta">
                  <strong>{row.sequenceLabel}</strong>
                  <span>{formatDateTime(row.time)}</span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="logger-empty-state">No sequence progression entries are available yet.</div>
        )}
      </div>
    </Panel>
  )
}

export const LoggerControlPage = () => {
  const { status, anomaly, busy } = useAppStore()
  const refresh = useAutoRefresh(1000)
  const runAction = useRunAction()
  const [operationResult, setOperationResult] = useState(null)
  const [selectedTimeZone, setSelectedTimeZone] = useState(DEFAULT_DASHBOARD_TIME_ZONE.timeZone)

  const securityEvents = useMemo(() => (
    status?.recent_security_events?.length
      ? status.recent_security_events
      : anomaly?.security_events || []
  ), [anomaly, status])
  const appendOnlyActivity = useMemo(() => (
    status?.append_only_activity || []
  ), [status])

  if (!status) return <LoadingSpinner />

  const handleVerifyChain = async () => {
    await runAction('Chain verified', () => api.verify())
    setOperationResult('Chain verification completed')
  }

  const handleVerifyLedger = async () => {
    await runAction('Recovery ledger verified', () => api.verifyLedger())
    setOperationResult('Recovery ledger verification completed')
  }

  const handleRestoreLedger = async () => {
    await runAction('SQLite restored from ledger', () => api.restoreLedger())
    setOperationResult('Restore from recovery ledger completed')
  }

  return (
    <AppLayout>
      <Header
        title="Logger"
        status={status.status}
        onRefresh={refresh}
        busy={busy}
        selectedTimeZone={selectedTimeZone}
        onTimeZoneChange={setSelectedTimeZone}
      />

      <div className="p-6 space-y-6 logger-dashboard">
        <StatusOverview status={status} anomaly={anomaly} />

        <div className="grid grid-cols-3 gap-6 logger-primary-row">
          <ChainStatusPanel status={status} busy={busy} onVerifyChain={handleVerifyChain} />
          <VerificationTimeline status={status} selectedTimeZone={selectedTimeZone} />
          <RecoveryReadiness
            status={status}
            events={securityEvents}
            busy={busy}
            onVerify={handleVerifyLedger}
            onRestore={handleRestoreLedger}
          />
        </div>

        <div className="grid grid-cols-3 gap-6 logger-audit-row">
          <div className="col-span-2">
            <AppendOnlyActivity activity={appendOnlyActivity} selectedTimeZone={selectedTimeZone} />
          </div>
          <TrustedReadinessChecks status={status} layout="linear" />
        </div>

        <div className="grid grid-cols-3 gap-6 logger-evidence-row">
          <EvidenceIntakeSummary sources={status.source_summary || []} />
          <div className="col-span-2">
            <ChainGrowthAnchorHistory status={status} />
          </div>
        </div>

        {operationResult && (
          <Alert variant="info" className="text-sm">
            {operationResult}
          </Alert>
        )}
      </div>
    </AppLayout>
  )
}
