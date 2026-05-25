import React, { useEffect, useRef, useState } from 'react'
import { Clock, Download, FileText, Play, RefreshCw, Send, ShieldCheck, Trash2, Upload } from 'lucide-react'
import { useAppStore } from '@/store/appStore'
import { useAutoRefresh } from '@/hooks/useApi'
import { Header, AppLayout } from '@/components/layout/Layout'
import { StatusOverview } from '@/components/sections/StatusComponents'
import { Panel, Button, Input, LoadingSpinner, Alert } from '@/components/ui/Common'
import { ForensicTimeline } from '@/components/charts/PlotlyCharts'
import { ProvenanceGraphD3 } from '@/components/charts/ProvenanceGraphD3'
import { api, handleApiError } from '@/api/client'
import { DEFAULT_DASHBOARD_TIME_ZONE, getTimeZoneOption } from '@/utils/timeZones'

const escapePdfText = (value = '') => String(value)
  .replace(/[\\()]/g, match => `\\${match}`)
  .replace(/[^\x20-\x7E]/g, ' ')

const wrapPdfLine = (line = '', limit = 92) => {
  const words = String(line).split(/\s+/)
  const lines = []
  let current = ''

  words.forEach(word => {
    if (!current) {
      current = word
      return
    }
    if (`${current} ${word}`.length > limit) {
      lines.push(current)
      current = word
      return
    }
    current = `${current} ${word}`
  })

  if (current) lines.push(current)
  return lines.length ? lines : ['']
}

const buildSimplePdfBlob = (title, content) => {
  const sourceLines = [
    title,
    '',
    ...String(content || '').split(/\r?\n/),
  ].flatMap(line => wrapPdfLine(line))
  const pageLines = []
  for (let index = 0; index < sourceLines.length; index += 46) {
    pageLines.push(sourceLines.slice(index, index + 46))
  }

  const objects = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    `<< /Type /Pages /Kids [${pageLines.map((_, index) => `${4 + index * 2} 0 R`).join(' ')}] /Count ${pageLines.length} >>`,
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
  ]

  pageLines.forEach((lines, index) => {
    const pageObject = 4 + index * 2
    const contentObject = pageObject + 1
    const stream = [
      'BT',
      '/F1 10 Tf',
      '40 800 Td',
      '14 TL',
      ...lines.map(line => `(${escapePdfText(line)}) Tj T*`),
      'ET',
    ].join('\n')
    objects.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> /Contents ${contentObject} 0 R >>`)
    objects.push(`<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`)
  })

  let pdf = '%PDF-1.4\n'
  const offsets = [0]
  objects.forEach((object, index) => {
    offsets.push(pdf.length)
    pdf += `${index + 1} 0 obj\n${object}\nendobj\n`
  })
  const xrefStart = pdf.length
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`
  offsets.slice(1).forEach(offset => {
    pdf += `${String(offset).padStart(10, '0')} 00000 n \n`
  })
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF`

  return new Blob([pdf], { type: 'application/pdf' })
}

const formatSgtTimestamp = (value = new Date()) => new Intl.DateTimeFormat('en-SG', {
  timeZone: 'Asia/Singapore',
  year: 'numeric',
  month: 'short',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false,
  timeZoneName: 'short',
}).format(value)

const severityPalette = {
  high: { color: '#FF6478', background: 'rgba(255, 100, 120, 0.14)', border: 'rgba(255, 100, 120, 0.45)' },
  medium: { color: '#FFD166', background: 'rgba(255, 209, 102, 0.14)', border: 'rgba(255, 209, 102, 0.45)' },
  low: { color: '#39D8FF', background: 'rgba(57, 216, 255, 0.12)', border: 'rgba(57, 216, 255, 0.4)' },
  normal: { color: '#49E38F', background: 'rgba(73, 227, 143, 0.12)', border: 'rgba(73, 227, 143, 0.35)' },
}

const evidenceSeverityFilters = [
  { label: 'All', value: 'all' },
  { label: 'High', value: 'high' },
  { label: 'Medium', value: 'medium' },
  { label: 'Low', value: 'low' },
]

const normalizedSeverity = (value) => {
  const text = String(value || 'normal').toLowerCase()
  if (text.includes('critical') || text.includes('high')) return 'high'
  if (text.includes('warning') || text.includes('medium')) return 'medium'
  if (text.includes('low')) return 'low'
  return 'normal'
}

const formatEvidenceTimestamp = (value, timeZoneOption = DEFAULT_DASHBOARD_TIME_ZONE) => {
  if (!value) return `- ${timeZoneOption.label}`
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return `${String(value)} ${timeZoneOption.label}`
  const time = new Intl.DateTimeFormat('en-SG', {
    timeZone: timeZoneOption.timeZone,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(date)
  return `${time} ${timeZoneOption.label}`
}

const extractArincLabel = (entry = {}) => {
  const haystack = [
    entry.label_octal,
    entry.service,
    entry.protocol,
    entry.source_component,
    entry.target_component,
    entry.summary,
    entry.explanation,
  ].filter(Boolean).join(' ')
  const match = haystack.match(/\b(206|360)\b/i)
  return match?.[1] || null
}

const isArincEvidence = (entry = {}, service = '') => {
  const text = [
    entry.data_format,
    entry.protocol,
    entry.service,
    entry.source_component,
    entry.target_component,
    service,
  ].filter(Boolean).join(' ').toLowerCase()
  return text.includes('arinc') || text.includes('avionics word') || text.includes('label ')
}

const evidenceProtocolLabel = (entry = {}) => {
  const rawService = entry.service || entry.protocol || entry.source_type || entry.event_type || 'event'
  if (isArincEvidence(entry, rawService)) {
    return `ARINC ${extractArincLabel(entry) || '206'}`
  }
  return String(rawService || 'event')
    .replace(/_/g, ' ')
    .trim()
    .toUpperCase()
}

const evidenceComponentLabel = (value = '') => {
  const text = String(value || '').trim()
  const arincLabel = text.match(/\blabel\s+(\d+)\b/i)?.[1]
  if (arincLabel) return `ARINC ${arincLabel === '360' ? '360' : '206'}`
  if (text.toLowerCase().includes('arinc 429 bus')) return 'ARINC Bus'
  return text || 'Unknown'
}

const evidenceSourceValue = (entry = {}) => (
  entry.source_component ||
  entry.source ||
  entry.src ||
  entry.src_ip ||
  entry.source_ip ||
  entry.attacker_ip ||
  entry.source_file ||
  'source unknown'
)

const evidenceTargetValue = (entry = {}) => (
  entry.target_component ||
  entry.target ||
  entry.dst ||
  entry.dst_ip ||
  entry.destination_ip ||
  (entry.target_sequence ? `SEQ #${entry.target_sequence}` : '') ||
  'target unknown'
)

const attackerSourceValue = (item = {}) => {
  const details = item.details || {}
  const actor = details.actor || item.actor || ''
  const ip = details.attacker_ip || details.actor_ip || item.attacker_ip || item.source_ip
  if (ip) return String(ip)
  const actorIp = String(actor).match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)?.[0]
  return actorIp || '203.0.113.45'
}

const auditEventText = (item = {}) => [
  item.kind,
  item.activity,
  item.event,
  item.source_type,
  item.classification,
  item.severity,
  item.context,
  item.operation,
  item.details?.operation,
  item.details?.reason,
].filter(Boolean).join(' ').toLowerCase()

const auditEventTime = (item = {}) => (
  item.recorded_at ||
  item.created_at ||
  item.detected_at ||
  item.occurred_at ||
  item.timestamp
)

const auditSequenceLabel = (item = {}) => (
  item.sequence ||
  item.target_sequence ||
  item.details?.target_sequence ||
  item.evidence_id ||
  item.attempt_id ||
  '-'
)

const titleCase = (value = '') => String(value || '')
  .replace(/_/g, ' ')
  .replace(/\s+/g, ' ')
  .trim()
  .replace(/\b\w/g, letter => letter.toUpperCase())

const buildAuditEvidenceEntries = (appendOnlyActivity = [], securityEvents = []) => {
  const seen = new Set()
  const auditEntries = []

  const addAuditEntry = (item = {}, fallbackKind = 'security') => {
    const text = auditEventText(item)
    const isMutation = item.kind === 'mutation_attempt' ||
      text.includes('mutation') ||
      text.includes('tamper_attempt') ||
      item.event === 'tamper_attempt_blocked' ||
      item.event === 'tamper_attempt_no_effect' ||
      text.includes('update attempt') ||
      text.includes('delete attempt') ||
      Boolean(item.details?.operation && item.details?.target_sequence)
    const isRecovery = text.includes('restore') ||
      text.includes('recovery') ||
      text.includes('ledger') ||
      text.includes('tamper') ||
      item.kind === 'security_event' ||
      item.source_type === 'SECURITY_EVENT' ||
      fallbackKind === 'recovery'

    if (!isMutation && !isRecovery) return

    const sequence = auditSequenceLabel(item)
    const occurredAt = auditEventTime(item)
    const recordId = isMutation
      ? item.record_id || item.attempt_id || `${item.operation || 'mutation'}-${sequence}-${occurredAt}`
      : item.record_id || (sequence && sequence !== '-' ? `seq-${sequence}` : null) || `${item.event || item.kind || fallbackKind}-${occurredAt}`
    const key = `${isMutation ? 'mutation' : 'recovery'}:${recordId}`
    if (seen.has(key)) return
    seen.add(key)

    const operation = item.operation || item.details?.operation
    const activity = item.activity || item.event || operation || (isMutation ? 'Database mutation attempt' : 'Recovery / security audit')
    const status = item.synced_to_chain === true || text.includes('blocked')
      ? 'Blocked'
      : text.includes('restored') || text.includes('restore')
        ? 'Recovery'
        : text.includes('tamper') || text.includes('corrupt')
          ? 'Detected'
          : titleCase(item.classification || item.severity || 'Recorded')
    const targetSequence = item.target_sequence || item.details?.target_sequence || item.sequence
    const source = isMutation
      ? attackerSourceValue(item)
      : item.details?.actor || item.actor || item.source_file || item.source_type || 'Audit Trail'
    const target = targetSequence && targetSequence !== '-'
      ? `SEQ #${targetSequence}`
      : item.details?.table || item.sqlite_action || 'Evidence Chain'

    auditEntries.push({
      audit_event: true,
      audit_type: isMutation ? 'mutation' : 'recovery',
      audit_status: status,
      sequence,
      occurred_at: occurredAt,
      recorded_at: item.recorded_at || item.created_at || occurredAt,
      source_type: isMutation ? 'DB_MUTATION' : 'SECURITY_AUDIT',
      source_file: item.source_file,
      source_component: source,
      attacker_ip: isMutation ? source : undefined,
      target_sequence: targetSequence,
      target_component: target,
      service: isMutation ? 'DB Mutation' : 'Recovery / Security',
      severity: isMutation ? 'HIGH' : normalizedSeverity(item.severity || item.classification) === 'high' ? 'HIGH' : 'MEDIUM',
      anomaly_score: null,
      predicted_anomaly: isMutation ? 1 : 0,
      summary: `${titleCase(activity)}${status ? ` (${status})` : ''}. ${item.context || item.details?.reason || item.details?.operation || 'Audit event recorded by the append-only logger.'}`,
      explanation: item.context || item.details?.reason || item.details?.operation || '',
    })
  }

  appendOnlyActivity.forEach(item => addAuditEntry(item, 'activity'))
  securityEvents.forEach(item => addAuditEntry(item, 'recovery'))

  return auditEntries.sort((left, right) => (
    Number(left.sequence === '-' ? 0 : left.sequence || 0) - Number(right.sequence === '-' ? 0 : right.sequence || 0)
  ))
}

const compactEvidenceForChat = (entry = {}) => ({
  sequence: entry.sequence,
  evidence_id: entry.evidence_id,
  occurred_at: entry.occurred_at || entry.recorded_at || entry.timestamp,
  source_file: entry.source_file,
  source_type: entry.source_type,
  source: evidenceSourceValue(entry),
  target: evidenceTargetValue(entry),
  protocol: evidenceProtocolLabel(entry),
  severity: entry.severity,
  anomaly_score: entry.anomaly_score ?? entry.risk ?? entry.raw_score,
  predicted_anomaly: entry.predicted_anomaly,
  audit_type: entry.audit_type,
  audit_status: entry.audit_status,
  anomaly_type: entry.anomaly_type,
  top_features: Array.isArray(entry.top_features) ? entry.top_features.slice(0, 6) : [],
  explanation: entry.explanation || entry.summary || '',
})

const formatDocumentSize = (bytes = 0) => {
  const value = Number(bytes || 0)
  if (!Number.isFinite(value) || value <= 0) return 'stored'
  if (value >= 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MB`
  return `${Math.max(1, Math.round(value / 1024))} KB`
}

const normalizeBBBotDocument = (doc = {}) => ({
  id: doc.id || doc.path || doc.name,
  name: doc.name || 'Regulation document',
  sizeLabel: doc.sizeLabel || formatDocumentSize(doc.size_bytes || doc.size),
  type: doc.content_type || doc.type || 'document',
  uploadedAt: doc.uploaded_at || doc.uploadedAt || '',
  excerpt: doc.excerpt || '',
  storedPath: doc.path || doc.storedPath,
  textAvailable: Boolean(doc.text_available ?? doc.textAvailable),
  contextStatus: doc.context_status || (doc.text_available ? 'text indexed' : 'stored'),
})

export const ForensicReplayPage = () => {
  const { status, anomaly, replay, busy, setToastMessage, bbChatLog: chatLog, setBBChatLog: setChatLog } = useAppStore()
  const refresh = useAutoRefresh(1000)
  const provenanceGraphRef = useRef(null)

  const [chatMessage, setChatMessage] = useState('')
  const [chatSending, setChatSending] = useState(false)
  const [manualRefreshBusy, setManualRefreshBusy] = useState(false)
  const [provenanceUiState, setProvenanceUiState] = useState({
    isLoading: false,
    isExporting: false,
    hasGraph: false,
    hasGeneratedGraph: false,
  })
  const [evidenceQuery, setEvidenceQuery] = useState('')
  const [evidenceSeverityFilter, setEvidenceSeverityFilter] = useState('all')
  const [partIsDocuments, setPartIsDocuments] = useState([])
  const [selectedTimeZone, setSelectedTimeZone] = useState(DEFAULT_DASHBOARD_TIME_ZONE.timeZone)

  useEffect(() => {
    let cancelled = false
    api.getBBBotDocuments()
      .then(response => {
        if (!cancelled) {
          setPartIsDocuments((response.data.documents || []).map(normalizeBBBotDocument))
        }
      })
      .catch(error => {
        if (!cancelled) setToastMessage(`Could not load BB_bot documents: ${handleApiError(error)}`)
      })
    return () => {
      cancelled = true
    }
  }, [setToastMessage])

  if (!status) return <LoadingSpinner />

  const activeTimeZone = getTimeZoneOption(selectedTimeZone)
  const trusted = status.trusted_readiness?.trusted || false
  const replayEvidence = Array.isArray(replay?.evidence_stream) && replay.evidence_stream.length
    ? replay.evidence_stream
    : Array.isArray(replay?.timeline) && replay.timeline.length
      ? replay.timeline
      : []
  const anomalyEvidence = Array.isArray(anomaly?.ranked_anomalies) && anomaly.ranked_anomalies.length
    ? anomaly.ranked_anomalies
    : Array.isArray(anomaly?.score_trace) && anomaly.score_trace.length
      ? anomaly.score_trace
      : Array.isArray(anomaly?.records)
        ? anomaly.records
        : []
  const entries = replayEvidence.length ? replayEvidence : anomalyEvidence
  const scoreTrace = anomaly?.score_trace?.length ? anomaly.score_trace : anomaly?.records || []
  const forensicTimelineEntries = scoreTrace.length ? scoreTrace : entries
  const appendOnlyActivity = status?.append_only_activity || []
  const securityEvents = status?.recent_security_events?.length
    ? status.recent_security_events
    : anomaly?.security_events || []
  const auditEvidenceEntries = buildAuditEvidenceEntries(appendOnlyActivity, securityEvents)
  const hasTimelineData = forensicTimelineEntries.length > 0 || appendOnlyActivity.length > 0 || securityEvents.length > 0
  const timelineEntriesForDisplay = trusted ? forensicTimelineEntries : []
  const liveTrafficActive = Boolean(status?.live_traffic?.active)
  const graphCanGenerate = trusted && !liveTrafficActive && (
    Number(anomaly?.total_ai_records || 0) > 0 ||
    Number(replay?.count || 0) > 0 ||
    forensicTimelineEntries.length > 0
  )
  const shapReasonCount = forensicTimelineEntries.filter(entry => (
    entry.explanation ||
    entry.summary ||
    (Array.isArray(entry.top_features) && entry.top_features.length > 0)
  )).length
  const recoveryStatus = status.recovery_ledger?.status || status.recovery_status || 'unknown'
  const recoveryReady = String(recoveryStatus).toLowerCase().includes('verified') || status.recovery_ledger?.ok === true
  const partIsReady = trusted && (entries.length > 0 || forensicTimelineEntries.length > 0) && hasTimelineData && shapReasonCount > 0
  const reportSgtTime = formatSgtTimestamp()
  const normalizedEvidenceQuery = evidenceQuery.trim().toLowerCase()
  const aiEvidenceStreamEntries = trusted ? entries
    .filter(entry => ['high', 'medium', 'low', 'normal'].includes(normalizedSeverity(entry.severity)))
    : []
  const evidenceStreamEntries = [...aiEvidenceStreamEntries, ...auditEvidenceEntries]
    .sort((left, right) => (
      Number(left.sequence ?? left.evidence_id ?? left.source_offset ?? 0) -
      Number(right.sequence ?? right.evidence_id ?? right.source_offset ?? 0)
    ))
  const severityFilteredEntries = evidenceSeverityFilter === 'all'
    ? evidenceStreamEntries
    : evidenceStreamEntries.filter(entry => normalizedSeverity(entry.severity) === evidenceSeverityFilter)
  const filteredEntries = normalizedEvidenceQuery
    ? severityFilteredEntries.filter(entry => [
      entry.sequence,
      entry.occurred_at,
      entry.recorded_at,
      entry.service,
      entry.source_type,
      entry.severity,
      entry.anomaly_score,
      entry.source_component,
      entry.source,
      entry.src,
      entry.src_ip,
      entry.source_ip,
      entry.target_component,
      entry.target,
      entry.dst,
      entry.dst_ip,
      entry.destination_ip,
      entry.explanation,
      entry.summary,
      entry.audit_type,
      entry.audit_status,
      evidenceProtocolLabel(entry),
    ].filter(Boolean).join(' ').toLowerCase().includes(normalizedEvidenceQuery))
    : severityFilteredEntries

  const complianceRows = [
    {
      label: 'Chain verification status',
      value: trusted ? 'Verified' : 'Not Verified',
      ready: trusted,
    },
    {
      label: 'Evidence integrity',
      value: recoveryReady ? `Recovery Ledger ${String(recoveryStatus).replaceAll('_', ' ')}` : String(recoveryStatus).replaceAll('_', ' '),
      ready: recoveryReady,
    },
    {
      label: 'Part-IS reporting requirements',
      value: partIsReady
        ? `${forensicTimelineEntries.length || entries.length} evidence items, timeline, SHAP reasons`
        : `Need evidence, timeline, and SHAP reasons (${shapReasonCount} found)`,
      ready: partIsReady,
    },
    {
      label: 'Time to incident report',
      value: partIsReady ? `Ready at ${reportSgtTime}` : `Pending inputs as of ${reportSgtTime}`,
      ready: partIsReady,
      icon: 'time',
    },
  ]
  const complianceReadyCount = complianceRows.filter(row => row.ready).length
  const evidenceSeverityCounts = evidenceStreamEntries.reduce((counts, entry) => {
    const severity = normalizedSeverity(entry.severity)
    counts[severity] = (counts[severity] || 0) + 1
    return counts
  }, { high: 0, medium: 0, low: 0, normal: 0 })
  const complianceGuidance = [
    {
      title: 'Confirm evidence trust',
      text: trusted
        ? 'The replay data can be used for investigation.'
        : 'Pause the investigation export until chain verification is restored.',
      ready: trusted,
    },
    {
      title: 'Start with serious records',
      text: evidenceSeverityCounts.high > 0 || evidenceSeverityCounts.medium > 0
        ? `Review ${evidenceSeverityCounts.high} high and ${evidenceSeverityCounts.medium} medium severity records first.`
        : 'No high or medium severity records are currently visible in the filtered stream.',
      ready: evidenceSeverityCounts.high === 0 && evidenceSeverityCounts.medium === 0,
    },
    {
      title: 'Use the graph for relationships',
      text: 'Select nodes in the provenance graph to see which systems, services, and evidence records are connected.',
      ready: true,
    },
    {
      title: 'Prepare the report package',
      text: partIsReady
        ? 'Evidence count, timeline context, and SHAP reasons are available for the incident report.'
        : 'Check that evidence records, timeline context, and SHAP explanations are available before reporting.',
      ready: partIsReady,
    },
  ]
  const reportingChecklist = [
    { label: 'Evidence records available', value: evidenceStreamEntries.length, ready: evidenceStreamEntries.length > 0 },
    { label: 'Timeline context available', value: hasTimelineData ? 'Available' : 'Missing', ready: hasTimelineData },
    { label: 'SHAP explanation records', value: shapReasonCount, ready: shapReasonCount > 0 },
    { label: 'Regulation documents staged', value: partIsDocuments.length, ready: partIsDocuments.length > 0 },
  ]

  const handleChatSubmit = async (e) => {
    e.preventDefault()
    if (!chatMessage.trim() || chatSending) return

    const question = chatMessage
    setChatLog(prev => [...prev, { role: 'user', text: question }])
    setChatMessage('')
    setChatSending(true)

    try {
      const response = await api.chat(question, {
        visible_evidence_records: filteredEntries.length,
        evidence_entries: (filteredEntries.length ? filteredEntries : evidenceStreamEntries).slice(0, 300).map(compactEvidenceForChat),
        timeline_events: forensicTimelineEntries.slice(-300).map(compactEvidenceForChat),
        raw_sequence_entries: (status?.sequence_entries || []).slice(0, 500),
        anomaly_summary: {
          total_ai_records: anomaly?.total_ai_records,
          anomalies: anomaly?.anomalies,
          severity_counts: anomaly?.severity_counts,
          total_alerts: anomaly?.total_alerts,
        },
        provenance_state: provenanceUiState,
        chain_status: trusted ? 'verified' : 'not_verified',
        uploaded_documents: partIsDocuments.map(doc => ({ name: doc.name, sizeLabel: doc.sizeLabel })),
        compliance_ready: partIsReady,
        report_time_sgt: reportSgtTime,
      })
      setChatLog(prev => [...prev, { role: 'bot', text: response.data.answer || response.data.response }])
    } catch (error) {
      setChatLog(prev => [...prev, { role: 'bot', text: `Error: ${handleApiError(error)}` }])
    } finally {
      setChatSending(false)
    }
  }

  const handleChatKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      e.currentTarget.form?.requestSubmit()
    }
  }

  const handlePartIsUpload = async (event) => {
    const files = Array.from(event.target.files || [])
    if (!files.length) return

    const documents = await Promise.all(files.map(file => new Promise(resolve => {
      const sizeLabel = `${Math.max(1, Math.round(file.size / 1024))} KB`
      const baseDocument = {
        id: `${file.name}-${file.lastModified}-${file.size}`,
        name: file.name,
        sizeLabel,
        type: file.type || 'document',
        uploadedAt: formatSgtTimestamp(),
        excerpt: '',
      }

      const textReader = new FileReader()
      const binaryReader = new FileReader()
      const isTextLike = /\.(txt|md|csv|json)$/i.test(file.name) || String(file.type || '').startsWith('text/')

      binaryReader.onload = async () => {
        const dataUrl = String(binaryReader.result || '')
        const contentBase64 = dataUrl.includes(',') ? dataUrl.split(',').pop() : ''
        let textContent = ''
        let excerpt = ''
        if (isTextLike) {
          textContent = String(textReader.result || '')
          excerpt = textContent.replace(/\s+/g, ' ').slice(0, 1200)
        }
        try {
          const uploadResponse = await api.uploadBBBotDocument({
            name: file.name,
            type: file.type || 'document',
            size: file.size,
            content_base64: contentBase64,
            content_text: textContent,
          })
          resolve({
            ...baseDocument,
            id: uploadResponse.data.id || baseDocument.id,
            excerpt: uploadResponse.data.excerpt || excerpt,
            storedPath: uploadResponse.data.path,
          })
        } catch (error) {
          resolve({
            ...baseDocument,
            excerpt,
            uploadError: handleApiError(error),
          })
        }
      }
      binaryReader.onerror = () => resolve(baseDocument)

      if (isTextLike) {
        textReader.onload = () => binaryReader.readAsDataURL(file)
        textReader.onerror = () => binaryReader.readAsDataURL(file)
        textReader.readAsText(file)
      } else {
        binaryReader.readAsDataURL(file)
      }
    })))

    try {
      const response = await api.getBBBotDocuments()
      setPartIsDocuments((response.data.documents || []).map(normalizeBBBotDocument))
    } catch {
      setPartIsDocuments(prev => {
        const existingIds = new Set(prev.map(doc => doc.id))
        return [...prev, ...documents.map(normalizeBBBotDocument).filter(doc => !existingIds.has(doc.id))]
      })
    }
    const failedUploads = documents.filter(doc => doc.uploadError).length
    setToastMessage(
      failedUploads
        ? `${failedUploads} upload${failedUploads === 1 ? '' : 's'} failed; other documents were staged`
        : `${documents.length} Part-IS/regulation document${documents.length === 1 ? '' : 's'} uploaded to BB_bot context`
    )
    event.target.value = ''
  }

  const handleDeletePartIsDocument = async (documentId) => {
    if (!documentId) return
    try {
      await api.deleteBBBotDocument(documentId)
      const response = await api.getBBBotDocuments()
      setPartIsDocuments((response.data.documents || []).map(normalizeBBBotDocument))
      setToastMessage('Regulation document removed from BB_bot context')
    } catch (error) {
      setToastMessage(`Document delete failed: ${handleApiError(error)}`)
    }
  }

  const handleManualRefresh = async () => {
    if (manualRefreshBusy) return
    setManualRefreshBusy(true)
    try {
      await refresh()
    } finally {
      setManualRefreshBusy(false)
    }
  }

  const handleProvenanceExport = async (data) => {
    try {
      await api.stageBBBotContext({
        trigger: 'provenance_export',
        graph_filters: data.params || {},
        graph_data: data.graphData || {},
        provenance_summary: data.summary || '',
      })
      setToastMessage('Provenance graph exported and BB Chat context updated')
    } catch (error) {
      setToastMessage(`Graph exported, but BB Chat context update failed: ${handleApiError(error)}`)
    }
  }

  const handleDownloadPdfReport = async () => {
    try {
      const response = await api.report()
      const content = response.data.content || response.data.report || response.data
      const readinessSummary = [
        `Compliance readiness generated: ${reportSgtTime}`,
        `Chain verification: ${trusted ? 'Verified' : 'Not Verified'}`,
        `Evidence integrity: ${String(recoveryStatus).replaceAll('_', ' ')}`,
        `Part-IS readiness: ${partIsReady ? 'Met' : 'Needs review'}`,
        `Uploaded regulation documents: ${partIsDocuments.map(doc => doc.name).join(', ') || 'None'}`,
        '',
      ].join('\n')
      const blob = buildSimplePdfBlob('BlueBox Forensic Analysis Report', `${readinessSummary}${content}`)
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `bluebox-forensic-analysis-${new Date().toISOString().split('T')[0]}.pdf`
      a.click()
      window.URL.revokeObjectURL(url)
      setToastMessage('Forensic analysis PDF downloaded')
    } catch (error) {
      setToastMessage(`PDF report failed: ${handleApiError(error)}`)
    }
  }

  return (
    <AppLayout>
      <Header
        title="Forensic Replay"
        // subtitle="Incident Reconstruction and Analysis"
        status={status.status}
        onRefresh={handleManualRefresh}
        busy={manualRefreshBusy}
        selectedTimeZone={selectedTimeZone}
        onTimeZoneChange={setSelectedTimeZone}
      />

      <div className="p-6 space-y-6">
        <StatusOverview status={status} anomaly={anomaly} />

        {!trusted && (
          <Alert variant="critical">
            Chain verification failed. Forensic replay is restricted for evidence integrity.
          </Alert>
        )}

        {/* Main Charts */}
        <div className="grid grid-cols-1 gap-6">
          {/* Interactive Provenance Graph */}
          <Panel
            title="Interactive Provenance Graph"
            subtitle="Anomaly Relationships"
            headerAction={(
              <div className="flex flex-wrap items-center justify-end gap-3">
                <Button
                  variant="success"
                  className="inline-flex items-center justify-center gap-2 whitespace-nowrap px-3"
                  onClick={() => provenanceGraphRef.current?.generateGraph()}
                  disabled={provenanceUiState.isLoading || !graphCanGenerate}
                  aria-label="Generate provenance graph"
                  title={graphCanGenerate ? 'Generate graph from current filters' : 'Available after traffic simulation completes'}
                >
                  <Play size={15} aria-hidden="true" />
                  Generate
                </Button>
                <Button
                  variant="ghost"
                  className="inline-flex items-center justify-center gap-2 whitespace-nowrap px-3"
                  onClick={() => provenanceGraphRef.current?.refresh()}
                  disabled={provenanceUiState.isLoading || !provenanceUiState.hasGeneratedGraph}
                  aria-label="Refresh provenance graph"
                >
                  <RefreshCw size={15} aria-hidden="true" />
                  Refresh
                </Button>
                <Button
                  variant="primary"
                  className="inline-flex items-center justify-center gap-2 whitespace-nowrap px-3"
                  onClick={() => provenanceGraphRef.current?.exportGraph()}
                  disabled={provenanceUiState.isLoading || provenanceUiState.isExporting || !provenanceUiState.hasGraph}
                  aria-label="Export provenance graph"
                >
                  <Download size={15} aria-hidden="true" />
                  Export
                </Button>
              </div>
            )}
          >
            <div style={{ height: '700px', display: 'flex', flexDirection: 'column', position: 'relative' }}>
              <ProvenanceGraphD3
                ref={provenanceGraphRef}
                forensicData={replay}
                onExport={handleProvenanceExport}
                onUiStateChange={setProvenanceUiState}
              />
            </div>
          </Panel>

          <div className="grid grid-cols-1 xl:grid-cols-5 gap-6">
            <div className="xl:col-span-3">
              <Panel title="Forensic Timeline" subtitle="Unified Evidence Trace" className="h-full">
                {hasTimelineData ? (
                  <ForensicTimeline
                    entries={timelineEntriesForDisplay}
                    appendOnlyActivity={appendOnlyActivity}
                    securityEvents={securityEvents}
                    unified
                    selectedTimeZone={selectedTimeZone}
                  />
                ) : (
                  <div className="h-80 flex items-center justify-center text-bluebox-muted">
                    No events recorded
                  </div>
                )}
              </Panel>
            </div>

            <div className="xl:col-span-2">
              <Panel
                title="Evidence Stream"
                subtitle={`Entries to Investigate`}
                className="h-full"
                headerAction={(
                  <Input
                    value={evidenceQuery}
                    onChange={(e) => setEvidenceQuery(e.target.value)}
                    placeholder="Filter Evidence"
                    className="w-50 max-w-full text-xs"
                    disabled={evidenceStreamEntries.length === 0}
                  />
                )}
              >
                {trusted || auditEvidenceEntries.length > 0 ? (
                  <div className="flex min-h-0 flex-1 flex-col gap-3">
                    {!trusted && auditEvidenceEntries.length > 0 && (
                      <Alert variant="warning" className="mb-0">
                        Chain verification is not trusted. Showing mutation, recovery, and security audit events only.
                      </Alert>
                    )}
                    <div className="forensic-chart-toolbar mb-0" aria-label="Evidence severity filter">
                      <div className="forensic-chart-controls">
                        {evidenceSeverityFilters.map(option => (
                          <button
                            key={option.value}
                            type="button"
                            className={evidenceSeverityFilter === option.value ? 'active' : ''}
                            onClick={() => setEvidenceSeverityFilter(option.value)}
                          >
                            {option.label}
                          </button>
                        ))}
                      </div>
                    </div>

                    <div className="evidence-stream-list">
                      {filteredEntries.length > 0 ? (
                        filteredEntries.map((entry, idx) => {
                          const isAudit = Boolean(entry.audit_event)
                          const severity = normalizedSeverity(entry.severity)
                          const palette = severityPalette[severity]
                          const score = Number(entry.anomaly_score ?? entry.risk ?? entry.raw_score)
                          const eventType = evidenceProtocolLabel(entry)
                          const source = evidenceComponentLabel(evidenceSourceValue(entry))
                          const target = evidenceComponentLabel(evidenceTargetValue(entry))
                          const summary = entry.summary || entry.explanation || 'No explanation recorded for this evidence item.'

                          return (
                            <div
                              key={`${entry.audit_type || 'ai'}-${entry.evidence_id || entry.sequence || idx}-${idx}`}
                              className="evidence-stream-card rounded-lg border border-cyan-950 bg-bluebox-dark px-4 py-3 transition-smooth hover:border-cyan-800 hover:bg-cyan-950/20"
                            >
                              <div className="flex items-start justify-between gap-3">
                                <div className="min-w-0">
                                  <div className="flex flex-wrap items-center gap-2">
                                    <span className="font-mono text-sm font-bold uppercase tracking-wide text-bluebox-cyan">
                                      SEQ #{entry.sequence ?? '-'}
                                    </span>
                                    <span
                                      className="rounded-full border px-2.5 py-1 text-[10px] font-black uppercase tracking-wider"
                                      style={{
                                        color: palette.color,
                                        borderColor: palette.border,
                                        backgroundColor: palette.background,
                                      }}
                                    >
                                      {severity}
                                    </span>
                                    {Number(entry.predicted_anomaly || 0) === 1 && (
                                      <span className="rounded-full border border-pink-400/40 bg-pink-400/10 px-2.5 py-1 text-[10px] font-black uppercase tracking-wider text-pink-300">
                                        {isAudit ? entry.audit_type : 'flagged'}
                                      </span>
                                    )}
                                    {isAudit && entry.audit_status && (
                                      <span className="rounded-full border border-cyan-400/35 bg-cyan-400/10 px-2.5 py-1 text-[10px] font-black uppercase tracking-wider text-bluebox-cyan">
                                        {entry.audit_status}
                                      </span>
                                    )}
                                  </div>
                                  <p className="mt-1 truncate text-sm font-semibold uppercase tracking-wide text-bluebox-text">
                                    {eventType}
                                  </p>
                                </div>
                                <div className="shrink-0 text-right">
                                  <p className="text-[10px] font-black uppercase tracking-wider text-bluebox-muted">
                                    {isAudit ? 'Status' : 'Score'}
                                  </p>
                                  <p className="font-mono text-sm font-bold text-bluebox-text">
                                    {isAudit ? (entry.audit_status || 'Recorded') : Number.isFinite(score) ? score.toFixed(3) : '0.000'}
                                  </p>
                                </div>
                              </div>

                              <div className="mt-3 grid grid-cols-1 md:grid-cols-3 gap-2 text-xs">
                                <div className="min-w-0 rounded border border-cyan-950 bg-bluebox-panel px-3 py-2">
                                  <p className="text-[10px] font-black uppercase tracking-wider text-bluebox-muted">Time</p>
                                  <p className="truncate font-mono text-bluebox-text">
                                    {formatEvidenceTimestamp(entry.occurred_at || entry.recorded_at || entry.timestamp, activeTimeZone)}
                                  </p>
                                </div>
                                <div className="min-w-0 rounded border border-cyan-950 bg-bluebox-panel px-3 py-2">
                                  <p className="text-[10px] font-black uppercase tracking-wider text-bluebox-muted">Source</p>
                                  <p className="truncate text-bluebox-text">{source}</p>
                                </div>
                                <div className="min-w-0 rounded border border-cyan-950 bg-bluebox-panel px-3 py-2">
                                  <p className="text-[10px] font-black uppercase tracking-wider text-bluebox-muted">Target</p>
                                  <p className="truncate text-bluebox-text">{target}</p>
                                </div>
                              </div>

                              <p
                                className="mt-3 overflow-hidden text-xs leading-relaxed text-bluebox-muted"
                                style={{ display: '-webkit-box', WebkitLineClamp: 1, WebkitBoxOrient: 'vertical' }}
                              >
                                {summary}
                              </p>
                            </div>
                          )
                        })
                      ) : (
                        <div className="h-40 flex items-center justify-center text-bluebox-muted text-sm">
                          No evidence records match the current filter.
                        </div>
                      )}
                    </div>
                  </div>
                ) : (
                  <Alert variant="warning">Evidence restricted due to untrusted chain state</Alert>
                )}
              </Panel>
            </div>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
            <Panel
              title="Compliance Readiness"
              subtitle={`EU Part-IS Requirements`}
              className="h-full"
            >
              <div className="flex flex-1 flex-col gap-4">
                <div className="rounded-lg border border-cyan-900 bg-bluebox-dark p-4">
                  <div className="mb-4 flex items-center justify-between gap-3">
                    <div className="flex items-center gap-2">
                      <ShieldCheck size={17} className="text-bluebox-cyan" aria-hidden="true" />
                      <div>
                        <p className="text-[10px] font-black uppercase tracking-wider text-bluebox-muted">Readiness Summary</p>
                        <h3 className="text-sm font-bold text-bluebox-text">Incident Package Status</h3>
                      </div>
                    </div>
                    <span className="rounded-full border border-cyan-900 px-2.5 py-1 text-xs font-semibold text-bluebox-cyan">
                      {Math.round((complianceReadyCount / complianceRows.length) * 100)}%
                    </span>
                  </div>

                  <div className="mt-4 grid gap-2">
                    {complianceRows.map(row => (
                      <div
                        key={row.label}
                        className="flex items-start gap-3 rounded-md border border-cyan-950 bg-bluebox-panel px-3 py-2"
                      >
                        <span
                          className="mt-1 h-2.5 w-2.5 shrink-0 rounded-full"
                          style={{ backgroundColor: row.ready ? '#49E38F' : '#FF6478' }}
                        />
                        <div className="min-w-0">
                          <div className="flex items-center justify-between gap-3">
                            <p className="text-xs font-semibold text-bluebox-text">{row.label}</p>
                            <span className="shrink-0 text-[10px] font-black uppercase tracking-wider text-bluebox-muted">
                              {row.ready ? 'Ready' : 'Review'}
                            </span>
                          </div>
                          <p className="mt-1 text-xs text-bluebox-muted">{row.value}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="flex-1 rounded-lg border border-cyan-900 bg-bluebox-dark p-4">
                  <div className="mb-3 flex items-center gap-2">
                    <ShieldCheck size={17} className="text-bluebox-cyan" aria-hidden="true" />
                    <div>
                      <p className="text-[10px] font-black uppercase tracking-wider text-bluebox-muted">Engineer Guidance</p>
                      <h3 className="text-sm font-bold text-bluebox-text">Investigation Steps</h3>
                    </div>
                  </div>

                  <div className="space-y-2">
                    {complianceGuidance.map((item, idx) => (
                      <div
                        key={item.title}
                        className="flex items-start gap-3 rounded-md border border-cyan-950 bg-bluebox-panel px-3 py-2"
                      >
                        <span className="mt-0.5 inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-cyan-900 text-xs font-black text-bluebox-cyan">
                          {idx + 1}
                        </span>
                        <div className="min-w-0">
                          <p className="text-xs font-semibold text-bluebox-text">{item.title}</p>
                          <p className="mt-1 text-xs leading-relaxed text-bluebox-muted">{item.text}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

              </div>
            </Panel>

            <div className="xl:col-span-2">
              <Panel title="Chatbot For Forensic Investigation" subtitle="BB Chat" className="h-full min-h-0 overflow-hidden">
                <div className="flex min-h-0 h-full flex-col gap-4 overflow-hidden">
                  <div className="grid grid-cols-1 gap-4 lg:grid-cols-[3fr_2fr]">
                    <div className="rounded-lg border border-cyan-900 bg-bluebox-dark p-4">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <div className="flex items-center gap-2 text-xs font-black uppercase tracking-wider text-bluebox-muted">
                            <FileText size={14} aria-hidden="true" />
                            RAG Knowledge Base
                          </div>
                          <p className="mt-1 text-sm font-semibold text-bluebox-text">Upload EU Part-IS / Regulation Documents</p>
                        </div>
                        <span className="rounded-full border border-cyan-900 px-2 py-1 text-xs font-semibold text-bluebox-cyan">
                          {partIsDocuments.length} docs
                        </span>
                      </div>

                      <div className="mt-6 mb-5 grid grid-cols-1 md:grid-cols-2 gap-3">
                        <label className="inline-flex items-center justify-center gap-2 rounded-md border border-cyan-900 bg-bluebox-panel px-4 py-2 text-sm font-semibold text-bluebox-text cursor-pointer transition-smooth hover:border-bluebox-cyan hover:text-bluebox-cyan">
                          <Upload size={15} aria-hidden="true" />
                          <span>Upload Documents</span>
                          <input
                            type="file"
                            multiple
                            accept=".pdf,.txt,.md,.json,.csv"
                            className="hidden"
                            onChange={handlePartIsUpload}
                          />
                        </label>
                        <Button
                          variant="success"
                          onClick={handleDownloadPdfReport}
                          disabled={!trusted || busy}
                          className="inline-flex items-center justify-center gap-2 whitespace-nowrap px-4"
                        >
                          <Download size={15} aria-hidden="true" />
                          Forensic Analysis Report
                        </Button>
                      </div>

                      <div className="max-h-32 overflow-y-auto space-y-2">
                        {partIsDocuments.length > 0 ? (
                          partIsDocuments.map(doc => (
                            <div key={doc.id} className="flex items-center justify-between gap-3 rounded border border-cyan-950 bg-bluebox-panel px-3 py-2 text-xs">
                              <div className="min-w-0">
                                <span className="block truncate text-bluebox-text">{doc.name}</span>
                                <span className="block truncate text-[10px] text-bluebox-muted">{doc.contextStatus}</span>
                              </div>
                              <div className="flex shrink-0 items-center gap-2">
                                <span className="text-bluebox-muted">{doc.sizeLabel}</span>
                                <button
                                  type="button"
                                  onClick={() => handleDeletePartIsDocument(doc.id)}
                                  className="inline-flex h-7 w-7 items-center justify-center rounded border border-pink-400/30 text-pink-300 transition-smooth hover:border-pink-300 hover:bg-pink-400/10"
                                  aria-label={`Delete ${doc.name}`}
                                  title={`Delete ${doc.name}`}
                                >
                                  <Trash2 size={13} aria-hidden="true" />
                                </button>
                              </div>
                            </div>
                          ))
                        ) : (
                          <p className="text-xs text-bluebox-muted">
                            No regulation documents uploaded.
                          </p>
                        )}
                      </div>
                    </div>

                    <div className="rounded-lg border border-cyan-900 bg-bluebox-dark p-4">
                      <div className="mb-3 flex items-center gap-2">
                          <Clock size={14} className="text-bluebox-cyan" aria-hidden="true" />
                          <p className="text-[10px] font-black uppercase tracking-wider text-bluebox-muted">Maintenance Checklist</p>
                      </div>
                      <div className="grid gap-2">
                        {reportingChecklist.map(item => (
                          <div key={item.label} className="flex items-center justify-between gap-2 rounded border border-cyan-950 bg-bluebox-panel px-2.5 py-2">
                            <span className="truncate text-[11px] font-semibold text-bluebox-text">{item.label}</span>
                            <div className="flex shrink-0 items-center gap-1.5">
                              <span className="font-mono text-[11px] text-bluebox-muted">{item.value}</span>
                              <span
                                className="h-2 w-2 rounded-full"
                                style={{ backgroundColor: item.ready ? '#49E38F' : '#FF6478' }}
                              />
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                  <div className="flex h-[460px] min-h-0 max-h-[460px] flex-col overflow-hidden rounded-lg border border-cyan-900 bg-bluebox-dark">
                    <div className="flex items-center justify-between border-b border-cyan-950 px-4 py-3">
                      <p className="text-xs font-black uppercase tracking-wider text-bluebox-muted">Assistant Session</p>
                      <span className="text-xs font-semibold text-bluebox-cyan">
                        {partIsDocuments.length ? 'Document Context Active' : 'Evidence Context Active'}
                      </span>
                    </div>
                    <div className="min-h-0 flex-1 overflow-y-auto space-y-4 p-4 text-sm">
                      {chatLog.map((msg, idx) => (
                        <div key={idx} className={`flex items-start gap-3 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                          {msg.role !== 'user' && (
                            <span className="mt-1 inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-cyan-900 bg-bluebox-panel text-[10px] font-black text-bluebox-cyan">
                              BB
                            </span>
                          )}
                          <div
                            className={`max-w-[78%] rounded-2xl border px-4 py-3 shadow-sm ${
                              msg.role === 'user'
                                ? 'rounded-tr-md border-transparent bg-bluebox-cyan text-bluebox-dark'
                                : 'border-cyan-900 bg-bluebox-panel text-bluebox-text'
                            }`}
                          >
                            <p className="mb-1 text-[10px] font-black uppercase tracking-wider opacity-70">
                              {msg.role === 'user' ? 'Analyst' : 'Assistant'}
                            </p>
                            <p className="whitespace-pre-wrap leading-relaxed">{msg.text}</p>
                          </div>
                          {msg.role === 'user' && (
                            <span className="mt-1 inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-bluebox-cyan text-[10px] font-black text-bluebox-dark">
                              You
                            </span>
                          )}
                        </div>
                      ))}
                    </div>

                    <form onSubmit={handleChatSubmit} className="border-t border-cyan-950 p-3">
                      <div className="flex items-end gap-2 rounded-2xl border border-cyan-900 bg-bluebox-panel px-3 py-2 transition-smooth focus-within:border-bluebox-cyan focus-within:shadow-[0_0_0_1px_rgba(57,216,255,0.25)]">
                        <textarea
                          value={chatMessage}
                          onChange={(e) => setChatMessage(e.target.value)}
                          onKeyDown={handleChatKeyDown}
                          placeholder="Message BlueBox assistant..."
                          rows={1}
                          className="max-h-32 min-h-[44px] flex-1 resize-none bg-transparent px-2 py-3 text-sm leading-relaxed text-bluebox-text outline-none placeholder:text-bluebox-muted"
                        />
                        <button
                          type="submit"
                          disabled={chatSending || !chatMessage.trim()}
                          className="mb-1 inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-bluebox-cyan text-bluebox-dark transition-smooth hover:bg-bluebox-aqua disabled:cursor-not-allowed disabled:bg-cyan-950 disabled:text-bluebox-muted"
                          aria-label="Send message"
                        >
                          <Send size={17} aria-hidden="true" />
                        </button>
                      </div>
                      <p className="mt-2 text-center text-[10px] font-semibold uppercase tracking-wider text-bluebox-muted">
                        Enter to send, Shift + Enter for a new line
                      </p>
                    </form>
                  </div>
                </div>
              </Panel>
            </div>
          </div>
        </div>

      </div>
    </AppLayout>
  )
}
