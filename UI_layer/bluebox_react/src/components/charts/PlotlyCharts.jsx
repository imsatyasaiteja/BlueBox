import Plot from 'react-plotly.js'
import { useEffect, useMemo, useRef, useState } from 'react'
import { getSeverityColor } from '@/utils/format'
import { DEFAULT_DASHBOARD_TIME_ZONE, formatTimeInZone, getTimeZoneOption } from '@/utils/timeZones'
import { useProgressiveList, useTweenNumber } from '@/hooks/useAnimatedNumber'

const normalizeRiskScore = (score = 0, severity = 'ANOMALY') => {
  const value = Number(score || 0)
  const severityRisk = {
    CRITICAL: 1,
    HIGH: 0.85,
    WARNING: 0.7,
    MEDIUM: 0.65,
    ANOMALY: 0.6,
    LOW: 0.4,
    INFO: 0.15,
    NONE: 0,
  }[String(severity || 'ANOMALY').toUpperCase()] ?? 0.6

  if (value < 0) return Math.max(severityRisk, Math.min(1, 0.55 + Math.abs(value) * 2))
  if (value <= 0.05) return Math.max(severityRisk, Math.max(0.25, 0.55 - value * 4))
  if (value <= 1) return Math.max(severityRisk, value)
  return severityRisk
}

const plotlyLayout = {
  autosize: true,
  template: 'plotly_dark',
  margin: { l: 66, r: 26, t: 22, b: 58 },
  plot_bgcolor: '#071826',
  paper_bgcolor: '#06111C',
  font: { family: 'Segoe UI, system-ui, sans-serif', size: 12, color: '#E8F7FF' },
  xaxis: { gridcolor: 'rgba(139,203,255,0.12)', zeroline: false, linecolor: 'rgba(139,203,255,0.25)' },
  yaxis: { gridcolor: 'rgba(139,203,255,0.12)', zeroline: false, linecolor: 'rgba(139,203,255,0.25)' },
}

const ONE_HOUR_MS = 60 * 60 * 1000
const WINDOW_PRESETS = [
  { label: '10s', value: 10_000 },
  { label: '30s', value: 30_000 },
  { label: '1m', value: 60_000 },
  { label: '5m', value: 5 * 60_000 },
  { label: '15m', value: 15 * 60_000 },
  { label: '1h', value: ONE_HOUR_MS },
]

const LOCK_ICON = {
  width: 512,
  height: 512,
  path: 'M144 224v-72C144 68 212 0 296 0s152 68 152 152v72h24c22 0 40 18 40 40v208c0 22-18 40-40 40H120c-22 0-40-18-40-40V264c0-22 18-40 40-40h24zm64 0h176v-72c0-49-39-88-88-88s-88 39-88 88v72zm88 88c-22 0-40 18-40 40 0 15 8 28 20 35v45h40v-45c12-7 20-20 20-35 0-22-18-40-40-40z',
}

const UNLOCK_ICON = {
  width: 512,
  height: 512,
  path: 'M208 224h264c22 0 40 18 40 40v208c0 22-18 40-40 40H120c-22 0-40-18-40-40V264c0-22 18-40 40-40h24v-72C144 68 212 0 296 0c67 0 124 43 144 104l-61 20c-12-35-45-60-83-60-49 0-88 39-88 88v72zm88 88c-22 0-40 18-40 40 0 15 8 28 20 35v45h40v-45c12-7 20-20 20-35 0-22-18-40-40-40z',
}

const FORENSIC_VIEW_SESSION_KEY = 'bluebox:forensicTimeline:view'

const readStoredTimelineView = () => {
  if (typeof window === 'undefined') return null

  try {
    const parsed = JSON.parse(window.sessionStorage.getItem(FORENSIC_VIEW_SESSION_KEY) || 'null')
    if (!parsed || !Array.isArray(parsed.range) || parsed.range.length !== 2) return null
    const range = parsed.range.map(value => Number(value))
    if (!range.every(Number.isFinite) || range[1] <= range[0]) return null
    return {
      viewLocked: Boolean(parsed.viewLocked),
      followNow: Boolean(parsed.followNow),
      range,
      windowMs: Number.isFinite(Number(parsed.windowMs)) ? Number(parsed.windowMs) : ONE_HOUR_MS,
    }
  } catch {
    return null
  }
}

const writeStoredTimelineView = (view) => {
  if (typeof window === 'undefined') return

  try {
    if (!view) {
      window.sessionStorage.removeItem(FORENSIC_VIEW_SESSION_KEY)
      return
    }
    window.sessionStorage.setItem(FORENSIC_VIEW_SESSION_KEY, JSON.stringify(view))
  } catch {
    // Session persistence is a UX enhancement; ignore storage failures.
  }
}

const getEventTime = (entry) => entry.occurred_at || entry.recorded_at || entry.created_at

const toTimeValue = (value) => {
  if (value === null || value === undefined || value === '') return null

  const numericValue = typeof value === 'number' ? value : Number(value)
  if (Number.isFinite(numericValue)) {
    return numericValue < 1_000_000_000_000 ? numericValue * 1000 : numericValue
  }

  const time = new Date(value).getTime()
  return Number.isFinite(time) ? time : null
}

const buildWindowRange = (endTime, windowMs) => {
  return [endTime - windowMs, endTime]
}

const formatLocalTime = (
  time,
  includeMilliseconds = false,
  timeZone = DEFAULT_DASHBOARD_TIME_ZONE.timeZone,
) => {
  return formatTimeInZone(time, timeZone, includeMilliseconds)
}

const getTickStep = (spanMs) => {
  if (spanMs <= 15_000) return 1_000
  if (spanMs <= 60_000) return 5_000
  if (spanMs <= 5 * 60_000) return 30_000
  if (spanMs <= 15 * 60_000) return 60_000
  if (spanMs <= ONE_HOUR_MS) return 10 * 60_000
  return 30 * 60_000
}

const buildTimeTicks = (range, timeZone = DEFAULT_DASHBOARD_TIME_ZONE.timeZone) => {
  if (!range) return { tickvals: [], ticktext: [] }

  const [start, end] = range
  const span = Math.max(1000, end - start)
  const step = getTickStep(span)
  const firstTick = Math.ceil(start / step) * step
  const tickvals = []

  for (let time = firstTick; time <= end; time += step) {
    tickvals.push(time)
    if (tickvals.length > 12) break
  }

  return {
    tickvals,
    ticktext: tickvals.map(time => formatLocalTime(time, span <= 15_000, timeZone)),
  }
}

const toTitleCase = (value = '') => {
  const text = String(value || '').trim()
  if (!text) return ''
  return text.toLowerCase().replace(/\b[a-z]/g, char => char.toUpperCase())
}

const eventText = (item = {}) => [
  item.kind,
  item.kind_label,
  item.activity,
  item.event,
  item.source_type,
  item.context,
  item.operation,
  item.details?.operation,
].filter(Boolean).join(' ').toLowerCase()

const timelineEventTime = (item = {}) => (
  item.recorded_at ||
  item.created_at ||
  item.detected_at ||
  item.occurred_at ||
  item.timestamp
)

const sequenceLabel = (item = {}) => (
  item.sequence ||
  item.target_sequence ||
  item.details?.target_sequence ||
  item.evidence_id ||
  item.attempt_id ||
  '-'
)

const auditEventTitle = (item = {}) => {
  if (item.activity) return item.activity
  if (item.event) return toTitleCase(String(item.event).replaceAll('_', ' '))
  if (item.operation || item.details?.operation) {
    return `${toTitleCase(item.operation || item.details.operation)} attempt`
  }
  return 'Audit event'
}

const auditEventStatus = (item = {}) => {
  const text = eventText(item)
  if (item.synced_to_chain === true || text.includes('blocked')) return 'Blocked'
  if (text.includes('restore') || text.includes('recovery')) return 'Recovery'
  if (text.includes('corrupt') || text.includes('tamper')) return 'Detected'
  if (text.includes('successful') || text.includes('restored')) return 'Successful'
  return toTitleCase(item.classification || item.severity || 'Recorded')
}

const buildUnifiedAuditEvents = ({ appendOnlyActivity = [], securityEvents = [], timeZone }) => {
  const seen = new Set()
  const mutationEvents = []
  const recoveryEvents = []

  const addEvent = (lane, item = {}, source) => {
    const timeValue = toTimeValue(timelineEventTime(item))
    if (timeValue === null) return

    const recordKey = item.record_id ||
      (item.attempt_id ? `attempt-${item.attempt_id}` : null) ||
      (item.sequence ? `seq-${item.sequence}` : null) ||
      `${item.event || item.kind || source}-${item.created_at || item.recorded_at || item.detected_at || ''}`
    const key = [lane, recordKey].filter(Boolean).join(':')
    if (seen.has(key)) return
    seen.add(key)

    const target = lane === 'mutation' ? mutationEvents : recoveryEvents
    target.push({
      time: timeValue,
      title: auditEventTitle(item),
      status: auditEventStatus(item),
      sequence: sequenceLabel(item),
      severity: item.severity || item.classification || 'INFO',
      context: item.context || item.details?.reason || item.details?.operation || item.source_type || source,
      displayedTime: formatLocalTime(timeValue, true, timeZone),
    })
  }

  appendOnlyActivity.forEach(item => {
    const text = eventText(item)
    if (item.kind === 'mutation_attempt') {
      addEvent('mutation', item, 'append-only activity')
      return
    }
    if (item.kind === 'security_event' || item.source_type === 'SECURITY_EVENT') {
      addEvent('recovery', item, 'security audit')
      return
    }
    if (text.includes('update attempt') || text.includes('delete attempt') || text.includes('mutation')) {
      addEvent('mutation', item, 'append-only activity')
    }
  })

  securityEvents.forEach(item => addEvent('recovery', item, 'security audit'))

  return {
    mutationEvents: mutationEvents.sort((left, right) => left.time - right.time),
    recoveryEvents: recoveryEvents.sort((left, right) => left.time - right.time),
  }
}

export const ForensicTimeline = ({
  entries = [],
  appendOnlyActivity = [],
  securityEvents = [],
  unified = false,
  progressive = false,
  currentTime = new Date(),
  selectedTimeZone = DEFAULT_DASHBOARD_TIME_ZONE.timeZone,
}) => {
  const [initialView] = useState(() => readStoredTimelineView())
  const [windowMs, setWindowMs] = useState(initialView?.windowMs || ONE_HOUR_MS)
  const [followNow, setFollowNow] = useState(initialView ? initialView.followNow : true)
  const [userRange, setUserRange] = useState(initialView?.range || null)
  const [viewLocked, setViewLocked] = useState(Boolean(initialView?.viewLocked))
  const viewLockedRef = useRef(viewLocked)
  const activeRangeRef = useRef(null)
  const chartRightEdgeRef = useRef(currentTime.getTime())
  const windowMsRef = useRef(windowMs)
  const activeTimeZone = getTimeZoneOption(selectedTimeZone)

  const sortedEntries = useMemo(() => {
    return [...entries].sort((a, b) =>
      toTimeValue(getEventTime(a) || 0) - toTimeValue(getEventTime(b) || 0)
    )
  }, [entries])
  const visibleEntries = useProgressiveList(sortedEntries, {
    enabled: progressive,
    intervalMs: 18,
    initialCount: 3,
  })

  const eventTimes = useMemo(() => {
    if (!visibleEntries.length) return []

    const sourceTimes = visibleEntries.map(e => toTimeValue(getEventTime(e)))
    const validTimes = sourceTimes.filter(value => value !== null)
    const latestSourceTime = validTimes.length ? Math.max(...validTimes) : currentTime.getTime()

    return sourceTimes.map((value, index) => {
      const fallback = latestSourceTime + index
      return value ?? fallback
    })
  }, [currentTime, visibleEntries])

  const unifiedAuditEvents = useMemo(() => (
    unified
      ? buildUnifiedAuditEvents({
        appendOnlyActivity,
        securityEvents,
        timeZone: activeTimeZone.timeZone,
      })
      : { mutationEvents: [], recoveryEvents: [] }
  ), [activeTimeZone.timeZone, appendOnlyActivity, securityEvents, unified])

  const data = useMemo(() => {
    const hasAnyTimelineData = visibleEntries.length ||
      unifiedAuditEvents.mutationEvents.length ||
      unifiedAuditEvents.recoveryEvents.length
    if (!hasAnyTimelineData) return [{ x: [], y: [], type: 'scatter', name: 'No data' }]

    const riskValues = visibleEntries.map(e => normalizeRiskScore(e.anomaly_score, e.severity) * 100)
    const customRows = visibleEntries.map((e, index) => [
      formatLocalTime(eventTimes[index] ?? currentTime.getTime(), true, activeTimeZone.timeZone),
      e.sequence || '-',
      Number(e.anomaly_score || 0).toFixed(4),
      e.severity || 'NONE',
      e.predicted_anomaly ? 'Flagged' : 'Normal',
    ])
    const anomalyIndexes = visibleEntries
      .map((entry, index) => Number(entry.predicted_anomaly || 0) === 1 ? index : -1)
      .filter(index => index >= 0)

    const traces = visibleEntries.length ? [{
        x: eventTimes,
        y: riskValues,
        customdata: customRows,
        type: 'scattergl',
        mode: 'markers+lines',
        name: 'AI risk trace',
        showlegend: true,
        marker: {
          size: 6,
          color: visibleEntries.map(e => getSeverityColor(e.severity)),
          line: { width: 1.2, color: '#06111C' },
          opacity: 0.9,
        },
        line: { color: 'rgba(57, 216, 255, 0.48)', width: 1.8, shape: 'linear' },
        hovertemplate:
          '<b>%{customdata[0]}</b><br>Seq: %{customdata[1]}<br>Risk: %{y:.1f}%<br>Raw score: %{customdata[2]}<br>Severity: %{customdata[3]}<br>%{customdata[4]}<extra></extra>',
      }] : []

    if (anomalyIndexes.length) {
      traces.push({
        x: anomalyIndexes.map(index => eventTimes[index]),
        y: anomalyIndexes.map(index => riskValues[index]),
        customdata: anomalyIndexes.map(index => customRows[index]),
        type: 'scattergl',
        mode: 'markers',
        name: 'Flagged anomalies',
        showlegend: true,
        marker: {
          size: 8,
          symbol: 'diamond',
          color: anomalyIndexes.map(index => getSeverityColor(visibleEntries[index].severity)),
          line: { width: 1.4, color: '#E8F7FF' },
          opacity: 1,
        },
        hovertemplate:
          '<b>Anomaly %{customdata[0]}</b><br>Seq: %{customdata[1]}<br>Risk: %{y:.1f}%<br>Raw score: %{customdata[2]}<br>Severity: %{customdata[3]}<extra></extra>',
      })
    }

    if (unified && unifiedAuditEvents.mutationEvents.length) {
      traces.push({
        x: unifiedAuditEvents.mutationEvents.map(event => event.time),
        y: unifiedAuditEvents.mutationEvents.map(() => 104),
        customdata: unifiedAuditEvents.mutationEvents.map(event => [
          event.displayedTime,
          event.title,
          event.sequence,
          event.status,
          event.context,
        ]),
        type: 'scattergl',
        mode: 'markers',
        name: 'Database mutations',
        showlegend: false,
        marker: {
          size: 11,
          symbol: 'square',
          color: unifiedAuditEvents.mutationEvents.map(event => event.status === 'Blocked' ? '#FFD166' : '#FF6478'),
          line: { width: 1.4, color: '#E8F7FF' },
          opacity: 0.96,
        },
        hovertemplate:
          '<b>%{customdata[1]}</b><br>%{customdata[0]}<br>Seq: %{customdata[2]}<br>Status: %{customdata[3]}<br>%{customdata[4]}<extra></extra>',
      })
    }

    if (unified && unifiedAuditEvents.recoveryEvents.length) {
      traces.push({
        x: unifiedAuditEvents.recoveryEvents.map(event => event.time),
        y: unifiedAuditEvents.recoveryEvents.map(() => 116),
        customdata: unifiedAuditEvents.recoveryEvents.map(event => [
          event.displayedTime,
          event.title,
          event.sequence,
          event.status,
          event.context,
        ]),
        type: 'scattergl',
        mode: 'markers',
        name: 'Recovery / security audit',
        showlegend: false,
        marker: {
          size: 12,
          symbol: 'triangle-up',
          color: '#B8A7FF',
          line: { width: 1.4, color: '#E8F7FF' },
          opacity: 0.96,
        },
        hovertemplate:
          '<b>%{customdata[1]}</b><br>%{customdata[0]}<br>Seq: %{customdata[2]}<br>Status: %{customdata[3]}<br>%{customdata[4]}<extra></extra>',
      })
    }

    return traces
  }, [activeTimeZone.timeZone, currentTime, eventTimes, unified, unifiedAuditEvents, visibleEntries])

  const chartRightEdge = currentTime.getTime()
  const activeRange = followNow
    ? buildWindowRange(chartRightEdge, windowMs)
    : userRange
  const plotRange = activeRange || undefined
  const timeTicks = useMemo(() => buildTimeTicks(activeRange, activeTimeZone.timeZone), [activeRange, activeTimeZone.timeZone])

  viewLockedRef.current = viewLocked
  activeRangeRef.current = activeRange
  chartRightEdgeRef.current = chartRightEdge
  windowMsRef.current = windowMs

  useEffect(() => {
    if (viewLocked && activeRange) {
      writeStoredTimelineView({
        viewLocked,
        followNow,
        range: activeRange,
        windowMs,
      })
      return
    }

    writeStoredTimelineView(null)
  }, [activeRange, followNow, viewLocked, windowMs])

  const handleRelayout = (event = {}) => {
    if (viewLocked) return

    if (event['xaxis.autorange']) {
      setFollowNow(true)
      setUserRange(null)
      return
    }

    const start = event['xaxis.range[0]'] || event['xaxis.range']?.[0]
    const end = event['xaxis.range[1]'] || event['xaxis.range']?.[1]

    if (start !== undefined && end !== undefined) {
      const nextRange = [Number(start), Number(end)]
      if (activeRange && Math.abs(nextRange[0] - activeRange[0]) < 2 && Math.abs(nextRange[1] - activeRange[1]) < 2) {
        return
      }
      setFollowNow(false)
      setUserRange(nextRange)
    }
  }

  const setPresetWindow = (nextWindowMs) => {
    setWindowMs(nextWindowMs)
    setFollowNow(true)
    setUserRange(null)
    setViewLocked(false)
  }

  const toggleViewLock = () => {
    if (viewLockedRef.current) {
      setViewLocked(false)
      return
    }

    const rangeToLock = activeRangeRef.current || buildWindowRange(chartRightEdgeRef.current, windowMsRef.current)
    setFollowNow(false)
    setUserRange(rangeToLock)
    setViewLocked(true)
  }

  const thresholdShapes = [
    { type: 'line', xref: 'paper', x0: 0, x1: 1, y0: 40, y1: 40, line: { color: 'rgba(255,209,102,0.45)', width: 1, dash: 'dot' } },
    { type: 'line', xref: 'paper', x0: 0, x1: 1, y0: 70, y1: 70, line: { color: 'rgba(255,100,120,0.45)', width: 1, dash: 'dot' } },
    { type: 'line', xref: 'x', x0: chartRightEdge, x1: chartRightEdge, yref: 'paper', y0: 0, y1: 1, line: { color: 'rgba(73,227,143,0.7)', width: 1.5 } },
  ]

  const unifiedLaneShapes = unified ? [
    { type: 'line', xref: 'paper', x0: 0, x1: 1, y0: 104, y1: 104, line: { color: 'rgba(255,209,102,0.35)', width: 1, dash: 'dash' } },
    { type: 'line', xref: 'paper', x0: 0, x1: 1, y0: 116, y1: 116, line: { color: 'rgba(184,167,255,0.38)', width: 1, dash: 'dash' } },
  ] : []

  const timelineAnnotations = [
    {
      x: chartRightEdge,
      y: 1,
      xref: 'x',
      yref: 'paper',
      text: 'NOW',
      showarrow: false,
      xanchor: 'left',
      yanchor: 'bottom',
      font: { size: 10, color: '#49E38F' },
      bgcolor: 'rgba(6,17,28,0.72)',
      bordercolor: 'rgba(73,227,143,0.45)',
      borderpad: 3,
    },
    {
      x: 0.985,
      y: 40,
      xref: 'paper',
      yref: 'y',
      text: 'Medium',
      showarrow: false,
      xanchor: 'right',
      yanchor: 'bottom',
      font: { size: 10, color: '#FFD166' },
      bgcolor: 'rgba(6,17,28,0.76)',
      bordercolor: 'rgba(255,209,102,0.34)',
      borderpad: 3,
    },
    {
      x: 0.985,
      y: 70,
      xref: 'paper',
      yref: 'y',
      text: 'High',
      showarrow: false,
      xanchor: 'right',
      yanchor: 'bottom',
      font: { size: 10, color: '#FF6478' },
      bgcolor: 'rgba(6,17,28,0.76)',
      bordercolor: 'rgba(255,100,120,0.34)',
      borderpad: 3,
    },
    ...(unified ? [
      {
        x: 0.01,
        y: 104,
        xref: 'paper',
        yref: 'y',
        text: 'DB mutations',
        showarrow: false,
        xanchor: 'left',
        yanchor: 'middle',
        font: { size: 10, color: '#FFD166' },
        bgcolor: 'rgba(6,17,28,0.72)',
        bordercolor: 'rgba(255,209,102,0.26)',
        borderpad: 3,
      },
      {
        x: 0.01,
        y: 116,
        xref: 'paper',
        yref: 'y',
        text: 'Recovery / security',
        showarrow: false,
        xanchor: 'left',
        yanchor: 'middle',
        font: { size: 10, color: '#B8A7FF' },
        bgcolor: 'rgba(6,17,28,0.72)',
        bordercolor: 'rgba(184,167,255,0.26)',
        borderpad: 3,
      },
    ] : []),
  ]

  return (
    <div className="forensic-chart-shell">
      <div className="forensic-chart-toolbar" aria-label="Timeline zoom controls">
        <div className="forensic-chart-controls" aria-label="Timeline time window controls">
          {WINDOW_PRESETS.map(preset => (
            <button
              key={preset.label}
              type="button"
              className={followNow && windowMs === preset.value ? 'active' : ''}
              onClick={() => setPresetWindow(preset.value)}
            >
              {preset.label}
            </button>
          ))}
          <button type="button" onClick={() => {
            setFollowNow(true)
            setUserRange(null)
            setViewLocked(false)
          }}>Now</button>
        </div>
      </div>
      <div className={`forensic-chart-canvas ${viewLocked ? 'locked' : ''}`}>
        <Plot
          key={viewLocked ? 'forensic-timeline-locked' : 'forensic-timeline-unlocked'}
          data={data}
          layout={{
            ...plotlyLayout,
            dragmode: viewLocked ? false : 'pan',
            hovermode: 'closest',
            uirevision: followNow ? `forensic-follow-${activeRange?.[0]}-${activeRange?.[1]}` : 'forensic-manual',
            xaxis: {
              ...plotlyLayout.xaxis,
              title: `Event Time (${activeTimeZone.label})`,
              type: 'linear',
              range: plotRange,
              tickmode: 'array',
              tickvals: timeTicks.tickvals,
              ticktext: timeTicks.ticktext,
              fixedrange: viewLocked,
            },
            yaxis: {
              ...plotlyLayout.yaxis,
              title: unified ? 'Risk Level (%) / Audit Lanes' : 'Risk Level (%)',
              range: [0, 140],
              fixedrange: true,
            },
            showlegend: true,
            legend: {
              orientation: 'h',
              x: 0.012,
              y: 0.988,
              xanchor: 'left',
              yanchor: 'top',
              font: { size: 11 },
              bgcolor: 'rgba(6,17,28,0.76)',
              bordercolor: 'rgba(139,203,255,0.2)',
              borderwidth: 1,
            },
            shapes: [...thresholdShapes, ...unifiedLaneShapes],
            annotations: timelineAnnotations,
            height: 560,
          }}
          style={{ width: '100%', height: '560px' }}
          config={{
            responsive: true,
            displayModeBar: true,
            displaylogo: false,
            scrollZoom: !viewLocked,
            doubleClick: 'reset',
            modeBarButtons: [
              [
                'resetScale2d',
                {
                  name: viewLocked ? 'Unlock view' : 'Lock view',
                  title: viewLocked ? 'Unlock view' : 'Lock view',
                  icon: viewLocked ? UNLOCK_ICON : LOCK_ICON,
                  click: toggleViewLock,
                },
              ],
              ['pan2d', 'autoScale2d'],
              ['zoomIn2d', 'zoomOut2d'],
            ],
            modeBarButtonsToRemove: [
              'zoom2d',
              'lasso2d',
              'select2d',
              'toImage',
              'hoverClosestCartesian',
              'hoverCompareCartesian',
              'toggleSpikelines',
            ],
          }}
          useResizeHandler
          onRelayout={handleRelayout}
          onDoubleClick={() => {
            if (viewLocked) return false
            setFollowNow(true)
            setUserRange(null)
            return false
          }}
        />
      </div>
    </div>
  )
}

const flaggedEntries = (entries = []) =>
  entries.filter(item => Number(item.predicted_anomaly || 0) === 1)

const addCount = (counts, key) => {
  const label = key || 'Unknown'
  counts[label] = (counts[label] || 0) + 1
}

const topCounts = (counts, limit = 8) =>
  Object.entries(counts)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, limit)

const basename = (value = '') => {
  const text = String(value || '')
  return text.split(/[\\/]/).pop() || text || 'Unknown'
}

const scenarioFromPath = (value = '') => {
  const text = String(value || '')
  const match = text.match(/logger_demo[\\/]+([^\\/]+)/i) || text.match(/standalone_([^\\/]+)/i)
  return match?.[1]?.replace(/_/g, ' ')
}

const sourceLabel = (entry = {}) => {
  if (entry.domain) return String(entry.domain).replace(/_/g, ' ')
  const file = basename(entry.source_file)
  return file.replace(/(_traffic|_scores)?\.csv$/i, '').replace(/_/g, ' ') || 'Unknown source'
}

const volumeLabel = (entry = {}) => {
  if (entry.protocol) return String(entry.protocol).toUpperCase()
  if (entry.label_octal) return `ARINC ${entry.label_octal}`
  if (entry.domain) return String(entry.domain).replace(/_/g, ' ')
  if (entry.data_format) return String(entry.data_format)
  return sourceLabel(entry)
}

const familyLabel = (entry = {}) => {
  const anomalyType = String(entry.anomaly_type || '').trim()
  if (anomalyType && anomalyType.toLowerCase() !== 'none') return anomalyType.replace(/_/g, ' ')
  return scenarioFromPath(entry.source_file) || sourceLabel(entry)
}

const reasonTheme = (feature = '') => {
  const text = String(feature || '').toLowerCase()
  if (/port|dst_port|sensitive/.test(text)) return 'Port misuse'
  if (/protocol/.test(text)) return 'Protocol violation'
  if (/frequency|burst|rate|pps/.test(text)) return 'Traffic burst'
  if (/size|packet|payload/.test(text)) return 'Payload size'
  if (/cross.?domain|domain|lateral/.test(text)) return 'Cross-domain movement'
  if (/ssm|parity|data_bits|label|raw_hex/.test(text)) return 'ARINC integrity'
  return feature ? String(feature).replace(/_/g, ' ') : 'Model threshold'
}

const featureName = (feature) => {
  if (typeof feature === 'string') return feature
  if (feature && typeof feature === 'object') {
    return feature.feature || feature.name || feature.label || feature.reason || ''
  }
  return ''
}

const ChartEmpty = ({ label = 'No flagged anomaly evidence' }) => (
  <div className="h-72 flex items-center justify-center text-bluebox-muted text-sm">
    {label}
  </div>
)

const compactChartLayout = {
  ...plotlyLayout,
  height: 320,
  margin: { l: 58, r: 24, t: 18, b: 54 },
  showlegend: false,
}

export const SeverityTrendOverTime = ({ entries = [] }) => {
  const data = useMemo(() => {
    const flagged = flaggedEntries(entries)
    if (!flagged.length) return []

    const buckets = []
    const bucketSet = new Set()
    const counts = {
      High: {},
      Medium: {},
      Low: {},
    }

    flagged.forEach(entry => {
      const time = toTimeValue(getEventTime(entry))
      if (!time) return
      const bucketTime = Math.floor(time / 60000) * 60000
      const bucket = formatLocalTime(bucketTime)
      if (!bucketSet.has(bucket)) {
        bucketSet.add(bucket)
        buckets.push(bucket)
      }

      const rank = severityRank(entry.severity)
      const severity = rank >= 3 ? 'High' : rank === 2 ? 'Medium' : 'Low'
      counts[severity][bucket] = (counts[severity][bucket] || 0) + 1
    })

    return [
      { name: 'High', color: '#FF6478' },
      { name: 'Medium', color: '#FFD166' },
      { name: 'Low', color: '#39D8FF' },
    ].map(item => ({
      x: buckets,
      y: buckets.map(bucket => counts[item.name][bucket] || 0),
      type: 'scatter',
      mode: 'lines+markers',
      name: item.name,
      line: { color: item.color, width: 2.4, shape: 'spline' },
      marker: { size: 7, color: item.color },
      hovertemplate: `<b>${item.name}</b><br>%{x}<br>Events: %{y}<extra></extra>`,
    }))
  }, [entries])

  if (!data.length) return <ChartEmpty />

  return (
    <Plot
      data={data}
      layout={{
        ...compactChartLayout,
        showlegend: true,
        legend: { orientation: 'h', x: 1, y: 1.18, xanchor: 'right', yanchor: 'top', font: { size: 11 } },
        xaxis: { ...plotlyLayout.xaxis, title: 'Event Minute' },
        yaxis: { ...plotlyLayout.yaxis, title: 'Flagged Events', rangemode: 'tozero' },
      }}
      style={{ width: '100%', height: '320px' }}
      config={{ responsive: true, displayModeBar: false }}
    />
  )
}

export const TopAnomalySources = ({ entries = [] }) => {
  const rows = useMemo(() => {
    const counts = {}
    flaggedEntries(entries).forEach(entry => addCount(counts, sourceLabel(entry)))
    return topCounts(counts, 8)
  }, [entries])

  if (!rows.length) return <ChartEmpty />

  return (
    <Plot
      data={[{
        x: rows.map(([, count]) => count),
        y: rows.map(([label]) => label),
        type: 'bar',
        orientation: 'h',
        marker: { color: '#39D8FF' },
        hovertemplate: '<b>%{y}</b><br>Flagged: %{x}<extra></extra>',
      }]}
      layout={{
        ...compactChartLayout,
        margin: { l: 106, r: 18, t: 18, b: 42 },
        bargap: 0.36,
        xaxis: { ...plotlyLayout.xaxis, title: 'Flagged Events', rangemode: 'tozero' },
        yaxis: { ...plotlyLayout.yaxis, autorange: 'reversed', automargin: true },
      }}
      style={{ width: '100%', height: '320px' }}
      config={{ responsive: true, displayModeBar: false }}
    />
  )
}

export const TopShapReasonThemes = ({ entries = [] }) => {
  const rows = useMemo(() => {
    const counts = {}
    flaggedEntries(entries).forEach(entry => {
      const features = Array.isArray(entry.top_features) ? entry.top_features : []
      if (!features.length) {
        addCount(counts, 'Model threshold')
        return
      }
      features.slice(0, 3).forEach(feature => addCount(counts, reasonTheme(featureName(feature))))
    })
    return topCounts(counts, 8)
  }, [entries])

  if (!rows.length) return <ChartEmpty label="No SHAP reason themes available" />

  return (
    <Plot
      data={[{
        x: rows.map(([, count]) => count),
        y: rows.map(([label]) => label),
        type: 'bar',
        orientation: 'h',
        marker: { color: '#91AEC5' },
        hovertemplate: '<b>%{y}</b><br>Mentions: %{x}<extra></extra>',
      }]}
      layout={{
        ...compactChartLayout,
        margin: { l: 154, r: 32, t: 22, b: 48 },
        bargap: 0.4,
        xaxis: { ...plotlyLayout.xaxis, title: 'Mentions', rangemode: 'tozero' },
        yaxis: { ...plotlyLayout.yaxis, autorange: 'reversed', automargin: true, tickfont: { size: 12 } },
      }}
      style={{ width: '100%', height: '320px' }}
      config={{ responsive: true, displayModeBar: false }}
    />
  )
}

export const AnomalyVolumeBreakdown = ({ entries = [] }) => {
  const rows = useMemo(() => {
    const counts = {}
    flaggedEntries(entries).forEach(entry => addCount(counts, volumeLabel(entry)))
    return topCounts(counts, 10)
  }, [entries])

  if (!rows.length) return <ChartEmpty />

  return (
    <Plot
      data={[{
        x: rows.map(([, count]) => count),
        y: rows.map(([label]) => label),
        type: 'bar',
        orientation: 'h',
        marker: { color: rows.map(([label]) => label.startsWith('ARINC') ? '#FFD166' : '#39D8FF') },
        hovertemplate: '<b>%{y}</b><br>Flagged: %{x}<extra></extra>',
      }]}
      layout={{
        ...compactChartLayout,
        height: 360,
        margin: { l: 116, r: 20, t: 20, b: 48 },
        xaxis: { ...plotlyLayout.xaxis, title: 'Flagged Events', rangemode: 'tozero' },
        yaxis: { ...plotlyLayout.yaxis, autorange: 'reversed', automargin: true },
      }}
      style={{ width: '100%', height: '360px' }}
      config={{ responsive: true, displayModeBar: false }}
    />
  )
}

export const AttackFamilyBreakdown = ({ entries = [] }) => {
  const rows = useMemo(() => {
    const counts = {}
    flaggedEntries(entries).forEach(entry => addCount(counts, familyLabel(entry)))
    return topCounts(counts, 8)
  }, [entries])

  if (!rows.length) return <ChartEmpty />

  return (
    <Plot
      data={[{
        labels: rows.map(([label]) => label),
        values: rows.map(([, count]) => count),
        type: 'pie',
        hole: 0.52,
        marker: {
          colors: ['#39D8FF', '#FFD166', '#91AEC5', '#16F0C5', '#B8A7FF', '#FF9E64', '#6EE7B7', '#FF6478'],
          line: { color: '#06111C', width: 2 },
        },
        textinfo: 'none',
        textposition: 'none',
        hovertemplate: '<b>%{label}</b><br>Flagged: %{value}<br>%{percent}<extra></extra>',
      }]}
      layout={{
        ...compactChartLayout,
        height: 360,
        margin: { l: 24, r: 220, t: 20, b: 24 },
        showlegend: true,
        legend: { x: 1.02, y: 0.5, xanchor: 'left', yanchor: 'middle', font: { size: 11 } },
      }}
      style={{ width: '100%', height: '360px' }}
      config={{ responsive: true, displayModeBar: false }}
    />
  )
}

export const SeverityDistribution = ({ anomalies = [], summary = null }) => {
  const data = useMemo(() => {
    const counts = {
      High: 0,
      Medium: 0,
      Low: 0,
      Normal: 0,
    }

    const addSeverityCount = (severityValue, count = 1, flagged = true) => {
      const severity = String(severityValue || '').toUpperCase()
      if (!flagged || severity === 'NONE' || severity === 'NORMAL' || severity === 'INFO' || severity === 'UNKNOWN') counts.Normal += count
      else if (severity === 'CRITICAL' || severity === 'HIGH') counts.High += count
      else if (severity === 'WARNING' || severity === 'MEDIUM') counts.Medium += count
      else if (severity === 'LOW') counts.Low += count
      else counts.Normal += count
    }

    if (summary?.severity_counts && Object.keys(summary.severity_counts).length) {
      Object.entries(summary.severity_counts).forEach(([severity, count]) => {
        addSeverityCount(severity, Number(count || 0), true)
      })
    } else {
      anomalies.forEach(a => {
        addSeverityCount(a.severity, 1, Number(a.predicted_anomaly || 0) === 1)
      })
    }

    const labels = Object.keys(counts).filter(label => counts[label] > 0)
    const values = labels.map(label => counts[label])

    return [{
      labels,
      values,
      type: 'pie',
      hole: 0.58,
      sort: false,
      marker: {
        colors: labels.map(label => ({
          High: '#FF6478',
          Medium: '#FFD166',
          Low: '#39D8FF',
          Normal: '#16F0C5',
        }[label] || '#91AEC5'),
        ),
        line: { color: '#39D8FF', width: 2 },
      },
      textinfo: 'none',
      textposition: 'none',
      hovertemplate: '<b>%{label}</b><br>Events: %{value}<extra></extra>',
    }]
  }, [anomalies, summary])

  return (
    <Plot
      data={data}
      layout={{
        ...plotlyLayout,
        height: 320,
        margin: { l: 18, r: 18, t: 18, b: 58 },
        showlegend: true,
        legend: { orientation: 'h', x: 0.5, y: -0.12, xanchor: 'center', yanchor: 'top', font: { size: 11 } },
      }}
      style={{ width: '100%', height: '320px' }}
      config={{ responsive: true, displayModeBar: false }}
    />
  )
}

export const EventCompositionBar = ({ entries = [] }) => {
  const data = useMemo(() => {
    if (!entries.length) return [{ x: ['No Data'], y: [0], type: 'bar' }]

    const eventTypes = {}
    entries.forEach(e => {
      const type = e.event_type || 'unknown'
      eventTypes[type] = (eventTypes[type] || 0) + 1
    })

    return [{
      x: Object.keys(eventTypes),
      y: Object.values(eventTypes),
      type: 'bar',
      orientation: 'v',
      marker: { color: '#39D8FF', line: { color: '#16F0C5', width: 2 } },
      text: Object.values(eventTypes),
      textposition: 'outside',
      hovertemplate: '<b>%{x}</b><br>Count: %{y}<extra></extra>',
    }]
  }, [entries])

  return (
    <Plot
      data={data}
      layout={{
        ...plotlyLayout,
        title: 'Event Type Composition',
        xaxis: { ...plotlyLayout.xaxis, title: 'Event Type' },
        yaxis: { ...plotlyLayout.yaxis, title: 'Count' },
        height: 350,
        showlegend: false,
      }}
      style={{ width: '100%', height: '350px' }}
      config={{ responsive: true, displayModeBar: false }}
    />
  )
}

const severityRank = (severity = '') => {
  switch (String(severity).toUpperCase()) {
    case 'CRITICAL':
    case 'HIGH':
      return 3
    case 'WARNING':
    case 'MEDIUM':
      return 2
    case 'LOW':
      return 1
    default:
      return 0
  }
}

const postureFromEvidence = ({ flagged, total }) => {
  const alertRate = total > 0 ? flagged / total : 0
  if (alertRate >= 0.15) return { label: 'Critical', className: 'critical' }
  if (alertRate >= 0.05) return { label: 'Elevated', className: 'elevated' }
  if (alertRate >= 0.01) return { label: 'Caution', className: 'watch' }
  return { label: 'Safe', className: 'nominal' }
}

const ALERT_RATE_BANDS = [
  { label: 'Safe', range: '<1%', color: '#22C55E' },
  { label: 'Caution', range: '1-5%', color: '#38BDF8' },
  { label: 'Elevated', range: '5-15%', color: '#F59E0B' },
  { label: 'Critical', range: '15%+', color: '#EF4444' },
]

export const AIAnomalyAssessment = ({ anomaly = null, entries = [], animate = false }) => {
  const assessment = useMemo(() => {
    const records = entries.length ? entries : anomaly?.records || []
    const recentRecords = anomaly?.records || []
    const total = Number(anomaly?.total_ai_records || 0) || records.length
    const flaggedRecords = records.filter(item => Number(item.predicted_anomaly || 0) === 1)
    const authoritativeFlagged = Number(anomaly?.anomalies ?? NaN)
    const flagged = Number.isFinite(authoritativeFlagged) ? authoritativeFlagged : flaggedRecords.length
    const high = flaggedRecords.filter(item => severityRank(item.severity) === 3).length
    const medium = flaggedRecords.filter(item => severityRank(item.severity) === 2).length
    const low = flaggedRecords.filter(item => severityRank(item.severity) === 1).length
    const normal = Math.max(total - flagged, 0)
    const latest = recentRecords[0] || records[records.length - 1] || null
    const highestPriority = anomaly?.ranked_anomalies?.[0] || flaggedRecords
      .slice()
      .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || normalizeRiskScore(b.anomaly_score, b.severity) - normalizeRiskScore(a.anomaly_score, a.severity))[0] || null
    const posture = postureFromEvidence({ flagged, total })
    const alertRate = total > 0 ? (flagged / total) * 100 : 0

    return { records, total, flagged, high, medium, low, normal, latest, highestPriority, posture, alertRate }
  }, [anomaly, entries])

  const severityRows = [
    { label: 'High', value: assessment.high, className: 'high' },
    { label: 'Medium', value: assessment.medium, className: 'medium' },
    { label: 'Low', value: assessment.low, className: 'low' },
    { label: 'Normal', value: assessment.normal, className: 'normal' },
  ]
  const maxSeverityCount = Math.max(...severityRows.map(row => row.value), 1)
  const targetGaugeValue = Math.max(0, Math.min(100, assessment.alertRate))
  const gaugeValue = useTweenNumber(targetGaugeValue, {
    enabled: animate,
    durationMs: 900,
    precision: 1,
  })
  const gaugeTicks = Array.from({ length: 21 }, (_, index) => index * 5)
  const gaugeData = [{
    type: 'indicator',
    mode: 'gauge+number',
    value: gaugeValue,
    // title: { text: 'Alert Rate' },
    domain: { x: [0, 1], y: [0, 1] },
    gauge: {
      axis: {
        range: [0, 100],
        tickwidth: 1,
        tickcolor: '#E8F7FF',
        tickfont: { color: '#E8F7FF', size: 8 },
        tickmode: 'array',
        tickvals: gaugeTicks,
        ticktext: gaugeTicks.map(value => String(value)),
      },
      bar: { color: '#F8FAFC', thickness: 0.18 },
      bgcolor: '#071826',
      borderwidth: 1,
      bordercolor: 'rgba(139,203,255,0.25)',
      steps: [
        { range: [0, 1], color: '#22C55E' },
        { range: [1, 5], color: '#38BDF8' },
        { range: [5, 15], color: '#F59E0B' },
        { range: [15, 100], color: '#EF4444' },
      ],
      threshold: {
        line: { color: '#F8FAFC', width: 4 },
        thickness: 0.75,
        value: gaugeValue,
      },
    },
    number: { suffix: '%', valueformat: '.1f' },
  }]

  return (
    <div className="ai-risk-panel">
      <div className={`ai-gauge-card ${assessment.posture.className}`}>
        <Plot
          data={gaugeData}
          layout={{
            ...plotlyLayout,
            height: 215,
            margin: { l: 18, r: 18, t: 30, b: 34 },
            font: { ...plotlyLayout.font, size: 11 },
          }}
          style={{ width: '100%', height: '215px' }}
          config={{ responsive: true, displayModeBar: false }}
        />
        <div className="ai-posture-strip">
          <span>Security Posture</span>
          <strong>{assessment.posture.label}</strong>
        </div>
        <div className="ai-gauge-legend" aria-label="Alert rate posture bands">
          {ALERT_RATE_BANDS.map(band => (
            <div key={band.label}>
              <span style={{ backgroundColor: band.color }} />
              <strong>{band.label}</strong>
              <em>{band.range}</em>
            </div>
          ))}
        </div>
      </div>

      <div className="ai-severity-stack" aria-label="AI severity distribution">
        {severityRows.map(row => (
          <div key={row.label} className="ai-severity-row">
            <span>{row.label}</span>
            <div className="ai-severity-track">
              <div
                className={`ai-severity-fill ${row.className}`}
                style={{ width: `${Math.max(4, (row.value / maxSeverityCount) * 100)}%` }}
              />
            </div>
            <strong>{row.value}</strong>
          </div>
        ))}
      </div>

      <div className="ai-evidence-notes">
        <div>
          <span>Newest evidence</span>
          <strong>
            {assessment.latest
              ? `Entry #${assessment.latest.sequence || assessment.latest.evidence_id || '-'} / ${Number(assessment.latest.predicted_anomaly || 0) === 1 ? 'Flagged' : 'Normal'}`
              : 'No verdict'}
          </strong>
        </div>
        <div>
          <span>Top alert entry</span>
          <strong>{assessment.highestPriority ? `Entry #${assessment.highestPriority.sequence || assessment.highestPriority.evidence_id || '-'} / ${toTitleCase(assessment.highestPriority.severity || 'Anomaly')}` : 'No flagged evidence'}</strong>
        </div>
      </div>
    </div>
  )
}

export const ScoreGauge = ({ score = 0 }) => {
  const data = useMemo(() => {
    const value = Math.max(0, Math.min(100, normalizeRiskScore(score) * 100))

    return [{
      type: 'indicator',
      mode: 'gauge+number',
      value: value,
      title: { text: 'Current Risk' },
      domain: { x: [0, 1], y: [0, 1] },
      gauge: {
        axis: { range: [0, 100], tickwidth: 1, tickcolor: '#91AEC5' },
        bar: { color: value >= 70 ? '#FF6478' : value >= 40 ? '#FFD166' : '#16F0C5' },
        bgcolor: '#071826',
        borderwidth: 1,
        bordercolor: 'rgba(139,203,255,0.25)',
        steps: [
          { range: [0, 40], color: 'rgba(22, 240, 197, 0.12)' },
          { range: [40, 70], color: 'rgba(255, 209, 102, 0.14)' },
          { range: [70, 100], color: 'rgba(255, 100, 120, 0.16)' },
        ],
        threshold: {
          line: { color: '#E8F7FF', width: 3 },
          thickness: 0.75,
          value,
        },
      },
      number: { suffix: '%', valueformat: '.1f' },
    }]
  }, [score])

  return (
    <Plot
      data={data}
      layout={{
        ...plotlyLayout,
        height: 350,
        margin: { l: 34, r: 34, t: 46, b: 28 },
      }}
      style={{ width: '100%', height: '350px' }}
      config={{ responsive: true, displayModeBar: false }}
    />
  )
}
