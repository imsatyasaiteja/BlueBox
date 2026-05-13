import Plot from 'react-plotly.js'
import { useMemo } from 'react'
import { formatTime, getSeverityColor } from '@/utils/format'

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

export const ForensicTimeline = ({ entries = [] }) => {
  const data = useMemo(() => {
    if (!entries.length) return [{ x: [], y: [], type: 'scatter', name: 'No data' }]

    const sorted = [...entries].sort((a, b) =>
      new Date(a.recorded_at || a.created_at || a.occurred_at || 0) - new Date(b.recorded_at || b.created_at || b.occurred_at || 0)
    )

    return [{
      x: sorted.map(e => e.recorded_at || e.created_at || e.occurred_at),
      y: sorted.map(e => normalizeRiskScore(e.anomaly_score, e.severity) * 100),
      customdata: sorted.map(e => [
        e.sequence || '-',
        Number(e.anomaly_score || 0).toFixed(4),
        e.severity || 'NONE',
        e.predicted_anomaly ? 'Flagged' : 'Normal',
      ]),
      type: 'scatter',
      mode: 'markers+lines',
      name: 'Risk',
      marker: {
        size: sorted.map(e => Number(e.predicted_anomaly || 0) === 1 ? 9 : 5),
        color: sorted.map(e => getSeverityColor(e.severity)),
        line: { width: 2, color: '#06111C' },
        opacity: 0.9,
      },
      line: { color: 'rgba(57, 216, 255, 0.45)', width: 2, shape: 'spline' },
      fill: 'tozeroy',
      fillcolor: 'rgba(57, 216, 255, 0.08)',
      hovertemplate:
        '<b>%{x|%H:%M:%S}</b><br>Seq: %{customdata[0]}<br>Risk: %{y:.1f}%<br>Raw score: %{customdata[1]}<br>Severity: %{customdata[2]}<br>%{customdata[3]}<extra></extra>',
    }]
  }, [entries])

  return (
    <Plot
      data={data}
      layout={{
        ...plotlyLayout,
        xaxis: { ...plotlyLayout.xaxis, title: 'Event Time', type: 'date', tickformat: '%H:%M:%S' },
        yaxis: { ...plotlyLayout.yaxis, title: 'Risk Level (%)', range: [0, 100] },
        shapes: [
          { type: 'line', xref: 'paper', x0: 0, x1: 1, y0: 40, y1: 40, line: { color: 'rgba(255,209,102,0.45)', width: 1, dash: 'dot' } },
          { type: 'line', xref: 'paper', x0: 0, x1: 1, y0: 70, y1: 70, line: { color: 'rgba(255,100,120,0.45)', width: 1, dash: 'dot' } },
        ],
        height: 400,
      }}
      style={{ width: '100%', height: '400px' }}
      config={{ responsive: true, displayModeBar: false }}
    />
  )
}

export const SeverityDistribution = ({ anomalies = [] }) => {
  const data = useMemo(() => {
    const counts = {
      High: 0,
      Medium: 0,
      Low: 0,
      Normal: 0,
      Unknown: 0,
    }

    anomalies.forEach(a => {
      const severity = String(a.severity || '').toUpperCase()
      const flagged = Number(a.predicted_anomaly || 0) === 1
      if (!flagged || severity === 'NONE' || severity === 'NORMAL') counts.Normal++
      else if (severity === 'CRITICAL' || severity === 'HIGH') counts.High++
      else if (severity === 'WARNING' || severity === 'MEDIUM') counts.Medium++
      else if (severity === 'LOW') counts.Low++
      else counts.Unknown++
    })

    const labels = Object.keys(counts).filter(label => counts[label] > 0)
    const values = labels.map(label => counts[label])

    return [{
      labels,
      values,
      type: 'pie',
      hole: 0.58,
      sort: false,
      marker: {
        color: labels.map(label => ({
          High: '#FF6478',
          Medium: '#FFD166',
          Low: '#39D8FF',
          Normal: '#16F0C5',
          Unknown: '#91AEC5',
        }[label] || '#91AEC5'),
        ),
        line: { color: '#39D8FF', width: 2 },
      },
      textinfo: 'label+percent',
      textposition: 'inside',
      hovertemplate: '<b>%{label}</b><br>Events: %{value}<extra></extra>',
    }]
  }, [anomalies])

  return (
    <Plot
      data={data}
      layout={{
        ...plotlyLayout,
        height: 350,
        margin: { l: 24, r: 96, t: 20, b: 26 },
        showlegend: true,
        legend: { x: 1.02, y: 0.5, xanchor: 'left', yanchor: 'middle', font: { size: 12 } },
      }}
      style={{ width: '100%', height: '350px' }}
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
