import React from 'react'
import { useAppStore } from '@/store/appStore'
import { useAutoRefresh, useRunAction } from '@/hooks/useApi'
import { Header, AppLayout } from '@/components/layout/Layout'
import { StatusOverview, AnomalyList } from '@/components/sections/StatusComponents'
import { Panel, Button, Select, Input, LoadingSpinner, Alert } from '@/components/ui/Common'
import { ForensicTimeline, SeverityDistribution, ScoreGauge } from '@/components/charts/PlotlyCharts'
import { api } from '@/api/client'

const SCENARIOS = [
  { value: 'mixed_attack', label: 'Mixed Attack' },
  { value: 'normal', label: 'Normal Traffic' },
  { value: 'lateral_movement', label: 'Lateral Movement' },
  { value: 'command_injection', label: 'Command Injection' },
  { value: 'replay_attack', label: 'Replay Attack' },
]

export const AnomalyDetectionPage = () => {
  const {
    status,
    anomaly,
    busy,
    scenario,
    duration,
    setScenario,
    setDuration,
  } = useAppStore()

  const refresh = useAutoRefresh(5000)
  const runAction = useRunAction()

  const handleRunDemo = async () => {
    await runAction('Demo generated & scored', () =>
      api.demo(scenario, duration)
    )
  }

  const handleDownloadReport = async () => {
    try {
      const response = await api.report()
      const content = response.data.content || response.data.report || response.data
      const filename = response.data.filename || `bluebox-report-${new Date().toISOString().split('T')[0]}.txt`
      const blob = new Blob([content], { type: 'text/plain' })
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      a.click()
      window.URL.revokeObjectURL(url)
    } catch (error) {
      console.error('Report download failed:', error)
    }
  }

  if (!status) return <LoadingSpinner />

  const trusted = status.trusted_readiness?.trusted || false
  const aiRecords = anomaly?.records || []
  const scoreTrace = anomaly?.score_trace || aiRecords
  const anomalyScore = anomaly?.min_score ?? 0

  return (
    <AppLayout>
      <Header
        title="Anomaly Detection"
        // subtitle={trusted ? `${status.total_entries} entries | ${anomaly?.total_ai_records || 0} AI records` : 'AI Analysis'}
        status={status.status}
        onRefresh={refresh}
        busy={busy}
      />

      <div className="p-6 space-y-6">
        <StatusOverview status={status} anomaly={anomaly} />

        {!trusted && (
          <Alert variant="critical">
            Trusted readiness gate is not satisfied. Evidence display is restricted for integrity protection.
          </Alert>
        )}

        <div className="grid grid-cols-3 gap-6">
          <div className="col-span-2">
            <Panel title="Forensic Timeline" subtitle="Anomaly Score Trace">
              {trusted && scoreTrace.length > 0 ? (
                <ForensicTimeline entries={scoreTrace} />
              ) : (
                <div className="h-80 flex items-center justify-center text-bluebox-muted">
                  No data available
                </div>
              )}
            </Panel>
          </div>

          <div>
            <Panel title="Risk Assessment" subtitle="Current Score">
              {trusted ? (
                <ScoreGauge score={anomalyScore} />
              ) : (
                <div className="h-80 flex items-center justify-center text-bluebox-muted">
                  Locked
                </div>
              )}
            </Panel>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-6">
          <Panel title="Severity Mix" subtitle="Verdict Distribution">
            {trusted && anomaly ? (
              <SeverityDistribution anomalies={anomaly.records || []} />
            ) : (
              <div className="h-80 flex items-center justify-center text-bluebox-muted">
                No data
              </div>
            )}
          </Panel>

          <Panel title="Pipeline Controls" subtitle="Generate, Score, Ingest">
            <div className="space-y-4">
              <Select
                label="Scenario"
                value={scenario}
                onChange={(e) => setScenario(e.target.value)}
                options={SCENARIOS}
              />
              <Input
                label="Duration (seconds)"
                type="number"
                min="1"
                max="30"
                value={duration}
                onChange={(e) => setDuration(parseInt(e.target.value))}
              />
              <Button
                variant="primary"
                onClick={handleRunDemo}
                disabled={busy}
                className="w-full"
              >
                {busy ? 'Running...' : 'Generate + Score + Ingest'}
              </Button>
              <Button
                variant="ghost"
                onClick={handleDownloadReport}
                disabled={busy}
                className="w-full"
              >
                Download Report
              </Button>
            </div>
          </Panel>
        </div>

        <AnomalyList
          anomalies={anomaly?.ranked_anomalies || []}
          securityEvents={anomaly?.security_events || []}
          gateMessage={trusted ? '' : 'Evidence hidden due to untrusted chain state'}
        />
      </div>
    </AppLayout>
  )
}
