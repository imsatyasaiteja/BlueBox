import React, { useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { useAutoRefresh } from '@/hooks/useApi'
import { Header, AppLayout } from '@/components/layout/Layout'
import { Panel, Button, Input, LoadingSpinner, Alert, Modal, Table } from '@/components/ui/Common'
import { ForensicTimeline, EventCompositionBar } from '@/components/charts/PlotlyCharts'
import { InteractiveForensicGraph } from '@/components/charts/InteractiveForensicGraph'
import { api, handleApiError } from '@/api/client'
import { formatForDisplay, formatTime } from '@/utils/format'

export const ForensicReplayPage = () => {
  const { status, replay, busy, setToastMessage } = useAppStore()
  const refresh = useAutoRefresh(5000)

  const [chatMessage, setChatMessage] = useState('')
  const [chatLog, setChatLog] = useState([
    { role: 'bot', text: 'Ask about the attack path, which components were affected, or which sequences to inspect.' }
  ])
  const [selectedEntryDetail, setSelectedEntryDetail] = useState(null)

  if (!status) return <LoadingSpinner />

  const trusted = status.trusted_readiness?.trusted || false
  const entries = replay?.evidence_stream || replay?.timeline || []
  const hasAnomalousEvidence = entries.some(e => Number(e.predicted_anomaly || 0) === 1 || e.severity)
  const handleChatSubmit = async (e) => {
    e.preventDefault()
    if (!chatMessage.trim()) return

    setChatLog([...chatLog, { role: 'user', text: chatMessage }])
    setChatMessage('')

    try {
      const response = await api.chat(chatMessage)
      setChatLog(prev => [...prev, { role: 'bot', text: response.data.answer || response.data.response }])
    } catch (error) {
      setChatLog(prev => [...prev, { role: 'bot', text: `Error: ${handleApiError(error)}` }])
    }
  }

  const handleDownloadEvidence = async () => {
    try {
      const response = await api.report()
      const content = response.data.content || response.data.report || response.data
      const filename = response.data.filename || `bluebox-evidence-${new Date().toISOString().split('T')[0]}.txt`
      const blob = new Blob([content], { type: 'text/plain' })
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      a.click()
      window.URL.revokeObjectURL(url)
      setToastMessage('Evidence package downloaded')
    } catch (error) {
      setToastMessage(`Download failed: ${handleApiError(error)}`)
    }
  }

  const investigationSteps = [
    { title: 'Verify Chain', description: 'Validate hash chain integrity', status: status.status === 'verified' ? 'complete' : 'alert' },
    { title: 'Identify Suspicious', description: 'Locate anomalous entries', status: hasAnomalousEvidence ? 'complete' : 'pending' },
    { title: 'Inspect Raw Data', description: 'Review detailed payloads', status: 'ready' },
    { title: 'Export Report', description: 'Generate forensic package', status: 'pending' },
  ]

  return (
    <AppLayout>
      <Header
        title="Forensic Replay"
        // subtitle="Incident Reconstruction and Analysis"
        status={status.status}
        onRefresh={refresh}
        busy={busy}
      />

      <div className="p-6 space-y-6">
        {!trusted && (
          <Alert variant="critical">
            Chain verification failed. Forensic replay is restricted for evidence integrity.
          </Alert>
        )}

        {/* Main Charts */}
        <div className="grid grid-cols-1 gap-6">
          {/* Interactive Provenance Graph */}
          <Panel title="Interactive Provenance Graph" subtitle="Attack Path & Anomaly Relationships">
            <div style={{ height: '600px', display: 'flex', flexDirection: 'column' }}>
              <InteractiveForensicGraph forensicData={replay} />
            </div>
          </Panel>

          <Panel title="Forensic Timeline" subtitle="Anomalous Events Over Time">
            {trusted && entries.length > 0 ? (
              <ForensicTimeline entries={entries} />
            ) : (
              <div className="h-80 flex items-center justify-center text-bluebox-muted">
                {trusted ? 'No events recorded' : 'Evidence restricted'}
              </div>
            )}
          </Panel>

          <Panel title="Event Composition" subtitle="Event Type Distribution">
            {trusted && entries.length > 0 ? (
              <EventCompositionBar entries={entries} />
            ) : (
              <div className="h-80 flex items-center justify-center text-bluebox-muted">
                No data available
              </div>
            )}
          </Panel>
        </div>

        <div className="grid grid-cols-2 gap-6">
          {/* Investigation Steps */}
          <Panel title="Investigation Steps" subtitle="Forensic Workflow">
            <div className="space-y-3">
              {investigationSteps.map((step, idx) => (
                <div
                  key={idx}
                  className="flex gap-4 p-3 rounded-lg border-l-4"
                  style={{
                    borderColor: step.status === 'complete' ? '#49E38F' : step.status === 'alert' ? '#FF6478' : step.status === 'ready' ? '#39D8FF' : '#91AEC5',
                    backgroundColor: step.status === 'complete' ? 'rgba(73, 227, 143, 0.08)' : step.status === 'alert' ? 'rgba(255, 100, 120, 0.08)' : 'rgba(139, 203, 255, 0.08)',
                  }}
                >
                  <div className="flex-1">
                    <p className="font-semibold text-sm">{idx + 1}. {step.title}</p>
                    <p className="text-xs text-bluebox-muted">{step.description}</p>
                  </div>
                  <div className="text-xl">
                    {step.status === 'complete' && 'Done'}
                    {step.status === 'alert' && 'Review'}
                    {step.status === 'ready' && 'Ready'}
                    {step.status === 'pending' && 'Pending'}
                  </div>
                </div>
              ))}
            </div>
          </Panel>

          {/* Chat Assistant */}
          <Panel title="Evidence Assistant" subtitle="Query Evidence">
            <div className="flex flex-col gap-3 h-full">
              <div className="flex-1 overflow-y-auto space-y-2 bg-bluebox-dark p-3 rounded text-sm max-h-64">
                {chatLog.map((msg, idx) => (
                  <div key={idx} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                    <div
                      className={`px-3 py-2 rounded-lg max-w-xs ${
                        msg.role === 'user'
                          ? 'bg-bluebox-cyan text-bluebox-dark'
                          : 'bg-bluebox-panel text-bluebox-text'
                      }`}
                    >
                      {msg.text}
                    </div>
                  </div>
                ))}
              </div>

              <form onSubmit={handleChatSubmit} className="flex gap-2">
                <Input
                  value={chatMessage}
                  onChange={(e) => setChatMessage(e.target.value)}
                  placeholder="Ask about the evidence..."
                  className="flex-1 text-xs"
                />
                <Button variant="primary" type="submit" disabled={busy || !trusted}>
                  Send
                </Button>
              </form>
            </div>
          </Panel>
        </div>

        {/* Evidence Stream */}
        <Panel title="Evidence Stream" subtitle={`${entries.length} records`}>
          {trusted ? (
            <div className="overflow-auto max-h-96">
              <Table
                columns={[
                  { key: 'sequence', label: 'Seq', render: (val) => <span className="font-mono">{val}</span> },
                  { key: 'occurred_at', label: 'Time', render: (val) => <span className="font-mono text-xs">{formatTime(val)}</span> },
                  { key: 'service', label: 'Type', render: (val, row) => <span className="text-xs">{val || row.source_type || 'event'}</span> },
                  { key: 'anomaly_score', label: 'Score', render: (val) => <span className="font-mono">{parseFloat(val || 0).toFixed(3)}</span> },
                  { key: 'severity', label: 'Severity', render: (val) => <span style={{ color: val === 'critical' ? '#FF6478' : val === 'warning' ? '#FFD166' : '#16F0C5' }}>{val}</span> },
                  { key: 'target_component', label: 'Affected Component', render: (val) => <span className="text-xs">{val || '-'}</span> },
                ]}
                rows={entries.slice(0, 50)}
                onRowClick={setSelectedEntryDetail}
              />
            </div>
          ) : (
            <Alert variant="warning">Evidence restricted due to untrusted chain state</Alert>
          )}
        </Panel>

        {/* Report Actions */}
        <Panel title="Report & Export" subtitle="Generate Forensic Package">
          <Button
            variant="success"
            onClick={handleDownloadEvidence}
            disabled={!trusted || busy}
            className="w-full"
          >
            {busy ? 'Generating...' : 'Download Evidence Package'}
          </Button>
        </Panel>

        {/* Entry Detail Modal */}
        {selectedEntryDetail && (
          <Modal
            title="Entry Detail"
            isOpen={!!selectedEntryDetail}
            onClose={() => setSelectedEntryDetail(null)}
          >
            <pre className="text-xs bg-bluebox-dark p-3 rounded overflow-auto max-h-96">
              {formatForDisplay(selectedEntryDetail)}
            </pre>
          </Modal>
        )}
      </div>
    </AppLayout>
  )
}
