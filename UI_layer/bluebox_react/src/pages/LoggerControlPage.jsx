import React, { useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { useAutoRefresh, useRunAction } from '@/hooks/useApi'
import { Header, AppLayout } from '@/components/layout/Layout'
import { ChainStatusPanel, TrustedReadinessChecks, StatusOverview } from '@/components/sections/StatusComponents'
import { Panel, Button, Input, Select, LoadingSpinner, Alert, Textarea } from '@/components/ui/Common'
import { api } from '@/api/client'

export const LoggerControlPage = () => {
  const { status, anomaly, busy } = useAppStore()
  const refresh = useAutoRefresh(5000)
  const runAction = useRunAction()

  const [appendJson, setAppendJson] = useState('')
  const [ingestPath, setIngestPath] = useState('')
  const [tamperSeq, setTamperSeq] = useState('')
  const [tamperOp, setTamperOp] = useState('delete')
  const [operationResult, setOperationResult] = useState(null)

  if (!status) return <LoadingSpinner />

  const handleVerifyChain = async () => {
    await runAction('Chain verified', () => api.verify())
  }

  const handleAnchorHead = async () => {
    await runAction('Head anchored', () => api.anchor())
  }

  const handleAppendJson = async () => {
    if (!appendJson.trim()) {
      alert('Please enter JSON data')
      return
    }
    try {
      const payload = JSON.parse(appendJson)
      await runAction('JSON appended', () => api.append(payload))
      setAppendJson('')
      setOperationResult('Entry appended successfully')
    } catch (error) {
      alert(`Invalid JSON: ${error.message}`)
    }
  }

  const handleIngestPath = async () => {
    if (!ingestPath.trim()) {
      alert('Please enter a path')
      return
    }
    await runAction('Path ingested', () => api.ingest(ingestPath))
    setIngestPath('')
  }

  const handleVerifyLedger = async () => {
    await runAction('Recovery ledger verified', () => api.verifyLedger())
  }

  const handleInitLedger = async () => {
    await runAction('Recovery ledger initialized', () => api.initLedger())
  }

  const handleRestoreLedger = async () => {
    await runAction('SQLite restored from ledger', () => api.restoreLedger())
  }

  const handleTamperAttempt = async () => {
    if (!tamperSeq) {
      alert('Please enter sequence number')
      return
    }
    await runAction(`Tamper simulation (${tamperOp})`, () =>
      api.tamper(parseInt(tamperSeq), tamperOp)
    )
    setTamperSeq('')
  }

  return (
    <AppLayout>
      <Header
        title="Logger"
        // subtitle="Protected Evidence Storage"
        status={status.status}
        onRefresh={refresh}
        busy={busy}
      />

      <div className="p-6 space-y-6">
        <StatusOverview status={status} anomaly={anomaly} />

        <div className="grid grid-cols-2 gap-6">
          {/* Chain Status */}
          <ChainStatusPanel status={status} />

          {/* Trust Checks */}
          <TrustedReadinessChecks status={status} />
        </div>

        <div className="grid grid-cols-2 gap-6">
          {/* Manual Append */}
          <Panel title="Manual Entry" subtitle="Append JSON">
            <div className="space-y-3">
              <Textarea
                label="JSON Payload"
                value={appendJson}
                onChange={(e) => setAppendJson(e.target.value)}
                placeholder='{"event_type": "security_event", "details": "..."}'
                rows={5}
                className="font-mono text-xs"
              />
              <Button
                variant="primary"
                onClick={handleAppendJson}
                disabled={busy}
                className="w-full"
              >
                {busy ? 'Appending...' : 'Append Entry'}
              </Button>
            </div>
          </Panel>

          {/* Ingest Path */}
          <Panel title="Bulk Ingest" subtitle="Load from Path">
            <div className="space-y-3">
              <Input
                label="Path"
                value={ingestPath}
                onChange={(e) => setIngestPath(e.target.value)}
                placeholder="/data/traffic.csv"
              />
              <Button
                variant="primary"
                onClick={handleIngestPath}
                disabled={busy}
                className="w-full"
              >
                {busy ? 'Ingesting...' : 'Ingest Path'}
              </Button>
            </div>
          </Panel>
        </div>

        <div className="grid grid-cols-2 gap-6">
          {/* Recovery Ledger Controls */}
          <Panel title="Recovery Ledger" subtitle="Ledger Management">
            <div className="space-y-2">
              <Button
                variant="ghost"
                onClick={handleVerifyLedger}
                disabled={busy}
                className="w-full text-left"
              >
                Verify Ledger
              </Button>
              <Button
                variant="ghost"
                onClick={handleInitLedger}
                disabled={busy}
                className="w-full text-left"
              >
                Initialize Ledger
              </Button>
              <Button
                variant="danger"
                onClick={handleRestoreLedger}
                disabled={busy}
                className="w-full text-left"
              >
                Restore from Ledger
              </Button>
            </div>
          </Panel>

          {/* Chain Verification */}
          <Panel title="Chain Integrity" subtitle="Verification Controls">
            <div className="space-y-2">
              <Button
                variant="success"
                onClick={handleVerifyChain}
                disabled={busy}
                className="w-full"
              >
                {busy ? 'Verifying...' : 'Verify Chain'}
              </Button>
              <Button
                variant="warning"
                onClick={handleAnchorHead}
                disabled={busy}
                className="w-full"
              >
                {busy ? 'Anchoring...' : 'Anchor Head'}
              </Button>
            </div>
          </Panel>
        </div>

        {/* Tamper Lab */}
        <Panel title="Tamper Lab" subtitle="Security Testing">
          <div className="space-y-3">
            <Alert variant="warning" className="text-xs">
              Test tamper protection by attempting to delete or modify log entries
            </Alert>
            <div className="grid grid-cols-3 gap-3">
              <Input
                label="Sequence #"
                type="number"
                value={tamperSeq}
                onChange={(e) => setTamperSeq(e.target.value)}
                placeholder="1"
              />
              <Select
                label="Operation"
                value={tamperOp}
                onChange={(e) => setTamperOp(e.target.value)}
                options={[
                  { value: 'delete', label: 'Delete' },
                  { value: 'update', label: 'Update' },
                ]}
              />
              <div className="flex items-end">
                <Button
                  variant="danger"
                  onClick={handleTamperAttempt}
                  disabled={busy}
                  className="w-full"
                >
                  Tamper
                </Button>
              </div>
            </div>
          </div>
        </Panel>

        {operationResult && (
          <Alert variant="info" className="text-sm">
            {operationResult}
          </Alert>
        )}
      </div>
    </AppLayout>
  )
}
