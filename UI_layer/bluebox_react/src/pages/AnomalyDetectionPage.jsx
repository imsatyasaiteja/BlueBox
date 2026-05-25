import React, { useMemo, useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { useAutoRefresh } from '@/hooks/useApi'
import { Header, AppLayout } from '@/components/layout/Layout'
import { StatusOverview, AnomalyList } from '@/components/sections/StatusComponents'
import { Panel, LoadingSpinner, Alert } from '@/components/ui/Common'
import {
  AIAnomalyAssessment,
  AnomalyVolumeBreakdown,
  AttackFamilyBreakdown,
  ForensicTimeline,
  SeverityDistribution,
  TopAnomalySources,
  TopShapReasonThemes,
} from '@/components/charts/PlotlyCharts'
import { useLiveClock } from '@/hooks/useLiveClock'
import { DEFAULT_DASHBOARD_TIME_ZONE } from '@/utils/timeZones'

export const AnomalyDetectionPage = () => {
  const {
    status,
    anomaly,
    busy,
  } = useAppStore()

  const refresh = useAutoRefresh(1000)
  const liveNow = useLiveClock()
  const [selectedTimeZone, setSelectedTimeZone] = useState(DEFAULT_DASHBOARD_TIME_ZONE.timeZone)
  const aiRecords = anomaly?.records || []
  const scoreTrace = anomaly?.score_trace || aiRecords
  const chartNow = useMemo(() => {
    const minute = Math.floor(liveNow.getTime() / 60000) * 60000
    return new Date(minute)
  }, [liveNow])

  if (!status) return <LoadingSpinner />

  const trusted = status.trusted_readiness?.trusted || false
  return (
    <AppLayout>
      <Header
        title="Anomaly Detection"
        // status={status.status}
        onRefresh={refresh}
        busy={busy}
        currentTime={liveNow}
        selectedTimeZone={selectedTimeZone}
        onTimeZoneChange={setSelectedTimeZone}
        flightRoute={{ origin: 'SIN', destination: 'LHR' }}
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
            <Panel title="Forensic Timeline" subtitle="Anomaly Score Trace" className="h-full">
              {trusted && scoreTrace.length > 0 ? (
                <ForensicTimeline
                  entries={scoreTrace}
                  currentTime={chartNow}
                  selectedTimeZone={selectedTimeZone}
                />
              ) : (
                <div className="h-80 flex items-center justify-center text-bluebox-muted">
                  No data available
                </div>
              )}
            </Panel>
          </div>

          <div>
            <Panel title="Risk Assessment" subtitle="Alert Rate" className="h-full">
              {trusted ? (
                <AIAnomalyAssessment anomaly={anomaly} entries={scoreTrace} />
              ) : (
                <div className="h-full min-h-[500px] flex items-center justify-center text-bluebox-muted">
                  Locked
                </div>
              )}
            </Panel>
          </div>
        </div>

        <div className="grid gap-6" style={{ gridTemplateColumns: '0.88fr 0.96fr 1.18fr' }}>
          <div>
            <Panel title="Verdict Distribution" subtitle="Severity Verdict Mix">
              {trusted && anomaly ? (
                <SeverityDistribution anomalies={scoreTrace} summary={anomaly} />
              ) : (
                <div className="h-80 flex items-center justify-center text-bluebox-muted">
                  No data
                </div>
              )}
            </Panel>
          </div>

          <Panel title="Anomaly Sources" subtitle="Top Anomaly Sources">
            {trusted && scoreTrace.length > 0 ? (
              <TopAnomalySources entries={scoreTrace} />
            ) : (
              <div className="h-80 flex items-center justify-center text-bluebox-muted">
                No data
              </div>
            )}
          </Panel>

          <Panel title="SHAP Themes" subtitle="Top SHAP Reasons">
            {trusted && scoreTrace.length > 0 ? (
              <TopShapReasonThemes entries={scoreTrace} />
            ) : (
              <div className="h-80 flex items-center justify-center text-bluebox-muted">
                No SHAP data
              </div>
            )}
          </Panel>
        </div>

        <div className="grid grid-cols-3 gap-6">
          <Panel title="Volume Breakdown" subtitle="Protocols, Labels, and Assets">
            {trusted && scoreTrace.length > 0 ? (
              <AnomalyVolumeBreakdown entries={scoreTrace} />
            ) : (
              <div className="h-80 flex items-center justify-center text-bluebox-muted">
                No data
              </div>
            )}
          </Panel>

          <div className="col-span-2">
            <Panel title="Attack Families" subtitle="Attack Patterns Breakdown">
              {trusted && scoreTrace.length > 0 ? (
                <AttackFamilyBreakdown entries={scoreTrace} />
              ) : (
                <div className="h-80 flex items-center justify-center text-bluebox-muted">
                  No data
                </div>
              )}
            </Panel>
          </div>
        </div>

        <AnomalyList
          anomalies={scoreTrace.length ? scoreTrace : anomaly?.ranked_anomalies || []}
          securityEvents={anomaly?.security_events || []}
          gateMessage={trusted ? '' : 'Evidence hidden due to untrusted chain state'}
        />
      </div>
    </AppLayout>
  )
}
