import React from 'react'
import { useAppStore } from '@/store/appStore'
import { AnomalyDetectionPage } from '@/pages/AnomalyDetectionPage'
import { LoggerControlPage } from '@/pages/LoggerControlPage'
import { ForensicReplayPage } from '@/pages/ForensicReplayPage'
import { Toast } from '@/components/ui/Common'

export default function App() {
  const { activeSection, toastMessage, setToastMessage } = useAppStore()

  React.useEffect(() => {
    if (toastMessage) {
      const timer = setTimeout(() => setToastMessage(null), 3000)
      return () => clearTimeout(timer)
    }
  }, [toastMessage, setToastMessage])

  return (
    <>
      {activeSection === 'anomaly' && <AnomalyDetectionPage />}
      {activeSection === 'logger' && <LoggerControlPage />}
      {activeSection === 'replay' && <ForensicReplayPage />}

      <Toast message={toastMessage} show={!!toastMessage} />
    </>
  )
}
