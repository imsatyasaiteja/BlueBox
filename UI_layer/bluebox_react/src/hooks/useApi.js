import { useCallback, useEffect } from 'react'
import { api, handleApiError } from '@/api/client'
import { useAppStore } from '@/store/appStore'

export const useRefresh = () => {
  const { activeSection, setStatus, setAnomaly, setReplay, setBusy, setToastMessage } = useAppStore()

  const refresh = useCallback(async () => {
    try {
      setBusy(true)

      // Always fetch status
      const statusRes = await api.getStatus()
      setStatus(statusRes.data)

      const trusted = statusRes.data?.trusted_readiness?.trusted || false

      // Fetch section-specific data
      if ((activeSection === 'anomaly' || activeSection === 'logger') && trusted) {
        const anomalyRes = await api.getAnomaly()
        setAnomaly(anomalyRes.data)
      }

      if (activeSection === 'replay' && trusted) {
        const replayRes = await api.getReplay()
        setReplay(replayRes.data)
      }
    } catch (error) {
      setToastMessage(`Error refreshing: ${handleApiError(error)}`)
    } finally {
      setBusy(false)
    }
  }, [activeSection, setStatus, setAnomaly, setReplay, setBusy, setToastMessage])

  return refresh
}

export const useAutoRefresh = (interval = 5000) => {
  const refresh = useRefresh()

  useEffect(() => {
    // Initial refresh
    refresh()

    // Setup auto-refresh
    const timer = setInterval(refresh, interval)

    return () => clearInterval(timer)
  }, [refresh, interval])

  return refresh
}

export const useRunAction = () => {
  const { setBusy, setToastMessage } = useAppStore()
  const refresh = useRefresh()

  const runAction = useCallback(async (label, fn) => {
    try {
      setBusy(true)
      await fn()
      setToastMessage(label)
      await refresh()
    } catch (error) {
      setToastMessage(`Failed: ${handleApiError(error)}`)
    } finally {
      setBusy(false)
    }
  }, [setBusy, setToastMessage, refresh])

  return runAction
}
