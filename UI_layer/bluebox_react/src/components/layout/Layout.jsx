import React, { useState } from 'react'
import { BarChart3, Clock3, History, RefreshCw, ShieldCheck } from 'lucide-react'
import { useAppStore } from '@/store/appStore'
import { useLiveClock } from '@/hooks/useLiveClock'
import {
  DASHBOARD_TIME_ZONES,
  DEFAULT_DASHBOARD_TIME_ZONE,
  formatTimeInZone,
  getTimeZoneOption,
} from '@/utils/timeZones'
import blueboxWordmark from '../../../images/bb_white_nobg.png'
import blueboxLogo from '../../../images/logo_white_nobg.png'
import routePlane from '../../../images/plane_nobg.png'

const DEFAULT_FLIGHT_ROUTE = { origin: 'SIN', destination: 'LHR' }

const normalizeFlightRoute = (flightRoute) => {
  if (!flightRoute) return null
  if (typeof flightRoute === 'string') {
    const parts = flightRoute.split(/\s*(?:=>|->|to)\s*/i).filter(Boolean)
    return {
      origin: parts[0] || flightRoute,
      destination: parts[1] || '',
    }
  }
  return {
    origin: flightRoute.origin || flightRoute.from || 'SIN',
    destination: flightRoute.destination || flightRoute.to || 'BRS',
  }
}

export const Sidebar = () => {
  const { activeSection, setActiveSection } = useAppStore()

  const navItems = [
    { id: 'anomaly', label: 'Anomaly Detection', Icon: BarChart3 },
    { id: 'logger', label: 'Logger', Icon: ShieldCheck },
    { id: 'replay', label: 'Forensic Replay', Icon: History },
  ]

  return (
    <aside className="sidebar-shell w-64 bg-bluebox-panel border-r border-cyan-900 flex flex-col h-screen sticky top-0">
      <div className="sidebar-brand">
        <img src={blueboxLogo} alt="BlueBox logo" className="bluebox-brand-logo" />
        <img src={blueboxWordmark} alt="BlueBox" className="bluebox-brand-wordmark" />
      </div>

      <nav className="sidebar-nav flex flex-col gap-2">
        {navItems.map(item => {
          const { Icon } = item
          return (
            <button
              key={item.id}
              onClick={() => setActiveSection(item.id)}
              className={`sidebar-nav-button w-full rounded-lg transition-smooth font-semibold flex items-center ${
                activeSection === item.id
                  ? 'bg-gradient-to-r from-bluebox-cyan to-bluebox-aqua text-bluebox-dark'
                  : 'text-bluebox-text hover:bg-cyan-900 hover:bg-opacity-20'
              }`}
            >
              <Icon size={16} aria-hidden="true" />
              <span>{item.label}</span>
            </button>
          )
        })}
      </nav>

      <div className="mt-auto text-xs text-bluebox-muted space-y-1">
        <p>Built by Satya, Vedant, Fia</p>
        <p>React + Plotly</p>
      </div>
    </aside>
  )
}

export const Header = ({
  title,
  subtitle,
  status = null,
  onRefresh = null,
  busy = false,
  currentTime = null,
  selectedTimeZone = null,
  onTimeZoneChange = null,
  flightRoute = DEFAULT_FLIGHT_ROUTE,
}) => {
  const fallbackTime = useLiveClock()
  const [internalTimeZone, setInternalTimeZone] = useState(DEFAULT_DASHBOARD_TIME_ZONE.timeZone)
  const clockTime = currentTime || fallbackTime
  const activeTimeZone = getTimeZoneOption(selectedTimeZone || internalTimeZone)
  const route = normalizeFlightRoute(flightRoute)
  const handleTimeZoneChange = (event) => {
    const nextTimeZone = event.target.value
    if (onTimeZoneChange) onTimeZoneChange(nextTimeZone)
    else setInternalTimeZone(nextTimeZone)
  }

  return (
    <header className="bg-bluebox-panel border-b border-cyan-900 px-6 py-4 flex justify-between items-start sticky top-0 z-40">
      <div>
        <p className="text-eyebrow">Dashboard</p>
        <h1 className="text-heading-1">{title}</h1>
        {subtitle && <p className="text-bluebox-muted text-sm mt-1">{subtitle}</p>}
      </div>

      <div className="header-actions">
        {route && (
          <div className="flight-route-chip" aria-label={`Flight route ${route.origin} to ${route.destination}`}>
            <span>{route.origin}</span>
            <img src={routePlane} alt="" aria-hidden="true" className="flight-route-plane" />
            <span>{route.destination}</span>
          </div>
        )}
        {onRefresh && (
          <button
            onClick={onRefresh}
            disabled={busy}
            className={`btn-ghost header-refresh-button inline-flex items-center gap-2 ${busy ? 'opacity-50 cursor-wait' : ''}`}
          >
            <RefreshCw size={16} className={busy ? 'animate-spin' : ''} aria-hidden="true" />
            Refresh
          </button>
        )}
        <div className="dashboard-clock" aria-label="Live dashboard time">
          <Clock3 size={16} aria-hidden="true" />
          <div className="dashboard-clock-readout">
            <span className="font-mono tabular-nums">{formatTimeInZone(clockTime, activeTimeZone.timeZone)}</span>
          </div>
          <select
            className="dashboard-timezone-select"
            value={activeTimeZone.timeZone}
            onChange={handleTimeZoneChange}
            aria-label="Dashboard time zone"
          >
            {DASHBOARD_TIME_ZONES.map(option => (
              <option key={option.timeZone} value={option.timeZone}>
                {option.label}
              </option>
            ))}
          </select>
        </div>
      </div>
    </header>
  )
}

export const AppLayout = ({ children }) => {
  return (
    <div className="flex h-screen bg-bluebox-dark">
      <Sidebar />
      <main className="flex-1 min-w-0 overflow-y-auto">
        {children}
      </main>
    </div>
  )
}
