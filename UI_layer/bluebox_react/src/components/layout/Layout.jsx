import React from 'react'
import { BarChart3, History, RefreshCw, ShieldCheck } from 'lucide-react'
import { useAppStore } from '@/store/appStore'

// const logo = 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMzIiIGhlaWdodD0iMzIiIHZpZXdCb3g9IjAgMCAzMiAzMiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cmVjdCB3aWR0aD0iMzIiIGhlaWdodD0iMzIiIGZpbGw9IiMwNjExMUMiLz48cmVjdCB4PSIyIiB5PSIyIiB3aWR0aD0iMjgiIGhlaWdodD0iMjgiIGZpbGw9Im5vbmUiIHN0cm9rZT0iIzM5RDhGRiIgc3Ryb2tlLXdpZHRoPSIyIi8+PHBhdGggZD0iTTggOEwyNCAyNCIgc3Ryb2tlPSIjMTZGMEM1IiBzdHJva2Utd2lkdGg9IjIiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIvPjwvc3ZnPg=='
const logo = 'images/logo_crop.png'

export const Sidebar = () => {
  const { activeSection, setActiveSection } = useAppStore()

  const navItems = [
    { id: 'anomaly', label: 'Anomaly Detection', Icon: BarChart3 },
    { id: 'logger', label: 'Logger', Icon: ShieldCheck },
    { id: 'replay', label: 'Forensic Replay', Icon: History },
  ]

  return (
    <aside className="w-64 bg-bluebox-panel border-r border-cyan-900 flex flex-col gap-4 p-4 h-screen sticky top-0">
      <div className="flex items-center gap-3">
        <img src={logo} alt="BlueBox" className="w-45 h-6" />
        {/* <span className="font-bold text-lg text-bluebox-cyan">BlueBox</span> */}
      </div>

      <nav className="flex flex-col gap-2">
        {navItems.map(item => {
          const { Icon } = item
          return (
            <button
              key={item.id}
              onClick={() => setActiveSection(item.id)}
              className={`w-full px-4 py-3 rounded-lg transition-smooth text-sm font-semibold flex items-center gap-3 ${
                activeSection === item.id
                  ? 'bg-gradient-to-r from-bluebox-cyan to-bluebox-aqua text-bluebox-dark'
                  : 'text-bluebox-text hover:bg-cyan-900 hover:bg-opacity-20'
              }`}
            >
              <Icon size={18} aria-hidden="true" />
              <span>{item.label}</span>
            </button>
          )
        })}
      </nav>

      <div className="mt-auto text-xs text-bluebox-muted space-y-1">
        <p>Built by Fia, Vedant, Satya</p>
        <p>React + Plotly</p>
      </div>
    </aside>
  )
}

export const Header = ({ title, subtitle, status = null, onRefresh = null, busy = false }) => {
  return (
    <header className="bg-bluebox-panel border-b border-cyan-900 px-6 py-4 flex justify-between items-start sticky top-0 z-40">
      <div>
        <p className="text-eyebrow">Dashboard</p>
        <h1 className="text-heading-1">{title}</h1>
        {subtitle && <p className="text-bluebox-muted text-sm mt-1">{subtitle}</p>}
      </div>

      <div className="flex items-center gap-3">
        {status && <div className={`status-pill ${status.toLowerCase()}`}>{status}</div>}
        {onRefresh && (
          <button
            onClick={onRefresh}
            disabled={busy}
            className={`btn-ghost inline-flex items-center gap-2 ${busy ? 'opacity-50 cursor-wait' : ''}`}
          >
            <RefreshCw size={16} className={busy ? 'animate-spin' : ''} aria-hidden="true" />
            Refresh
          </button>
        )}
      </div>
    </header>
  )
}

export const AppLayout = ({ children }) => {
  return (
    <div className="flex h-screen bg-bluebox-dark">
      <Sidebar />
      <main className="flex-1 overflow-y-auto">
        {children}
      </main>
    </div>
  )
}
