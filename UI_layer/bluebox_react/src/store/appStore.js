import { create } from 'zustand'

const DEFAULT_BB_CHAT_LOG = [
  { role: 'bot', text: 'Ask about the attack path, which components were affected, or which sequences to inspect.' },
]

const loadSessionJson = (key, fallback) => {
  if (typeof window === 'undefined') return fallback
  try {
    const value = window.sessionStorage.getItem(key)
    return value ? JSON.parse(value) : fallback
  } catch {
    return fallback
  }
}

const saveSessionJson = (key, value) => {
  if (typeof window === 'undefined') return
  try {
    window.sessionStorage.setItem(key, JSON.stringify(value))
  } catch {
    // Session persistence is best-effort only.
  }
}

export const useAppStore = create((set) => ({
  // Navigation
  activeSection: 'anomaly',
  setActiveSection: (section) => set({ activeSection: section }),

  // Data state
  status: null,
  anomaly: null,
  replay: null,
  setStatus: (status) => set({ status }),
  setAnomaly: (anomaly) => set({ anomaly }),
  setReplay: (replay) => set({ replay }),

  // UI state
  busy: false,
  setBusy: (busy) => set({ busy }),
  
  toastMessage: null,
  setToastMessage: (message) => set({ toastMessage: message }),

  // Form state
  scenario: 'mixed_attack',
  duration: 3,
  setScenario: (scenario) => set({ scenario }),
  setDuration: (duration) => set({ duration }),

  // Modal/drawer state
  selectedEntry: null,
  setSelectedEntry: (entry) => set({ selectedEntry: entry }),

  entryDetail: null,
  setEntryDetail: (detail) => set({ entryDetail: detail }),

  // BB Chat state persists while navigating dashboards in this browser tab.
  bbChatLog: loadSessionJson('bluebox.bbChatLog', DEFAULT_BB_CHAT_LOG),
  setBBChatLog: (updater) => set((state) => {
    const nextLog = typeof updater === 'function' ? updater(state.bbChatLog) : updater
    saveSessionJson('bluebox.bbChatLog', nextLog)
    return { bbChatLog: nextLog }
  }),

  // Reset
  reset: () => {
    saveSessionJson('bluebox.bbChatLog', DEFAULT_BB_CHAT_LOG)
    set({
      activeSection: 'anomaly',
      status: null,
      anomaly: null,
      replay: null,
      busy: false,
      toastMessage: null,
      selectedEntry: null,
      entryDetail: null,
      bbChatLog: DEFAULT_BB_CHAT_LOG,
    })
  },
}))
