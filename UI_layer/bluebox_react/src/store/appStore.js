import { create } from 'zustand'

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

  // Reset
  reset: () => set({
    activeSection: 'anomaly',
    status: null,
    anomaly: null,
    replay: null,
    busy: false,
    toastMessage: null,
    selectedEntry: null,
    entryDetail: null,
  }),
}))
