import axios from 'axios'

const API_BASE = '/api'

const apiClient = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
})

export const api = {
  // Status & data endpoints
  getStatus: () => apiClient.get('/status'),
  getAnomaly: () => apiClient.get('/anomaly'),
  getReplay: () => apiClient.get('/replay'),
  getProvenanceGraph: (severity = 0.5) => apiClient.get('/provenance-graph', { params: { severity } }),
  getEntries: (limit = 50, offset = 0) => apiClient.get('/entries', { params: { limit, offset } }),
  getEntry: (sequence) => apiClient.get(`/entry/${sequence}`),

  // Control operations
  verify: () => apiClient.post('/verify', {}),
  anchor: () => apiClient.post('/anchor', {}),
  verifyLedger: () => apiClient.post('/verify-ledger', {}),
  initLedger: () => apiClient.post('/init-ledger', {}),
  restoreLedger: () => apiClient.post('/restore-ledger', {}),

  // Data operations
  append: (payload) => apiClient.post('/append', payload),
  ingest: (path) => apiClient.post('/ingest', { path }),
  demo: (scenario, duration) => apiClient.post('/demo', { scenario, duration }),
  tamper: (sequence, operation) => apiClient.post('/tamper-attempt', { sequence, operation }),

  // Report & ledger
  report: () => apiClient.get('/report'),
  ledger: () => apiClient.get('/ledger'),

  // Chat (basic)
  chat: (message) => apiClient.post('/chat', { question: message }),
}

export const handleApiError = (error) => {
  if (error.response) {
    return error.response.data?.error || error.response.statusText
  }
  if (error.request) {
    return 'No response from server'
  }
  return error.message
}
