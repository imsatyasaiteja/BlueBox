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
  getProvenanceGraph: (severity = 0.5, params = {}) =>
    apiClient.get('/provenance-graph', { params: { severity, ...params } }),
  getProvenanceGraphFiltered: (filters = {}) =>
    apiClient.get('/provenance-graph', { params: filters }),
  exportProvenanceGraphPng: (filters = {}) =>
    apiClient.get('/provenance-graph/export/png', {
      params: filters,
      responseType: 'blob',
    }),
  exportProvenanceGraphSummary: (filters = {}) =>
    apiClient.get('/provenance-graph/export/summary', { params: filters }),
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

  // BB Chat
  chat: (message, context = {}) => apiClient.post('/chat', { question: message, context }, { timeout: 120000 }),
  getBBBotDocuments: () => apiClient.get('/bb-bot/documents'),
  uploadBBBotDocument: (document) => apiClient.post('/bb-bot/upload', document),
  deleteBBBotDocument: (documentId) => apiClient.post('/bb-bot/delete', { id: documentId }),
  stageBBBotContext: (context) => apiClient.post('/bb-bot/context', context),
}

export const handleApiError = (error) => {
  if (error.code === 'ECONNABORTED') {
    return 'BB Chat timed out while waiting for Ollama. Check that Ollama is running and the selected model is loaded.'
  }
  if (error.response) {
    return error.response.data?.error || error.response.statusText
  }
  if (error.request) {
    return 'No response from server'
  }
  return error.message
}
