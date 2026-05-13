export const formatNumber = (value, digits = 3) => {
  const num = Number(value || 0)
  return Number.isFinite(num) ? num.toFixed(digits) : '0.000'
}

export const formatTime = (value) => {
  if (!value) return '-'
  try {
    const date = new Date(value)
    return date.toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  } catch {
    return String(value)
  }
}

export const formatDateTime = (value) => {
  if (!value) return '-'
  try {
    const date = new Date(value)
    return `${date.toLocaleDateString()} ${date.toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })}`
  } catch {
    return String(value)
  }
}

export const truncateHash = (hash, length = 12) => {
  if (!hash) return '-'
  return hash.length > length ? `${hash.slice(0, length)}...` : hash
}

export const getSeverityColor = (severity) => {
  switch (severity?.toLowerCase()) {
    case 'critical':
    case 'high':
      return '#FF6478'
    case 'warning':
    case 'medium':
      return '#FFD166'
    case 'low':
      return '#39D8FF'
    case 'normal':
    case 'none':
      return '#16F0C5'
    default:
      return '#39D8FF'
  }
}

export const getStatusClass = (status) => {
  switch (status?.toLowerCase()) {
    case 'verified':
      return 'verified'
    case 'failed':
      return 'failed'
    default:
      return 'neutral'
  }
}

export const getSensitiveKeyPattern = /hash|digest|signature|cipher|encrypt|algorithm|nonce|salt|secret|private|public|(^|_)(iv|key)($|_)|(^|_)sha(?:1|224|256|384|512|_?\d+)($|_)/i

export const getSensitiveValuePattern = /\b[a-f0-9]{32,}\b/i

export const redactSensitiveData = (value) => {
  if (Array.isArray(value)) {
    return value.map(redactSensitiveData)
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([key]) => !getSensitiveKeyPattern.test(key))
        .map(([key, item]) => [key, redactSensitiveData(item)])
    )
  }
  if (typeof value === 'string' && getSensitiveValuePattern.test(value)) {
    return '[redacted]'
  }
  return value
}

export const formatForDisplay = (value) => {
  return JSON.stringify(redactSensitiveData(value), null, 2)
}
