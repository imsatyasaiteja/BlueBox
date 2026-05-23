export const DASHBOARD_TIME_ZONES = [
  { label: 'SGT', timeZone: 'Asia/Singapore', name: 'Singapore' },
  { label: 'IST', timeZone: 'Asia/Kolkata', name: 'India' },
  { label: 'CET', timeZone: 'Europe/Paris', name: 'Central Europe' },
  { label: 'UTC', timeZone: 'UTC', name: 'Coordinated Universal Time' },
  { label: 'GMT', timeZone: 'Europe/London', name: 'Greenwich / London' },
  { label: 'EST', timeZone: 'America/New_York', name: 'Eastern US' },
  { label: 'PST', timeZone: 'America/Los_Angeles', name: 'Pacific US' },
]

export const DEFAULT_DASHBOARD_TIME_ZONE = DASHBOARD_TIME_ZONES[0]

export const getTimeZoneOption = (timeZone) => {
  return DASHBOARD_TIME_ZONES.find(option => option.timeZone === timeZone) || DEFAULT_DASHBOARD_TIME_ZONE
}

export const formatTimeInZone = (value, timeZone, includeMilliseconds = false) => {
  const date = value instanceof Date ? value : new Date(value)
  const base = new Intl.DateTimeFormat([], {
    timeZone,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(date)

  return includeMilliseconds ? `${base}.${String(date.getMilliseconds()).padStart(3, '0')}` : base
}
