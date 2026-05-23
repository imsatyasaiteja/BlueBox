import { useEffect, useRef, useState } from 'react'

const toFiniteNumber = value => {
  const number = Number(value)
  return Number.isFinite(number) ? number : 0
}

export const useSteppedNumber = (
  target,
  {
    intervalMs = 35,
    initialValue = null,
    enabled = true,
  } = {},
) => {
  const normalizedTarget = Math.max(0, Math.floor(toFiniteNumber(target)))
  const [displayValue, setDisplayValue] = useState(() => {
    const startingValue = initialValue === null || initialValue === undefined
      ? normalizedTarget
      : initialValue
    return Math.max(0, Math.floor(toFiniteNumber(startingValue)))
  })

  useEffect(() => {
    if (!enabled) {
      if (displayValue !== normalizedTarget) setDisplayValue(normalizedTarget)
      return undefined
    }

    if (displayValue === normalizedTarget) return undefined

    if (normalizedTarget < displayValue) {
      setDisplayValue(normalizedTarget)
      return undefined
    }

    const timer = window.setTimeout(() => {
      setDisplayValue(value => Math.min(value + 1, normalizedTarget))
    }, intervalMs)

    return () => window.clearTimeout(timer)
  }, [displayValue, enabled, intervalMs, normalizedTarget])

  return displayValue
}

export const useTweenNumber = (
  target,
  {
    durationMs = 700,
    precision = 1,
    enabled = true,
  } = {},
) => {
  const normalizedTarget = toFiniteNumber(target)
  const [displayValue, setDisplayValue] = useState(normalizedTarget)
  const frameRef = useRef(null)
  const displayRef = useRef(normalizedTarget)

  useEffect(() => {
    displayRef.current = displayValue
  }, [displayValue])

  useEffect(() => {
    if (!enabled) {
      displayRef.current = normalizedTarget
      if (displayValue !== normalizedTarget) setDisplayValue(normalizedTarget)
      return undefined
    }

    const startValue = toFiniteNumber(displayRef.current)
    const delta = normalizedTarget - startValue

    if (Math.abs(delta) < 0.001) {
      displayRef.current = normalizedTarget
      setDisplayValue(normalizedTarget)
      return undefined
    }

    const startedAt = performance.now()

    const animate = now => {
      const progress = Math.min((now - startedAt) / durationMs, 1)
      const eased = 1 - ((1 - progress) ** 3)
      const nextValue = startValue + delta * eased
      const scale = 10 ** precision
      const rounded = Math.round(nextValue * scale) / scale
      displayRef.current = rounded
      setDisplayValue(rounded)

      if (progress < 1) {
        frameRef.current = window.requestAnimationFrame(animate)
      }
    }

    frameRef.current = window.requestAnimationFrame(animate)

    return () => {
      if (frameRef.current) window.cancelAnimationFrame(frameRef.current)
    }
  }, [durationMs, enabled, normalizedTarget, precision])

  return displayValue
}

export const useProgressiveList = (
  items = [],
  {
    intervalMs = 35,
    initialCount = 2,
    enabled = true,
  } = {},
) => {
  const total = Array.isArray(items) ? items.length : 0
  const [visibleCount, setVisibleCount] = useState(() => Math.min(Math.max(initialCount, 0), total))

  useEffect(() => {
    if (!enabled) {
      setVisibleCount(total)
      return
    }

    setVisibleCount(previous => {
      if (!total) return 0
      if (previous <= 0 || total < previous) return Math.min(Math.max(initialCount, 1), total)
      return Math.min(previous, total)
    })
  }, [enabled, initialCount, total])

  useEffect(() => {
    if (!enabled || !total || visibleCount >= total) return undefined

    const timer = window.setTimeout(() => {
      setVisibleCount(value => Math.min(value + 1, total))
    }, intervalMs)

    return () => window.clearTimeout(timer)
  }, [enabled, intervalMs, total, visibleCount])

  if (!enabled) return Array.isArray(items) ? items : []
  return Array.isArray(items) ? items.slice(0, visibleCount) : []
}
