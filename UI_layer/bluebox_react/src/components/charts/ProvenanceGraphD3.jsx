import React, { forwardRef, useCallback, useEffect, useImperativeHandle, useMemo, useRef, useState } from 'react'
import * as d3 from 'd3'
import { Lock, Maximize2, Move, RotateCcw, Unlock, X, ZoomIn, ZoomOut } from 'lucide-react'
import { api } from '@/api/client'
import { Alert, Spinner } from '@/components/ui/Common'
import './ProvenanceGraphD3.css'

const DOMAIN_CONFIG = {
  avionics: { label: 'Avionics', color: '#7dd3fc' },
  afdx: { label: 'AFDX', color: '#38bdf8' },
  cabin: { label: 'Cabin', color: '#f0abfc' },
  maintenance: { label: 'Maintenance', color: '#fbbf24' },
  integrity: { label: 'Integrity', color: '#fb7185' },
  unknown: { label: 'Unknown', color: '#94a3b8' },
}

const SEVERITY_LEVELS = {
  HIGH: { label: 'High', color: '#f97316' },
  MEDIUM: { label: 'Medium', color: '#fbbf24' },
  LOW: { label: 'Low', color: '#93c5fd' },
  NORMAL: { label: 'Normal', color: '#94a3b8' },
}

const EVENT_TYPES = {
  anomaly: 'AI Anomaly',
  chain_integrity: 'Chain Integrity',
}

const TIME_WINDOWS = [
  { value: 'all', label: 'All Time', ms: null },
  { value: '300000', label: 'Last 5 Min', ms: 300000 },
  { value: '1800000', label: 'Last 30 Min', ms: 1800000 },
  { value: '3600000', label: 'Last 1 Hour', ms: 3600000 },
  { value: '86400000', label: 'Last 24 Hours', ms: 86400000 },
]

const LIMIT_OPTIONS = [10, 15, 20, 30]

const KIND_LABELS = {
  domain: 'Domain',
  source: 'Source',
  event: 'Evidence',
  target: 'Target',
  pattern: 'Pattern',
}

const normalizePayload = (payload = {}) => {
  const rawNodes = Array.isArray(payload.nodes)
    ? payload.nodes
    : Object.values(payload.nodes || {})
  const rawLinks = Array.isArray(payload.links)
    ? payload.links
    : Array.isArray(payload.edges)
      ? payload.edges
      : []

  return {
    ...payload,
    nodes: rawNodes.filter(node => node && node.id),
    links: rawLinks.filter(link => link && link.source && link.target),
    positions: payload.positions || {},
    attack_paths: payload.attack_paths || [],
    components: payload.components || [],
    statistics: payload.statistics || {},
  }
}

const formatPercent = value => {
  const number = Number(value || 0) * 100
  return Number.isFinite(number) ? `${number.toFixed(1)}%` : '0.0%'
}

const formatNumber = value => {
  const number = Number(value || 0)
  return Number.isInteger(number) ? String(number) : number.toFixed(2)
}

const formatRawScore = value => {
  const number = Number(value)
  return Number.isFinite(number) ? number.toFixed(4) : '-'
}

const formatTimestamp = value => {
  if (!value) return '-'
  const parsed = new Date(value)
  return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString()
}

const formatTraceTime = value => {
  if (!value) return '-'
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return String(value)
  const time = parsed.toLocaleTimeString([], {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
  return `${time}.${String(parsed.getMilliseconds()).padStart(3, '0')}`
}

const displayDomain = domain => DOMAIN_CONFIG[domain]?.label || domain || 'Unknown'

const displayEventType = eventType => EVENT_TYPES[eventType] || String(eventType || 'Unknown')

const nodeColor = node => {
  if (node.event_type === 'mutation_attempt' && node.kind === 'event') return '#f43f5e'
  if (node.event_type === 'chain_integrity' && node.kind === 'event') return '#fb7185'
  return node.domain_color || node.color || DOMAIN_CONFIG[node.domain]?.color || DOMAIN_CONFIG.unknown.color
}

const eventTypeColor = type => {
  if (type === 'mutation_attempt') return '#f43f5e'
  if (type === 'chain_integrity') return '#fb7185'
  return '#38bdf8'
}

const nodeRadius = node => {
  const risk = Number(node.risk || 0)
  const centrality = Number(node.centrality || 0)
  if (node.kind === 'event') return 12 + risk * 9 + centrality * 10
  if (node.kind === 'domain') return 11
  if (node.kind === 'pattern') return 10
  return 9 + Math.min(Number(node.event_count || 1), 4)
}

const truncate = (value, limit = 28) => {
  const text = String(value || '')
  return text.length <= limit ? text : `${text.slice(0, limit - 1)}.`
}

const titleCase = value => String(value || '')
  .replaceAll('_', ' ')
  .replace(/\s+/g, ' ')
  .trim()
  .replace(/\b\w/g, letter => letter.toUpperCase())

const seededUnit = value => {
  let hash = 2166136261
  const text = String(value)
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index)
    hash = Math.imul(hash, 16777619)
  }
  return (hash >>> 0) / 4294967295
}

const clamp = (value, min, max) => Math.max(min, Math.min(max, value))

const createSoftAnchorForce = (strength = 0.034) => {
  let forceNodes = []
  const force = alpha => {
    forceNodes.forEach(node => {
      if (!Number.isFinite(node.anchorX) || !Number.isFinite(node.anchorY)) return
      node.vx += (node.anchorX - node.x) * strength * alpha
      node.vy += (node.anchorY - node.y) * strength * alpha
    })
  }
  force.initialize = nodes => {
    forceNodes = nodes
  }
  return force
}

const createAmbientDriftForce = () => {
  let forceNodes = []
  let tick = 0
  const force = alpha => {
    tick += 1
    forceNodes.forEach(node => {
      if (node.fx != null || node.fy != null) return
      const phase = seededUnit(`${node.id}:phase`) * Math.PI * 2
      const speed = 0.012 + seededUnit(`${node.id}:speed`) * 0.012
      const strength = node.kind === 'event' ? 0.2 : 0.15
      node.vx += Math.sin(tick * speed + phase) * strength * alpha
      node.vy += Math.cos(tick * speed * 0.82 + phase) * strength * alpha
    })
  }
  force.initialize = nodes => {
    forceNodes = nodes
  }
  return force
}

const selectedNodeRows = node => {
  if (!node) return []
  if (node.kind === 'event') {
    return [
      formatTraceTime(node.timestamp || node.occurred_at),
      `Seq: ${node.sequence || '-'}`,
      `Risk: ${formatPercent(node.risk)}`,
      `Raw score: ${formatRawScore(node.anomaly_score)}`,
      `Severity: ${node.severity || 'NORMAL'}`,
      displayEventType(node.event_type) || 'Flagged',
    ]
  }
  return [
    truncate(node.label, 28),
    `Role: ${node.incident_role || KIND_LABELS[node.kind] || node.kind || 'Node'}`,
    `Domain: ${node.domain && node.domain !== 'unknown' ? displayDomain(node.domain) : 'Not Mapped'}`,
    `Links: ${Number(node.in_degree || 0) + Number(node.out_degree || 0)}`,
  ]
}

const edgeDescription = (link, selectedNodeId) => {
  const direction = link.source === selectedNodeId ? 'Outgoing' : 'Incoming'
  const relation = String(link.label || link.relation || 'linked').replaceAll('_', ' ')
  const related = link.source === selectedNodeId ? link.targetNode : link.sourceNode
  return `${direction}: ${relation} ${truncate(related?.label || related?.id || 'node', 24)}`
}

const edgeLabel = link => {
  const relationLabels = {
    observed: 'Observed Via',
    target: 'Affects',
    pattern: 'Matches',
    flow: 'Traffic Flow',
    domain: 'Domain Context',
    domain_pattern: 'Domain Pattern',
    shared_pattern: 'Shared Pattern',
    shared_target: 'Shared Target',
    shared_source: 'Shared Source',
    shared_flow: 'Shared Flow',
    domain_sequence: 'Domain Sequence',
    pivot: 'Pivot Path',
  }
  const relation = String(link.relation || link.label || 'linked')
  const relationKey = relation.toLowerCase()
  return relationLabels[relationKey] || titleCase(relation.replace(/->/g, ' '))
}

export const ProvenanceGraphD3 = forwardRef(({
  forensicData = {},
  onExport = null,
  onNodeSelect = null,
  onUiStateChange = null,
}, ref) => {
  const svgRef = useRef(null)
  const containerRef = useRef(null)
  const onNodeSelectRef = useRef(onNodeSelect)
  const zoomRef = useRef(null)
  const graphBoundsRef = useRef(null)
  const nodeBoundsRef = useRef(null)
  const nodePositionsRef = useRef(new Map())
  const nodeAnchorsRef = useRef(new Map())
  const simulationRef = useRef(null)
  const zoomTransformRef = useRef(null)
  const selectedNodeRef = useRef(null)

  const [graphData, setGraphData] = useState(null)
  const [visibleNodeLimit, setVisibleNodeLimit] = useState(0)
  const [hasGeneratedGraph, setHasGeneratedGraph] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [isExporting, setIsExporting] = useState(false)
  const [error, setError] = useState(null)
  const [selectedNode, setSelectedNode] = useState(null)
  const [severityFilter, setSeverityFilter] = useState([])
  const [domainFilter, setDomainFilter] = useState([])
  const [eventTypeFilter, setEventTypeFilter] = useState([])
  const [timeWindow, setTimeWindow] = useState('all')
  const [limit, setLimit] = useState(10)
  const [isGraphLocked, setIsGraphLocked] = useState(false)
  const [isPanEnabled, setIsPanEnabled] = useState(true)

  useEffect(() => {
    onNodeSelectRef.current = onNodeSelect
  }, [onNodeSelect])

  useEffect(() => {
    selectedNodeRef.current = selectedNode
  }, [selectedNode])

  const buildFilterParams = useCallback(() => {
    const params = { limit }
    const selectedWindow = TIME_WINDOWS.find(option => option.value === timeWindow)

    if (severityFilter.length) params.severity_levels = severityFilter.join(',')
    if (domainFilter.length) params.domains = domainFilter.join(',')
    if (eventTypeFilter.length) params.event_types = eventTypeFilter.join(',')
    if (selectedWindow?.ms) params.time_window_ms = selectedWindow.ms

    return params
  }, [domainFilter, eventTypeFilter, limit, severityFilter, timeWindow])

  const fetchGraphData = useCallback(async ({
    resetView = false,
    resetSelection = false,
    showLoading = true,
  } = {}) => {
    if (showLoading) setIsLoading(true)
    setError(null)
    try {
      const response = await api.getProvenanceGraphFiltered(buildFilterParams())
      const nextGraph = normalizePayload(response.data)
      if (resetView) {
        nodePositionsRef.current.clear()
        nodeAnchorsRef.current.clear()
        zoomTransformRef.current = null
      }
      setGraphData(nextGraph)
      setHasGeneratedGraph(true)
      setVisibleNodeLimit(nextGraph.nodes.length)
      const selectedId = selectedNodeRef.current?.id
      if (
        resetSelection ||
        (selectedId && !nextGraph.nodes.some(node => node.id === selectedId))
      ) {
        setSelectedNode(null)
      }
    } catch (err) {
      setError(`Failed to load provenance graph: ${err.message}`)
    } finally {
      if (showLoading) setIsLoading(false)
    }
  }, [buildFilterParams])

  const filterSignature = useMemo(() => JSON.stringify(buildFilterParams()), [buildFilterParams])

  const clearGraph = useCallback(() => {
    simulationRef.current?.stop()
    nodePositionsRef.current.clear()
    nodeAnchorsRef.current.clear()
    zoomTransformRef.current = null
    setGraphData(null)
    setVisibleNodeLimit(0)
    setSelectedNode(null)
    setHasGeneratedGraph(false)
    if (svgRef.current) d3.select(svgRef.current).selectAll('*').remove()
  }, [])

  useEffect(() => {
    clearGraph()
  }, [clearGraph, filterSignature])

  const visibleGraphData = useMemo(() => {
    if (!graphData) return null
    const nodeLimit = Math.min(Math.max(visibleNodeLimit, 0), graphData.nodes.length)
    const visibleNodes = graphData.nodes.slice(0, nodeLimit)
    const visibleIds = new Set(visibleNodes.map(node => node.id))
    const visibleLinks = (graphData.links || []).filter(link => (
      visibleIds.has(link.source) && visibleIds.has(link.target)
    ))
    const visibleEventCount = visibleNodes.filter(node => node.kind === 'event').length

    return {
      ...graphData,
      nodes: visibleNodes,
      links: visibleLinks,
      displayed_count: visibleEventCount,
      node_count: visibleNodes.length,
      edge_count: visibleLinks.length,
    }
  }, [graphData, visibleNodeLimit])

  const activeDomains = useMemo(() => {
    const domains = new Set((visibleGraphData?.nodes || []).map(node => node.domain || 'unknown'))
    return Object.entries(DOMAIN_CONFIG).filter(([domain]) => domain !== 'unknown' && domains.has(domain))
  }, [visibleGraphData])

  const eventNodes = useMemo(
    () => (visibleGraphData?.nodes || []).filter(node => node.kind === 'event'),
    [visibleGraphData]
  )

  const fitGraphToBounds = useCallback((bounds, duration = 450) => {
    if (!svgRef.current || !zoomRef.current || !bounds) return
    const graphBounds = graphBoundsRef.current
    if (!graphBounds) return

    const padding = 62
    const width = Math.max(1, bounds.maxX - bounds.minX)
    const height = Math.max(1, bounds.maxY - bounds.minY)
    const scale = Math.max(
      0.32,
      Math.min(
        2.2,
        (graphBounds.visibleWidth - padding * 2) / width,
        (graphBounds.visibleHeight - padding * 2) / height
      )
    )
    const translateX = (graphBounds.visibleWidth - width * scale) / 2 - bounds.minX * scale
    const translateY = (graphBounds.visibleHeight - height * scale) / 2 - bounds.minY * scale
    d3.select(svgRef.current)
      .transition()
      .duration(duration)
      .call(zoomRef.current.transform, d3.zoomIdentity.translate(translateX, translateY).scale(scale))
  }, [])

  const handleResetAxes = useCallback(() => {
    if (isGraphLocked) return
    setSelectedNode(null)
    fitGraphToBounds(graphBoundsRef.current?.worldBounds || nodeBoundsRef.current, 420)
  }, [fitGraphToBounds, isGraphLocked])

  const handleAutoscale = useCallback(() => {
    if (isGraphLocked) return
    fitGraphToBounds(nodeBoundsRef.current || graphBoundsRef.current?.worldBounds, 420)
  }, [fitGraphToBounds, isGraphLocked])

  const handleZoomBy = useCallback(scaleFactor => {
    if (isGraphLocked) return
    if (!svgRef.current || !zoomRef.current) return
    d3.select(svgRef.current)
      .transition()
      .duration(220)
      .call(zoomRef.current.scaleBy, scaleFactor)
  }, [isGraphLocked])

  useEffect(() => {
    if (!visibleGraphData || !svgRef.current || !containerRef.current) return

    simulationRef.current?.stop()
    const graphHost = svgRef.current.parentElement
    const visibleWidth = graphHost?.clientWidth || containerRef.current.clientWidth || 1120
    const visibleHeight = graphHost?.clientHeight || 620
    const worldWidth = Math.max(1380, visibleWidth * 1.7, visibleGraphData.nodes.length * 46)
    const worldHeight = Math.max(780, visibleHeight * 1.45, visibleGraphData.nodes.length * 30)
    const worldPadding = 86

    const hasCachedPositions = nodePositionsRef.current.size > 0
    const nodes = visibleGraphData.nodes.map(node => {
      const cached = nodePositionsRef.current.get(node.id)
      const anchor = nodeAnchorsRef.current.get(node.id)
      const seedX = seededUnit(`${node.id}:x`)
      const seedY = seededUnit(`${node.id}:y`)
      const radiusBias = node.kind === 'event' ? 0.76 : 1
      const seededX = worldPadding + seedX * (worldWidth - worldPadding * 2)
      const seededY = worldPadding + seedY * (worldHeight - worldPadding * 2)
      const x = cached?.x ?? anchor?.x ?? ((seededX - worldWidth / 2) * radiusBias + worldWidth / 2)
      const y = cached?.y ?? anchor?.y ?? ((seededY - worldHeight / 2) * radiusBias + worldHeight / 2)
      const clampedX = clamp(Number(x), worldPadding, worldWidth - worldPadding)
      const clampedY = clamp(Number(y), worldPadding, worldHeight - worldPadding)
      const anchorX = clamp(Number(anchor?.x ?? clampedX), worldPadding, worldWidth - worldPadding)
      const anchorY = clamp(Number(anchor?.y ?? clampedY), worldPadding, worldHeight - worldPadding)
      if (!anchor) {
        nodeAnchorsRef.current.set(node.id, { x: anchorX, y: anchorY })
      }
      return {
        ...node,
        x: clampedX,
        y: clampedY,
        anchorX,
        anchorY,
      }
    })
    const nodeById = new Map(nodes.map(node => [node.id, node]))
    const links = visibleGraphData.links
      .map(link => ({
        ...link,
        sourceNode: nodeById.get(link.source),
        targetNode: nodeById.get(link.target),
      }))
      .filter(link => link.sourceNode && link.targetNode)

    const maxX = worldWidth
    const maxY = worldHeight
    graphBoundsRef.current = {
      visibleWidth,
      visibleHeight,
      worldWidth,
      worldHeight,
      worldBounds: {
        minX: 0,
        minY: 0,
        maxX: worldWidth,
        maxY: worldHeight,
      },
    }

    const svg = d3.select(svgRef.current)
    svg.selectAll('*').remove()
    svg
      .attr('width', visibleWidth)
      .attr('height', visibleHeight)
      .attr('viewBox', `0 0 ${visibleWidth} ${visibleHeight}`)

    const defs = svg.append('defs')
    const arrowMarker = defs
      .append('marker')
      .attr('id', 'provenance-arrow')
      .attr('viewBox', '0 -5 10 10')
      .attr('markerWidth', 8)
      .attr('markerHeight', 8)
      .attr('refX', 8.5)
      .attr('refY', 0)
      .attr('orient', 'auto')
      .attr('markerUnits', 'userSpaceOnUse')

    arrowMarker.append('path')
      .attr('d', 'M1,-3.8 C4.5,-2.2 7,-0.9 8.8,0 C7,0.9 4.5,2.2 1,3.8 L2.4,0 Z')
      .attr('fill', '#8aa4b7')
      .attr('stroke', 'rgba(232, 247, 255, 0.45)')
      .attr('stroke-width', 0.7)
      .attr('stroke-linejoin', 'round')

    const selectedArrowMarker = defs
      .append('marker')
      .attr('id', 'provenance-arrow-selected')
      .attr('viewBox', '0 -5 10 10')
      .attr('markerWidth', 9)
      .attr('markerHeight', 9)
      .attr('refX', 8.5)
      .attr('refY', 0)
      .attr('orient', 'auto')
      .attr('markerUnits', 'userSpaceOnUse')

    selectedArrowMarker.append('path')
      .attr('d', 'M1,-3.8 C4.5,-2.2 7,-0.9 8.8,0 C7,0.9 4.5,2.2 1,3.8 L2.4,0 Z')
      .attr('fill', '#39d8ff')
      .attr('stroke', 'rgba(232, 247, 255, 0.68)')
      .attr('stroke-width', 0.8)
      .attr('stroke-linejoin', 'round')

    const gridPattern = defs
      .append('pattern')
      .attr('id', 'provenance-grid-pattern')
      .attr('width', 32)
      .attr('height', 32)
      .attr('patternUnits', 'userSpaceOnUse')

    gridPattern.append('rect')
      .attr('width', 32)
      .attr('height', 32)
      .attr('fill', '#06111c')

    gridPattern.append('path')
      .attr('d', 'M 32 0 L 0 0 0 32')
      .attr('fill', 'none')
      .attr('stroke', 'rgba(57, 216, 255, 0.07)')
      .attr('stroke-width', 1)

    defs
      .append('filter')
      .attr('id', 'node-glow')
      .append('feDropShadow')
      .attr('dx', 0)
      .attr('dy', 0)
      .attr('stdDeviation', 3)
      .attr('flood-color', '#39d8ff')
      .attr('flood-opacity', 0.45)

    const viewport = svg.append('g').attr('class', 'provenance-viewport')
    const surface = viewport.append('rect')
      .attr('class', 'provenance-network-surface')
      .attr('width', maxX)
      .attr('height', maxY)
      .attr('fill', 'url(#provenance-grid-pattern)')
      .attr('rx', 0)

    const selectedNodeId = selectedNode?.id || null
    const selectedNeighborhood = new Set(selectedNodeId ? [selectedNodeId] : [])
    if (selectedNodeId) {
      links.forEach(link => {
        if (link.source === selectedNodeId) selectedNeighborhood.add(link.target)
        if (link.target === selectedNodeId) selectedNeighborhood.add(link.source)
      })
    }
    const hasNodeSelection = selectedNeighborhood.size > 0
    const selectedGraphNode = selectedNodeId ? nodeById.get(selectedNodeId) : null
    const selectedIncidentLinks = selectedNodeId
      ? links.filter(link => link.source === selectedNodeId || link.target === selectedNodeId)
      : []
    const calloutRows = selectedGraphNode ? selectedNodeRows(selectedGraphNode).slice(0, 6) : []

    const linkLayer = viewport.append('g').attr('class', 'provenance-links')
    const linkPath = linkLayer.selectAll('path')
      .data(links, link => link.id || `${link.source}-${link.target}-${link.relation}`)
      .join('path')
      .attr('class', link => {
        const classes = ['provenance-link']
        if (link.relation?.includes('shared') || link.relation === 'pivot' || link.relation === 'domain_sequence') {
          classes.push('provenance-link-correlation')
        }
        if (selectedNodeId && (link.source === selectedNodeId || link.target === selectedNodeId)) classes.push('is-linked')
        if (hasNodeSelection && link.source !== selectedNodeId && link.target !== selectedNodeId) {
          classes.push('is-muted')
        }
        return classes.join(' ')
      })
      .attr('marker-end', link => (
        selectedNodeId && (link.source === selectedNodeId || link.target === selectedNodeId)
          ? 'url(#provenance-arrow-selected)'
          : 'url(#provenance-arrow)'
      ))
      .style('stroke-width', link => 1.2 + Math.min(Number(link.weight || 1), 5) * 0.45)

    const nodeLayer = viewport.append('g').attr('class', 'provenance-nodes')
    const nodeGroup = nodeLayer.selectAll('g')
      .data(nodes, node => node.id)
      .join('g')
      .attr('class', node => {
        const classes = ['provenance-node-group', `kind-${node.kind || 'unknown'}`]
        if (selectedNode?.id === node.id) classes.push('is-selected')
        if (selectedNodeId && selectedNeighborhood.has(node.id)) classes.push('is-linked')
        if (hasNodeSelection && !selectedNeighborhood.has(node.id)) classes.push('is-muted')
        return classes.join(' ')
      })
      .attr('tabIndex', 0)
      .style('cursor', 'pointer')
      .on('click', (event, node) => {
        event.stopPropagation()
        setSelectedNode(node)
        onNodeSelectRef.current?.(node)
      })

    nodeGroup.each(function drawNode(node) {
      const group = d3.select(this)
      const radius = nodeRadius(node)
      const color = nodeColor(node)

      if (node.kind === 'domain') {
        group.append('rect')
          .attr('class', 'provenance-node-shape')
          .attr('x', -radius)
          .attr('y', -radius)
          .attr('width', radius * 2)
          .attr('height', radius * 2)
          .attr('rx', 4)
          .attr('fill', color)
      } else if (node.kind === 'pattern') {
        group.append('path')
          .attr('class', 'provenance-node-shape')
          .attr('d', `M0,${-radius} L${radius},0 L0,${radius} L${-radius},0 Z`)
          .attr('fill', color)
      } else {
        group.append('circle')
          .attr('class', 'provenance-node-shape')
          .attr('r', radius)
          .attr('fill', color)
      }

      if (node.kind === 'event') {
        group.append('circle')
          .attr('class', 'provenance-risk-ring')
          .attr('r', radius + 4)
          .attr('stroke', SEVERITY_LEVELS[node.severity]?.color || '#39d8ff')
      }
    })

    const annotationLayer = viewport.append('g').attr('class', 'provenance-annotations')
    const edgeLabelGroup = annotationLayer.selectAll('g.provenance-selected-edge-label')
      .data(selectedIncidentLinks, link => link.id || `${link.source}-${link.target}-${link.relation}`)
      .join('g')
      .attr('class', 'provenance-selected-edge-label')
      .style('pointer-events', 'none')

    edgeLabelGroup.append('rect')
      .attr('rx', 10)
      .attr('y', -12)
      .attr('height', 22)
      .attr('x', link => -Math.max(82, edgeLabel(link).length * 7 + 20) / 2)
      .attr('width', link => Math.max(82, edgeLabel(link).length * 7 + 20))

    edgeLabelGroup.append('text')
      .attr('y', 2.5)
      .attr('text-anchor', 'middle')
      .text(link => edgeLabel(link))

    const calloutWidth = selectedGraphNode?.kind === 'event' ? 178 : 196
    const calloutHeight = Math.max(54, calloutRows.length * 19 + 14)
    const calloutGroup = selectedGraphNode
      ? annotationLayer.append('g')
        .attr('class', `provenance-node-callout kind-${selectedGraphNode.kind || 'unknown'}`)
        .style('pointer-events', 'none')
      : null

    if (calloutGroup) {
      calloutGroup.append('rect')
        .attr('width', calloutWidth)
        .attr('height', calloutHeight)
        .attr('rx', 2)

      calloutRows.forEach((row, index) => {
        calloutGroup.append('text')
          .attr('class', index === 0 ? 'callout-title' : null)
          .attr('x', 10)
          .attr('y', 20 + index * 19)
          .text(row)
      })
    }

    const updatePositions = () => {
      nodes.forEach(node => {
        const minX = 42
        const maxNodeX = maxX - 42
        const minY = 42
        const maxNodeY = maxY - 42
        if (node.x < minX || node.x > maxNodeX) {
          node.x = clamp(node.x, minX, maxNodeX)
          node.vx *= -0.18
        }
        if (node.y < minY || node.y > maxNodeY) {
          node.y = clamp(node.y, minY, maxNodeY)
          node.vy *= -0.18
        }
      })

      const bounds = nodes.reduce((acc, node) => ({
        minX: Math.min(acc.minX, node.x),
        minY: Math.min(acc.minY, node.y),
        maxX: Math.max(acc.maxX, node.x),
        maxY: Math.max(acc.maxY, node.y),
      }), { minX: Infinity, minY: Infinity, maxX: -Infinity, maxY: -Infinity })

      if (Number.isFinite(bounds.minX)) {
        nodeBoundsRef.current = {
          minX: Math.max(0, bounds.minX - 120),
          minY: Math.max(0, bounds.minY - 110),
          maxX: Math.min(maxX, bounds.maxX + 120),
          maxY: Math.min(maxY, bounds.maxY + 110),
        }
        nodes.forEach(node => {
          nodePositionsRef.current.set(node.id, { x: node.x, y: node.y })
        })
      }

      linkPath.attr('d', link => {
        const source = link.sourceNode
        const target = link.targetNode
        const dx = target.x - source.x
        const dy = target.y - source.y
        const distance = Math.max(1, Math.hypot(dx, dy))
        const unitX = dx / distance
        const unitY = dy / distance
        const sourceRadius = nodeRadius(source) + 5
        const targetRadius = nodeRadius(target) + 12
        const startX = source.x + unitX * sourceRadius
        const startY = source.y + unitY * sourceRadius
        const endX = target.x - unitX * targetRadius
        const endY = target.y - unitY * targetRadius
        return `M${startX},${startY} L${endX},${endY}`
      })

      nodeGroup.attr('transform', node => `translate(${node.x},${node.y})`)

      edgeLabelGroup.attr('transform', (link, index) => {
        const dx = link.targetNode.x - link.sourceNode.x
        const dy = link.targetNode.y - link.sourceNode.y
        const length = Math.max(1, Math.hypot(dx, dy))
        const midX = (link.sourceNode.x + link.targetNode.x) / 2
        const midY = (link.sourceNode.y + link.targetNode.y) / 2
        const offset = 15 + (index % 2) * 9
        const x = midX + (-dy / length) * offset
        const y = midY + (dx / length) * offset
        return `translate(${x},${y})`
      })

      if (calloutGroup && selectedGraphNode) {
        const radius = nodeRadius(selectedGraphNode)
        const fitsRight = selectedGraphNode.x + radius + calloutWidth + 38 < maxX
        const x = fitsRight
          ? selectedGraphNode.x + radius + 18
          : selectedGraphNode.x - calloutWidth - radius - 18
        const y = Math.max(12, Math.min(maxY - calloutHeight - 12, selectedGraphNode.y - calloutHeight / 2))
        calloutGroup.attr('transform', `translate(${x},${y})`)
      }
    }

    const simulationLinks = links.map(link => ({
      source: link.source,
      target: link.target,
      relation: link.relation,
      weight: Number(link.weight || 1),
    }))
    const simulation = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(simulationLinks)
        .id(node => node.id)
        .distance(link => {
          if (link.relation?.includes('shared')) return 155
          if (link.relation === 'pivot' || link.relation === 'domain_sequence') return 180
          return 118
        })
        .strength(link => Math.min(0.26, 0.06 + Number(link.weight || 1) * 0.028)))
      .force('charge', d3.forceManyBody().strength(node => (node.kind === 'event' ? -220 : -132)))
      .force('collision', d3.forceCollide().radius(node => nodeRadius(node) + 24).strength(0.86))
      .force('center', d3.forceCenter(maxX / 2, maxY / 2))
      .force('x', d3.forceX(maxX / 2).strength(0.004))
      .force('y', d3.forceY(maxY / 2).strength(0.005))
      .force('anchor', createSoftAnchorForce())
      .force('drift', createAmbientDriftForce())
      .velocityDecay(0.42)
      .alpha(hasCachedPositions ? 0.28 : 0.72)
      .alphaTarget(isGraphLocked ? 0 : 0.046)
      .on('tick', updatePositions)

    simulationRef.current = simulation
    if (isGraphLocked) simulation.stop()

    if (!isGraphLocked) {
      nodeGroup.call(
        d3.drag()
        .on('start', function handleStart(event) {
          d3.select(this).raise().classed('is-dragging', true)
          if (!event.active) simulation.alphaTarget(0.12).restart()
          event.subject.fx = event.subject.x
          event.subject.fy = event.subject.y
          event.sourceEvent?.stopPropagation()
        })
        .on('drag', function handleDrag(event, node) {
          node.fx = Math.max(42, Math.min(maxX - 42, event.x))
          node.fy = Math.max(42, Math.min(maxY - 42, event.y))
          node.x = node.fx
          node.y = node.fy
          updatePositions()
        })
        .on('end', function handleEnd(event) {
          d3.select(this).classed('is-dragging', false)
          const displacedIds = new Set([event.subject.id])
          links.forEach(link => {
            if (link.source === event.subject.id) displacedIds.add(link.target)
            if (link.target === event.subject.id) displacedIds.add(link.source)
          })
          nodes.forEach(node => {
            if (!displacedIds.has(node.id)) return
            const previousAnchor = nodeAnchorsRef.current.get(node.id) || { x: node.anchorX, y: node.anchorY }
            const retention = node.id === event.subject.id ? 1 : 0.46
            const anchorX = clamp(previousAnchor.x + (node.x - previousAnchor.x) * retention, 42, maxX - 42)
            const anchorY = clamp(previousAnchor.y + (node.y - previousAnchor.y) * retention, 42, maxY - 42)
            node.anchorX = anchorX
            node.anchorY = anchorY
            nodeAnchorsRef.current.set(node.id, { x: anchorX, y: anchorY })
            nodePositionsRef.current.set(node.id, { x: node.x, y: node.y })
          })
          if (!event.active) simulation.alphaTarget(0.046)
          event.subject.fx = null
          event.subject.fy = null
        })
      )
    }

    const zoom = d3.zoom()
      .scaleExtent([0.32, 2.6])
      .filter(event => {
        if (isGraphLocked) return false
        if (event.type === 'dblclick') return false
        if (event.type === 'mousedown' || event.type === 'touchstart' || event.type === 'touchmove') {
          return isPanEnabled
        }
        return true
      })
      .on('zoom', event => {
        zoomTransformRef.current = event.transform
        viewport.attr('transform', event.transform)
      })
    zoomRef.current = zoom

    svg.call(zoom)
    svg.on('click', () => {
      setSelectedNode(null)
    })
    svg.on('dblclick.zoom', null)

    updatePositions()

    if (zoomTransformRef.current) {
      svg.call(zoom.transform, zoomTransformRef.current)
    } else if (nodes.length) {
      const initialBounds = nodeBoundsRef.current || graphBoundsRef.current?.worldBounds
      const padding = 62
      const width = Math.max(1, initialBounds.maxX - initialBounds.minX)
      const height = Math.max(1, initialBounds.maxY - initialBounds.minY)
      const initialScale = Math.max(0.32, Math.min(1.15, (visibleWidth - padding * 2) / width, (visibleHeight - padding * 2) / height))
      const initialTransform = d3.zoomIdentity
        .translate(
          (visibleWidth - width * initialScale) / 2 - initialBounds.minX * initialScale,
          (visibleHeight - height * initialScale) / 2 - initialBounds.minY * initialScale
        )
        .scale(initialScale)
      svg.call(zoom.transform, initialTransform)
    }

    surface.on('click', () => {
      setSelectedNode(null)
    })

    return () => {
      simulation.stop()
    }
  }, [isGraphLocked, isPanEnabled, selectedNode, visibleGraphData])

  const toggleValue = (value, setter) => {
    setter(prev => prev.includes(value) ? prev.filter(item => item !== value) : [...prev, value])
  }

  const resetFilters = () => {
    setSeverityFilter([])
    setDomainFilter([])
    setEventTypeFilter([])
    setTimeWindow('all')
    setLimit(10)
  }

  const handleGenerate = useCallback(() => {
    fetchGraphData({
      resetView: true,
      resetSelection: true,
      showLoading: true,
    })
  }, [fetchGraphData])

  const handleRefresh = useCallback(() => {
    if (!hasGeneratedGraph) return
    fetchGraphData({
      resetView: false,
      resetSelection: false,
      showLoading: true,
    })
  }, [fetchGraphData, hasGeneratedGraph])

  const handleExport = async () => {
    setIsExporting(true)
    setError(null)
    try {
      const params = buildFilterParams()
      const [pngResponse, summaryResponse] = await Promise.all([
        api.exportProvenanceGraphPng(params),
        api.exportProvenanceGraphSummary(params),
      ])

      const date = new Date().toISOString().split('T')[0]
      const pngUrl = window.URL.createObjectURL(pngResponse.data)
      const pngLink = document.createElement('a')
      pngLink.href = pngUrl
      pngLink.download = `bluebox-provenance-${date}.png`
      pngLink.click()
      window.URL.revokeObjectURL(pngUrl)

      const summaryText = summaryResponse.data?.summary || ''
      const summaryBlob = new Blob([summaryText], { type: 'text/plain' })
      const summaryUrl = window.URL.createObjectURL(summaryBlob)
      const summaryLink = document.createElement('a')
      summaryLink.href = summaryUrl
      summaryLink.download = `bluebox-provenance-${date}.txt`
      summaryLink.click()
      window.URL.revokeObjectURL(summaryUrl)

      onExport?.({
        png: pngResponse.data,
        summary: summaryText,
        params,
        graphData,
      })
    } catch (err) {
      setError(`Export failed: ${err.message}`)
    } finally {
      setIsExporting(false)
    }
  }

  useImperativeHandle(ref, () => ({
    resetFilters,
    generateGraph: handleGenerate,
    refresh: handleRefresh,
    exportGraph: handleExport,
  }), [handleExport, handleGenerate, handleRefresh])

  useEffect(() => {
    onUiStateChange?.({
      isLoading,
      isExporting,
      hasGraph: Boolean(graphData?.nodes?.length),
      hasGeneratedGraph,
    })
  }, [graphData, hasGeneratedGraph, isExporting, isLoading, onUiStateChange])

  const totalReplayEvents = forensicData?.evidence_stream?.length || forensicData?.timeline?.length || 0
  const displayedCount = graphData?.displayed_count || (graphData?.nodes || []).filter(node => node.kind === 'event').length || 0
  const filteredCount = graphData?.filtered_count || 0
  const nodeCount = graphData?.node_count || graphData?.nodes?.length || 0
  const edgeCount = graphData?.edge_count || graphData?.links?.length || 0
  const selectedNodeConnections = useMemo(() => {
    if (!selectedNode || !visibleGraphData) return []
    const nodeById = new Map((visibleGraphData.nodes || []).map(node => [node.id, node]))
    return (visibleGraphData.links || [])
      .filter(link => link.source === selectedNode.id || link.target === selectedNode.id)
      .map(link => {
        const outgoing = link.source === selectedNode.id
        const relatedNodeId = outgoing ? link.target : link.source
        const relatedNode = nodeById.get(relatedNodeId)
        const enrichedLink = {
          ...link,
          sourceNode: nodeById.get(link.source),
          targetNode: nodeById.get(link.target),
        }
        return {
          id: link.id || `${link.source}-${link.target}-${link.relation}`,
          direction: outgoing ? 'Outgoing' : 'Incoming',
          relation: edgeDescription(enrichedLink, selectedNode.id),
          relationType: link.relation || 'linked',
          relatedLabel: relatedNode?.label || relatedNodeId,
          relatedRole: relatedNode?.incident_role || KIND_LABELS[relatedNode?.kind] || relatedNode?.kind || 'Node',
        }
      })
      .sort((left, right) => left.direction.localeCompare(right.direction) || left.relation.localeCompare(right.relation))
  }, [selectedNode, visibleGraphData])

  return (
    <div className="provenance-network" ref={containerRef}>
      <div className="provenance-filter-bar">
        <div className="provenance-filter-group">
          <span>Severity</span>
          <div className="provenance-chip-row">
            {Object.entries(SEVERITY_LEVELS).map(([level, config]) => (
              <button
                key={level}
                type="button"
                className={severityFilter.includes(level) ? 'is-active' : ''}
                style={{ '--chip-color': config.color }}
                onClick={() => toggleValue(level, setSeverityFilter)}
              >
                {config.label}
              </button>
            ))}
          </div>
        </div>

        <div className="provenance-filter-group">
          <span>Domain</span>
          <div className="provenance-chip-row">
            {Object.entries(DOMAIN_CONFIG).filter(([domain]) => domain !== 'unknown' && domain !== 'integrity').map(([domain, config]) => (
              <button
                key={domain}
                type="button"
                className={domainFilter.includes(domain) ? 'is-active' : ''}
                style={{ '--chip-color': config.color }}
                onClick={() => toggleValue(domain, setDomainFilter)}
              >
                {config.label}
              </button>
            ))}
          </div>
        </div>

        <div className="provenance-filter-group">
          <span>Event Type</span>
          <div className="provenance-chip-row">
            {Object.entries(EVENT_TYPES).map(([type, label]) => (
              <button
                key={type}
                type="button"
                className={eventTypeFilter.includes(type) ? 'is-active' : ''}
                style={{ '--chip-color': eventTypeColor(type) }}
                onClick={() => toggleValue(type, setEventTypeFilter)}
              >
                {label}
              </button>
            ))}
          </div>
        </div>

        <div className="provenance-selects">
          <label>
            <span>Window</span>
            <select value={timeWindow} onChange={event => setTimeWindow(event.target.value)}>
              {TIME_WINDOWS.map(option => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </select>
          </label>
          <label>
            <span>Top Events</span>
            <select value={limit} onChange={event => setLimit(Number(event.target.value))}>
              {LIMIT_OPTIONS.map(option => (
                <option key={option} value={option}>Top {option}</option>
              ))}
            </select>
          </label>
        </div>
      </div>

      {error && <Alert variant="critical">{error}</Alert>}

      <div className="provenance-workspace">
        <aside className="provenance-left-panel">
          <section>
            <div className="provenance-side-heading">
              <span>Graph Summary</span>
            </div>
            <div className="provenance-metrics">
              <div>
                <span>Displayed Events</span>
                <strong>{displayedCount}</strong>
              </div>
              <div>
                <span>Linked Nodes</span>
                <strong>{nodeCount}</strong>
              </div>
              <div>
                <span>Relationships</span>
                <strong>{edgeCount}</strong>
              </div>
            </div>
          </section>
        </aside>

        <div className="provenance-graph-shell">
          {isLoading && (
            <div className="provenance-loading">
              <Spinner size="lg" />
              <span>Building provenance graph</span>
            </div>
          )}

          {!isLoading && graphData && graphData.nodes.length === 0 && (
            <div className="provenance-empty">
              <strong>No provenance graph for these filters</strong>
              <span>
                {filteredCount > 0
                  ? 'Events matched the filters, but no graph relationships could be constructed.'
                  : `No AI/security events matched this view. Replay contains ${totalReplayEvents} records.`}
              </span>
            </div>
          )}

          <svg ref={svgRef} className="provenance-graph-svg" aria-label="Provenance investigation graph" />

          <div className="provenance-graph-modebar" aria-label="Provenance graph controls">
            <button type="button" title="Reset axes" aria-label="Reset axes" onClick={handleResetAxes} disabled={isGraphLocked}>
              <RotateCcw size={15} />
            </button>
            <button
              type="button"
              title={isGraphLocked ? 'Unlock graph motion and zoom' : 'Lock graph motion and zoom'}
              aria-label={isGraphLocked ? 'Unlock graph motion and zoom' : 'Lock graph motion and zoom'}
              aria-pressed={isGraphLocked}
              className={isGraphLocked ? 'is-active' : ''}
              onClick={() => setIsGraphLocked(value => !value)}
            >
              {isGraphLocked ? <Lock size={15} /> : <Unlock size={15} />}
            </button>
            <button
              type="button"
              title={isPanEnabled ? 'Disable pan' : 'Enable pan'}
              aria-label={isPanEnabled ? 'Disable pan' : 'Enable pan'}
              aria-pressed={isPanEnabled}
              className={!isGraphLocked && isPanEnabled ? 'is-active' : ''}
              onClick={() => setIsPanEnabled(value => !value)}
              disabled={isGraphLocked}
            >
              <Move size={15} />
            </button>
            <button type="button" title="Autoscale" aria-label="Autoscale" onClick={handleAutoscale} disabled={isGraphLocked}>
              <Maximize2 size={15} />
            </button>
            <button type="button" title="Zoom in" aria-label="Zoom in" onClick={() => handleZoomBy(1.22)} disabled={isGraphLocked}>
              <ZoomIn size={15} />
            </button>
            <button type="button" title="Zoom out" aria-label="Zoom out" onClick={() => handleZoomBy(0.82)} disabled={isGraphLocked}>
              <ZoomOut size={15} />
            </button>
          </div>

          <div className="provenance-legend">
            <span>Domains</span>
            {activeDomains.map(([domain, config]) => (
              <div key={domain}>
                <i style={{ backgroundColor: config.color }} />
                {config.label}
              </div>
            ))}
            <em>Nodes are colored by domain. Event size tracks risk and centrality.</em>
          </div>
        </div>

        <aside className="provenance-side-panel">
          <section>
            <div className="provenance-side-heading">
              <span>Selected Node</span>
              {selectedNode && (
                <button type="button" onClick={() => setSelectedNode(null)} aria-label="Clear selected node">
                  <X size={14} />
                </button>
              )}
            </div>
            {selectedNode ? (
              <div className="provenance-node-details">
                <strong>{selectedNode.label}</strong>
                {selectedNode.kind === 'event' && (
                  <div className="provenance-node-summary">
                    <div>
                      <span>Time</span>
                      <strong>{formatTimestamp(selectedNode.timestamp || selectedNode.occurred_at)}</strong>
                    </div>
                    <div>
                      <span>Seq</span>
                      <strong>{selectedNode.sequence ? `#${selectedNode.sequence}` : '-'}</strong>
                    </div>
                    <div>
                      <span>Risk</span>
                      <strong>{formatPercent(selectedNode.risk)}</strong>
                    </div>
                    <div>
                      <span>Raw Score</span>
                      <strong>{formatRawScore(selectedNode.anomaly_score)}</strong>
                    </div>
                    <div>
                      <span>Severity</span>
                      <strong>{selectedNode.severity || 'Normal'}</strong>
                    </div>
                    <div>
                      <span>Status</span>
                      <strong>{displayEventType(selectedNode.event_type) || 'Flagged'}</strong>
                    </div>
                  </div>
                )}
                <dl>
                  <div>
                    <dt>Role</dt>
                    <dd>{selectedNode.incident_role || KIND_LABELS[selectedNode.kind] || selectedNode.kind}</dd>
                  </div>
                  {selectedNode.event_type && (
                    <div>
                      <dt>Event Type</dt>
                      <dd>{displayEventType(selectedNode.event_type)}</dd>
                    </div>
                  )}
                  <div>
                    <dt>Domain</dt>
                    <dd>{selectedNode.domain && selectedNode.domain !== 'unknown' ? displayDomain(selectedNode.domain) : 'Not Mapped'}</dd>
                  </div>
                  {selectedNode.severity && (
                    <div>
                      <dt>Severity</dt>
                      <dd>{selectedNode.severity}</dd>
                    </div>
                  )}
                  {selectedNode.risk > 0 && (
                    <div>
                      <dt>Risk</dt>
                      <dd>{formatPercent(selectedNode.risk)}</dd>
                    </div>
                  )}
                  {selectedNode.centrality != null && (
                    <div>
                      <dt>Centrality</dt>
                      <dd>{formatNumber(selectedNode.centrality)}</dd>
                    </div>
                  )}
                  {selectedNode.sequence && (
                    <div>
                      <dt>Sequence</dt>
                      <dd>#{selectedNode.sequence}</dd>
                    </div>
                  )}
                  {(selectedNode.timestamp || selectedNode.occurred_at) && (
                    <div>
                      <dt>Timestamp</dt>
                      <dd>{formatTimestamp(selectedNode.timestamp || selectedNode.occurred_at)}</dd>
                    </div>
                  )}
                  {selectedNode.anomaly_score != null && (
                    <div>
                      <dt>Raw Score</dt>
                      <dd>{formatRawScore(selectedNode.anomaly_score)}</dd>
                    </div>
                  )}
                  {selectedNode.source_component && (
                    <div>
                      <dt>Source</dt>
                      <dd>{selectedNode.source_component}</dd>
                    </div>
                  )}
                  {selectedNode.target_component && (
                    <div>
                      <dt>Target</dt>
                      <dd>{selectedNode.target_component}</dd>
                    </div>
                  )}
                  {selectedNode.pattern && (
                    <div>
                      <dt>Pattern</dt>
                      <dd>{selectedNode.pattern}</dd>
                    </div>
                  )}
                </dl>
                {(selectedNode.explanation || selectedNode.description) && (
                  <div className="provenance-description-card">
                    <span>Description</span>
                    <p>{selectedNode.explanation || selectedNode.description}</p>
                  </div>
                )}
                {Array.isArray(selectedNode.top_features) && selectedNode.top_features.length > 0 && (
                  <div className="provenance-feature-list">
                    {selectedNode.top_features.slice(0, 5).map(feature => (
                      <span key={feature}>{String(feature).replaceAll('_', ' ')}</span>
                    ))}
                  </div>
                )}
                {selectedNodeConnections.length > 0 && (
                  <div className="provenance-connection-list">
                    <h4>Connected Links</h4>
                    {selectedNodeConnections.map(connection => (
                      <div key={connection.id} className="provenance-connection-item">
                        <span>{connection.direction}</span>
                        <strong>{connection.relation}</strong>
                        <p>{connection.relatedLabel}</p>
                        <em>{connection.relatedRole}</em>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ) : (
              <p>Select a Node to Inspect Evidence</p>
            )}
          </section>
        </aside>
      </div>
    </div>
  )
})

export default ProvenanceGraphD3
