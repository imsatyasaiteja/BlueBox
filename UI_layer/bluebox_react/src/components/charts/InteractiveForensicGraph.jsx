import React, { useRef, useEffect, useState, useCallback } from 'react'
import { api } from '@/api/client'
import { formatTime } from '@/utils/format'
import './ProvenanceGraph.css'

const DEFAULT_RISK_THRESHOLD = 0.5
const GRAPH_PADDING = 70
const SEVERITY_RISK = {
  CRITICAL: 1,
  HIGH: 0.85,
  WARNING: 0.7,
  MEDIUM: 0.65,
  ANOMALY: 0.6,
  LOW: 0.4,
  INFO: 0.15,
  NONE: 0,
}

const normalizeRisk = (value, severity = 'ANOMALY') => {
  const score = Number(value || 0)
  const severityRisk = SEVERITY_RISK[String(severity || 'ANOMALY').toUpperCase()] ?? 0.6
  if (score < 0) return Math.max(severityRisk, Math.min(1, 0.55 + Math.abs(score) * 2))
  if (score <= 0.05) return Math.max(severityRisk, Math.max(0.25, 0.55 - score * 4))
  if (score <= 1) return Math.max(severityRisk, score)
  return severityRisk
}

const normalizeGraphPayload = (payload = {}) => {
  const rawNodes = payload.nodes || {}
  const nodeMap = Array.isArray(rawNodes)
    ? Object.fromEntries(rawNodes.filter(node => node?.id).map(node => [node.id, node]))
    : rawNodes
  const nodes = Object.fromEntries(
    Object.entries(nodeMap).map(([id, node]) => [
      id,
      {
        ...node,
        risk: node?.kind === 'anomaly' ? normalizeRisk(node.risk ?? node.anomaly_score, node.severity) : node?.risk || 0,
      },
    ]),
  )
  const positions = { ...(payload.positions || {}) }

  Object.values(nodes).forEach(node => {
    if (!node?.id || positions[node.id]) return
    if (Number.isFinite(Number(node.x)) && Number.isFinite(Number(node.y))) {
      const x = Number(node.x)
      const y = Number(node.y)
      positions[node.id] = [x <= 1 ? x * 800 : x, y <= 1 ? y * 600 : y]
    }
  })

  return {
    ...payload,
    nodes,
    edges: payload.edges || [],
    positions,
    statistics: payload.statistics || {},
  }
}

const fitPositionsToCanvas = (rawPositions = {}, width = 800, height = 500) => {
  const entries = Object.entries(rawPositions)
    .map(([id, pos]) => {
      const x = Array.isArray(pos) ? Number(pos[0]) : Number(pos?.x)
      const y = Array.isArray(pos) ? Number(pos[1]) : Number(pos?.y)
      return [id, [x, y]]
    })
    .filter(([, pos]) => Number.isFinite(pos[0]) && Number.isFinite(pos[1]))

  if (!entries.length) return {}
  if (entries.length === 1) return { [entries[0][0]]: [width / 2, height / 2] }

  const xs = entries.map(([, pos]) => pos[0])
  const ys = entries.map(([, pos]) => pos[1])
  const minX = Math.min(...xs)
  const maxX = Math.max(...xs)
  const minY = Math.min(...ys)
  const maxY = Math.max(...ys)
  const spanX = Math.max(maxX - minX, 1)
  const spanY = Math.max(maxY - minY, 1)
  const usableWidth = Math.max(width - GRAPH_PADDING * 2, 200)
  const usableHeight = Math.max(height - GRAPH_PADDING * 2, 160)

  return Object.fromEntries(
    entries.map(([id, pos]) => [
      id,
      [
        GRAPH_PADDING + ((pos[0] - minX) / spanX) * usableWidth,
        GRAPH_PADDING + ((pos[1] - minY) / spanY) * usableHeight,
      ],
    ]),
  )
}

export const InteractiveForensicGraph = ({ forensicData = {}, onNodeSelect = null }) => {
  const canvasRef = useRef(null)
  const containerRef = useRef(null)
  const animationRef = useRef(null)

  const [severityThreshold, setSeverityThreshold] = useState(DEFAULT_RISK_THRESHOLD)
  const [selectedNode, setSelectedNode] = useState(null)
  const [detailPanel, setDetailPanel] = useState(null)
  const [isLoading, setIsLoading] = useState(false)
  const [hoveredNode, setHoveredNode] = useState(null)
  const [graphData, setGraphData] = useState(null)
  const [error, setError] = useState(null)
  const replayVersion = `${forensicData?.timeline?.length || 0}:${forensicData?.evidence_stream?.length || 0}`

  const canvasState = useRef({
    nodes: {},
    edges: [],
    nodeList: [],
    pan: { x: 0, y: 0 },
    zoom: 1,
    isDragging: false,
    dragStart: { x: 0, y: 0 },
    rawPositions: {},
    positions: {},
    selectedNodes: new Set(),
  })

  const resizeCanvas = useCallback(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const host = canvas.parentElement
    const rect = host?.getBoundingClientRect()
    const width = Math.max(Math.floor(rect?.width || 900), 320)
    const height = Math.max(Math.floor(rect?.height || 460), 320)
    const dpr = window.devicePixelRatio || 1

    canvas.width = Math.floor(width * dpr)
    canvas.height = Math.floor(height * dpr)
    canvas.style.width = `${width}px`
    canvas.style.height = `${height}px`

    const ctx = canvas.getContext('2d')
    ctx?.setTransform(dpr, 0, 0, dpr, 0, 0)
    canvasState.current.positions = fitPositionsToCanvas(canvasState.current.rawPositions, width, height)
  }, [])

  useEffect(() => {
    const fetchGraph = async () => {
      setIsLoading(true)
      setError(null)
      try {
        const response = await api.getProvenanceGraph(severityThreshold)
        const normalized = normalizeGraphPayload(response.data)
        setGraphData(normalized)

        const nodes = normalized.nodes || {}
        const edges = normalized.edges || []
        const positions = normalized.positions || {}

        canvasState.current.nodes = nodes
        canvasState.current.edges = edges
        canvasState.current.nodeList = Object.values(nodes)
        canvasState.current.rawPositions = positions
      } catch (err) {
        const fallback = normalizeGraphPayload(forensicData?.attack_graph || {})
        if (fallback.nodes && Object.keys(fallback.nodes).length > 0) {
          setGraphData(fallback)
          canvasState.current.nodes = fallback.nodes
          canvasState.current.edges = fallback.edges || []
          canvasState.current.nodeList = Object.values(fallback.nodes)
          canvasState.current.rawPositions = fallback.positions || {}
        } else {
          setError(err.response?.data?.error || err.message)
        }
      } finally {
        setIsLoading(false)
      }
    }

    fetchGraph()
  }, [severityThreshold, replayVersion])

  useEffect(() => {
    const frame = window.requestAnimationFrame(resizeCanvas)
    window.addEventListener('resize', resizeCanvas)
    return () => {
      window.cancelAnimationFrame(frame)
      window.removeEventListener('resize', resizeCanvas)
    }
  }, [graphData, resizeCanvas])

  // Draw graph on canvas
  const drawGraph = useCallback(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const width = canvas.clientWidth || canvas.width
    const height = canvas.clientHeight || canvas.height
    const { nodeList, edges, positions, pan, zoom, selectedNodes } = canvasState.current

    ctx.fillStyle = 'rgba(6, 17, 28, 0.5)'
    ctx.fillRect(0, 0, width, height)

    ctx.save()
    ctx.translate(pan.x, pan.y)
    ctx.scale(zoom, zoom)

    edges.forEach(edge => {
      const startPos = positions[edge.source]
      const endPos = positions[edge.target]
      if (!startPos || !endPos) return

      const isSelectedEdge = selectedNodes.has(edge.source) || selectedNodes.has(edge.target)
      const isHoveredEdge = hoveredNode && (edge.source === hoveredNode || edge.target === hoveredNode)
      const color = isSelectedEdge
        ? '#FFD166'
        : isHoveredEdge
          ? 'rgba(139, 203, 255, 0.9)'
          : edge.temporal
            ? 'rgba(255, 100, 120, 0.6)'
            : 'rgba(57, 216, 255, 0.3)'
      const lineWidth = isSelectedEdge ? 3.5 : edge.temporal ? 2.5 : 1.5

      ctx.strokeStyle = color
      ctx.lineWidth = lineWidth / zoom
      ctx.lineCap = 'round'
      ctx.lineJoin = 'round'

      ctx.beginPath()
      ctx.moveTo(startPos[0], startPos[1])

      if (edge.temporal) {
        ctx.setLineDash([5, 5])
        ctx.lineTo(endPos[0], endPos[1])
        ctx.stroke()
        ctx.setLineDash([])

        const angle = Math.atan2(endPos[1] - startPos[1], endPos[0] - startPos[0])
        const arrowSize = 12
        ctx.fillStyle = isSelectedEdge ? '#FFD166' : 'rgba(255, 100, 120, 0.8)'
        ctx.beginPath()
        ctx.moveTo(endPos[0], endPos[1])
        ctx.lineTo(endPos[0] - arrowSize * Math.cos(angle - Math.PI / 6), endPos[1] - arrowSize * Math.sin(angle - Math.PI / 6))
        ctx.lineTo(endPos[0] - arrowSize * Math.cos(angle + Math.PI / 6), endPos[1] - arrowSize * Math.sin(angle + Math.PI / 6))
        ctx.closePath()
        ctx.fill()
      } else {
        ctx.lineTo(endPos[0], endPos[1])
        ctx.stroke()
      }

      const midX = (startPos[0] + endPos[0]) / 2
      const midY = (startPos[1] + endPos[1]) / 2
      ctx.font = `10px Segoe UI, system-ui, sans-serif`
      ctx.fillStyle = '#8BCBFF'
      ctx.textAlign = 'center'
      ctx.textBaseline = 'middle'
      ctx.fillText(edge.label || '', midX, midY)
    })

    nodeList.forEach(node => {
      const pos = positions[node.id]
      if (!pos) return

      const isSelected = selectedNodes.has(node.id)
      const isHovered = hoveredNode === node.id

      const baseRadius = node.kind === 'anomaly' ? 25 : 20
      const riskBonus = (node.risk || 0) * 15
      const radius = baseRadius + riskBonus

      let color = '#39D8FF'
      if (node.kind === 'anomaly') {
        const risk = node.risk || 0
        if (risk > 0.8) color = '#FF2E63'
        else if (risk > 0.6) color = '#FF6B6B'
        else if (risk > 0.4) color = '#FFA500'
        else color = '#FFD700'
      } else if (node.kind === 'target') {
        color = '#FF6478'
      }

      ctx.fillStyle = color
      ctx.beginPath()
      ctx.arc(pos[0], pos[1], radius / zoom, 0, Math.PI * 2)
      ctx.fill()

      if (isSelected || isHovered) {
        ctx.strokeStyle = isSelected ? '#39D8FF' : '#FFA500'
        ctx.lineWidth = (isSelected ? 3 : 2) / zoom
        ctx.stroke()
      }

      ctx.fillStyle = 'white'
      ctx.font = `bold 11px Segoe UI, system-ui, sans-serif`
      ctx.textAlign = 'center'
      ctx.textBaseline = 'middle'
      const nodeLabel = String(node.label || node.id || 'node')
      const label = nodeLabel.length > 12 ? `${nodeLabel.substring(0, 10)}..` : nodeLabel
      ctx.fillText(label, pos[0], pos[1])
    })

    ctx.restore()
  }, [hoveredNode])

  const selectGraphNode = useCallback(
    node => {
      if (!node) return
      setSelectedNode(node)
      setDetailPanel(node)
      canvasState.current.selectedNodes.clear()
      canvasState.current.selectedNodes.add(node.id)
      onNodeSelect?.(node)
    },
    [onNodeSelect],
  )

  const handleCanvasMouseDown = useCallback(
    e => {
      const canvas = canvasRef.current
      if (!canvas) return

      const rect = canvas.getBoundingClientRect()
      const x = (e.clientX - rect.left - canvasState.current.pan.x) / canvasState.current.zoom
      const y = (e.clientY - rect.top - canvasState.current.pan.y) / canvasState.current.zoom

      let clickedNode = null
      for (const node of canvasState.current.nodeList) {
        const pos = canvasState.current.positions[node.id]
        if (!pos) continue

        const baseRadius = node.kind === 'anomaly' ? 25 : 20
        const riskBonus = (node.risk || 0) * 15
        const radius = baseRadius + riskBonus

        const dist = Math.hypot(pos[0] - x, pos[1] - y)
        if (dist < radius * 1.2) {
          clickedNode = node
          break
        }
      }

      if (clickedNode && clickedNode.kind === 'anomaly') {
        selectGraphNode(clickedNode)
      } else {
        canvasState.current.isDragging = true
        canvasState.current.dragStart = { x: e.clientX, y: e.clientY }
      }
    },
    [selectGraphNode],
  )

  const handleCanvasMouseMove = useCallback(e => {
    if (canvasState.current.isDragging) {
      const dx = e.clientX - canvasState.current.dragStart.x
      const dy = e.clientY - canvasState.current.dragStart.y

      canvasState.current.pan.x += dx
      canvasState.current.pan.y += dy
      canvasState.current.dragStart = { x: e.clientX, y: e.clientY }
    }

    const canvas = canvasRef.current
    if (!canvas) return

    const rect = canvas.getBoundingClientRect()
    const x = (e.clientX - rect.left - canvasState.current.pan.x) / canvasState.current.zoom
    const y = (e.clientY - rect.top - canvasState.current.pan.y) / canvasState.current.zoom

    let hoveredNodeId = null
    for (const node of canvasState.current.nodeList) {
      const pos = canvasState.current.positions[node.id]
      if (!pos) continue

      const baseRadius = node.kind === 'anomaly' ? 25 : 20
      const riskBonus = (node.risk || 0) * 15
      const radius = baseRadius + riskBonus

      const dist = Math.hypot(pos[0] - x, pos[1] - y)
      if (dist < radius * 1.2) {
        hoveredNodeId = node.id
        break
      }
    }

    setHoveredNode(hoveredNodeId)
  }, [])

  const handleCanvasMouseUp = useCallback(() => {
    canvasState.current.isDragging = false
  }, [])

  const handleCanvasWheel = useCallback(
    e => {
      e.preventDefault()
      const zoomFactor = e.deltaY > 0 ? 0.9 : 1.1
      const newZoom = Math.max(0.5, Math.min(3, canvasState.current.zoom * zoomFactor))
      canvasState.current.zoom = newZoom
    },
    [],
  )

  useEffect(() => {
    const animate = () => {
      drawGraph()
      animationRef.current = requestAnimationFrame(animate)
    }

    animationRef.current = requestAnimationFrame(animate)
    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current)
      }
    }
  }, [drawGraph])

  const handleResetView = () => {
    canvasState.current.pan = { x: 0, y: 0 }
    canvasState.current.zoom = 1
    canvasState.current.selectedNodes.clear()
    setSelectedNode(null)
    setDetailPanel(null)
  }

  if (error) {
    return (
      <div className="provenance-graph-container">
        <div className="graph-empty">
          <div className="text-5xl">!</div>
          <div>Error loading graph: {error}</div>
        </div>
      </div>
    )
  }

  if (isLoading) {
    return (
      <div className="provenance-graph-container">
        <div className="graph-empty">
          <div className="text-2xl">Loading...</div>
        </div>
      </div>
    )
  }

  if (!graphData || !graphData.nodes || Object.keys(graphData.nodes).length === 0) {
    return (
      <div className="provenance-graph-container">
        <div className="graph-empty">
          <div className="text-5xl">No Graph</div>
          <div>No anomalous events to display</div>
          <div className="text-xs text-bluebox-muted">Lower the minimum risk or generate anomaly evidence</div>
        </div>
      </div>
    )
  }

  const stats = graphData.statistics || {}
  const topAnomalyNodes = Object.values(graphData.nodes || {})
    .filter(node => node.kind === 'anomaly')
    .sort((a, b) => (b.risk || 0) - (a.risk || 0))
    .slice(0, 6)

  return (
    <div className="provenance-graph-container" ref={containerRef}>
      <div className="provenance-graph-controls">
        <div className="graph-filter-group">
          <label>Minimum Risk</label>
          <div className="graph-range-input">
            <input
              type="range"
              className="graph-range-slider"
              min="0"
              max="1"
              step="0.1"
              value={severityThreshold}
              onChange={e => setSeverityThreshold(parseFloat(e.target.value))}
            />
            <span className="graph-range-value">{(severityThreshold * 100).toFixed(0)}%</span>
          </div>
        </div>

        <div className="graph-filter-group graph-top-node-group">
          <label>Top Anomaly Nodes</label>
          <div className="graph-top-node-list">
            {topAnomalyNodes.map(node => (
              <button
                key={node.id}
                type="button"
                className={`graph-top-node ${selectedNode?.id === node.id ? 'active' : ''}`}
                onClick={() => selectGraphNode(node)}
              >
                <span>{node.label}</span>
                <strong>{((node.risk || 0) * 100).toFixed(0)}</strong>
              </button>
            ))}
          </div>
        </div>

        <div className="graph-filter-group" style={{ alignContent: 'flex-end' }}>
          <button
            onClick={handleResetView}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm font-medium transition"
          >
            Reset View
          </button>
        </div>
      </div>

      <div className="provenance-graph-canvas-container">
        <canvas
          ref={canvasRef}
          className="provenance-graph-canvas"
          onMouseDown={handleCanvasMouseDown}
          onMouseMove={handleCanvasMouseMove}
          onMouseUp={handleCanvasMouseUp}
          onMouseLeave={handleCanvasMouseUp}
          onWheel={handleCanvasWheel}
          style={{ cursor: canvasState.current.isDragging ? 'grabbing' : 'grab' }}
        />

        {detailPanel && (
          <div className="node-detail-panel">
            <button
              type="button"
              className="detail-panel-close"
              onClick={() => setDetailPanel(null)}
              aria-label="Close node details"
            >
              X
            </button>

            <div className="detail-panel-header">
              <div className="detail-panel-title">
                <span className={`detail-panel-kind kind-${detailPanel.kind}`}>{detailPanel.kind}</span>
                <span>{detailPanel.label}</span>
              </div>
            </div>

            {detailPanel.kind === 'anomaly' && (
              <>
                <div className="detail-panel-row">
                  <span className="detail-panel-label">Risk Score</span>
                  <div
                    className="detail-risk-badge"
                    style={{
                      background:
                        detailPanel.risk > 0.8 ? '#FF2E63' : detailPanel.risk > 0.6 ? '#FF6B6B' : '#FFA500',
                    }}
                  >
                    {((detailPanel.risk || 0) * 100).toFixed(0)}
                  </div>
                </div>

                <div className="detail-panel-row">
                  <span className="detail-panel-label">Severity</span>
                  <span className="detail-panel-value">{detailPanel.severity}</span>
                </div>

                <div className="detail-panel-row">
                  <span className="detail-panel-label">Anomaly Score</span>
                  <span className="detail-panel-value">
                    {Number(detailPanel.anomaly_score || 0).toFixed(4)}
                  </span>
                </div>

                {detailPanel.occurred_at && (
                  <div className="detail-panel-row">
                    <span className="detail-panel-label">Occurred At</span>
                    <span className="detail-panel-value">{formatTime(detailPanel.occurred_at)}</span>
                  </div>
                )}

                {detailPanel.explanation && (
                  <div className="detail-panel-row">
                    <span className="detail-panel-label">Explanation</span>
                    <span className="detail-panel-value" style={{ fontSize: '11px', lineHeight: '1.3' }}>
                      {detailPanel.explanation}
                    </span>
                  </div>
                )}
              </>
            )}

            {detailPanel.summary && (
              <div className="detail-panel-row">
                <span className="detail-panel-label">Summary</span>
                <span className="detail-panel-value">{detailPanel.summary}</span>
              </div>
            )}
          </div>
        )}
      </div>

      <div className="provenance-graph-legend">
        <div className="legend-item">
          <div className="legend-box" style={{ background: '#39D8FF' }} />
          <span>Source</span>
        </div>
        <div className="legend-item">
          <div className="legend-box" style={{ background: '#FFD700' }} />
          <span>Low Risk</span>
        </div>
        <div className="legend-item">
          <div className="legend-box" style={{ background: '#FFA500' }} />
          <span>Medium Risk</span>
        </div>
        <div className="legend-item">
          <div className="legend-box" style={{ background: '#FF6B6B' }} />
          <span>High Risk</span>
        </div>
        <div className="legend-item">
          <div className="legend-box" style={{ background: '#FF2E63' }} />
          <span>Critical</span>
        </div>
        <div className="legend-item">
          <div className="legend-box" style={{ background: '#FF6478' }} />
          <span>Target</span>
        </div>
        <div className="legend-item">
          <div className="legend-line" style={{ background: 'rgba(255, 100, 120, 0.6)' }} />
          <span>Temporal</span>
        </div>
      </div>

      {stats && (
        <div className="graph-stats-panel">
          <div className="stat-item">
            <div className="stat-value">{stats.total_nodes || 0}</div>
            <div className="stat-label">Total Nodes</div>
          </div>
          <div className="stat-item">
            <div className="stat-value">{stats.anomalies || 0}</div>
            <div className="stat-label">Anomalies</div>
          </div>
          <div className="stat-item">
            <div className="stat-value">{stats.critical_anomalies || 0}</div>
            <div className="stat-label">Critical</div>
          </div>
          <div className="stat-item">
            <div className="stat-value">{((stats.max_risk || 0) * 100).toFixed(0)}%</div>
            <div className="stat-label">Max Risk</div>
          </div>
          <div className="stat-item">
            <div className="stat-value">{stats.total_edges || 0}</div>
            <div className="stat-label">Relationships</div>
          </div>
          <div className="stat-item">
            <div className="stat-value">{((stats.avg_risk || 0) * 100).toFixed(0)}%</div>
            <div className="stat-label">Avg Risk</div>
          </div>
        </div>
      )}
    </div>
  )
}

export default InteractiveForensicGraph
