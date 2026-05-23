import React, { useRef, useEffect, useState, useCallback } from 'react'
import { api } from '@/api/client'
import './ProvenanceGraph.css'

/**
 * Interactive Canvas-based Provenance Graph
 * Renders networkx graph data with domain-based colors and inline hover info
 * Features:
 * - Domain-based node coloring (avionics, afdx, cabin, maintenance, integrity)
 * - Physics-based force layout from backend
 * - Inline hover tooltips (no modals)
 * - Click to pin details panel
 * - Zoom and pan controls
 */

const DOMAIN_COLORS = {
  avionics: '#7dd3fc',
  afdx: '#38bdf8',
  cabin: '#f0abfc',
  maintenance: '#fbbf24',
  integrity: '#fb7185',
  unknown: '#94a3b8',
}

const NODE_TYPE_COLORS = {
  source: '#e8f7ff',
  anomaly: '#ff69b4',
  target: '#90ee90',
  event: '#ffe4b5',
  process: '#87ceeb',
  file: '#d3d3d3',
  network: '#ff6347',
}

const RISK_THRESHOLDS = {
  CRITICAL: 1.0,
  HIGH: 0.85,
  MEDIUM: 0.65,
  WARNING: 0.7,
  ANOMALY: 0.6,
  LOW: 0.4,
  INFO: 0.15,
}

export const ProvenanceGraphCanvas = ({
  forensicData = {},
  onNodeSelect = null,
  onExport = null,
}) => {
  const canvasRef = useRef(null)
  const containerRef = useRef(null)
  const animationRef = useRef(null)

  const [graphData, setGraphData] = useState(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState(null)
  const [hoveredNode, setHoveredNode] = useState(null)
  const [selectedNode, setSelectedNode] = useState(null)
  const [detailPanel, setDetailPanel] = useState(null)

  const canvasState = useRef({
    nodes: [],
    edges: [],
    positions: {},
    pan: { x: 0, y: 0 },
    zoom: 1,
    isDragging: false,
    dragStart: { x: 0, y: 0 },
  })

  // Fetch graph data from backend
  const fetchGraphData = useCallback(async () => {
    setIsLoading(true)
    setError(null)
    try {
      const response = await api.getProvenanceGraphFiltered({})
      setGraphData(response.data)
      if (response.data.nodes) {
        canvasState.current.nodes = Array.isArray(response.data.nodes)
          ? response.data.nodes
          : Object.values(response.data.nodes || {})
        canvasState.current.edges = response.data.edges || response.data.links || []
        canvasState.current.positions = response.data.positions || {}
      }
    } catch (err) {
      setError(`Failed to fetch provenance graph: ${err.message}`)
      console.error('Graph fetch error:', err)
    } finally {
      setIsLoading(false)
    }
  }, [])

  // Initial fetch
  useEffect(() => {
    fetchGraphData()
  }, [fetchGraphData])

  // Resize canvas
  const resizeCanvas = useCallback(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const container = containerRef.current
    const width = container?.clientWidth || 1000
    const height = container?.clientHeight || 600
    const dpr = window.devicePixelRatio || 1

    canvas.width = Math.floor(width * dpr)
    canvas.height = Math.floor(height * dpr)
    canvas.style.width = `${width}px`
    canvas.style.height = `${height}px`

    const ctx = canvas.getContext('2d')
    if (ctx) ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
  }, [])

  useEffect(() => {
    resizeCanvas()
    window.addEventListener('resize', resizeCanvas)
    return () => window.removeEventListener('resize', resizeCanvas)
  }, [resizeCanvas])

  // Get node color based on domain/risk
  const getNodeColor = (node) => {
    if (node.kind === 'anomaly') {
      const risk = node.risk || 0
      if (risk > 0.8) return '#ff2e63'
      if (risk > 0.6) return '#ff6b6b'
      if (risk > 0.4) return '#ffa500'
      return '#ffd700'
    }
    const domain = node.domain || node.kind || 'unknown'
    return DOMAIN_COLORS[domain] || NODE_TYPE_COLORS[node.kind] || '#94a3b8'
  }

  // Draw graph on canvas
  const drawGraph = useCallback(() => {
    const canvas = canvasRef.current
    if (!canvas || !graphData) return

    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const width = canvas.clientWidth || 1000
    const height = canvas.clientHeight || 600
    const { nodes, edges, positions, pan, zoom } = canvasState.current

    // Clear canvas
    ctx.fillStyle = '#06111c'
    ctx.fillRect(0, 0, width, height)

    ctx.save()
    ctx.translate(pan.x, pan.y)
    ctx.scale(zoom, zoom)

    // Draw edges first
    edges.forEach(edge => {
      const sourcePos = positions[edge.source]
      const targetPos = positions[edge.target]
      if (!sourcePos || !targetPos) return

      const isSelected = selectedNode === edge.source || selectedNode === edge.target
      const isHovered = hoveredNode === edge.source || hoveredNode === edge.target

      ctx.strokeStyle = isSelected ? '#ffd166' : isHovered ? 'rgba(139, 203, 255, 0.8)' : 'rgba(57, 216, 255, 0.4)'
      ctx.lineWidth = isSelected ? 2.5 : isHovered ? 2 : 1.5
      ctx.lineCap = 'round'
      ctx.lineJoin = 'round'

      ctx.beginPath()
      ctx.moveTo(sourcePos[0], sourcePos[1])
      ctx.lineTo(targetPos[0], targetPos[1])
      ctx.stroke()

      // Arrow
      const angle = Math.atan2(targetPos[1] - sourcePos[1], targetPos[0] - sourcePos[0])
      const arrowSize = 10
      ctx.fillStyle = ctx.strokeStyle
      ctx.beginPath()
      ctx.moveTo(targetPos[0], targetPos[1])
      ctx.lineTo(targetPos[0] - arrowSize * Math.cos(angle - Math.PI / 6), targetPos[1] - arrowSize * Math.sin(angle - Math.PI / 6))
      ctx.lineTo(targetPos[0] - arrowSize * Math.cos(angle + Math.PI / 6), targetPos[1] - arrowSize * Math.sin(angle + Math.PI / 6))
      ctx.closePath()
      ctx.fill()

      // Edge label
      ctx.font = '10px Segoe UI, system-ui, sans-serif'
      ctx.fillStyle = '#8bcbff'
      ctx.textAlign = 'center'
      ctx.textBaseline = 'middle'
      const midX = (sourcePos[0] + targetPos[0]) / 2
      const midY = (sourcePos[1] + targetPos[1]) / 2
      ctx.fillText(edge.label || '', midX, midY)
    })

    // Draw nodes
    nodes.forEach(node => {
      const pos = positions[node.id]
      if (!pos) return

      const isSelected = selectedNode === node.id
      const isHovered = hoveredNode === node.id
      const baseRadius = 20
      const riskBonus = (node.risk || 0) * 10

      const radius = baseRadius + riskBonus
      const color = getNodeColor(node)

      // Node circle
      ctx.fillStyle = color
      ctx.strokeStyle = isSelected ? '#ffd166' : isHovered ? '#39d8ff' : 'white'
      ctx.lineWidth = isSelected ? 3 : isHovered ? 2 : 1.5
      ctx.beginPath()
      ctx.arc(pos[0], pos[1], radius, 0, Math.PI * 2)
      ctx.fill()
      ctx.stroke()

      // Node label
      ctx.fillStyle = '#06111c'
      ctx.font = 'bold 11px Segoe UI, system-ui, sans-serif'
      ctx.textAlign = 'center'
      ctx.textBaseline = 'middle'
      const label = node.label ? node.label.substring(0, 15) : node.id.substring(0, 8)
      ctx.fillText(label, pos[0], pos[1])
    })

    ctx.restore()

    // Draw inline tooltip on hover
    if (hoveredNode && graphData) {
      const node = graphData.nodes.find(n => n.id === hoveredNode)
      if (node) {
        const pos = canvasState.current.positions[hoveredNode]
        if (pos) {
          const tooltipWidth = 280
          const tooltipHeight = 120
          const tooltipX = pos[0] * zoom + pan.x
          const tooltipY = pos[1] * zoom + pan.y + 40

          // Tooltip background
          ctx.fillStyle = 'rgba(6, 17, 28, 0.95)'
          ctx.strokeStyle = '#39d8ff'
          ctx.lineWidth = 2
          ctx.fillRect(tooltipX, tooltipY, tooltipWidth, tooltipHeight)
          ctx.strokeRect(tooltipX, tooltipY, tooltipWidth, tooltipHeight)

          // Tooltip text
          ctx.fillStyle = '#e8f7ff'
          ctx.font = 'bold 12px Segoe UI, system-ui, sans-serif'
          ctx.textAlign = 'left'
          ctx.fillText(node.label || node.id, tooltipX + 10, tooltipY + 20)

          ctx.font = '10px Segoe UI, system-ui, sans-serif'
          ctx.fillStyle = '#91aec5'
          const details = [
            `Type: ${node.kind || 'unknown'}`,
            `Domain: ${node.domain || 'N/A'}`,
            `Risk: ${(node.risk || 0).toFixed(2)}`,
            node.severity ? `Severity: ${node.severity}` : '',
          ].filter(Boolean)
          details.forEach((detail, idx) => {
            ctx.fillText(detail, tooltipX + 10, tooltipY + 35 + idx * 15)
          })
        }
      }
    }
  }, [graphData, selectedNode, hoveredNode])

  // Mouse event handlers
  const handleCanvasMouseMove = useCallback(
    e => {
      if (!canvasRef.current || !graphData) return

      const rect = canvasRef.current.getBoundingClientRect()
      const x = (e.clientX - rect.left - canvasState.current.pan.x) / canvasState.current.zoom
      const y = (e.clientY - rect.top - canvasState.current.pan.y) / canvasState.current.zoom

      const { nodes, positions } = canvasState.current
      let foundNode = null

      for (const node of nodes) {
        const pos = positions[node.id]
        if (!pos) continue

        const baseRadius = 20
        const riskBonus = (node.risk || 0) * 10
        const radius = baseRadius + riskBonus

        const dist = Math.hypot(pos[0] - x, pos[1] - y)
        if (dist < radius * 1.2) {
          foundNode = node.id
          break
        }
      }

      setHoveredNode(foundNode)

      if (canvasState.current.isDragging) {
        canvasState.current.pan.x += e.clientX - canvasState.current.dragStart.x
        canvasState.current.pan.y += e.clientY - canvasState.current.dragStart.y
        canvasState.current.dragStart = { x: e.clientX, y: e.clientY }
      }
    },
    [graphData]
  )

  const handleCanvasMouseDown = useCallback(e => {
    canvasState.current.isDragging = true
    canvasState.current.dragStart = { x: e.clientX, y: e.clientY }
  }, [])

  const handleCanvasMouseUp = useCallback(e => {
    canvasState.current.isDragging = false
  }, [])

  const handleCanvasClick = useCallback(e => {
    if (!canvasRef.current || !graphData) return

    const rect = canvasRef.current.getBoundingClientRect()
    const x = (e.clientX - rect.left - canvasState.current.pan.x) / canvasState.current.zoom
    const y = (e.clientY - rect.top - canvasState.current.pan.y) / canvasState.current.zoom

    const { nodes, positions } = canvasState.current
    for (const node of nodes) {
      const pos = positions[node.id]
      if (!pos) continue

      const baseRadius = 20
      const riskBonus = (node.risk || 0) * 10
      const radius = baseRadius + riskBonus

      const dist = Math.hypot(pos[0] - x, pos[1] - y)
      if (dist < radius * 1.2) {
        setSelectedNode(node.id)
        setDetailPanel(node)
        onNodeSelect?.(node)
        break
      }
    }
  }, [graphData, onNodeSelect])

  useEffect(() => {
    const canvas = canvasRef.current
    if (canvas) {
      canvas.addEventListener('mousemove', handleCanvasMouseMove)
      canvas.addEventListener('mousedown', handleCanvasMouseDown)
      canvas.addEventListener('mouseup', handleCanvasMouseUp)
      canvas.addEventListener('click', handleCanvasClick)

      return () => {
        canvas.removeEventListener('mousemove', handleCanvasMouseMove)
        canvas.removeEventListener('mousedown', handleCanvasMouseDown)
        canvas.removeEventListener('mouseup', handleCanvasMouseUp)
        canvas.removeEventListener('click', handleCanvasClick)
      }
    }
  }, [handleCanvasMouseMove, handleCanvasMouseDown, handleCanvasMouseUp, handleCanvasClick])

  // Animation loop
  useEffect(() => {
    const animate = () => {
      drawGraph()
      animationRef.current = requestAnimationFrame(animate)
    }
    animationRef.current = requestAnimationFrame(animate)
    return () => cancelAnimationFrame(animationRef.current)
  }, [drawGraph])

  if (isLoading) {
    return <div className="flex items-center justify-center h-full text-bluebox-muted">Loading provenance graph...</div>
  }

  if (error) {
    return <div className="flex items-center justify-center h-full text-bluebox-red">{error}</div>
  }

  return (
    <div className="provenance-graph-container flex flex-col h-full" ref={containerRef}>
      <canvas
        ref={canvasRef}
        className="provenance-graph-canvas flex-1"
        style={{ cursor: hoveredNode ? 'pointer' : 'grab' }}
      />

      {/* Inline Detail Panel (Right Side) */}
      {detailPanel && (
        <div className="absolute bottom-4 right-4 card-panel w-80 max-h-96 overflow-y-auto bg-bluebox-panel border-l-4 border-bluebox-cyan">
          <div className="flex justify-between items-start mb-4">
            <h3 className="text-heading-2 text-bluebox-cyan">{detailPanel.label || detailPanel.id}</h3>
            <button
              onClick={() => {
                setDetailPanel(null)
                setSelectedNode(null)
              }}
              className="text-bluebox-muted hover:text-bluebox-text text-lg"
            >
              ✕
            </button>
          </div>

          <div className="space-y-2 text-xs">
            <div>
              <span className="text-bluebox-muted font-semibold">Type:</span>{' '}
              <span className="text-bluebox-text">{detailPanel.kind || 'unknown'}</span>
            </div>
            <div>
              <span className="text-bluebox-muted font-semibold">Domain:</span>{' '}
              <span className="text-bluebox-text">{detailPanel.domain || 'N/A'}</span>
            </div>
            <div>
              <span className="text-bluebox-muted font-semibold">Risk Score:</span>{' '}
              <span
                className={
                  (detailPanel.risk || 0) > 0.7 ? 'text-bluebox-red' : 'text-bluebox-green'
                }
              >
                {(detailPanel.risk || 0).toFixed(3)}
              </span>
            </div>
            {detailPanel.severity && (
              <div>
                <span className="text-bluebox-muted font-semibold">Severity:</span>{' '}
                <span
                  className={
                    detailPanel.severity === 'CRITICAL'
                      ? 'text-bluebox-red'
                      : detailPanel.severity === 'HIGH'
                        ? 'text-orange-400'
                        : 'text-bluebox-green'
                  }
                >
                  {detailPanel.severity}
                </span>
              </div>
            )}
            {detailPanel.source_component && (
              <div>
                <span className="text-bluebox-muted font-semibold">Source:</span>{' '}
                <span className="text-bluebox-text font-mono text-xs">{detailPanel.source_component}</span>
              </div>
            )}
            {detailPanel.target_component && (
              <div>
                <span className="text-bluebox-muted font-semibold">Target:</span>{' '}
                <span className="text-bluebox-text font-mono text-xs">{detailPanel.target_component}</span>
              </div>
            )}
            {detailPanel.description && (
              <div>
                <span className="text-bluebox-muted font-semibold">Description:</span>
                <p className="text-bluebox-text text-xs mt-1 leading-relaxed">{detailPanel.description}</p>
              </div>
            )}
            {detailPanel.metadata && (
              <pre className="text-xs bg-bluebox-dark p-2 rounded overflow-auto text-bluebox-muted">
                {JSON.stringify(detailPanel.metadata, null, 2)}
              </pre>
            )}
          </div>
        </div>
      )}

      {/* Graph Legend */}
      <div className="absolute top-4 left-4 bg-bluebox-panel p-3 rounded border border-bluebox-cyan text-xs space-y-1">
        <div className="text-bluebox-cyan font-semibold mb-2">Domains</div>
        {Object.entries(DOMAIN_COLORS).map(([domain, color]) => (
          <div key={domain} className="flex items-center gap-2">
            <div
              className="w-3 h-3 rounded-full border border-white"
              style={{ backgroundColor: color }}
            />
            <span className="text-bluebox-text capitalize">{domain}</span>
          </div>
        ))}
      </div>

      {/* Graph Stats */}
      {graphData && (
        <div className="absolute top-4 right-4 bg-bluebox-panel p-3 rounded border border-bluebox-cyan text-xs text-bluebox-muted">
          <div className="text-bluebox-cyan font-semibold mb-2">Graph Stats</div>
          <div>Nodes: {graphData.node_count || 0}</div>
          <div>Edges: {graphData.edge_count || 0}</div>
        </div>
      )}
    </div>
  )
}
