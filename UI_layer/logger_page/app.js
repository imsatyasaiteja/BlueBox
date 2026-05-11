const state = {
  status: null,
  anomaly: null,
  replay: null,
  graph: {
    nodes: [],
    edges: [],
    layout_engine: "python",
    hovered: null,
    selected: null,
  },
  busy: false,
  activeSection: document.body.dataset.page || "anomaly",
  warnedCapability: false,
};

const $ = (id) => document.getElementById(id);
const setText = (id, value) => {
  const node = $(id);
  if (node) node.textContent = value;
};
const on = (id, eventName, handler) => {
  const node = $(id);
  if (node) node.addEventListener(eventName, handler);
};
const DEMO_EVENT_KEY = "bluebox:lastDemoRun";

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || response.statusText);
  }
  return payload;
}

function setBusy(value) {
  state.busy = value;
  document.querySelectorAll("button").forEach((button) => {
    button.disabled = value;
  });
}

function toast(message) {
  const node = $("toast");
  node.textContent = message;
  node.classList.add("show");
  window.clearTimeout(toast.timer);
  toast.timer = window.setTimeout(() => node.classList.remove("show"), 3000);
}

function shortHash(value) {
  if (!value || value === "-") return "-";
  return `${value.slice(0, 12)}...${value.slice(-12)}`;
}

function formatFailure(value) {
  if (!value) return "none";
  return JSON.stringify(value, null, 2);
}

function chainFailed(status) {
  return status.status === "failed" || status.trusted_readiness?.checks?.chain_verified === false;
}

function displayAnchorStatus(status) {
  const anchor = status.anchor || {};
  if (status.display_status?.anchor) return status.display_status.anchor;
  if (chainFailed(status)) return "not trusted";
  return anchor.status || "missing";
}

function displayRecoveryStatus(status) {
  const ledger = status.recovery_ledger || {};
  if (status.display_status?.recovery_ledger) return status.display_status.recovery_ledger;
  if (chainFailed(status) && ledger.ok) return "restore ready";
  return ledger.status || "missing";
}

function fmtNumber(value, digits = 3) {
  const number = Number(value || 0);
  return Number.isFinite(number) ? number.toFixed(digits) : "0.000";
}

function formatReplayTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function formatReplayDateTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return `${date.toLocaleDateString()} ${date.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  })}`;
}

function emptyAnomalySummary(totalEntries = 0) {
  return {
    total_entries: totalEntries,
    total_ai_records: 0,
    anomalies: 0,
    normal: 0,
    security_events_count: 0,
    total_alerts: 0,
    min_score: 0,
    max_score: 0,
    severity_counts: {},
    latest_checkpoint: null,
    records: [],
    score_trace: [],
    ranked_anomalies: [],
    security_events: [],
  };
}

async function refresh() {
  const status = await api("/api/status");
  const trusted = Boolean(status.trusted_readiness?.trusted);
  const needsAnomaly = state.activeSection === "anomaly";
  const anomaly = trusted && needsAnomaly
    ? await api("/api/anomaly")
    : emptyAnomalySummary(status.total_entries ?? 0);
  state.status = status;
  state.anomaly = anomaly;
  renderStatus(status, anomaly);

  if (!trusted) {
    if (state.activeSection === "anomaly") {
      renderAnomaly(anomaly, "Trusted readiness gate is not satisfied.");
    }
    if (state.activeSection === "replay") {
      renderReplay({ timeline: [], evidence_stream: [], attack_graph: { nodes: [], edges: [] }, composition: {} });
      renderReplayEvidenceStream([], "Evidence hidden until chain, recovery evidence, AI evidence, and checkpoints verify.");
    }
    return;
  }

  if (state.activeSection === "anomaly") {
    renderAnomaly(anomaly);
  }

  if (state.activeSection !== "replay") {
    return;
  }

  const replay = await api("/api/replay");
  state.replay = replay;
  renderReplay(replay);
  renderReplayEvidenceStream(replay.evidence_stream || []);
}

function renderStatus(status, anomaly) {
  const pill = $("statusPill");
  if (pill) {
    pill.textContent = status.status || "unknown";
    pill.className = `status-pill ${status.status || ""}`;
  }

  const healthCore = $("healthCore");
  const healthText = status.status === "verified" ? "OK" : status.status === "failed" ? "FAIL" : "IDLE";
  if (healthCore) {
    healthCore.textContent = healthText;
    healthCore.className = `orbit-core ${status.status || ""}`;
  }

  setText("totalEntries", status.total_entries ?? 0);
  setText("checkedEntries", status.checked_entries ?? 0);
  setText("anchorStatus", displayAnchorStatus(status));
  setText("ledgerStatus", displayRecoveryStatus(status));
  setText("headSequence", status.head?.sequence ?? 0);
  setText("headHash", status.head?.head_hash || "-");
  setText("failure", formatFailure(status.first_failure || status.trusted_readiness?.checks));
  const capabilityReady = status.demo_capabilities?.demo_attaches_ai_evidence === true;
  setText(
    "dbLine",
    capabilityReady
      ? `Entries ${status.total_entries ?? 0} | AI evidence ${anomaly.total_ai_records ?? 0} | ${status.status || "unknown"}`
      : "Server restart required: demo API is not advertising AI evidence attachment.",
  );
  if (!capabilityReady && !state.warnedCapability) {
    state.warnedCapability = true;
    toast("Restart the API server to load the AI evidence demo pipeline.");
  }

  setText("sideChain", status.status || "unknown");
  setText("sideAnomalies", anomaly.anomalies ?? 0);
  setText("sideTrusted", String(Boolean(status.trusted_readiness?.trusted)));
  drawChainGauge(status);
}

function renderAnomaly(anomaly, gateMessage = "") {
  setText("totalEntries", anomaly.total_entries ?? state.status?.total_entries ?? 0);
  setText("aiEvidenceCount", anomaly.total_ai_records ?? 0);
  setText("aiAnomalyCount", anomaly.total_alerts ?? anomaly.anomalies ?? 0);
  setText("aiMaxScore", fmtNumber(anomaly.min_score));
  setText("aiCheckpointCount", anomaly.latest_checkpoint?.batch_size ?? 0);

  const ranked = anomaly.ranked_anomalies || [];
  drawScoreChart(anomaly.score_trace || anomaly.records || []);
  drawSeverityPie(anomaly);
  renderFlaggedAnomalies(ranked, anomaly.security_events || [], gateMessage);
}

function renderFlaggedAnomalies(rankedAnomalies, securityEvents = [], gateMessage = "") {
  const list = $("flaggedAnomalies");
  if (!list) return;
  list.replaceChildren();
  const flagged = (rankedAnomalies || [])
    .filter((item) => Number(item.predicted_anomaly) === 1)
    .sort((a, b) => Number(a.anomaly_score || 0) - Number(b.anomaly_score || 0));

  if (!flagged.length && !securityEvents.length) {
    list.innerHTML = `
      <div class="alert-card empty-alert">
        <strong>No flagged anomalies attached</strong>
        <span>${gateMessage || "Current evidence set has no AI anomaly or logger security alert."}</span>
      </div>
    `;
    return;
  }

  for (const item of flagged.slice(0, 30)) {
    const node = document.createElement("div");
    node.className = "alert-card";
    const drivers = (item.top_features || []).join(" / ") || "drivers unavailable";
    node.innerHTML = `
      <div class="alert-score">${fmtNumber(item.anomaly_score)}</div>
      <div>
        <strong>${item.severity || "ANOMALY"} | AI anomaly | seq #${item.sequence}</strong>
        <span><b class="shap-keyword">SHAP Driver</b> ${item.explanation || "Model verdict exceeded anomaly threshold."}</span>
        <small>${drivers} | evidence #${item.evidence_id}</small>
      </div>
    `;
    list.appendChild(node);
  }

  for (const item of securityEvents.slice(0, 12)) {
    const node = document.createElement("div");
    node.className = "alert-card security-alert";
    const detail = item.details?.operation
      ? `${item.details.operation} attempt against sequence #${item.details.target_sequence || "latest"}`
      : item.event || "security event";
    node.innerHTML = `
      <div class="alert-score">SEC</div>
      <div>
        <strong>${item.severity || "HIGH"} | logger security event | seq #${item.sequence}</strong>
        <span>${detail}</span>
        <small>${item.event || "security_event"}</small>
      </div>
    `;
    list.appendChild(node);
  }
}

function drawScoreChart(records) {
  const canvas = $("scoreChart");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const width = canvas.width;
  const height = canvas.height;
  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = "#03101b";
  ctx.fillRect(0, 0, width, height);

  const left = 72;
  const right = 28;
  const top = 24;
  const bottom = 76;
  const plotWidth = width - left - right;
  const plotHeight = height - top - bottom;

  ctx.strokeStyle = "rgba(139,203,255,0.16)";
  ctx.lineWidth = 1;
  for (let x = left; x <= width - right; x += plotWidth / 5) {
    ctx.beginPath();
    ctx.moveTo(x, top);
    ctx.lineTo(x, top + plotHeight);
    ctx.stroke();
  }
  for (let y = top; y <= top + plotHeight; y += plotHeight / 4) {
    ctx.beginPath();
    ctx.moveTo(left, y);
    ctx.lineTo(width - right, y);
    ctx.stroke();
  }
  ctx.strokeStyle = "rgba(232,247,255,0.42)";
  ctx.beginPath();
  ctx.moveTo(left, top);
  ctx.lineTo(left, top + plotHeight);
  ctx.lineTo(width - right, top + plotHeight);
  ctx.stroke();

  if (!records.length) {
    ctx.fillStyle = "#91aec5";
    ctx.font = "18px Segoe UI";
    ctx.fillText("No AI score data yet", left + 8, height / 2);
    return;
  }

  const sampleStep = Math.max(1, Math.ceil(records.length / 160));
  const plotted = records.filter((_, index) => index % sampleStep === 0);
  const values = plotted.map((record) => Number(record.anomaly_score || 0));
  let min = Math.min(...values);
  let max = Math.max(...values);
  if (min === max) {
    min -= 0.01;
    max += 0.01;
  }
  const padding = Math.max((max - min) * 0.12, 0.005);
  min -= padding;
  max += padding;
  const span = max - min;
  const step = plotWidth / Math.max(1, plotted.length - 1);
  const point = (value, index) => [
    left + index * step,
    top + (value - min) / span * plotHeight,
  ];

  ctx.strokeStyle = "#39d8ff";
  ctx.lineWidth = 3;
  ctx.beginPath();
  plotted.forEach((record, index) => {
    const [x, y] = point(Number(record.anomaly_score || 0), index);
    if (index === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();

  for (let index = 0; index < plotted.length; index += 1) {
    const record = plotted[index];
    const [x, y] = point(Number(record.anomaly_score || 0), index);
    ctx.fillStyle = Number(record.predicted_anomaly) ? "#ff6478" : "#16f0c5";
    ctx.beginPath();
    ctx.arc(x, y, Number(record.predicted_anomaly) ? 5 : 3, 0, Math.PI * 2);
    ctx.fill();
  }

  ctx.fillStyle = "#91aec5";
  ctx.font = "12px Segoe UI";
  ctx.textAlign = "right";
  for (let index = 0; index <= 4; index += 1) {
    const value = min + (span * index) / 4;
    const y = top + (plotHeight * index) / 4 + 4;
    ctx.fillText(value.toFixed(3), left - 10, y);
  }
  ctx.textAlign = "center";
  ctx.fillStyle = "#91aec5";
  for (let index = 0; index <= 5; index += 1) {
    const recordIndex = Math.round((Math.max(0, plotted.length - 1) * index) / 5);
    const record = plotted[recordIndex] || plotted[0];
    const x = left + (plotWidth * index) / 5;
    ctx.fillText(`#${record?.sequence ?? recordIndex + 1}`, x, top + plotHeight + 18);
  }
  ctx.textAlign = "center";
  ctx.fillText("Evidence sequence", left + plotWidth / 2, height - 16);
  ctx.save();
  ctx.translate(18, top + plotHeight / 2);
  ctx.rotate(-Math.PI / 2);
  ctx.fillText("Anomaly score", 0, 0);
  ctx.restore();

  ctx.textAlign = "left";
  ctx.fillStyle = "#ff6478";
  ctx.fillText("red = AI flagged", left, height - 38);
  ctx.fillStyle = "#16f0c5";
  ctx.fillText("green = normal", left + 110, height - 38);
  ctx.fillStyle = "#91aec5";
  ctx.fillText("top = higher risk", left + 230, height - 38);
}

function drawSeverityPie(anomaly) {
  const canvas = $("severityPie");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const width = canvas.width;
  const height = canvas.height;
  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = "#03101b";
  ctx.fillRect(0, 0, width, height);

  const anomalies = Number(anomaly.anomalies || 0);
  const normal = Math.max(0, Number(anomaly.normal || 0));
  const security = Number(anomaly.security_events_count || 0);
  const rawTotal = anomalies + normal + security;
  const total = Math.max(1, rawTotal);
  const slices = [
    { label: "AI normal", value: normal, color: "#16f0c5" },
    { label: "AI flagged", value: anomalies, color: "#ff6478" },
    { label: "Logger alert", value: security, color: "#ffd166" },
  ].filter((slice) => slice.value > 0);
  const cx = width * 0.34;
  const cy = height * 0.50;
  const radius = Math.min(width, height) * 0.28;
  let start = -Math.PI / 2;
  for (const slice of slices) {
    const angle = (slice.value / total) * Math.PI * 2;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, radius, start, start + angle);
    ctx.closePath();
    ctx.fillStyle = slice.color;
    ctx.fill();
    start += angle;
  }
  ctx.beginPath();
  ctx.arc(cx, cy, radius * 0.58, 0, Math.PI * 2);
  ctx.fillStyle = "#03101b";
  ctx.fill();
  ctx.fillStyle = "#e8f7ff";
  ctx.font = "700 28px Segoe UI";
  ctx.textAlign = "center";
  ctx.fillText(String(rawTotal), cx, cy - 2);
  ctx.font = "12px Segoe UI";
  ctx.fillStyle = "#91aec5";
  ctx.fillText("records", cx, cy + 18);
  ctx.textAlign = "left";

  if (!slices.length) {
    ctx.fillStyle = "#91aec5";
    ctx.font = "14px Segoe UI";
    ctx.fillText("No verdict data", width * 0.62, cy);
    return;
  }

  slices.forEach((slice, index) => {
    const y = 76 + index * 48;
    const x = width * 0.66;
    ctx.fillStyle = slice.color;
    ctx.fillRect(x, y - 13, 15, 15);
    ctx.fillStyle = "#e8f7ff";
    ctx.font = "700 13px Segoe UI";
    ctx.fillText(slice.label, x + 24, y);
    ctx.fillStyle = "#91aec5";
    ctx.font = "12px Segoe UI";
    ctx.fillText(`${slice.value} records | ${((slice.value / total) * 100).toFixed(1)}%`, x + 24, y + 17);
  });
}

function drawChainGauge(status) {
  const canvas = $("chainGauge");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const width = canvas.width;
  const height = canvas.height;
  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = "#03101b";
  ctx.fillRect(0, 0, width, height);

  const checks = status.trusted_readiness?.checks || {};
  const values = Object.values(checks);
  const passed = values.filter(Boolean).length;
  const total = Math.max(1, values.length);
  const pct = passed / total;
  const cx = width * 0.32;
  const cy = height * 0.72;
  const radius = Math.min(width, height) * 0.44;

  ctx.lineWidth = 22;
  ctx.strokeStyle = "rgba(139,203,255,0.15)";
  ctx.beginPath();
  ctx.arc(cx, cy, radius, Math.PI, 0);
  ctx.stroke();

  const grad = ctx.createLinearGradient(cx - radius, cy, cx + radius, cy);
  grad.addColorStop(0, "#39d8ff");
  grad.addColorStop(1, pct === 1 ? "#16f0c5" : "#ffd166");
  ctx.strokeStyle = grad;
  ctx.beginPath();
  ctx.arc(cx, cy, radius, Math.PI, Math.PI + pct * Math.PI);
  ctx.stroke();

  ctx.fillStyle = "#e8f7ff";
  ctx.font = "800 34px Segoe UI";
  ctx.textAlign = "center";
  ctx.fillText(`${Math.round(pct * 100)}%`, cx, cy - 20);
  ctx.font = "12px Segoe UI";
  ctx.fillStyle = "#91aec5";
  ctx.fillText("trusted checks", cx, cy + 2);
  ctx.textAlign = "left";

  const labels = [
    ["Chain", checks.chain_verified],
    ["Recovery", checks.recovery_ledger_verified],
    ["AI Ledger", checks.ai_evidence_ledger_verified],
    ["Merkle", checks.ai_checkpoints_verified],
    ["Checkpointed", checks.ai_evidence_checkpointed],
  ];
  labels.forEach((item, index) => {
    const y = 62 + index * 30;
    ctx.fillStyle = item[1] ? "#16f0c5" : "#ff6478";
    ctx.fillRect(width * 0.64, y - 11, 14, 14);
    ctx.fillStyle = "#e8f7ff";
    ctx.font = "700 13px Segoe UI";
    ctx.fillText(item[0], width * 0.64 + 24, y);
  });
}

function renderEntries(entries, emptyMessage = "No trusted entries available.") {
  const tbody = $("entries");
  if (!tbody) return;
  tbody.replaceChildren();
  setText("entryCountLabel", `${entries.length} shown`);
  if (!entries.length) {
    const row = document.createElement("tr");
    row.innerHTML = `<td colspan="6" class="empty-row">${emptyMessage}</td>`;
    tbody.appendChild(row);
    return;
  }
  for (const entry of entries) {
    const row = document.createElement("tr");
    const typeClass = String(entry.source_type || "").toLowerCase().replace(/[^a-z0-9]+/g, "-");
    row.innerHTML = `
      <td class="seq-cell">#${entry.sequence}</td>
      <td><span class="badge ${typeClass}">${entry.source_type}</span></td>
      <td>${entry.source_offset}</td>
      <td>${entry.ingest_mode || "-"}</td>
      <td>${entry.source_file || "-"}</td>
      <td><button class="ghost" data-sequence="${entry.sequence}">Open</button></td>
    `;
    tbody.appendChild(row);
  }
  tbody.querySelectorAll("button").forEach((button) => {
    button.addEventListener("click", () => openEntry(button.dataset.sequence));
  });
}

function renderReplayEvidenceStream(entries, emptyMessage = "No anomalous evidence available.") {
  const tbody = $("entries");
  if (!tbody) return;
  tbody.replaceChildren();
  setText("entryCountLabel", `${entries.length} shown`);
  if (!entries.length) {
    const row = document.createElement("tr");
    row.innerHTML = `<td colspan="6" class="empty-row">${emptyMessage}</td>`;
    tbody.appendChild(row);
    return;
  }
  for (const entry of entries) {
    const row = document.createElement("tr");
    const component = entry.target_component || entry.source_file || "unknown";
    row.innerHTML = `
      <td>${formatReplayTime(entry.occurred_at)}</td>
      <td class="seq-cell">#${entry.sequence}</td>
      <td><span class="badge ${String(entry.severity || "").toLowerCase()}">${entry.severity || "ANOMALY"}</span></td>
      <td>${fmtNumber(entry.anomaly_score)}</td>
      <td>${component}</td>
      <td><button class="ghost" data-sequence="${entry.sequence}">Open</button></td>
    `;
    tbody.appendChild(row);
  }
  tbody.querySelectorAll("button").forEach((button) => {
    button.addEventListener("click", () => openEntry(button.dataset.sequence));
  });
}

function renderReplay(replay) {
  const items = replay.evidence_stream || replay.timeline || [];
  drawAttackGraph(replay.attack_graph || { nodes: [], edges: [] });
  drawReplayTimeline(items);
  drawReplayMix(items);
}

function formatDemoResult(result) {
  const totalFlagged = Object.values(result.ai_results || {}).reduce(
    (sum, item) => sum + Number(item.true_positives || 0) + Number(item.false_positives || 0),
    0,
  );
  const totalAttached = Object.values(result.ai_attachments || {}).reduce(
    (sum, item) => sum + Number(item.attached || 0),
    0,
  );
  const attachments = Object.entries(result.ai_attachments || {})
    .map(([name, item]) => {
      const checkpoint = item.checkpoint?.checkpoint_id
        ? `checkpoint #${item.checkpoint.checkpoint_id}`
        : "no checkpoint";
      return `${name}: ${item.attached || 0} attached, ${item.missing_mappings || 0} missing, ${checkpoint}`;
    })
    .join("\n");
  const metrics = Object.entries(result.ai_results || {})
    .map(([name, item]) => {
      const detected = Number(item.true_positives || 0) + Number(item.false_positives || 0);
      return `${name}: ${detected} flagged / ${item.total_records || 0} scored, DR ${(Number(item.detection_rate || 0) * 100).toFixed(1)}%, FPR ${(Number(item.false_positive_rate || 0) * 100).toFixed(1)}%`;
    })
    .join("\n");
  return [
    `Scenario: ${result.scenario}`,
    `Duration: ${result.duration}s`,
    `Ingested entries: ${result.ingested_entries}`,
    `AI evidence attached: ${totalAttached}`,
    `Flagged anomalies: ${totalFlagged}`,
    `Trusted readiness: ${Boolean(result.status?.trusted_readiness?.trusted)}`,
    "",
    "AI scoring",
    metrics || "No scored CSVs returned.",
    "",
    "Evidence attachment",
    attachments || "No AI evidence attachments returned.",
  ].join("\n");
}

function notifyDemoRun() {
  try {
    localStorage.setItem(DEMO_EVENT_KEY, String(Date.now()));
  } catch {
    // Storage can be unavailable in hardened browser profiles; periodic refresh still works.
  }
}

function graphNodeAt(canvas, event) {
  const rect = canvas.getBoundingClientRect();
  const scaleX = canvas.width / rect.width;
  const scaleY = canvas.height / rect.height;
  const x = (event.clientX - rect.left) * scaleX;
  const y = (event.clientY - rect.top) * scaleY;
  return [...state.graph.nodes]
    .reverse()
    .find((node) => {
      const dx = x - node._x;
      const dy = y - node._y;
      return Math.sqrt(dx * dx + dy * dy) <= node._radius + 6;
    }) || null;
}

function showAttackGraphDetail(node) {
  const detail = $("attackGraphDetail");
  if (!detail) return;
  if (!node) {
    detail.textContent = "Select a graph node to inspect the suspected cause.";
    return;
  }
  if (node.kind === "anomaly") {
    detail.innerHTML = `
      <strong>${node.label}</strong>
      <span>Risk score ${fmtNumber(node.risk)}. ${node.summary || "Likely contributor to the observed attack path."}</span>
    `;
    return;
  }
  detail.innerHTML = `<strong>${node.label}</strong><span>${node.kind === "source" ? "Observed source component" : "Affected component or bus"}</span>`;
}

function drawAttackGraph(graph) {
  const canvas = $("attackGraph");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const width = canvas.width;
  const height = canvas.height;
  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = "#03101b";
  ctx.fillRect(0, 0, width, height);

  const nodes = (graph.nodes || []).map((node) => ({ ...node }));
  const edges = graph.edges || [];
  state.graph.nodes = nodes;
  state.graph.edges = edges;
  state.graph.layout_engine = graph.layout_engine || state.graph.layout_engine || "python";
  if (!nodes.length) {
    ctx.fillStyle = "#91aec5";
    ctx.font = "18px Segoe UI";
    ctx.fillText("No ranked attack path available yet", 34, height / 2);
    showAttackGraphDetail(null);
    return;
  }
  const byId = Object.fromEntries(nodes.map((node) => [node.id, node]));

  ctx.strokeStyle = "rgba(139,203,255,0.36)";
  ctx.lineWidth = 2;
  for (const edge of edges) {
    const a = byId[edge.source];
    const b = byId[edge.target];
    if (!a || !b) continue;
    const ax = Number(a.x) * width;
    const ay = Number(a.y) * height;
    const bx = Number(b.x) * width;
    const by = Number(b.y) * height;
    ctx.beginPath();
    ctx.moveTo(ax, ay);
    ctx.lineTo(bx, by);
    ctx.strokeStyle = edge.temporal ? "rgba(255,209,102,0.55)" : "rgba(139,203,255,0.30)";
    ctx.stroke();
  }

  for (const node of nodes) {
    const x = Number(node.x) * width;
    const y = Number(node.y) * height;
    const selected = state.graph.selected === node.id || state.graph.hovered === node.id;
    const radius = node.kind === "anomaly" ? (selected ? 30 : 24) : (selected ? 24 : 19);
    node._x = x;
    node._y = y;
    node._radius = radius;
    const color = node.kind === "anomaly" ? "#ff6478" : node.kind === "source" ? "#39d8ff" : "#ffd166";
    ctx.beginPath();
    ctx.arc(x, y, radius, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.globalAlpha = node.kind === "anomaly" ? 0.88 : 0.68;
    ctx.fill();
    ctx.globalAlpha = 1;
    ctx.strokeStyle = selected ? "#ffffff" : "rgba(232,247,255,0.72)";
    ctx.lineWidth = selected ? 3 : 1;
    ctx.stroke();
    ctx.fillStyle = "#e8f7ff";
    ctx.font = "700 12px Segoe UI";
    ctx.textAlign = "center";
    const label = String(node.label || "");
    ctx.fillText(label.length > 22 ? `${label.slice(0, 19)}...` : label, x, y + radius + 18);
  }

  ctx.textAlign = "left";
  ctx.fillStyle = "#91aec5";
  ctx.font = "12px Segoe UI";
  ctx.fillText(`top anomalous events: ${graph.top_event_count || 0}`, 28, height - 28);
  ctx.fillText(`layout: ${state.graph.layout_engine}`, 28, height - 10);
}

function drawReplayTimeline(items) {
  const canvas = $("replayTimelineGraph");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const width = canvas.width;
  const height = canvas.height;
  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = "#03101b";
  ctx.fillRect(0, 0, width, height);
  const left = 72;
  const right = 28;
  const top = 24;
  const bottom = 64;
  const plotWidth = width - left - right;
  const plotHeight = height - top - bottom;
  ctx.strokeStyle = "rgba(139,203,255,0.16)";
  for (let index = 0; index <= 4; index += 1) {
    const y = top + (plotHeight * index) / 4;
    ctx.beginPath();
    ctx.moveTo(left, y);
    ctx.lineTo(width - right, y);
    ctx.stroke();
  }
  ctx.strokeStyle = "rgba(232,247,255,0.42)";
  ctx.beginPath();
  ctx.moveTo(left, top);
  ctx.lineTo(left, top + plotHeight);
  ctx.lineTo(width - right, top + plotHeight);
  ctx.stroke();

  if (!items.length) {
    ctx.fillStyle = "#91aec5";
    ctx.font = "18px Segoe UI";
    ctx.fillText("No anomalous replay events yet", left + 8, height / 2);
    return;
  }
  const times = items.map((item) => new Date(item.occurred_at).getTime()).filter(Number.isFinite);
  const minTime = Math.min(...times);
  const maxTime = Math.max(...times);
  const scores = items.map((item) => Number(item.anomaly_score || 0));
  let minScore = Math.min(...scores);
  let maxScore = Math.max(...scores);
  if (minScore === maxScore) {
    minScore -= 0.01;
    maxScore += 0.01;
  }
  const scoreSpan = maxScore - minScore;
  const timeSpan = Math.max(1, maxTime - minTime);

  ctx.textAlign = "right";
  ctx.fillStyle = "#91aec5";
  ctx.font = "12px Segoe UI";
  for (let index = 0; index <= 4; index += 1) {
    const value = minScore + (scoreSpan * index) / 4;
    const y = top + (plotHeight * index) / 4 + 4;
    ctx.fillText(value.toFixed(3), left - 10, y);
  }

  items.forEach((item) => {
    const time = new Date(item.occurred_at).getTime();
    const x = left + ((time - minTime) / timeSpan) * plotWidth;
    const y = top + ((Number(item.anomaly_score || 0) - minScore) / scoreSpan) * plotHeight;
    ctx.fillStyle = "#ff6478";
    ctx.beginPath();
    ctx.arc(x, y, 7, 0, Math.PI * 2);
    ctx.fill();
    ctx.fillStyle = "#e8f7ff";
    ctx.font = "700 11px Segoe UI";
    ctx.textAlign = "center";
    ctx.fillText(`#${item.sequence}`, x, y - 12);
  });

  ctx.fillStyle = "#91aec5";
  ctx.font = "12px Segoe UI";
  ctx.textAlign = "left";
  ctx.fillText(formatReplayTime(minTime), left, height - 34);
  ctx.textAlign = "right";
  ctx.fillText(formatReplayTime(maxTime), width - right, height - 34);
  ctx.textAlign = "center";
  ctx.fillText("event time", left + plotWidth / 2, height - 14);
  ctx.save();
  ctx.translate(18, top + plotHeight / 2);
  ctx.rotate(-Math.PI / 2);
  ctx.fillText("risk score, top = higher risk", 0, 0);
  ctx.restore();
}

function drawReplayMix(items) {
  const canvas = $("replayMixChart");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const width = canvas.width;
  const height = canvas.height;
  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = "#03101b";
  ctx.fillRect(0, 0, width, height);
  const counts = items.reduce((acc, item) => {
    const key = item.service || item.target_component || item.source_type || "UNKNOWN";
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
  const entries = Object.entries(counts).slice(0, 6);
  if (!entries.length) {
    ctx.fillStyle = "#91aec5";
    ctx.font = "18px Segoe UI";
    ctx.fillText("No replay data yet", 42, height / 2);
    return;
  }
  const max = Math.max(...entries.map(([, value]) => value), 1);
  entries.forEach(([label, value], index) => {
    const y = 44 + index * 34;
    const barWidth = (width - 190) * (value / max);
    ctx.fillStyle = "#91aec5";
    ctx.font = "12px Segoe UI";
    ctx.fillText(label, 34, y);
    ctx.fillStyle = "rgba(139,203,255,0.13)";
    ctx.fillRect(130, y - 16, width - 180, 20);
    ctx.fillStyle = index % 2 ? "#39d8ff" : "#16f0c5";
    ctx.fillRect(130, y - 16, barWidth, 20);
    ctx.fillStyle = "#e8f7ff";
    ctx.font = "700 13px Segoe UI";
    ctx.fillText(String(value), 142 + barWidth, y);
  });
}

async function runAction(label, fn) {
  if (state.busy) return;
  setBusy(true);
  try {
    const result = await fn();
    toast(label);
    await refresh();
    return result;
  } catch (error) {
    toast(error.message);
  } finally {
    setBusy(false);
  }
}

async function openEntry(sequence) {
  await runAction(`Opened entry ${sequence}`, async () => {
    const entry = await api(`/api/entry/${sequence}`);
    setText("entryDetail", JSON.stringify(entry, null, 2));
  });
}

function bindAttackGraph() {
  const canvas = $("attackGraph");
  if (!canvas) return;
  canvas.addEventListener("mousemove", (event) => {
    const node = graphNodeAt(canvas, event);
    const next = node?.id || null;
    if (state.graph.hovered === next) return;
    state.graph.hovered = next;
    canvas.style.cursor = node ? "pointer" : "default";
    drawAttackGraph({ nodes: state.graph.nodes, edges: state.graph.edges, layout_engine: state.graph.layout_engine, top_event_count: state.graph.nodes.filter((item) => item.kind === "anomaly").length });
  });
  canvas.addEventListener("mouseleave", () => {
    state.graph.hovered = null;
    canvas.style.cursor = "default";
    drawAttackGraph({ nodes: state.graph.nodes, edges: state.graph.edges, layout_engine: state.graph.layout_engine, top_event_count: state.graph.nodes.filter((item) => item.kind === "anomaly").length });
  });
  canvas.addEventListener("click", (event) => {
    const node = graphNodeAt(canvas, event);
    state.graph.selected = node?.id || null;
    showAttackGraphDetail(node);
    drawAttackGraph({ nodes: state.graph.nodes, edges: state.graph.edges, layout_engine: state.graph.layout_engine, top_event_count: state.graph.nodes.filter((item) => item.kind === "anomaly").length });
  });
}

function appendChatMessage(role, text) {
  const log = $("replayChatLog");
  if (!log) return;
  const node = document.createElement("div");
  node.className = role === "user" ? "chat-user" : "chat-bot";
  node.textContent = text;
  log.appendChild(node);
  log.scrollTop = log.scrollHeight;
}

function handleReplayChatSubmit(event) {
  event.preventDefault();
  const input = $("replayChatInput");
  const question = input?.value.trim();
  if (!question) return;
  input.value = "";
  appendChatMessage("user", question);
  const count = state.replay?.evidence_stream?.length || 0;
  appendChatMessage(
    "bot",
    count
      ? `LLM backend pending. Current replay has ${count} ranked anomalous events. Select a graph node or open an evidence row to inspect the maintenance context.`
      : "LLM backend pending. Run Generate + Score + Ingest first, then return to this replay view.",
  );
}

function showSection(name) {
  state.activeSection = name;
  document.querySelectorAll(".section-view").forEach((section) => {
    section.classList.toggle("active", section.id === `section-${name}`);
  });
  document.querySelectorAll(".nav-item").forEach((button) => {
    button.classList.toggle("active", button.dataset.section === name);
  });
}

function bindActions() {
  bindAttackGraph();
  on("replayChatForm", "submit", handleReplayChatSubmit);
  on("refresh", "click", () => runAction("Refreshed", refresh));
  on("verify", "click", () =>
    runAction("Chain verified", async () => {
      const result = await api("/api/verify", { method: "POST", body: "{}" });
      setText("ledgerResult", JSON.stringify(result, null, 2));
    })
  );
  on("anchor", "click", () =>
    runAction("Head anchored", () => api("/api/anchor", { method: "POST", body: "{}" }))
  );
  on("verifyLedger", "click", () =>
    runAction("Recovery ledger verified", async () => {
      const result = await api("/api/verify-ledger", { method: "POST", body: "{}" });
      setText("ledgerResult", JSON.stringify(result, null, 2));
    })
  );
  // on("initLedger", "click", () =>
  //   runAction("Recovery ledger initialized", async () => {
  //     const result = await api("/api/init-ledger", { method: "POST", body: "{}" });
  //     setText("ledgerResult", JSON.stringify(result, null, 2));
  //   })
  // );
  on("restoreLedger", "click", () =>
    runAction("SQLite restored from ledger", async () => {
      const result = await api("/api/restore-ledger", {
        method: "POST",
        body: JSON.stringify({
          reason: $("restoreReason")?.value || "analyst_requested_restore",
          actor: "dashboard",
        }),
      });
      setText("ledgerResult", JSON.stringify(result, null, 2));
    })
  );
  on("append", "click", () =>
    runAction("JSON appended", () => {
      const payload = JSON.parse($("manualPayload").value);
      return api("/api/append", {
        method: "POST",
        body: JSON.stringify({ payload }),
      });
    })
  );
  on("ingest", "click", () =>
    runAction("Path ingested", () =>
      api("/api/ingest", {
        method: "POST",
        body: JSON.stringify({ path: $("ingestPath").value }),
      })
    )
  );
  on("runDemo", "click", () =>
    runAction("Demo scored, ingested, and attached", async () => {
      const result = await api("/api/demo", {
        method: "POST",
        body: JSON.stringify({
          scenario: $("scenario").value,
          duration: Number($("duration").value),
        }),
      });
      setText("anomalyResult", formatDemoResult(result));
      notifyDemoRun();
    })
  );
}

bindActions();
refresh().catch((error) => toast(error.message));
window.addEventListener("storage", (event) => {
  if (event.key === DEMO_EVENT_KEY && !state.busy) {
    refresh().catch((error) => toast(error.message));
  }
});
window.addEventListener("focus", () => {
  if (!state.busy) {
    refresh().catch((error) => toast(error.message));
  }
});
window.setInterval(() => {
  if (!state.busy) {
    refresh().catch((error) => console.warn(error.message));
  }
}, 3000);
