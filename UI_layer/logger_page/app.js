const state = {
  status: null,
  busy: false,
};

const $ = (id) => document.getElementById(id);

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
  toast.timer = window.setTimeout(() => node.classList.remove("show"), 2800);
}

function shortHash(value) {
  if (!value || value === "-") return "-";
  return `${value.slice(0, 12)}...${value.slice(-12)}`;
}

function formatFailure(value) {
  if (!value) return "none";
  return JSON.stringify(value, null, 2);
}

async function refresh() {
  const [status, entries] = await Promise.all([
    api("/api/status"),
    api("/api/entries?limit=80"),
  ]);
  state.status = status;
  renderStatus(status);
  renderEntries(entries.entries || []);
}

function renderStatus(status) {
  const pill = $("statusPill");
  pill.textContent = status.status || "unknown";
  pill.className = `status-pill ${status.status || ""}`;
  const healthCore = $("healthCore");
  const healthText = status.status === "verified" ? "OK" : status.status === "failed" ? "FAIL" : "IDLE";
  healthCore.textContent = healthText;
  healthCore.className = `orbit-core ${status.status || ""}`;

  $("totalEntries").textContent = status.total_entries ?? 0;
  $("checkedEntries").textContent = status.checked_entries ?? 0;
  $("anchorStatus").textContent = status.anchor?.status || "missing";
  $("ledgerStatus").textContent = status.recovery_ledger?.status || "missing";
  $("headSequence").textContent = status.head?.sequence ?? 0;
  $("headHash").textContent = status.head?.head_hash || "-";
  $("failure").textContent = formatFailure(status.first_failure);
  $("dbLine").textContent = `Entries ${status.total_entries ?? 0} | ${status.payload_storage || "encrypted"}`;
}

function renderEntries(entries) {
  const tbody = $("entries");
  tbody.replaceChildren();
  $("entryCountLabel").textContent = `${entries.length} shown`;
  if (!entries.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 6;
    cell.className = "empty-row";
    cell.textContent = "No entries yet. Append JSON or ingest a path to start the chain.";
    row.appendChild(cell);
    tbody.appendChild(row);
    return;
  }
  for (const entry of entries) {
    const row = document.createElement("tr");
    const typeClass = String(entry.source_type || "").toLowerCase().replace(/[^a-z0-9]+/g, "-");

    const seqCell = document.createElement("td");
    seqCell.className = "seq-cell";
    seqCell.textContent = `#${entry.sequence}`;
    row.appendChild(seqCell);

    const typeCell = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `badge ${typeClass}`.trim();
    badge.textContent = entry.source_type || "";
    typeCell.appendChild(badge);
    row.appendChild(typeCell);

    const offsetCell = document.createElement("td");
    offsetCell.textContent = entry.source_offset == null ? "" : String(entry.source_offset);
    row.appendChild(offsetCell);

    const ingestModeCell = document.createElement("td");
    ingestModeCell.textContent = entry.ingest_mode || "-";
    row.appendChild(ingestModeCell);

    const hashCell = document.createElement("td");
    hashCell.className = "hash-cell";
    hashCell.title = entry.entry_hash || "";
    hashCell.textContent = shortHash(entry.entry_hash);
    row.appendChild(hashCell);

    const actionCell = document.createElement("td");
    const button = document.createElement("button");
    button.className = "secondary";
    button.dataset.sequence = String(entry.sequence);
    button.textContent = "Open";
    actionCell.appendChild(button);
    row.appendChild(actionCell);

    tbody.appendChild(row);
  }
  tbody.querySelectorAll("button").forEach((button) => {
    button.addEventListener("click", () => openEntry(button.dataset.sequence));
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
    $("entryDetail").textContent = JSON.stringify(entry, null, 2);
  });
}

function selectedTamperSequence() {
  const value = $("tamperSequence").value.trim();
  return value ? Number(value) : null;
}

async function attemptTamper(operation) {
  await runAction(`Tamper ${operation} attempt recorded`, async () => {
    const result = await api("/api/tamper-attempt", {
      method: "POST",
      body: JSON.stringify({
        operation,
        sequence: selectedTamperSequence(),
        actor: "dashboard",
      }),
    });
    $("securityResult").textContent = JSON.stringify(result, null, 2);
  });
}

function bindActions() {
  $("refresh").addEventListener("click", () => runAction("Refreshed", refresh));

  $("verify").addEventListener("click", () =>
    runAction("Chain verified", async () => {
      const result = await api("/api/verify", { method: "POST", body: "{}" });
      $("entryDetail").textContent = JSON.stringify(result, null, 2);
    })
  );

  $("anchor").addEventListener("click", () =>
    runAction("Head anchored", () => api("/api/anchor", { method: "POST", body: "{}" }))
  );

  $("verifyLedger").addEventListener("click", () =>
    runAction("Recovery ledger verified", async () => {
      const result = await api("/api/verify-ledger", { method: "POST", body: "{}" });
      $("ledgerResult").textContent = JSON.stringify(result, null, 2);
    })
  );

  $("initLedger").addEventListener("click", () =>
    runAction("Recovery ledger initialized", async () => {
      const result = await api("/api/init-ledger", { method: "POST", body: "{}" });
      $("ledgerResult").textContent = JSON.stringify(result, null, 2);
    })
  );

  $("restoreLedger").addEventListener("click", () =>
    runAction("SQLite restored from ledger", async () => {
      const result = await api("/api/restore-ledger", {
        method: "POST",
        body: JSON.stringify({
          reason: $("restoreReason").value,
          actor: "dashboard",
        }),
      });
      $("ledgerResult").textContent = JSON.stringify(result, null, 2);
    })
  );

  $("append").addEventListener("click", () =>
    runAction("JSON appended", () => {
      const payload = JSON.parse($("manualPayload").value);
      return api("/api/append", {
        method: "POST",
        body: JSON.stringify({ payload }),
      });
    })
  );

  $("ingest").addEventListener("click", () =>
    runAction("Path ingested", () =>
      api("/api/ingest", {
        method: "POST",
        body: JSON.stringify({ path: $("ingestPath").value }),
      })
    )
  );

  $("runDemo").addEventListener("click", () =>
    runAction("Demo ingested", () =>
      api("/api/demo", {
        method: "POST",
        body: JSON.stringify({
          scenario: $("scenario").value,
          duration: Number($("duration").value),
        }),
      })
    )
  );

  $("attemptDelete").addEventListener("click", () => attemptTamper("delete"));
  $("attemptUpdate").addEventListener("click", () => attemptTamper("update"));
}

bindActions();
refresh().catch((error) => toast(error.message));
