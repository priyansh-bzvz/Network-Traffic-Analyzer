"use strict";

const protocols = [
  { name: "TCP", color: "#6c9eff", element: "tcp-count" },
  { name: "UDP", color: "#a78bfa", element: "udp-count" },
  { name: "ICMP", color: "#f6bd60", element: "icmp-count" },
  { name: "Other", color: "#7d8ca2", element: "other-count" },
];

const elements = {
  total: document.getElementById("total-count"),
  chartTotal: document.getElementById("chart-total"),
  chart: document.getElementById("protocol-chart"),
  legend: document.getElementById("protocol-legend"),
  rows: document.getElementById("packet-rows"),
  feedCount: document.getElementById("feed-count"),
  state: document.getElementById("capture-state"),
  stateText: document.getElementById("capture-state-text"),
  duration: document.getElementById("capture-duration"),
  selector: document.getElementById("interface-select"),
  start: document.getElementById("start-button"),
  stop: document.getElementById("stop-button"),
  reset: document.getElementById("reset-button"),
  export: document.getElementById("export-button"),
  notice: document.getElementById("notice"),
};

let requestInProgress = false;
let refreshInProgress = false;
let interfacesReady = false;
let interfacesAvailable = false;

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

function showNotice(message) {
  elements.notice.textContent = message;
  elements.notice.hidden = !message;
}

async function loadInterfaces() {
  try {
    const data = await requestJson("/api/interfaces");
    interfacesReady = true;
    interfacesAvailable = data.interfaces.length > 0;
    elements.selector.replaceChildren();

    if (!data.interfaces.length) {
      const option = document.createElement("option");
      option.value = "";
      option.textContent = "No interfaces available";
      elements.selector.append(option);
      elements.start.disabled = true;
      return;
    }

    for (const iface of data.interfaces) {
      const option = document.createElement("option");
      option.value = iface.name;
      option.textContent = iface.address
        ? `${iface.description} · ${iface.address}`
        : iface.description;
      elements.selector.append(option);
      if (iface.description.includes("Realtek") && iface.address) option.selected = true;
    }
    elements.start.disabled = false;
  } catch (error) {
    interfacesReady = true;
    interfacesAvailable = false;
    elements.selector.replaceChildren();
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "Interface list unavailable";
    elements.selector.append(option);
    elements.start.disabled = true;
    showNotice(error.message);
  }
}

function renderLegend(counts) {
  elements.legend.replaceChildren();
  for (const protocol of protocols) {
    const item = document.createElement("li");
    const swatch = document.createElement("span");
    swatch.className = "legend-swatch";
    swatch.style.backgroundColor = protocol.color;
    const label = document.createElement("span");
    label.textContent = protocol.name;
    const value = document.createElement("strong");
    value.textContent = Number(counts[protocol.name] || 0).toLocaleString();
    item.append(swatch, label, value);
    elements.legend.append(item);
  }
}

function renderChart(counts, total) {
  elements.chartTotal.textContent = Number(total).toLocaleString();
  if (!total) {
    elements.chart.style.background = "conic-gradient(#26374e 0 100%)";
    elements.chart.setAttribute("aria-label", "No packets captured yet");
    return;
  }

  let current = 0;
  const segments = protocols.map((protocol) => {
    const start = current;
    current += (Number(counts[protocol.name] || 0) / total) * 100;
    return `${protocol.color} ${start}% ${current}%`;
  });
  elements.chart.style.background = `conic-gradient(${segments.join(", ")})`;
  elements.chart.setAttribute("aria-label", `Protocol distribution for ${total} packets`);
}

function displayValue(value) {
  return value === null || value === undefined || value === "" ? "—" : String(value);
}

function formatDuration(seconds) {
  const elapsed = Math.max(0, Math.floor(Number(seconds) || 0));
  const hours = Math.floor(elapsed / 3600);
  const minutes = Math.floor((elapsed % 3600) / 60);
  const remainder = elapsed % 60;
  return [hours, minutes, remainder].map((part) => String(part).padStart(2, "0")).join(":");
}

function addCell(row, value, className = "") {
  const cell = document.createElement("td");
  if (className) cell.className = className;
  cell.textContent = displayValue(value);
  row.append(cell);
  return cell;
}

function renderPackets(packets) {
  elements.rows.replaceChildren();
  if (!packets.length) {
    const row = document.createElement("tr");
    row.className = "empty-row";
    const cell = document.createElement("td");
    cell.colSpan = 6;
    cell.textContent = "No packets captured yet. Start capture to see packet summaries.";
    row.append(cell);
    elements.rows.append(row);
    return;
  }

  for (const packet of packets) {
    const row = document.createElement("tr");
    let timeText = packet.timestamp;
    const parsedTime = new Date(packet.timestamp);
    if (!Number.isNaN(parsedTime.getTime())) timeText = parsedTime.toLocaleTimeString();
    addCell(row, timeText, "timestamp-cell");
    addCell(row, packet.source_ip, "ip-cell");
    addCell(row, packet.destination_ip, "ip-cell");
    const protocolCell = document.createElement("td");
    const pill = document.createElement("span");
    pill.className = "protocol-pill";
    pill.dataset.protocol = packet.protocol;
    pill.textContent = packet.protocol;
    protocolCell.append(pill);
    row.append(protocolCell);
    const ports = packet.source_port === null && packet.destination_port === null
      ? "—"
      : `${displayValue(packet.source_port)} → ${displayValue(packet.destination_port)}`;
    addCell(row, ports);
    addCell(row, `${Number(packet.packet_length).toLocaleString()} B`, "number-cell");
    elements.rows.append(row);
  }
}

function renderStatus(data) {
  const running = data.capture_status === "running";
  elements.state.dataset.state = running ? "running" : "stopped";
  elements.stateText.textContent = running ? "Capture running" : "Capture stopped";
  elements.duration.textContent = formatDuration(data.duration_seconds);
  elements.start.disabled = running || requestInProgress || !interfacesReady || !interfacesAvailable;
  elements.stop.disabled = !running || requestInProgress;
  elements.reset.disabled = running || requestInProgress;
  elements.export.disabled = !data.can_export || requestInProgress;
  if (data.selected_interface && running) {
    elements.selector.value = data.selected_interface;
  }
}

async function refreshDashboard() {
  if (refreshInProgress) return;
  refreshInProgress = true;
  try {
    const data = await requestJson("/api/stats");
    elements.total.textContent = Number(data.total_packets).toLocaleString();
    for (const protocol of protocols) {
      document.getElementById(protocol.element).textContent =
        Number(data.protocol_counts[protocol.name] || 0).toLocaleString();
    }
    renderLegend(data.protocol_counts);
    renderChart(data.protocol_counts, data.total_packets);
    renderPackets(data.recent_packets);
    elements.feedCount.textContent = `${data.recent_packets.length} recent packet${data.recent_packets.length === 1 ? "" : "s"}`;
    renderStatus(data);
  } catch (error) {
    showNotice(`Dashboard update failed: ${error.message}`);
  } finally {
    refreshInProgress = false;
  }
}

async function controlCapture(action) {
  if (requestInProgress) return;
  requestInProgress = true;
  renderStatus({ capture_status: action === "stop" ? "running" : "stopped" });
  showNotice("");
  try {
    const options = action === "start"
      ? { method: "POST", body: JSON.stringify({ interface: elements.selector.value || null }) }
      : { method: "POST", body: "{}" };
    await requestJson(`/api/capture/${action}`, options);
    await refreshDashboard();
  } catch (error) {
    showNotice(error.message);
    await refreshDashboard();
  } finally {
    requestInProgress = false;
    await refreshDashboard();
  }
}

async function resetStatistics() {
  if (requestInProgress) return;
  requestInProgress = true;
  showNotice("");
  try {
    await requestJson("/api/stats/reset", { method: "POST", body: "{}" });
    await refreshDashboard();
    showNotice("Statistics and session duration reset.");
  } catch (error) {
    showNotice(error.message);
  } finally {
    requestInProgress = false;
    await refreshDashboard();
  }
}

async function exportReport() {
  if (requestInProgress) return;
  requestInProgress = true;
  showNotice("");
  try {
    const response = await fetch("/api/report/export");
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || `Export failed (${response.status})`);
    }

    const reportBlob = await response.blob();
    const downloadUrl = URL.createObjectURL(reportBlob);
    const link = document.createElement("a");
    const disposition = response.headers.get("Content-Disposition") || "";
    const filename = disposition.match(/filename="?([^";]+)"?/i)?.[1] || "netscope_report.xlsx";
    link.href = downloadUrl;
    link.download = filename;
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(downloadUrl), 1000);
    showNotice("Excel report downloaded.");
  } catch (error) {
    showNotice(error.message);
  } finally {
    requestInProgress = false;
    await refreshDashboard();
  }
}

elements.start.addEventListener("click", () => controlCapture("start"));
elements.stop.addEventListener("click", () => controlCapture("stop"));
elements.reset.addEventListener("click", resetStatistics);
elements.export.addEventListener("click", exportReport);

renderLegend({ TCP: 0, UDP: 0, ICMP: 0, Other: 0 });
loadInterfaces().then(refreshDashboard);
window.setInterval(refreshDashboard, 1500);
