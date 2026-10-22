/* Overview: counters, charts, recent findings, capture control. */
"use strict";

(function () {
  const NS = window.NetShield;
  const $ = (id) => document.getElementById(id);
  const hasChart = typeof window.Chart !== "undefined";

  const state = {
    chart: null,
    proto: null,
    refreshToken: 0,
    files: [],
    interfaces: [],
    canCapture: false,
    running: false,
  };

  if (hasChart) {
    window.Chart.defaults.color = "#8095a9";
    window.Chart.defaults.borderColor = "rgba(29, 43, 58, 0.65)";
    window.Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
    window.Chart.defaults.font.size = 11;
  }

  function buildCharts() {
    if (!hasChart) return;
    const canvas = $("trafficChart");
    if (canvas) {
      const ctx = canvas.getContext("2d");
      const gradient = ctx.createLinearGradient(0, 0, 0, 230);
      gradient.addColorStop(0, "rgba(56, 189, 248, 0.28)");
      gradient.addColorStop(1, "rgba(56, 189, 248, 0.01)");
      state.chart = new window.Chart(ctx, {
        type: "line",
        data: {
          labels: [],
          datasets: [{
            label: "packets/s",
            data: [],
            borderColor: "#38bdf8",
            backgroundColor: gradient,
            fill: true,
            tension: 0.28,
            pointRadius: 0,
            pointHitRadius: 8,
            borderWidth: 1.6,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: false,
          interaction: { mode: "index", intersect: false },
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: "#0b121a",
              borderColor: "#1d2b3a",
              borderWidth: 1,
              titleColor: "#dbe7f1",
              bodyColor: "#8095a9",
              callbacks: {
                label: (ctx) => `${NS.fmt.int(ctx.parsed.y)} packets in that second`,
              },
            },
          },
          scales: {
            x: {
              grid: { display: false },
              border: { color: "#1d2b3a" },
              ticks: { maxTicksLimit: 7, maxRotation: 0, autoSkip: true },
            },
            y: {
              beginAtZero: true,
              grid: { color: "rgba(29, 43, 58, 0.5)" },
              border: { display: false },
              ticks: { precision: 0, maxTicksLimit: 5 },
            },
          },
        },
      });
    }

    const protoCanvas = $("protoChart");
    if (protoCanvas) {
      state.proto = new window.Chart(protoCanvas.getContext("2d"), {
        type: "doughnut",
        data: {
          labels: [],
          datasets: [{
            data: [],
            backgroundColor: [],
            borderColor: "#0d141c",
            borderWidth: 3,
            hoverOffset: 4,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: false,
          cutout: "64%",
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: "#0b121a",
              borderColor: "#1d2b3a",
              borderWidth: 1,
              callbacks: {
                label: (ctx) => {
                  const total = ctx.dataset.data.reduce((a, b) => a + b, 0) || 1;
                  const pct = ((ctx.parsed / total) * 100).toFixed(0);
                  return `${ctx.label}: ${NS.fmt.int(ctx.parsed)} (${pct}%)`;
                },
              },
            },
          },
        },
      });
    }
  }

  const PROTO_COLORS = { TCP: "#38bdf8", UDP: "#a78bfa", ICMP: "#fbbf24", OTHER: "#64748b" };

  function renderCounters(counters, blocked) {
    const open = counters.open || 0;
    const total = counters.total || 0;
    const bySeverity = counters.by_severity || {};
    $("statOpen").textContent = NS.fmt.int(open);
    $("statOpenMeta").textContent = `${NS.fmt.int(total)} total · ${NS.fmt.int(bySeverity.high || 0)} high, ${NS.fmt.int(bySeverity.medium || 0)} medium, ${NS.fmt.int(bySeverity.low || 0)} low`;

    const openHigh = (counters.open_by_severity || {}).high || 0;
    $("statHigh").textContent = NS.fmt.int(openHigh);
    $("statHighMeta").textContent = openHigh
      ? "needs triage"
      : "nothing high-severity is open";

    $("statBlocked").textContent = NS.fmt.int((blocked || []).length);
  }

  function renderTraffic(series) {
    const buckets = Array.isArray(series) ? series : [];
    $("seriesCount").textContent = buckets.length
      ? `${NS.fmt.int(buckets.length)} buckets`
      : "no buckets";

    if (!state.chart) {
      $("trafficEmpty").hidden = buckets.length > 0;
      if (buckets.length) {
        $("trafficEmpty").textContent =
          `Chart library unavailable. Latest bucket: ${buckets[buckets.length - 1].packets} packets/s.`;
        $("trafficEmpty").hidden = false;
      }
      return;
    }

    state.chart.data.labels = buckets.map((b) => NS.fmt.date(b.bucket_ts));
    state.chart.data.datasets[0].data = buckets.map((b) => b.packets);
    state.chart.update("none");
    $("trafficEmpty").hidden = buckets.length > 0;
  }

  function renderRate(series) {
    const buckets = Array.isArray(series) ? series : [];
    if (!buckets.length) {
      $("statRate").textContent = "no traffic yet";
      return;
    }
    const tail = buckets.slice(-10);
    const pps = tail.reduce((sum, b) => sum + b.packets, 0) / tail.length;
    const bytes = tail.reduce((sum, b) => sum + b.bytes, 0) / tail.length;
    $("statRate").textContent = `${pps.toFixed(pps < 10 ? 1 : 0)} pps avg · ${NS.fmt.bytes(bytes)}/s`;
  }

  function renderProtocols(counts) {
    const entries = Object.entries(counts || {});
    const total = entries.reduce((sum, [, value]) => sum + value, 0);

    const legend = $("protoLegend");
    legend.replaceChildren();
    for (const [name, value] of entries) {
      const item = document.createElement("span");
      item.className = "legend-item";
      const swatch = document.createElement("span");
      swatch.className = "swatch";
      swatch.style.background = PROTO_COLORS[name] || PROTO_COLORS.OTHER;
      const label = document.createElement("span");
      const pct = total ? ((value / total) * 100).toFixed(0) : "0";
      label.textContent = `${name} · ${NS.fmt.int(value)} (${pct}%)`;
      item.append(swatch, label);
      legend.append(item);
    }

    if (!state.proto) {
      $("protoEmpty").hidden = entries.length > 0;
      return;
    }
    state.proto.data.labels = entries.map(([name]) => name);
    state.proto.data.datasets[0].data = entries.map(([, value]) => value);
    state.proto.data.datasets[0].backgroundColor = entries.map(
      ([name]) => PROTO_COLORS[name] || PROTO_COLORS.OTHER
    );
    state.proto.update("none");
    $("protoEmpty").hidden = entries.length > 0;
  }

  function renderRecent(rows) {
    const wrap = $("recentWrap");
    if (!rows || !rows.length) {
      wrap.innerHTML = '<div class="empty"><strong>No detections yet</strong>Run a capture to generate findings.</div>';
      return;
    }
    const body = rows.map((row) => {
      const target = row.dst_ip
        ? `${NS.escapeHtml(row.dst_ip)}${row.dst_port ? `:${NS.escapeHtml(row.dst_port)}` : ""}`
        : "—";
      const sev = NS.severityClass(row.severity);
      return `<tr class="clickable" data-id="${NS.escapeHtml(row.id)}" tabindex="0">
        <td class="mono nowrap">${NS.escapeHtml(NS.fmt.date(row.detected_at))}</td>
        <td><span class="sev ${sev}">${NS.escapeHtml(row.severity)}</span></td>
        <td><div class="truncate" title="${NS.escapeHtml(row.title)}">${NS.escapeHtml(row.title)}</div><div class="faint small mono">${NS.escapeHtml(row.rule_id)}</div></td>
        <td class="mono nowrap">${NS.escapeHtml(row.src_ip || "—")}</td>
        <td class="mono nowrap">${target}</td>
        <td class="num">${NS.escapeHtml(row.score)}</td>
        <td><span class="status ${NS.escapeHtml(row.status)}">${NS.escapeHtml(row.status)}</span></td>
      </tr>`;
    }).join("");
    wrap.innerHTML = `<table>
      <thead><tr><th>Time</th><th>Severity</th><th>Rule</th><th>Source</th><th>Target</th><th class="num">Score</th><th>Status</th></tr></thead>
      <tbody>${body}</tbody></table>`;

    wrap.querySelectorAll("tr[data-id]").forEach((tr) => {
      const go = () => {
        window.location.href = `/alerts?focus=${encodeURIComponent(tr.dataset.id)}`;
      };
      tr.addEventListener("click", go);
      tr.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          go();
        }
      });
    });
  }

  function renderBlocked(targets) {
    const list = targets || [];
    const card = $("blockedCard");
    card.classList.toggle("hidden", list.length === 0);
    const wrap = $("blockedList");
    wrap.replaceChildren();
    for (const ip of list) {
      const chip = document.createElement("span");
      chip.className = "pill";
      const dot = document.createElement("span");
      dot.className = "dot";
      dot.style.background = "#f87171";
      const label = document.createElement("span");
      label.className = "mono";
      label.textContent = ip;
      const unblock = document.createElement("button");
      unblock.type = "button";
      unblock.className = "btn btn-sm btn-ghost";
      unblock.textContent = "Unblock";
      unblock.addEventListener("click", () => respond("simulate_unblock", ip));
      chip.append(dot, label, unblock);
      wrap.append(chip);
    }
  }

  async function respond(action, ip) {
    try {
      await NS.request("/api/response", {
        method: "POST",
        body: { action, target_ip: ip, reason: "dashboard" },
      });
      NS.toast(`${action === "simulate_block" ? "Blocked" : "Unblocked"} ${ip} (simulation).`, "ok");
      refresh();
    } catch (err) {
      NS.errorToast(err);
    }
  }

  async function refresh() {
    const token = ++state.refreshToken;
    try {
      const payload = await NS.request("/api/overview");
      if (token !== state.refreshToken) return;
      const data = payload.data;
      renderCounters(data.counters || {}, data.blocked_targets);
      $("statPackets").textContent = NS.fmt.int(data.packet_count || 0);
      renderRate(data.traffic_series);
      renderTraffic(data.traffic_series);
      renderProtocols(data.protocol_counts);
      renderRecent(data.recent_alerts);
      renderBlocked(data.blocked_targets);
      if (data.status) applyRunning(data.status.running);
    } catch (err) {
      if (token === state.refreshToken) console.warn("overview refresh failed", err);
    }
  }

  /* ------------------------------------------------------------- capture */
  function applyRunning(running) {
    state.running = Boolean(running);
    $("startBtn").disabled = state.running;
    $("stopBtnLocal").disabled = !state.running;
    document.querySelectorAll("#blockedList button").forEach((btn) => {
      btn.disabled = false;
    });
  }

  function fillFiles(files) {
    state.files = files;
    const select = $("pcapPath");
    const current = select.value;
    select.replaceChildren();
    if (!files.length) {
      const option = document.createElement("option");
      option.value = "";
      option.textContent = "No capture files available — upload one";
      select.append(option);
      return;
    }
    const groups = new Map();
    for (const file of files) {
      if (!groups.has(file.group)) groups.set(file.group, []);
      groups.get(file.group).push(file);
    }
    for (const [group, items] of groups) {
      const optgroup = document.createElement("optgroup");
      optgroup.label = group === "fixtures" ? "Sample captures" : "Uploaded / local captures";
      for (const file of items) {
        const option = document.createElement("option");
        option.value = file.path;
        option.textContent = `${file.name} · ${NS.fmt.bytes(file.size)}`;
        optgroup.append(option);
      }
      select.append(optgroup);
    }
    if (current && files.some((f) => f.path === current)) select.value = current;
  }

  function fillInterfaces(interfaces, canCapture) {
    state.interfaces = interfaces;
    state.canCapture = canCapture;
    const select = $("iface");
    select.replaceChildren();
    for (const name of interfaces) {
      const option = document.createElement("option");
      option.value = name;
      option.textContent = name;
      select.append(option);
    }
    if (!interfaces.length) {
      const option = document.createElement("option");
      option.value = "";
      option.textContent = "No interfaces discovered";
      select.append(option);
    }
    $("ifaceHelp").textContent = canCapture
      ? "Raw-socket privilege detected on this process."
      : "No raw-socket privilege: start the server with CAP_NET_RAW or sudo, or use PCAP replay.";
  }

  function syncMode() {
    const mode = $("captureMode").value;
    $("pcapField").classList.toggle("hidden", mode !== "pcap");
    $("liveField").classList.toggle("hidden", mode !== "live");
    const notice = $("captureNotice");
    if (mode === "demo") {
      notice.textContent = "Runs a 45-second labelled scenario covering every rule.";
    } else if (mode === "live") {
      notice.textContent = state.canCapture
        ? "Stop the capture when you have enough evidence."
        : "Live capture will fail without CAP_NET_RAW or root.";
    } else {
      notice.textContent = "";
    }
  }

  async function startCapture(event) {
    event.preventDefault();
    const mode = $("captureMode").value;
    const body = { mode };
    if (mode === "pcap") {
      body.path = $("pcapPath").value;
      if (!body.path) {
        NS.toast("Choose a capture file first.", "warn");
        return;
      }
    } else if (mode === "live") {
      body.iface = $("iface").value;
      body.confirm_authorization = $("authorize").checked;
      if (!body.confirm_authorization) {
        NS.toast("Confirm that you are authorised to capture on this interface.", "warn");
        return;
      }
    }
    $("startBtn").disabled = true;
    try {
      const payload = await NS.request("/api/capture/start", { method: "POST", body });
      NS.toast(`Capture started (${payload.data.capture.mode}).`, "ok", 3200);
      refresh();
    } catch (err) {
      NS.errorToast(err);
    } finally {
      $("startBtn").disabled = state.running;
    }
  }

  async function stopCapture() {
    try {
      await NS.request("/api/capture/stop", { method: "POST" });
      NS.toast("Capture stopped.", "ok", 3000);
      refresh();
    } catch (err) {
      NS.errorToast(err);
    }
  }

  async function uploadCapture(event) {
    event.preventDefault();
    const input = $("uploadFile");
    if (!input.files || !input.files.length) {
      NS.toast("Choose a capture file to upload.", "warn");
      return;
    }
    const button = $("uploadBtn");
    const form = new FormData();
    form.append("file", input.files[0]);
    button.disabled = true;
    $("uploadNotice").textContent = "";
    try {
      const payload = await NS.upload("/api/capture/upload", form);
      const file = payload.data.file;
      NS.toast(`Uploaded ${file.name}.`, "ok");
      input.value = "";
      const files = await NS.request("/api/capture/files");
      fillFiles(files.data.files);
      $("pcapPath").value = file.path;
      $("captureMode").value = "pcap";
      syncMode();
    } catch (err) {
      NS.errorToast(err);
      $("uploadNotice").textContent = err.message || "";
      $("uploadNotice").className = "notice err";
    } finally {
      button.disabled = false;
    }
  }

  async function loadSources() {
    try {
      const [files, ifaces] = await Promise.all([
        NS.request("/api/capture/files"),
        NS.request("/api/interfaces"),
      ]);
      fillFiles(files.data.files || []);
      fillInterfaces(ifaces.data.interfaces || [], Boolean(ifaces.data.can_capture));
    } catch (err) {
      console.warn("could not load capture sources", err);
    }
  }

  /* ---------------------------------------------------------------- boot */
  buildCharts();
  $("captureMode").addEventListener("change", syncMode);
  $("captureForm").addEventListener("submit", startCapture);
  $("stopBtnLocal").addEventListener("click", stopCapture);
  $("uploadForm").addEventListener("submit", uploadCapture);
  window.addEventListener("netshield:status", (event) => applyRunning(event.detail.running));
  syncMode();
  loadSources();
  refresh();
  NS.poll(refresh, 2500);
})();
