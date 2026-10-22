/* Alerts: filtered incident queue, evidence drawer, status + response actions. */
"use strict";

(function () {
  const NS = window.NetShield;
  const $ = (id) => document.getElementById(id);

  const state = {
    page: 1,
    perPage: 50,
    total: 0,
    pages: 1,
    filters: {},
    focus: null,
    loadToken: 0,
    allowFirewall: false,
    safeResponse: false,
    lastFocus: null,
  };

  function readUrl() {
    const params = new URLSearchParams(window.location.search);
    state.page = Math.max(1, Number(params.get("page")) || 1);
    state.perPage = [25, 50, 100].includes(Number(params.get("per_page")))
      ? Number(params.get("per_page"))
      : 50;
    state.filters = {
      severity: params.get("severity") || "",
      status: params.get("status") || "",
      rule: params.get("rule") || "",
      q: params.get("q") || "",
      from: params.get("from") || "",
      to: params.get("to") || "",
    };
    state.focus = params.get("focus") || null;

    $("fSeverity").value = state.filters.severity;
    $("fStatus").value = state.filters.status;
    $("fRule").value = state.filters.rule;
    $("fSearch").value = state.filters.q;
    $("fFrom").value = toLocalInput(state.filters.from);
    $("fTo").value = toLocalInput(state.filters.to);
    $("fPerPage").value = String(state.perPage);
  }

  function toLocalInput(iso) {
    if (!iso) return "";
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return "";
    const pad = (n) => String(n).padStart(2, "0");
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
  }

  function toIso(value) {
    if (!value) return "";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? "" : date.toISOString();
  }

  function writeUrl() {
    const params = new URLSearchParams();
    if (state.page > 1) params.set("page", state.page);
    if (state.perPage !== 50) params.set("per_page", state.perPage);
    for (const [key, value] of Object.entries(state.filters)) {
      if (value) params.set(key, value);
    }
    if (state.focus) params.set("focus", state.focus);
    const query = params.toString();
    history.replaceState(null, "", query ? `?${query}` : window.location.pathname);
  }

  function collectFilters() {
    state.filters = {
      severity: $("fSeverity").value,
      status: $("fStatus").value,
      rule: $("fRule").value,
      q: $("fSearch").value.trim(),
      from: toIso($("fFrom").value),
      to: toIso($("fTo").value),
    };
  }

  function queryString() {
    const params = new URLSearchParams();
    params.set("page", state.page);
    params.set("per_page", state.perPage);
    if (state.filters.severity) params.set("severity", state.filters.severity);
    if (state.filters.status) params.set("status", state.filters.status);
    if (state.filters.rule) params.set("rule", state.filters.rule);
    if (state.filters.q) params.set("q", state.filters.q);
    if (state.filters.from) params.set("from", state.filters.from);
    if (state.filters.to) params.set("to", state.filters.to);
    return params.toString();
  }

  function rowTarget(row) {
    if (!row.dst_ip) return "\u2014";
    return `${NS.escapeHtml(row.dst_ip)}${row.dst_port ? `:${NS.escapeHtml(row.dst_port)}` : ""}`;
  }

  function render(rows, meta) {
    const wrap = $("alertsWrap");
    const hasFilters = Object.values(state.filters).some(Boolean);
    if (!rows.length) {
      wrap.innerHTML = hasFilters
        ? '<div class="empty"><strong>No incidents match these filters</strong>Relax a filter or clear the search.</div>'
        : '<div class="empty"><strong>No incidents yet</strong>Run a capture or load the demo scenario.</div>';
    } else {
      const body = rows.map((row) => {
        const sev = NS.severityClass(row.severity);
        const demo = row.data_origin === "demonstration"
          ? '<span class="tag demo">demo</span>'
          : "";
        return `<tr class="clickable" data-id="${NS.escapeHtml(row.id)}" tabindex="0">
          <td class="mono nowrap">${NS.escapeHtml(NS.fmt.date(row.detected_at))}<div class="faint small nowrap">${NS.escapeHtml(NS.fmt.relative(row.detected_at))}</div></td>
          <td><span class="sev ${sev}">${NS.escapeHtml(row.severity)}</span></td>
          <td><div class="truncate" title="${NS.escapeHtml(row.title)}">${NS.escapeHtml(row.title)}</div><div class="faint small mono">${NS.escapeHtml(row.rule_id)} ${demo}</div></td>
          <td class="mono nowrap">${NS.escapeHtml(row.src_ip || "\u2014")}</td>
          <td class="mono nowrap">${rowTarget(row)}</td>
          <td class="num">${NS.escapeHtml(row.score)}</td>
          <td><span class="status ${NS.escapeHtml(row.status)}">${NS.escapeHtml(row.status)}</span></td>
        </tr>`;
      }).join("");
      wrap.innerHTML = `<table>
        <thead><tr><th>Detected</th><th>Severity</th><th>Rule</th><th>Source</th><th>Target</th><th class="num">Score</th><th>Status</th></tr></thead>
        <tbody>${body}</tbody></table>`;
      wrap.querySelectorAll("tr[data-id]").forEach((tr) => {
        const open = () => openIncident(tr.dataset.id);
        tr.addEventListener("click", open);
        tr.addEventListener("keydown", (event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            open();
          }
        });
      });
    }

    $("resultMeta").textContent = `${NS.fmt.int(meta.total)} incident${meta.total === 1 ? "" : "s"}`;
    $("pageInfo").textContent = meta.total
      ? `Page ${meta.page} of ${meta.pages}`
      : "No results";
    $("prevPage").disabled = meta.page <= 1;
    $("nextPage").disabled = meta.page >= meta.pages;
  }

  async function load() {
    const token = ++state.loadToken;
    try {
      const payload = await NS.request(`/api/alerts?${queryString()}`);
      if (token !== state.loadToken) return;
      state.total = payload.meta.total;
      state.pages = payload.meta.pages;
      if (state.page > payload.meta.pages) {
        state.page = payload.meta.pages;
        return load();
      }
      render(payload.data.incidents, payload.meta);
      writeUrl();
    } catch (err) {
      if (token === state.loadToken) NS.errorToast(err);
    }
  }

  function applyFilters() {
    collectFilters();
    state.page = 1;
    load();
  }

  /* ---------------------------------------------------------- formatting */
  function displayValue(value) {
    if (value === null || value === undefined) return "\u2014";
    if (Array.isArray(value)) return value.length ? value.join(", ") : "\u2014";
    if (typeof value === "object") return JSON.stringify(value);
    if (typeof value === "boolean") return value ? "yes" : "no";
    return String(value);
  }

  function kvSection(title, entries) {
    if (!entries.length) return "";
    const body = entries.map(([key, value]) => {
      const text = NS.escapeHtml(displayValue(value));
      return `<dt>${NS.escapeHtml(key.replace(/_/g, " "))}</dt><dd class="mono">${text}</dd>`;
    }).join("");
    return `<section><h3>${NS.escapeHtml(title)}</h3><dl class="kv">${body}</dl></section>`;
  }

  function buildDrawer(detail) {
    const incident = detail.incident;
    const sev = NS.severityClass(incident.severity);
    $("drawerSev").className = `sev ${sev}`;
    $("drawerSev").textContent = incident.severity;
    $("drawerStatus").className = `status ${incident.status}`;
    $("drawerStatus").textContent = incident.status;
    $("drawerId").textContent = incident.id;
    $("drawerHeading").textContent = incident.title;
    $("drawerBlocked").classList.toggle("hidden", !detail.blocked);

    const reasons = (incident.reasons || []).map((reason) => `<li>${NS.escapeHtml(reason)}</li>`).join("");

    const timeline = (detail.events || []).map((event) => {
      const detailText = event.detail ? NS.escapeHtml(event.detail) : "";
      return `<li>
        <div class="event-type">${NS.escapeHtml(event.event_type)}</div>
        <div class="event-meta">${NS.escapeHtml(NS.fmt.date(event.created_at, true))}${detailText ? ` · ${detailText}` : ""}</div>
      </li>`;
    }).join("");

    const evidenceEntries = Object.entries(incident.evidence || {});
    const factEntries = Object.entries(incident.facts || {}).filter(
      ([, value]) => value !== null && value !== undefined
    );

    const parts = [];

    parts.push(`<section><h3>Summary</h3><dl class="kv">
      <dt>Detected</dt><dd class="mono">${NS.escapeHtml(NS.fmt.date(incident.detected_at, true))}</dd>
      <dt>Window</dt><dd class="mono">${NS.escapeHtml(NS.fmt.date(incident.window_start, true))} &rarr; ${NS.escapeHtml(NS.fmt.date(incident.window_end, true))}</dd>
      <dt>Source</dt><dd class="mono">${NS.escapeHtml(incident.src_ip || "\u2014")}</dd>
      <dt>Target</dt><dd class="mono">${NS.escapeHtml(incident.dst_ip || "\u2014")}${incident.dst_port ? `:${NS.escapeHtml(incident.dst_port)}` : ""}</dd>
      <dt>Score</dt><dd class="mono">${NS.escapeHtml(incident.score)} / 100</dd>
      <dt>Packets</dt><dd class="mono">${NS.escapeHtml(incident.packet_count)}</dd>
      <dt>Seen</dt><dd class="mono">${NS.escapeHtml(incident.recurrence_count)} time${incident.recurrence_count === 1 ? "" : "s"}</dd>
      <dt>Data origin</dt><dd>${incident.data_origin === "demonstration" ? '<span class="tag demo">demonstration</span>' : "captured traffic"}</dd>
    </dl></section>`);

    parts.push(`<section><h3>Why it scored ${NS.escapeHtml(incident.score)}</h3>
      ${reasons ? `<ul class="reasons">${reasons}</ul>` : '<p class="small faint">No reasons recorded.</p>'}
      <p class="small faint mt-8">Evidence sufficiency: ${incident.evidence_sufficient ? "meets the scoring threshold" : "insufficient — severity capped at medium"}.</p>
    </section>`);

    if (evidenceEntries.length) {
      parts.push(kvSection("Evidence", evidenceEntries));
    }
    if (factEntries.length) {
      parts.push(`<section><h3>Packet facts</h3><pre class="json">${NS.escapeHtml(JSON.stringify(incident.facts, null, 2))}</pre></section>`);
    }

    parts.push(`<section><h3>Timeline</h3>${timeline ? `<ul class="timeline">${timeline}</ul>` : '<p class="small faint">No events.</p>'}</section>`);

    if (incident.analyst_notes) {
      parts.push(`<section><h3>Analyst notes</h3><p class="small">${NS.escapeHtml(incident.analyst_notes)}</p></section>`);
    }

    parts.push(`<section><h3>Add a note</h3>
      <div class="field"><textarea id="noteInput" rows="3" maxlength="2000" placeholder="Optional context stored with the next status change."></textarea></div>
      <p class="help mt-8"><a href="/traffic?src=${encodeURIComponent(incident.src_ip || "")}">Show this source in traffic &rarr;</a></p>
    </section>`);

    $("drawerBody").innerHTML = parts.join("");

    renderFooter(incident, detail);
  }

  function button(label, className, onClick) {
    const node = document.createElement("button");
    node.type = "button";
    node.className = className;
    node.textContent = label;
    node.addEventListener("click", onClick);
    return node;
  }

  function renderFooter(incident, detail) {
    const foot = $("drawerFoot");
    foot.replaceChildren();

    const note = () => {
      const input = $("noteInput");
      const value = input ? input.value.trim() : "";
      return value || undefined;
    };

    if (incident.status === "new") {
      foot.append(button("Acknowledge", "btn btn-sm", () => changeStatus(incident.id, "ack", note())));
    }
    if (incident.status !== "resolved") {
      foot.append(button("Resolve", "btn btn-sm btn-primary", () => changeStatus(incident.id, "resolve", note())));
    }

    if (incident.src_ip && state.safeResponse) {
      if (detail.blocked) {
        foot.append(button("Remove simulated block", "btn btn-sm btn-ghost", () => respond("simulate_unblock", incident)));
      } else {
        foot.append(button("Simulate block source", "btn btn-sm btn-danger", () => respond("simulate_block", incident)));
      }
    }
    if (incident.src_ip && state.allowFirewall) {
      foot.append(button("Firewall block (real)", "btn btn-sm btn-danger", () => respond("firewall_block", incident)));
    }
    if (incident.src_ip && !state.safeResponse && !state.allowFirewall) {
      const hint = document.createElement("a");
      hint.className = "btn btn-sm btn-ghost";
      hint.href = "/settings";
      hint.textContent = "Response actions disabled";
      foot.append(hint);
    }

    const close = button("Close", "btn btn-sm btn-ghost", closeDrawer);
    foot.append(close);
  }

  async function changeStatus(id, action, note) {
    try {
      const payload = await NS.request(`/api/alerts/${encodeURIComponent(id)}/${action}`, {
        method: "POST",
        body: note ? { note } : {},
      });
      NS.toast(payload.data.message || "Incident updated.", "ok", 3200);
      await load();
      await openIncident(id, { keepUrl: true });
    } catch (err) {
      NS.errorToast(err);
    }
  }

  async function respond(action, incident) {
    const ip = incident.src_ip;
    if (!ip) return;
    const body = {
      action,
      target_ip: ip,
      incident_id: incident.id,
      reason: "dashboard",
    };
    if (action === "firewall_block" || action === "firewall_unblock") {
      const verb = action === "firewall_block" ? "BLOCK" : "UNBLOCK";
      const token = window.prompt(
        `This changes real firewall rules on the host. Type ${verb} ${ip} to confirm.`
      );
      if (token === null) return;
      body.confirm_token = token.trim();
    }
    try {
      const payload = await NS.request("/api/response", { method: "POST", body });
      NS.toast(payload.data.action.message, "ok", 6000);
      await openIncident(incident.id, { keepUrl: true });
    } catch (err) {
      if (err.code === "response_disabled") {
        NS.toast("Safe response is disabled. Enable it on the Settings page first.", "warn", 8000);
      } else if (err.code === "firewall_disabled") {
        NS.toast("Real firewall changes are disabled in Settings.", "warn", 8000);
      } else if (err.code === "confirm_required") {
        NS.toast(`Confirmation token did not match. Expected BLOCK ${ip}.`, "err", 8000);
      } else if (err.code === "firewall_requires_root") {
        NS.toast("The server is not running as root — firewall changes refused.", "err", 8000);
      } else {
        NS.errorToast(err);
      }
    }
  }

  /* -------------------------------------------------------------- drawer */
  async function openIncident(id, options = {}) {
    state.lastFocus = document.activeElement;
    try {
      const payload = await NS.request(`/api/alerts/${encodeURIComponent(id)}`);
      const detail = payload.data;
      buildDrawer(detail);
      $("alertDrawer").classList.add("open");
      $("alertOverlay").classList.add("open");
      $("alertDrawer").focus();
      if (!options.keepUrl) {
        state.focus = id;
        writeUrl();
      }
    } catch (err) {
      NS.errorToast(err);
      if (err.status === 404) closeDrawer();
    }
  }

  function closeDrawer() {
    $("alertDrawer").classList.remove("open");
    $("alertOverlay").classList.remove("open");
    state.focus = null;
    writeUrl();
    if (state.lastFocus && state.lastFocus.focus) state.lastFocus.focus();
    state.lastFocus = null;
  }

  /* ---------------------------------------------------------------- boot */
  async function loadRules() {
    try {
      const payload = await NS.request("/api/rules");
      const select = $("fRule");
      for (const rule of payload.data.rules) {
        const option = document.createElement("option");
        option.value = rule.id;
        option.textContent = `${rule.title} (${rule.id})`;
        select.append(option);
      }
      select.value = state.filters.rule;
    } catch (err) {
      console.warn("could not load rules", err);
    }
  }

  async function loadCapabilities() {
    try {
      const payload = await NS.request("/api/settings");
      const config = payload.data.settings.safe_response;
      state.safeResponse = Boolean(config.enabled);
      state.allowFirewall = Boolean(config.allow_firewall_changes);
    } catch (err) {
      console.warn("could not load settings", err);
    }
  }

  readUrl();
  loadRules();
  loadCapabilities();
  load().then(() => {
    if (state.focus) openIncident(state.focus, { keepUrl: true });
  });

  $("alertFilters").addEventListener("submit", (event) => {
    event.preventDefault();
    applyFilters();
  });
  for (const id of ["fSeverity", "fStatus", "fRule", "fPerPage"]) {
    $(id).addEventListener("change", () => {
      state.perPage = Number($("fPerPage").value);
      applyFilters();
    });
  }
  $("fSearch").addEventListener("input", NS.debounce(applyFilters, 350));
  $("fFrom").addEventListener("change", applyFilters);
  $("fTo").addEventListener("change", applyFilters);
  $("resetFilters").addEventListener("click", () => {
    $("fSeverity").value = "";
    $("fStatus").value = "";
    $("fRule").value = "";
    $("fSearch").value = "";
    $("fFrom").value = "";
    $("fTo").value = "";
    state.perPage = 50;
    $("fPerPage").value = "50";
    applyFilters();
  });
  $("exportBtn").addEventListener("click", () => {
    collectFilters();
    const params = new URLSearchParams();
    if (state.filters.severity) params.set("severity", state.filters.severity);
    if (state.filters.status) params.set("status", state.filters.status);
    if (state.filters.rule) params.set("rule", state.filters.rule);
    if (state.filters.q) params.set("q", state.filters.q);
    if (state.filters.from) params.set("from", state.filters.from);
    if (state.filters.to) params.set("to", state.filters.to);
    const query = params.toString();
    NS.download(`/api/export/incidents.csv${query ? `?${query}` : ""}`);
  });
  $("prevPage").addEventListener("click", () => {
    if (state.page > 1) {
      state.page -= 1;
      load();
    }
  });
  $("nextPage").addEventListener("click", () => {
    if (state.page < state.pages) {
      state.page += 1;
      load();
    }
  });
  $("closeDrawer").addEventListener("click", closeDrawer);
  $("alertOverlay").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && $("alertDrawer").classList.contains("open")) closeDrawer();
  });
})();
