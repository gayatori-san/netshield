/* Traffic: paginated packet metadata with server-side filters. */
"use strict";

(function () {
  const NS = window.NetShield;
  const $ = (id) => document.getElementById(id);

  const state = {
    page: 1,
    perPage: 50,
    pages: 1,
    total: 0,
    filters: { proto: "", src: "", dst: "", q: "" },
    token: 0,
  };

  function readUrl() {
    const params = new URLSearchParams(window.location.search);
    state.page = Math.max(1, Number(params.get("page")) || 1);
    const perPage = Number(params.get("per_page"));
    state.perPage = [25, 50, 100, 200].includes(perPage) ? perPage : 50;
    state.filters = {
      proto: params.get("proto") || "",
      src: params.get("src") || "",
      dst: params.get("dst") || "",
      q: params.get("q") || "",
    };
    $("tProto").value = state.filters.proto;
    $("tSrc").value = state.filters.src;
    $("tDst").value = state.filters.dst;
    $("tSearch").value = state.filters.q;
    $("tPerPage").value = String(state.perPage);
  }

  function collectFilters() {
    state.filters = {
      proto: $("tProto").value,
      src: $("tSrc").value.trim(),
      dst: $("tDst").value.trim(),
      q: $("tSearch").value.trim(),
    };
  }

  function writeUrl() {
    const params = new URLSearchParams();
    if (state.page > 1) params.set("page", state.page);
    if (state.perPage !== 50) params.set("per_page", state.perPage);
    for (const [key, value] of Object.entries(state.filters)) {
      if (value) params.set(key, value);
    }
    const query = params.toString();
    history.replaceState(null, "", query ? `?${query}` : window.location.pathname);
  }

  function endpoint(port) {
    return port === null || port === undefined ? "" : `:${port}`;
  }

  function render(rows, meta) {
    const wrap = $("trafficWrap");
    const filtered = Object.values(state.filters).some(Boolean);
    if (!rows.length) {
      wrap.innerHTML = filtered
        ? '<div class="empty"><strong>No packets match these filters</strong>Broaden the filter or clear the search.</div>'
        : '<div class="empty"><strong>No packets stored</strong>Start a capture to populate the log.</div>';
    } else {
      const body = rows.map((row) => {
        const origin = row.origin === "demonstration" ? '<span class="tag demo">demo</span>' : '<span class="tag">real</span>';
        const blocked = row.blocked ? '<span class="tag blocked">blocked</span>' : "";
        const flags = row.flags || row.tcp_state || "";
        const proto = String(row.protocol || "").toUpperCase();
        return `<tr>
          <td class="mono nowrap">${NS.escapeHtml(NS.fmt.date(row.ts))}<div class="faint small nowrap">${NS.escapeHtml(NS.fmt.relative(row.ts))}</div></td>
          <td><span class="mono">${NS.escapeHtml(proto)}</span></td>
          <td class="mono nowrap">${NS.escapeHtml(row.src_ip)}${NS.escapeHtml(endpoint(row.src_port))}</td>
          <td class="mono nowrap">${NS.escapeHtml(row.dst_ip)}${NS.escapeHtml(endpoint(row.dst_port))}</td>
          <td class="num">${NS.escapeHtml(NS.fmt.bytes(row.size))}</td>
          <td class="mono nowrap faint">${NS.escapeHtml(flags)}</td>
          <td class="nowrap">${origin}</td>
          <td>${blocked}</td>
        </tr>`;
      }).join("");
      wrap.innerHTML = `<table>
        <thead><tr><th>Time</th><th>Proto</th><th>Source</th><th>Destination</th><th class="num">Bytes</th><th>Flags</th><th>Origin</th><th>Response</th></tr></thead>
        <tbody>${body}</tbody></table>`;
    }

    $("trafficMeta").textContent = `${NS.fmt.int(meta.total)} packet${meta.total === 1 ? "" : "s"}`;
    $("trafficPageInfo").textContent = meta.total ? `Page ${meta.page} of ${meta.pages}` : "No results";
    $("tPrev").disabled = meta.page <= 1;
    $("tNext").disabled = meta.page >= meta.pages;
  }

  function queryString() {
    const params = new URLSearchParams();
    params.set("page", state.page);
    params.set("per_page", state.perPage);
    if (state.filters.proto) params.set("proto", state.filters.proto);
    if (state.filters.src) params.set("src", state.filters.src);
    if (state.filters.dst) params.set("dst", state.filters.dst);
    if (state.filters.q) params.set("q", state.filters.q);
    return params.toString();
  }

  async function load() {
    const token = ++state.token;
    try {
      const payload = await NS.request(`/api/traffic?${queryString()}`);
      if (token !== state.token) return;
      state.total = payload.meta.total;
      state.pages = payload.meta.pages;
      if (state.page > payload.meta.pages) {
        state.page = payload.meta.pages;
        return load();
      }
      render(payload.data.packets, payload.meta);
      writeUrl();
    } catch (err) {
      if (token === state.token) NS.errorToast(err);
    }
  }

  function applyFilters() {
    collectFilters();
    state.page = 1;
    load();
  }

  readUrl();
  load();

  $("trafficFilters").addEventListener("submit", (event) => {
    event.preventDefault();
    applyFilters();
  });
  $("tProto").addEventListener("change", applyFilters);
  $("tPerPage").addEventListener("change", () => {
    state.perPage = Number($("tPerPage").value);
    applyFilters();
  });
  $("tSrc").addEventListener("input", NS.debounce(applyFilters, 400));
  $("tDst").addEventListener("input", NS.debounce(applyFilters, 400));
  $("tSearch").addEventListener("input", NS.debounce(applyFilters, 400));
  $("tRefresh").addEventListener("click", load);
  $("tReset").addEventListener("click", () => {
    $("tProto").value = "";
    $("tSrc").value = "";
    $("tDst").value = "";
    $("tSearch").value = "";
    state.perPage = 50;
    $("tPerPage").value = "50";
    applyFilters();
  });
  $("tPrev").addEventListener("click", () => {
    if (state.page > 1) {
      state.page -= 1;
      load();
    }
  });
  $("tNext").addEventListener("click", () => {
    if (state.page < state.pages) {
      state.page += 1;
      load();
    }
  });

  NS.poll(() => {
    const typing = ["tSrc", "tDst", "tSearch"].includes(document.activeElement && document.activeElement.id);
    if (!typing) load();
  }, 5000);
})();
