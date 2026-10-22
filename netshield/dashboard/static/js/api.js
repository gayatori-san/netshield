/* Shared client helpers: fetch envelope, formatting, toasts, polling. */
"use strict";

(function () {
  class ApiError extends Error {
    constructor(status, payload) {
      const error = (payload && payload.error) || {};
      super(error.message || `Request failed (${status})`);
      this.name = "ApiError";
      this.status = status;
      this.code = error.code || "error";
      this.detail = error.detail || {};
    }
  }

  async function request(path, options = {}) {
    const init = {
      method: options.method || "GET",
      headers: Object.assign({ Accept: "application/json" }, options.headers || {}),
      credentials: "same-origin",
    };
    if (options.body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(options.body);
    }
    if (options.signal) init.signal = options.signal;

    let response;
    try {
      response = await fetch(path, init);
    } catch (err) {
      if (err.name === "AbortError") throw err;
      throw new ApiError(0, { error: { message: "Network unreachable", code: "network" } });
    }

    if (response.status === 204) return { ok: true, data: null };
    let payload = null;
    const type = response.headers.get("Content-Type") || "";
    if (type.includes("application/json")) {
      payload = await response.json();
    }
    if (!response.ok || (payload && payload.ok === false)) {
      throw new ApiError(response.status, payload);
    }
    return payload || { ok: true, data: null };
  }

  async function upload(path, formData) {
    let response;
    try {
      response = await fetch(path, { method: "POST", body: formData, credentials: "same-origin" });
    } catch (err) {
      throw new ApiError(0, { error: { message: "Network unreachable", code: "network" } });
    }
    let payload = null;
    try {
      payload = await response.json();
    } catch (err) {
      payload = null;
    }
    if (!response.ok || (payload && payload.ok === false)) {
      throw new ApiError(response.status, payload);
    }
    return payload;
  }

  const pad = (n) => String(n).padStart(2, "0");

  function date(value, withDate) {
    if (value === null || value === undefined || Number.isNaN(value)) return "—";
    const d = new Date(Number(value) * 1000);
    if (Number.isNaN(d.getTime())) return "—";
    const time = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    if (!withDate) return time;
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${time}`;
  }

  function relative(value) {
    if (!value) return "—";
    const seconds = Math.max(0, Date.now() / 1000 - Number(value));
    if (seconds < 5) return "just now";
    if (seconds < 60) return `${Math.floor(seconds)}s ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
  }

  function duration(seconds) {
    const value = Number(seconds);
    if (!Number.isFinite(value)) return "—";
    if (value < 1) return `${Math.round(value * 1000)}ms`;
    if (value < 60) return `${value.toFixed(value < 10 ? 1 : 0)}s`;
    if (value < 3600) return `${Math.floor(value / 60)}m ${Math.round(value % 60)}s`;
    return `${Math.floor(value / 3600)}h ${Math.round((value % 3600) / 60)}m`;
  }

  const int = (value) => new Intl.NumberFormat().format(Number(value) || 0);

  function bytes(value) {
    const n = Number(value) || 0;
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
    if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MiB`;
    return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GiB`;
  }

  const HTML_ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  const escapeHtml = (value) =>
    String(value === null || value === undefined ? "" : value).replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]);

  const severityClass = (value) => {
    const text = String(value || "").toLowerCase();
    return ["high", "medium", "low"].includes(text) ? text : "low";
  };

  function toast(message, kind = "info", ttl = 5200) {
    const stack = document.getElementById("toasts");
    if (!stack) return;
    const node = document.createElement("div");
    node.className = `toast ${kind}`;
    const text = document.createElement("div");
    text.textContent = message;
    const close = document.createElement("button");
    close.type = "button";
    close.setAttribute("aria-label", "Dismiss");
    close.textContent = "×";
    close.addEventListener("click", () => node.remove());
    node.append(text, close);
    stack.append(node);
    if (ttl > 0) setTimeout(() => node.remove(), ttl);
  }

  function errorToast(err) {
    const fields = err && err.detail && err.detail.fields;
    if (Array.isArray(fields) && fields.length) {
      const first = fields[0];
      toast(`${first.field}: ${first.reason}`, "err");
      return;
    }
    const detail = err && err.detail;
    if (detail && detail.field) {
      toast(`${detail.field}: ${detail.reason || err.message}`, "err");
      return;
    }
    toast((err && err.message) || "Unexpected error", "err");
  }

  function poll(fn, intervalMs) {
    let timer = null;
    let stopped = false;
    async function tick() {
      if (stopped) return;
      if (document.hidden) {
        timer = setTimeout(tick, intervalMs);
        return;
      }
      try {
        await fn();
      } catch (err) {
        if (!err || err.name !== "AbortError") console.warn("poll failed", err);
      }
      if (!stopped) timer = setTimeout(tick, intervalMs);
    }
    tick();
    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
    };
  }

  function debounce(fn, delay) {
    let timer = null;
    return (...args) => {
      clearTimeout(timer);
      timer = setTimeout(() => fn(...args), delay);
    };
  }

  function download(url) {
    const link = document.createElement("a");
    link.href = url;
    link.rel = "noopener";
    document.body.append(link);
    link.click();
    link.remove();
  }

  window.NetShield = {
    ApiError,
    request,
    upload,
    toast,
    errorToast,
    poll,
    debounce,
    download,
    severityClass,
    escapeHtml,
    fmt: { date, relative, duration, int, bytes },
  };
})();
