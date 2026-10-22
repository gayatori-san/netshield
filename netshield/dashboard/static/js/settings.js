/* Settings: populate from the API, validate locally, PATCH-style PUT. */
"use strict";

(function () {
  const NS = window.NetShield;
  const $ = (id) => document.getElementById(id);
  const fields = Array.from(document.querySelectorAll("[data-path]"));

  const state = { lastFirewall: false, saving: false };

  function getPath(object, path) {
    return path.split(".").reduce((node, key) => (node == null ? undefined : node[key]), object);
  }

  function setPath(object, path, value) {
    const keys = path.split(".");
    let node = object;
    for (const key of keys.slice(0, -1)) {
      if (!node[key] || typeof node[key] !== "object") node[key] = {};
      node = node[key];
    }
    node[keys[keys.length - 1]] = value;
  }

  function populate(settings) {
    for (const input of fields) {
      const path = input.dataset.path;
      const kind = input.dataset.kind;
      const value = getPath(settings, path);
      if (kind === "bool") {
        input.checked = Boolean(value);
      } else if (kind === "ports") {
        input.value = Array.isArray(value) ? value.join(", ") : "";
      } else if (kind === "cidrs") {
        input.value = Array.isArray(value) ? value.join("\n") : "";
      } else {
        input.value = value === null || value === undefined ? "" : String(value);
      }
    }
    state.lastFirewall = Boolean(getPath(settings, "safe_response.allow_firewall_changes"));
  }

  function populateDeployment(settings) {
    const dl = $("deploymentInfo");
    const rows = [
      ["Database", settings.db_path],
      ["Default mode", (settings.capture || {}).default_mode],
      ["Flush interval", `${(settings.capture || {}).flush_interval_seconds}s`],
      ["Queue capacity", NS.fmt.int((settings.capture || {}).queue_maxsize)],
      ["Demo duration", `${settings.demo_duration}s`],
    ];
    dl.replaceChildren();
    for (const [label, value] of rows) {
      const dt = document.createElement("dt");
      dt.textContent = label;
      const dd = document.createElement("dd");
      dd.className = "mono";
      dd.textContent = value === undefined || value === null ? "\u2014" : String(value);
      dl.append(dt, dd);
    }
  }

  function clearErrors() {
    for (const input of fields) {
      input.removeAttribute("aria-invalid");
      const existing = document.getElementById(`${input.id}-err`);
      if (existing) existing.remove();
    }
    $("settingsNotice").textContent = "";
    $("settingsNotice").className = "notice";
  }

  function fieldError(name, reason) {
    const input = document.querySelector(`[data-path="${name}"]`);
    if (!input) return false;
    input.setAttribute("aria-invalid", "true");
    const node = document.createElement("span");
    node.className = "help err";
    node.id = `${input.id}-err`;
    node.textContent = reason;
    input.insertAdjacentElement("afterend", node);
    return true;
  }

  function showErrors(err) {
    const detail = err.detail || {};
    const list = Array.isArray(detail.fields) ? detail.fields : [];
    let mapped = false;
    for (const item of list) {
      if (fieldError(item.field, item.reason)) mapped = true;
      else if (!mapped) NS.toast(`${item.field}: ${item.reason}`, "err", 7000);
    }
    if (!list.length) {
      NS.errorToast(err);
    } else if (list.length > 1) {
      NS.toast(`${list.length} settings need attention.`, "err", 5000);
    }
  }

  function readValue(input) {
    const kind = input.dataset.kind;
    if (kind === "bool") return input.checked;
    const raw = input.value.trim();
    if (kind === "ports") {
      if (!raw) return [];
      return raw.split(/[\s,]+/).filter(Boolean).map((part) => {
        if (!/^\d+$/.test(part)) throw new Error("Sensitive ports must be whole numbers.");
        return Number(part);
      });
    }
    if (kind === "cidrs") {
      if (!raw) return [];
      return raw.split(/[\s,]+/).filter(Boolean);
    }
    if (raw === "") throw new Error("This value is required.");
    const number = Number(raw);
    if (!Number.isFinite(number)) throw new Error("Enter a number.");
    if (kind === "int" && !Number.isInteger(number)) throw new Error("Enter a whole number.");
    return number;
  }

  function buildPatch() {
    const patch = {};
    for (const input of fields) {
      setPath(patch, input.dataset.path, readValue(input));
    }
    return patch;
  }

  async function load() {
    try {
      const payload = await NS.request("/api/settings");
      populate(payload.data.settings);
      populateDeployment(payload.data.settings);
      clearErrors();
    } catch (err) {
      NS.errorToast(err);
    }
  }

  async function save(event) {
    event.preventDefault();
    if (state.saving) return;
    clearErrors();

    let patch;
    try {
      patch = buildPatch();
    } catch (err) {
      NS.toast(err.message, "err");
      return;
    }

    const firewall = Boolean(getPath(patch, "safe_response.allow_firewall_changes"));
    if (firewall && !state.lastFirewall) {
      const ok = window.confirm(
        "Enable real firewall changes? NetShield will be allowed to insert iptables INPUT DROP rules for lab-range targets when running as root. Only do this on a disposable lab host."
      );
      if (!ok) return;
    }

    state.saving = true;
    $("saveSettings").disabled = true;
    try {
      const payload = await NS.request("/api/settings", { method: "PUT", body: patch });
      populate(payload.data.settings);
      populateDeployment(payload.data.settings);
      $("settingsNotice").textContent = payload.data.message;
      $("settingsNotice").className = "notice ok";
      NS.toast(payload.data.message, payload.data.applied_immediately ? "ok" : "warn", 6000);
    } catch (err) {
      showErrors(err);
    } finally {
      state.saving = false;
      $("saveSettings").disabled = false;
    }
  }

  $("settingsForm").addEventListener("submit", save);
  $("reloadSettings").addEventListener("click", load);
  load();
})();
