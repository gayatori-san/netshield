/* Shell behaviour shared by every page: capture status, origin badge, stop. */
"use strict";

(function () {
  const NS = window.NetShield;
  const pill = document.getElementById("capturePill");
  const pillText = document.getElementById("capturePillText");
  const originBadge = document.getElementById("originBadge");
  const stopButton = document.getElementById("stopCapture");
  const shellStats = document.getElementById("shellStats");

  let lastError = null;

  function update(capture) {
    if (!capture) return;
    const state = String(capture.state || "idle");
    if (pill) {
      pill.className = `pill ${state}`;
      const label = capture.running ? `${state} · ${capture.mode}` : state;
      pillText.textContent = label;
      pill.title = capture.message || "";
    }
    if (originBadge) {
      if (capture.packets_processed) {
        const demo = capture.mode === "demo";
        originBadge.className = `origin-badge ${demo ? "demo" : "real"}`;
        originBadge.textContent = demo ? "demonstration data" : "captured traffic";
        originBadge.title = demo
          ? "Labelled synthetic traffic for the classroom demo — not live evidence."
          : "Metadata replayed from a capture file or observed on an interface.";
      } else {
        originBadge.className = "origin-badge";
        originBadge.textContent = "origin unknown";
        originBadge.title = "No packets processed yet.";
      }
    }
    if (stopButton) stopButton.classList.toggle("hidden", !capture.running);
    if (shellStats) {
      const parts = [];
      if (capture.packets_processed) parts.push(`${NS.fmt.int(capture.packets_processed)} packets`);
      if (capture.alerts_raised) parts.push(`${NS.fmt.int(capture.alerts_raised)} alerts`);
      if (capture.mode) parts.push(capture.mode);
      shellStats.textContent = parts.length ? parts.join(" · ") : "no capture yet";
    }
    if (state === "error" && capture.error && capture.error !== lastError) {
      lastError = capture.error;
      NS.toast(capture.error, "err", 9000);
    }
    if (state !== "error") lastError = null;
    window.dispatchEvent(new CustomEvent("netshield:status", { detail: capture }));
  }

  async function refreshStatus() {
    const payload = await NS.request("/api/capture/status");
    update(payload.data.capture);
  }

  if (stopButton) {
    stopButton.addEventListener("click", async () => {
      try {
        const payload = await NS.request("/api/capture/stop", { method: "POST" });
        update(payload.data.capture);
        NS.toast("Capture stopped.", "ok", 3000);
      } catch (err) {
        NS.errorToast(err);
      }
    });
  }

  NS.poll(refreshStatus, 2000);
})();
