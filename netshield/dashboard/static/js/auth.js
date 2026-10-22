/* Firebase web setup shared by the login page and the dashboard shell. */
"use strict";

(function () {
  const configNode = document.getElementById("firebase-web-config");
  let webConfig = null;
  if (configNode && configNode.textContent.trim()) {
    try {
      webConfig = JSON.parse(configNode.textContent);
    } catch (err) {
      webConfig = null;
    }
  }

  const hasSdk = typeof window.firebase !== "undefined";
  let auth = null;
  let initError = "";
  if (!webConfig) {
    initError = "Firebase web configuration is missing on the server.";
  } else if (!hasSdk) {
    initError = "The vendored Firebase SDK did not load.";
  } else {
    try {
      if (!window.firebase.apps.length) {
        window.firebase.initializeApp(webConfig);
      }
      auth = window.firebase.auth();
      auth.languageCode = "en";
    } catch (err) {
      initError = err && err.message ? err.message : "Firebase failed to initialise.";
    }
  }

  let cachedToken = null;
  let cachedUntil = 0;

  async function getIdToken(force) {
    if (!auth) throw new Error(initError || "Firebase is not configured.");
    const user = auth.currentUser;
    if (!user) throw new Error("No signed-in Firebase user.");
    const now = Date.now();
    if (!force && cachedToken && cachedUntil > now + 60000) return cachedToken;
    const token = await user.getIdToken(force === true);
    try {
      const payload = JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
      cachedUntil = payload.exp ? payload.exp * 1000 : now + 5 * 60 * 1000;
    } catch (err) {
      cachedUntil = now + 5 * 60 * 1000;
    }
    cachedToken = token;
    return token;
  }

  function clearToken() {
    cachedToken = null;
    cachedUntil = 0;
  }

  function redirectToLogin() {
    const next = window.location.pathname + window.location.search;
    window.location.assign(`/login?next=${encodeURIComponent(next)}`);
  }

  async function signOut() {
    clearToken();
    try {
      if (auth) await auth.signOut();
    } catch (err) {
      /* the server cookie is cleared regardless */
    }
    try {
      await fetch("/api/auth/logout", {
        method: "POST",
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      });
    } catch (err) {
      /* offline is fine; the redirect still happens */
    }
    window.location.assign("/login");
  }

  window.NetShieldAuth = {
    get auth() {
      return auth;
    },
    get error() {
      return initError;
    },
    get ready() {
      return Boolean(auth);
    },
    getIdToken,
    clearToken,
    redirectToLogin,
    signOut,
  };
})();
