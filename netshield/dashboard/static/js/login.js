/* Email/password sign-in and password reset. Accounts are admin-provisioned. */
"use strict";

(function () {
  const authApi = window.NetShieldAuth;
  const root = document.querySelector("[data-login]");
  if (!root || !authApi) return;

  const nextPath = root.dataset.next || "/";
  const ready = root.dataset.ready === "true" && authApi.ready;
  const form = document.getElementById("loginForm");
  const emailInput = document.getElementById("email");
  const passwordInput = document.getElementById("password");
  const submitButton = document.getElementById("loginSubmit");
  const message = document.getElementById("loginMessage");
  const forgotButton = document.getElementById("forgotPassword");
  const togglePassword = document.getElementById("togglePassword");

  function showMessage(text, kind) {
    message.textContent = text;
    message.className = `auth-message ${kind || ""}`.trim();
    message.hidden = !text;
  }

  function setBusy(busy) {
    submitButton.disabled = busy || !ready;
    submitButton.classList.toggle("loading", busy);
    Array.from(form.elements).forEach((element) => {
      if (element !== submitButton) element.disabled = busy || !ready;
    });
    if (forgotButton) forgotButton.disabled = busy || !ready;
  }

  function friendlyError(err) {
    const code = (err && err.code) || "";
    const map = {
      "auth/invalid-email": "That email address is not valid.",
      "auth/missing-email": "Enter an email address.",
      "auth/user-not-found": "No account exists for that email address.",
      "auth/wrong-password": "Incorrect email or password.",
      "auth/invalid-credential": "Incorrect email or password.",
      "auth/invalid-login-credentials": "Incorrect email or password.",
      "auth/user-disabled": "This account has been disabled.",
      "auth/too-many-requests": "Too many attempts. Wait a moment and try again.",
      "auth/network-request-failed": "The browser could not reach Firebase.",
      "auth/operation-not-allowed": "Email/password sign-in is not enabled for this project.",
      "auth/unauthorized-domain": "This domain is not authorised in Firebase Authentication.",
    };
    if (map[code]) return map[code];
    return (err && err.message) || "Authentication failed.";
  }

  async function establishSession() {
    const token = await authApi.getIdToken(true);
    const response = await fetch("/api/auth/session", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: "{}",
    });
    let payload = null;
    try {
      payload = await response.json();
    } catch (err) {
      payload = null;
    }
    if (!response.ok) {
      const messageText =
        (payload && payload.error && payload.error.message) ||
        `The server could not create a session (${response.status}).`;
      throw new Error(messageText);
    }
    window.location.assign(nextPath);
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!ready) return;
    setBusy(true);
    showMessage("", "");
    try {
      await authApi.auth.signInWithEmailAndPassword(
        emailInput.value.trim(),
        passwordInput.value
      );
      await establishSession();
    } catch (err) {
      showMessage(friendlyError(err), "err");
      setBusy(false);
    }
  });

  if (forgotButton) {
    forgotButton.addEventListener("click", async () => {
      const email = emailInput.value.trim();
      if (!email) {
        showMessage("Enter your email address first, then choose reset.", "err");
        emailInput.focus();
        return;
      }
      setBusy(true);
      try {
        await authApi.auth.sendPasswordResetEmail(email);
        showMessage("Password reset email sent. Check your inbox.", "ok");
      } catch (err) {
        showMessage(friendlyError(err), "err");
      } finally {
        setBusy(false);
      }
    });
  }

  if (togglePassword) {
    togglePassword.addEventListener("click", () => {
      const showing = passwordInput.type === "text";
      passwordInput.type = showing ? "password" : "text";
      togglePassword.setAttribute("aria-pressed", showing ? "false" : "true");
      togglePassword.textContent = showing ? "Show" : "Hide";
    });
  }

  if (!ready) {
    setBusy(false);
    return;
  }

  if (authApi.auth.currentUser) {
    form.classList.add("hidden");
    showMessage("Restoring your session…", "ok");
    establishSession().catch((err) => {
      form.classList.remove("hidden");
      showMessage(err.message || "Could not restore the session.", "err");
    });
  }
})();
