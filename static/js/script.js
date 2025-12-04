// static/js/script.js

document.addEventListener("DOMContentLoaded", () => {
  /* =========================================================
   * 0. Toast notification system
   * ========================================================= */
  function showToast(options) {
    if (!options) return;
    const { message, type = "info", title = null, duration = 4500 } = options;
    if (!message) return;

    let container = document.querySelector(".toast-container");
    if (!container) {
      container = document.createElement("div");
      container.className = "toast-container";
      document.body.appendChild(container);
    }

    const toast = document.createElement("div");
    toast.className = "toast";

    const validTypes = ["success", "error", "warning", "info"];
    const toastType = validTypes.includes(type) ? type : "info";
    toast.classList.add(`toast-${toastType}`);

    const icon = document.createElement("div");
    icon.className = "toast-icon";
    if (toastType === "success") icon.textContent = "✅";
    else if (toastType === "error") icon.textContent = "❌";
    else if (toastType === "warning") icon.textContent = "⚠️";
    else icon.textContent = "ℹ️";

    const content = document.createElement("div");
    content.className = "toast-content";

    const titleEl = document.createElement("div");
    titleEl.className = "toast-title";
    if (title) {
      titleEl.textContent = title;
    } else {
      if (toastType === "success") titleEl.textContent = "Success";
      else if (toastType === "error") titleEl.textContent = "Error";
      else if (toastType === "warning") titleEl.textContent = "Warning";
      else titleEl.textContent = "Notice";
    }

    const msgEl = document.createElement("div");
    msgEl.className = "toast-message";
    msgEl.textContent = message;

    content.appendChild(titleEl);
    content.appendChild(msgEl);

    const closeBtn = document.createElement("button");
    closeBtn.className = "toast-close";
    closeBtn.type = "button";
    closeBtn.setAttribute("aria-label", "Dismiss notification");
    closeBtn.textContent = "×";

    const progress = document.createElement("div");
    progress.className = "toast-progress";
    progress.style.animationDuration = `${duration}ms`;

    toast.appendChild(icon);
    toast.appendChild(content);
    toast.appendChild(closeBtn);
    toast.appendChild(progress);

    container.appendChild(toast);

    let removed = false;

    function removeToast() {
      if (removed) return;
      removed = true;
      toast.classList.add("toast-exiting");
      setTimeout(() => {
        toast.remove();
        if (container.children.length === 0) {
          container.remove();
        }
      }, 200);
    }

    const timer = setTimeout(removeToast, duration);

    closeBtn.addEventListener("click", () => {
      clearTimeout(timer);
      removeToast();
    });
  }

  // Expose for debugging if needed
  window.showToast = showToast;

  /* =========================================================
   * 1. Theme handling (light / dark) for app + auth pages
   * ========================================================= */
  function applyTheme(theme) {
    const appBody = document.querySelector(".app-body");
    const authBody = document.querySelector(".auth-body");
    const icon = document.getElementById("themeToggleIcon");

    const finalTheme = theme === "dark" ? "dark" : "light";

    if (appBody) appBody.setAttribute("data-theme", finalTheme);
    if (authBody) authBody.setAttribute("data-theme", finalTheme);

    if (icon) {
      icon.textContent = finalTheme === "dark" ? "☀️" : "🌙";
    }
  }

  const savedTheme = localStorage.getItem("theme") || "light";
  applyTheme(savedTheme);

  const themeToggle = document.getElementById("themeToggle");
  if (themeToggle) {
    themeToggle.addEventListener("click", () => {
      const current = localStorage.getItem("theme") || "light";
      const next = current === "dark" ? "light" : "dark";
      localStorage.setItem("theme", next);
      applyTheme(next);

      showToast({
        type: "info",
        title: "Theme switched",
        message: next === "dark" ? "Dark mode enabled." : "Light mode enabled.",
        duration: 2200,
      });
    });
  }

  /* =========================================================
   * 2. Top navigation: page switching (dashboard only)
   * ========================================================= */
  const navPills = document.querySelectorAll(".nav-pill");
  const pages = document.querySelectorAll(".page-section");

  navPills.forEach((pill) => {
    pill.addEventListener("click", () => {
      const targetId = pill.getAttribute("data-target");
      if (!targetId) return;

      navPills.forEach((p) => p.classList.remove("nav-pill-active"));
      pill.classList.add("nav-pill-active");

      pages.forEach((section) => {
        if (section.id === targetId) {
          section.classList.add("page-section-active");
        } else {
          section.classList.remove("page-section-active");
        }
      });

      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  });

  /* =========================================================
   * 3. Scan form: validation + overlay + toasts
   * ========================================================= */
  const form = document.getElementById("scanForm");
  const urlInput = document.getElementById("urlInput");
  const scanBtn = document.getElementById("scanBtn");
  const urlHint = document.getElementById("urlHint");

  // Evaluate URL and return { status, message }
  // status: "empty" | "error" | "warn" | "ok"
  function evaluateUrl(text) {
    const value = (text || "").trim();

    if (value.length === 0) {
      return {
        status: "empty",
        message: "Paste a financial or login URL to analyze.",
      };
    }

    // Very basic "looks like URL" check: must contain a dot and no spaces
    if (!value.includes(".") || value.includes(" ")) {
      return {
        status: "error",
        message:
          "This doesn’t look like a complete URL. Include a domain like example.com.",
      };
    }

    const vLower = value.toLowerCase();
    const suspectWords = [
      "login",
      "signin",
      "verify",
      "secure",
      "update",
      "bank",
      "payment",
      "paypal",
    ];
    const found = suspectWords.filter((w) => vLower.includes(w));

    if (found.length >= 2) {
      return {
        status: "warn",
        message: `Warning: Contains multiple sensitive terms (${found.join(
          ", "
        )}). High chance of phishing.`,
      };
    }

    if (found.length === 1) {
      return {
        status: "warn",
        message: `Looks like a login/payment link (found “${found[0]}”). Scan recommended.`,
      };
    }

    return {
      status: "ok",
      message:
        "Looks like a valid URL format. Final decision will use ML + OSINT.",
    };
  }

  function updateHint(value) {
    if (!urlHint || !urlInput) return "empty";

    const { status, message } = evaluateUrl(value);

    urlHint.textContent = message;
    urlHint.classList.remove("ok", "warn", "error");
    urlInput.classList.remove("valid", "invalid");

    if (status === "ok") {
      urlHint.classList.add("ok");
      urlInput.classList.add("valid");
    } else if (status === "warn") {
      urlHint.classList.add("warn");
      urlInput.classList.add("valid");
    } else if (status === "error") {
      urlHint.classList.add("error");
      urlInput.classList.add("invalid");
    }

    return status;
  }

  function showOverlay() {
    if (document.querySelector(".scan-overlay")) return;

    const overlay = document.createElement("div");
    overlay.className = "scan-overlay";

    overlay.innerHTML = `
      <div class="scan-overlay-inner">
        <div class="scan-spinner"></div>
        <div class="scan-overlay-title">Analyzing URL…</div>
        <div class="scan-overlay-text">
          Running Random Forest model and OSINT checks<br>
          (WHOIS, SSL, redirects, suspicious keywords).
        </div>
      </div>
    `;

    document.body.appendChild(overlay);
  }

  if (urlInput && urlHint) {
    // Focus input on load (only on dashboard page)
    if (form) {
      urlInput.focus();
    }

    // Live validation on typing
    urlInput.addEventListener("input", () => {
      updateHint(urlInput.value);
    });

    // Ctrl+Enter shortcut
    urlInput.addEventListener("keydown", (e) => {
      if (e.ctrlKey && e.key === "Enter" && form) {
        form.requestSubmit();
      }
    });

    // Initialize hint on first load
    updateHint(urlInput.value || "");
  }

  if (form && urlInput && scanBtn && urlHint) {
    form.addEventListener("submit", (e) => {
      const raw = urlInput.value || "";
      const trimmed = raw.trim();
      urlInput.value = trimmed;

      const status = updateHint(trimmed);

      if (status === "error" || status === "empty") {
        e.preventDefault();
        urlInput.focus();

        showToast({
          type: "error",
          message:
            status === "empty"
              ? "Please paste a URL before scanning."
              : "This doesn’t look like a valid URL. Include a domain like example.com.",
        });
        return;
      }

      if (status === "warn") {
        showToast({
          type: "warning",
          message:
            "This URL contains sensitive terms (login/payment). Proceeding with deep analysis.",
          duration: 3500,
        });
      } else if (status === "ok") {
        showToast({
          type: "success",
          message: "URL submitted to the ML model for analysis.",
          duration: 2600,
        });
      }

      // Add loading state to button
      scanBtn.classList.add("loading");
      scanBtn.disabled = true;

      // Show full-screen overlay
      showOverlay();
    });
  }

  /* =========================================================
   * 4. Flash messages from Flask → toasts (login/register)
   * ========================================================= */
  const flashScript = document.getElementById("flashData");
  if (flashScript) {
    try {
      const text = flashScript.textContent || flashScript.innerText || "";
      const trimmed = text.trim();
      if (trimmed) {
        const flashes = JSON.parse(trimmed);
        if (Array.isArray(flashes)) {
          flashes.forEach(([category, message]) => {
            let type = "info";
            if (category === "success") type = "success";
            else if (category === "error") type = "error";
            else if (category === "warning") type = "warning";

            showToast({
              type,
              message,
            });
          });
        }
      }
    } catch (err) {
      console.error("Failed to parse flash messages JSON:", err);
    }
  }
});
