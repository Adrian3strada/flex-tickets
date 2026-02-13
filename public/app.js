function badgeClass(estado) {
  if (estado === "cerrado") return "badge badge-closed"
  if (estado === "en_proceso") return "badge badge-progress"
  return "badge badge-open"
}

function escapeHtml(value) {
  return String(value || "—")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;")
}

function parseDateValue(value) {
  if (!value) return null
  const trimmed = String(value).trim()
  if (!trimmed) return null

  if (/^\d{4}-\d{2}-\d{2}$/.test(trimmed)) {
    const [year, month, day] = trimmed.split("-").map(Number)
    const date = new Date(year, month - 1, day)
    return Number.isNaN(date.getTime()) ? null : date
  }

  if (/^\d{4}-\d{2}-\d{2}T/.test(trimmed)) {
    const isoDate = new Date(trimmed)
    return Number.isNaN(isoDate.getTime()) ? null : isoDate
  }

  const match = trimmed.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})(?:,\s*(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([ap]\.?m\.?)?)?$/i)
  if (match) {
    const day = Number(match[1])
    const month = Number(match[2])
    const year = Number(match[3])
    let hours = Number(match[4] || 0)
    const minutes = Number(match[5] || 0)
    const seconds = Number(match[6] || 0)
    const meridian = (match[7] || "").toLowerCase().replace(".", "")
    if (meridian === "pm" && hours < 12) hours += 12
    if (meridian === "am" && hours === 12) hours = 0
    const date = new Date(year, month - 1, day, hours, minutes, seconds)
    return Number.isNaN(date.getTime()) ? null : date
  }

  const fallback = new Date(trimmed)
  return Number.isNaN(fallback.getTime()) ? null : fallback
}

function formatDateTime(value) {
  const date = parseDateValue(value)
  if (!date) return "—"
  return new Intl.DateTimeFormat("es-MX", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false
  }).format(date)
}

function ensureModalRoot() {
  let root = document.getElementById("modal-root")
  if (root) return root
  root = document.createElement("div")
  root.id = "modal-root"
  document.body.appendChild(root)
  return root
}

function showModal({ title, message, mode = "alert", confirmText = "Aceptar", cancelText = "Cancelar", placeholder = "", defaultValue = "" }) {
  const root = ensureModalRoot()
  root.innerHTML = ""
  const overlay = document.createElement("div")
  overlay.className = "modal-backdrop"
  const card = document.createElement("div")
  card.className = "modal-card"

  const header = document.createElement("div")
  header.className = "modal-header"
  header.textContent = title || "Aviso"

  const body = document.createElement("div")
  body.className = "modal-body"
  body.textContent = message || ""

  let input = null
  if (mode === "prompt") {
    input = document.createElement("input")
    input.className = "modal-input"
    input.type = "text"
    input.placeholder = placeholder
    input.value = defaultValue || ""
    body.appendChild(input)
  }

  const actions = document.createElement("div")
  actions.className = "modal-actions"

  const cancelBtn = document.createElement("button")
  cancelBtn.className = "btn btn-ghost"
  cancelBtn.type = "button"
  cancelBtn.textContent = cancelText

  const confirmBtn = document.createElement("button")
  confirmBtn.className = "btn btn-primary"
  confirmBtn.type = "button"
  confirmBtn.textContent = confirmText

  if (mode === "confirm" || mode === "prompt") {
    actions.appendChild(cancelBtn)
  }
  actions.appendChild(confirmBtn)

  card.appendChild(header)
  card.appendChild(body)
  card.appendChild(actions)
  overlay.appendChild(card)
  root.appendChild(overlay)

  return new Promise((resolve) => {
    function cleanup(result) {
      document.removeEventListener("keydown", onKey)
      root.innerHTML = ""
      resolve(result)
    }

    function onConfirm() {
      if (mode === "prompt") {
        cleanup(input ? String(input.value || "") : "")
        return
      }
      cleanup(true)
    }

    function onCancel() {
      if (mode === "prompt") {
        cleanup(null)
        return
      }
      cleanup(false)
    }

    overlay.addEventListener("click", (event) => {
      if (event.target === overlay) onCancel()
    })
    confirmBtn.addEventListener("click", onConfirm)
    cancelBtn.addEventListener("click", onCancel)

    function onKey(event) {
      if (event.key === "Escape") {
        onCancel()
      } else if (event.key === "Enter") {
        onConfirm()
      }
    }
    document.addEventListener("keydown", onKey)

    setTimeout(() => {
      if (input) {
        input.focus()
        input.select()
      } else {
        confirmBtn.focus()
      }
    }, 0)
  })
}

function uiAlert(message, options = {}) {
  return showModal({ ...options, message, mode: "alert" })
}

function uiConfirm(message, options = {}) {
  return showModal({ ...options, message, mode: "confirm" })
}

function uiPrompt(message, options = {}) {
  return showModal({ ...options, message, mode: "prompt" })
}

function ensureToastRoot() {
  let root = document.getElementById("toast-root")
  if (root) return root
  root = document.createElement("div")
  root.id = "toast-root"
  document.body.appendChild(root)
  return root
}

function showToast(message, type = "info", timeoutMs = 3200) {
  const root = ensureToastRoot()
  const toast = document.createElement("div")
  toast.className = `toast toast-${type}`
  toast.textContent = message
  root.appendChild(toast)

  requestAnimationFrame(() => {
    toast.classList.add("is-visible")
  })

  const timer = setTimeout(() => {
    toast.classList.remove("is-visible")
    setTimeout(() => toast.remove(), 250)
  }, timeoutMs)

  toast.addEventListener("click", () => {
    clearTimeout(timer)
    toast.classList.remove("is-visible")
    setTimeout(() => toast.remove(), 250)
  })
}

function getAdminToken() {
  return sessionStorage.getItem("adminToken")
}

const THEME_KEY = "ticketflex_theme"

function applyTheme(theme) {
  const next = theme === "dark" ? "dark" : "light"
  document.documentElement.setAttribute("data-theme", next)
  return next
}

function initThemeToggle() {
  const saved = localStorage.getItem(THEME_KEY)
  const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches
  let current = applyTheme(saved || (prefersDark ? "dark" : "light"))

  const btn = document.createElement("button")
  btn.className = "btn btn-ghost btn-icon theme-toggle"

  const icon = document.createElement("span")
  icon.className = "icon"
  icon.innerHTML = `
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"></path>
    </svg>
  `

  const label = document.createElement("span")
  const updateLabel = () => {
    label.textContent = current === "dark" ? "Modo claro" : "Modo oscuro"
  }
  updateLabel()

  btn.appendChild(icon)
  btn.appendChild(label)

  btn.addEventListener("click", () => {
    current = current === "dark" ? "light" : "dark"
    current = applyTheme(current)
    localStorage.setItem(THEME_KEY, current)
    updateLabel()
  })

  if (!saved && window.matchMedia) {
    const media = window.matchMedia("(prefers-color-scheme: dark)")
    media.addEventListener("change", (event) => {
      const stored = localStorage.getItem(THEME_KEY)
      if (stored) return
      current = applyTheme(event.matches ? "dark" : "light")
      updateLabel()
    })
  }

  const actions = document.querySelector(".topbar .actions")
  if (actions) {
    actions.appendChild(btn)
    return
  }

  const inline = document.querySelector(".theme-inline")
  if (inline) {
    inline.appendChild(btn)
    return
  }

  const floating = document.createElement("div")
  floating.className = "theme-floating"
  floating.appendChild(btn)
  document.body.appendChild(floating)
}

function initActionMenus() {
  function closeAll() {
    document.querySelectorAll(".actions-menu.open").forEach(menu => menu.classList.remove("open"))
  }

  document.addEventListener("click", (event) => {
    const toggle = event.target.closest(".menu-btn")
    if (toggle) {
      event.preventDefault()
      const menu = toggle.closest(".actions-menu")
      if (!menu) return
      const isOpen = menu.classList.contains("open")
      closeAll()
      if (!isOpen) menu.classList.add("open")
      return
    }

    if (!event.target.closest(".actions-menu")) {
      closeAll()
    }
  })

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      closeAll()
    }
  })
}

function fetchWithTimeout(url, options = {}, timeoutMs = 10000) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  const token = getAdminToken()
  const headers = { ...(options.headers || {}) }
  if (token) {
    headers["x-admin-token"] = token
  }
  const merged = { ...options, headers, signal: controller.signal, credentials: "omit" }
  return fetch(url, merged)
    .finally(() => clearTimeout(timer))
}

function ticketCard(t, index) {
  const ticketLabel = t.id ? escapeHtml(t.id) : `#${index + 1}`
  const titulo = t.titulo ? `<div class="ticket-context"><strong>${escapeHtml(t.titulo)}</strong></div>` : ""
  const comentario = t.comentario ? `<div class="ticket-context"><strong>Comentario:</strong> ${escapeHtml(t.comentario)}</div>` : ""
  const cierreLine = t.cierre ? `<span>Cerrado: ${escapeHtml(formatDateTime(t.cierre))}</span>` : ""
  return `
    <article class="ticket-card">
      <div class="ticket-header">
        <div class="ticket-title">Ticket ${ticketLabel}</div>
        <span class="${badgeClass(t.estado)}">${escapeHtml(t.estado)}</span>
      </div>
      <div class="ticket-body">
        ${titulo}
        <div class="ticket-context">${escapeHtml(t.contexto || "Sin descripción")}</div>
        <div class="ticket-meta">
          <div><strong>Nombre</strong>${escapeHtml(t.nombre || "—")}</div>
          <div><strong>Empleado</strong>${escapeHtml(t.empleado || "—")}</div>
          <div><strong>Proyecto</strong>${escapeHtml(t.proyecto || "—")}</div>
          <div><strong>Fase</strong>${escapeHtml(t.fase || "—")}</div>
          <div><strong>Asignado</strong>${escapeHtml(t.asignado || "—")}</div>
        </div>
        ${comentario}
      </div>
      <div class="ticket-footer">
        <span>Creado: ${escapeHtml(formatDateTime(t.fecha))}</span>
        ${cierreLine}
      </div>
    </article>
  `
}

function renderTickets(containerId, tickets) {
  const el = document.getElementById(containerId)
  if (!el) return
  el.innerHTML = tickets.length ? tickets.map(ticketCard).join("") : '<div class="empty">Sin tickets</div>'
}

function renderLoading(containerId, message = "Cargando...") {
  const el = document.getElementById(containerId)
  if (!el) return
  el.innerHTML = `
    <div class="skeleton-card skeleton">
      <div class="skeleton-line" style="width: 40%;"></div>
      <div class="skeleton-line" style="width: 85%;"></div>
      <div class="skeleton-line" style="width: 70%;"></div>
      <div class="skeleton-line" style="width: 55%;"></div>
    </div>
    <div class="skeleton-card skeleton">
      <div class="skeleton-line" style="width: 32%;"></div>
      <div class="skeleton-line" style="width: 90%;"></div>
      <div class="skeleton-line" style="width: 62%;"></div>
      <div class="skeleton-line" style="width: 48%;"></div>
    </div>
  `
}

function fetchTickets() {
  return fetchWithTimeout("/api/tickets")
    .then(res => {
      if (!res.ok) {
        throw new Error("No se pudieron cargar los tickets")
      }
      return res.json()
    })
    .catch(err => {
      console.error("Error al cargar tickets:", err)
      return []
    })
}

function fetchClosedTickets(days = 7) {
  return fetchWithTimeout(`/api/tickets/closed?days=${encodeURIComponent(days)}`)
    .then(res => {
      if (!res.ok) {
        throw new Error("No se pudieron cargar tickets cerrados")
      }
      return res.json()
    })
    .catch(err => {
      console.error("Error al cargar cerrados:", err)
      return []
    })
}

function calcStats(tickets) {
  const total = tickets.length
  const cerrados = tickets.filter(t => t.estado === "cerrado").length
  const activos = total - cerrados
  return { total, activos, cerrados }
}

function renderStats(tickets) {
  const stats = calcStats(tickets)
  const totalEl = document.getElementById("stat-total")
  const activosEl = document.getElementById("stat-activos")
  const cerradosEl = document.getElementById("stat-cerrados")
  if (totalEl) totalEl.textContent = stats.total
  if (activosEl) activosEl.textContent = stats.activos
  if (cerradosEl) cerradosEl.textContent = stats.cerrados
}

function renderRecentTickets(tickets, limit) {
  const el = document.getElementById("recientes")
  if (!el) return
  const list = tickets.slice(-limit).reverse()
  el.innerHTML = list.length ? list.map(ticketCard).join("") : '<div class="empty">Sin tickets recientes</div>'
}

function iniciarRefresco(targetId) {
  const totalSeconds = 5 * 60
  let remaining = totalSeconds
  const info = document.getElementById(targetId)

  function tick() {
    const minutes = String(Math.floor(remaining / 60)).padStart(2, "0")
    const seconds = String(remaining % 60).padStart(2, "0")
    if (info) info.textContent = `La página se refrescará en ${minutes}:${seconds}`
    if (remaining <= 0) {
      location.reload()
      return
    }
    remaining -= 1
  }

  tick()
  setInterval(tick, 1000)
}

let sessionCache = null

function fetchSession() {
  if (sessionCache) return Promise.resolve(sessionCache)
  return fetchWithTimeout("/api/me")
    .then(res => res.json())
    .then(data => {
      sessionCache = data
      return data
    })
    .catch(() => ({ logged: false }))
}

function resetSessionCache() {
  sessionCache = null
}

function ensureAuthUi() {
  const actions = document.querySelector(".topbar .actions")
  if (!actions) return

  fetchSession().then(session => {
    const existingLogin = actions.querySelector("a[href='login.html']")
    const existingLogout = actions.querySelector("a[href='#logout']")
    const existingAdmins = actions.querySelector("a[href='admins.html']")
    const existingInfo = actions.querySelector(".session-info")

    if (session.logged) {
      if (!existingInfo) {
        const info = document.createElement("span")
        info.className = "session-info muted-text"
        info.textContent = `Sesión: ${session.user}`
        actions.prepend(info)
      }
      if (existingLogin) existingLogin.remove()
      if (!existingLogout) {
        const link = document.createElement("a")
        link.className = "btn btn-ghost"
        link.href = "#logout"
        link.textContent = "Salir"
        link.addEventListener("click", (event) => {
          event.preventDefault()
          const adminToken = getAdminToken()
          fetch("/api/logout", { method: "POST", headers: adminToken ? { "x-admin-token": adminToken } : {} })
            .finally(() => {
              sessionStorage.removeItem("adminToken")
              resetSessionCache()
              location = "login.html"
            })
        })
        actions.prepend(link)
      }
      if (session.role === "superadmin" && !existingAdmins) {
        const adminLink = document.createElement("a")
        adminLink.className = "btn btn-ghost"
        adminLink.href = "admins.html"
        adminLink.textContent = "Admins"
        actions.prepend(adminLink)
      }
      return
    }

    if (existingLogout) existingLogout.remove()
    if (existingAdmins) existingAdmins.remove()
    if (existingInfo) existingInfo.remove()
    if (existingLogin) {
      existingLogin.textContent = "Iniciar sesión admin"
    }
    if (!existingLogin) {
      const link = document.createElement("a")
      link.className = "btn btn-ghost"
      link.href = "login.html"
      link.textContent = "Iniciar sesión admin"
      actions.prepend(link)
    }
  })
}

document.addEventListener("DOMContentLoaded", () => {
  ensureAuthUi()
  initThemeToggle()
  initActionMenus()
})

