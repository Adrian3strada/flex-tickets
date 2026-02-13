const express = require("express")
const fs = require("fs")
const path = require("path")
const crypto = require("crypto")
const sqlite3 = require("sqlite3")
const session = require("express-session")
const rateLimit = require("express-rate-limit")
const bcrypt = require("bcryptjs")
const generarExcel = require("./excelGenerator")
const nodemailer = require("nodemailer")
require("dotenv").config()

const app = express()
const rootDir = __dirname
const dataDir = process.env.DATA_DIR || process.env.RAILWAY_VOLUME_MOUNT_PATH || rootDir
const isProduction = process.env.NODE_ENV === "production"
const trustProxy = process.env.TRUST_PROXY || "loopback"
app.set("trust proxy", trustProxy)
app.use(express.json())
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff")
  res.setHeader("X-Frame-Options", "DENY")
  res.setHeader("Referrer-Policy", "no-referrer")
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
  )
  next()
})
if (isProduction && !process.env.SESSION_SECRET) {
  console.error("SESSION_SECRET debe estar definido en producción.")
  process.exit(1)
}

app.use(session({
  secret: process.env.SESSION_SECRET || "ticket-flex-dev-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: isProduction,
    maxAge: 1000 * 60 * 60 * 8
  }
}))
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: "draft-7",
  legacyHeaders: false
})

const loginWindowMinutes = Number(process.env.LOGIN_WINDOW_MINUTES) || 15
const loginLimit = Number(process.env.LOGIN_LIMIT) || 20
const loginLockMax = Number(process.env.LOGIN_LOCK_MAX) || 5
const loginLockMinutes = Number(process.env.LOGIN_LOCK_MINUTES) || 15

const loginLimiter = rateLimit({
  windowMs: loginWindowMinutes * 60 * 1000,
  limit: loginLimit,
  standardHeaders: "draft-7",
  legacyHeaders: false
})

app.use(express.static(path.join(rootDir, "public")))
app.get("/login", (req, res) => {
  res.sendFile("login.html", { root: path.join(rootDir, "public") })
})

const dbJsonPath = path.join(dataDir, "database.json")
const dbFile = path.join(dataDir, "database.sqlite")
const backupDir = path.join(dataDir, "backups")
const logDir = path.join(dataDir, "logs")
const logFile = `${logDir}/app.log`
const API_KEY = process.env.API_KEY
const ADMIN_TOKEN_TTL_HOURS = Number(process.env.ADMIN_TOKEN_TTL_HOURS) || 24
const DEFAULT_ADMIN_USERS = []
const MAX_FIELD_LEN = 500
const REQUIRED_FIELDS = [
  "titulo",
  "contexto",
  "proyecto",
  "fase",
  "nombre",
  "empleado"
]
const PRIORITY_VALUES = ["baja", "media", "alta", "critica"]
const CATEGORY_VALUES = ["incidencia", "mejora", "soporte", "otro"]
const CHANNEL_VALUES = ["web", "correo", "whatsapp", "telefono"]

let writeQueue = Promise.resolve()
let db
const loginAttempts = new Map()

const runDb = (sql, params = []) => new Promise((resolve, reject) => {
  db.run(sql, params, function (err) {
    if (err) return reject(err)
    return resolve(this)
  })
})

const getDb = (sql, params = []) => new Promise((resolve, reject) => {
  db.get(sql, params, (err, row) => {
    if (err) return reject(err)
    return resolve(row)
  })
})

const allDb = (sql, params = []) => new Promise((resolve, reject) => {
  db.all(sql, params, (err, rows) => {
    if (err) return reject(err)
    return resolve(rows)
  })
})

const withDbWrite = (handler) => {
  writeQueue = writeQueue.then(() => handler())
  return writeQueue
}

const listTickets = () => allDb("SELECT * FROM tickets ORDER BY id ASC")
const listCommentsForTicket = (ticketId) => allDb(
  "SELECT id, comentario, autor, tipo, created_at FROM ticket_comments WHERE ticket_id = ? ORDER BY created_at ASC",
  [ticketId]
);

const normalizeDbText = (value) => {
  const text = String(value ?? "").trim()
  return text ? text : null
}

const normalizeEnum = (value, allowed) => {
  const text = sanitizeString(value).toLowerCase()
  if (!text) return null
  return allowed.includes(text) ? text : null
}

const normalizeIsoDate = (value) => {
  if (!value) return null
  const parsed = parseDateValue(value)
  if (!parsed) return null
  return parsed.toISOString()
}

const ensureLogDir = () => {
  if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir)
  }
}

const logToFile = (level, message, meta = {}) => {
  ensureLogDir()
  const entry = {
    ts: new Date().toISOString(),
    level,
    message,
    meta
  }
  fs.appendFileSync(logFile, JSON.stringify(entry) + "\n")
}

const initDb = async () => {
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true })
  }
  db = new sqlite3.Database(dbFile)
  await runDb(`
    CREATE TABLE IF NOT EXISTS tickets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      titulo TEXT NOT NULL,
      contexto TEXT NOT NULL,
      proyecto TEXT NOT NULL,
      fase TEXT NOT NULL,
      nombre TEXT NOT NULL,
      empleado TEXT NOT NULL,
      estado TEXT NOT NULL DEFAULT 'abierto',
      fecha TEXT NOT NULL,
      actualizado TEXT NOT NULL,
      asignado TEXT,
      comentario TEXT,
      cierre TEXT
    )
  `)
  await runDb(`
    CREATE TABLE IF NOT EXISTS admin_sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      admin_id INTEGER NOT NULL,
      token TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL,
      last_used TEXT NOT NULL
    )
  `)
  await runDb(`
    CREATE TABLE IF NOT EXISTS admin_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user TEXT NOT NULL UNIQUE,
      pass TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'admin'
    )
  `)
  await runDb(`
    CREATE TABLE IF NOT EXISTS ticket_comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ticket_id INTEGER NOT NULL,
      comentario TEXT NOT NULL,
      autor TEXT,
      tipo TEXT NOT NULL DEFAULT 'nota',
      created_at TEXT NOT NULL
    )
  `)
  await runDb(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      action TEXT NOT NULL,
      ticket_id INTEGER,
      actor TEXT,
      ip TEXT,
      meta TEXT,
      created_at TEXT NOT NULL
    )
  `)

  await ensureTicketColumns()
  await migrateFromJson()
  await migrateAdminPasswords()
  await seedAdminUsers()
  await cleanupAdminSessions()
}

const migrateFromJson = async () => {
  if (!fs.existsSync(dbJsonPath)) return
  const row = await getDb("SELECT COUNT(*) as total FROM tickets")
  if (row?.total) return
  const raw = fs.readFileSync(dbJsonPath, "utf-8")
  let data = []
  try {
    data = JSON.parse(raw)
  } catch {
    return
  }
  if (!Array.isArray(data) || !data.length) return

  const insertSql = `
    INSERT INTO tickets (
      id, titulo, contexto, proyecto, fase, nombre, empleado,
      estado, fecha, actualizado, asignado, comentario, cierre
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `

  for (const ticket of data) {
    const parsedId = Number(ticket?.id)
    await runDb(insertSql, [
      Number.isFinite(parsedId) ? parsedId : null,
      normalizeDbText(ticket?.titulo) || "Sin título",
      normalizeDbText(ticket?.contexto) || "Sin descripción",
      normalizeDbText(ticket?.proyecto) || "Sin proyecto",
      normalizeDbText(ticket?.fase) || "Sin fase",
      normalizeDbText(ticket?.nombre) || "Sin nombre",
      normalizeDbText(ticket?.empleado) || "Sin empleado",
      normalizeDbText(ticket?.estado) || "abierto",
      normalizeDbText(ticket?.fecha) || new Date().toISOString(),
      normalizeDbText(ticket?.actualizado) || new Date().toISOString(),
      normalizeDbText(ticket?.asignado),
      normalizeDbText(ticket?.comentario),
      normalizeDbText(ticket?.cierre)
    ])
  }
}

const seedAdminUsers = async () => {
  const row = await getDb("SELECT COUNT(*) as total FROM admin_users")
  if (row?.total) return
  const user = sanitizeString(process.env.ADMIN_BOOTSTRAP_USER)
  const pass = sanitizeString(process.env.ADMIN_BOOTSTRAP_PASS)
  if (!user || !pass) {
    console.warn("ADMIN_BOOTSTRAP_USER/PASS no definidos: crea el primer admin manualmente en la BD.")
    return
  }
  const hashed = await hashPassword(pass)
  await runDb(
    "INSERT INTO admin_users (user, pass, role) VALUES (?, ?, ?)",
    [user, hashed, "superadmin"]
  )
}

const sanitizeString = (value) => String(value || "").trim()
const ticketExtraColumns = [
  { name: "prioridad", type: "TEXT" },
  { name: "categoria", type: "TEXT" },
  { name: "canal", type: "TEXT" },
  { name: "sla_due_at", type: "TEXT" },
  { name: "first_response_at", type: "TEXT" },
  { name: "first_response_by", type: "TEXT" },
  { name: "last_status_at", type: "TEXT" },
  { name: "last_status_by", type: "TEXT" },
  { name: "reopened_count", type: "INTEGER NOT NULL DEFAULT 0" },
  { name: "tipo_cierre", type: "TEXT" }
]
const ensureTicketColumns = async () => {
  const columns = await allDb("PRAGMA table_info(tickets)")
  const existing = new Set(columns.map(col => col.name))
  for (const col of ticketExtraColumns) {
    if (!existing.has(col.name)) {
      await runDb(`ALTER TABLE tickets ADD COLUMN ${col.name} ${col.type}`)
    }
  }
}
const enforceMaxLength = (value, label) => {
  const text = sanitizeString(value)
  if (text.length > MAX_FIELD_LEN) {
    return { ok: false, error: `${label} supera ${MAX_FIELD_LEN} caracteres` }
  }
  return { ok: true, value: text }
}

const isBcryptHash = (value) => typeof value === "string" && value.startsWith("$2")

const hashPassword = async (value) => {
  const text = sanitizeString(value)
  if (!text) return ""
  return bcrypt.hash(text, 10)
}

const loginKey = (req, user, scope = "admin") => {
  const ip = req.headers["x-forwarded-for"] || req.socket?.remoteAddress || ""
  return `${scope}:${String(user || "").toLowerCase()}|${ip}`
}

const getLoginAttempt = (key) => {
  const entry = loginAttempts.get(key)
  if (!entry) return { count: 0, lockedUntil: 0 }
  if (entry.lockedUntil && Date.now() > entry.lockedUntil) {
    loginAttempts.delete(key)
    return { count: 0, lockedUntil: 0 }
  }
  return entry
}

const registerLoginFailure = (key) => {
  const entry = getLoginAttempt(key)
  const count = entry.count + 1
  const lockMs = loginLockMinutes * 60 * 1000
  const lockedUntil = count >= loginLockMax ? Date.now() + lockMs : 0
  const next = { count, lockedUntil }
  loginAttempts.set(key, next)
  return next
}

const resetLoginAttempts = (key) => {
  loginAttempts.delete(key)
}

const migrateAdminPasswords = async () => {
  const admins = await allDb("SELECT id, pass FROM admin_users")
  if (!admins.length) return
  for (const admin of admins) {
    if (isBcryptHash(admin.pass)) continue
    const hashed = await hashPassword(admin.pass)
    if (!hashed) continue
    await runDb("UPDATE admin_users SET pass = ? WHERE id = ?", [hashed, admin.id])
  }
}


const ensureBackupDir = () => {
  if (!fs.existsSync(backupDir)) {
    fs.mkdirSync(backupDir)
  }
}

const backupDbIfNeeded = () => {
  ensureBackupDir()
  const stamp = new Date().toISOString().slice(0, 10)
  const target = `${backupDir}/database-${stamp}.sqlite`
  if (!fs.existsSync(target)) {
    fs.copyFileSync(dbFile, target)
  }
  cleanupBackups()
}

const cleanupBackups = () => {
  const retentionDays = Number(process.env.BACKUP_RETENTION_DAYS) || 14
  if (!Number.isFinite(retentionDays) || retentionDays <= 0) return
  const now = Date.now()
  const maxAgeMs = retentionDays * 24 * 60 * 60 * 1000
  const files = fs.readdirSync(backupDir)
  files.forEach((file) => {
    if (!file.startsWith("database-") || !file.endsWith(".sqlite")) return
    const fullPath = `${backupDir}/${file}`
    const stat = fs.statSync(fullPath)
    if (now - stat.mtimeMs > maxAgeMs) {
      fs.unlinkSync(fullPath)
    }
  })
}

const logAudit = async (action, ticketId, req, meta = {}) => {
  const actor = req.adminUser?.user || req.session?.user?.user || null
  const ip = req.headers["x-forwarded-for"] || req.socket?.remoteAddress || null
  const createdAt = new Date().toISOString()
  await runDb(
    "INSERT INTO audit_logs (action, ticket_id, actor, ip, meta, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    [action, ticketId || null, actor, String(ip || ""), JSON.stringify(meta), createdAt]
  )
  logToFile("info", action, { ticketId, actor, ip, meta })
}

const toCsvValue = (value) => {
  const text = value == null ? "" : String(value)
  const sanitized = text.replace(/\r?\n/g, " ").replace(/"/g, '""')
  return `"${sanitized}"`
}
const escapeHtml = (value) => String(value || "—")
  .replace(/&/g, "&amp;")
  .replace(/</g, "&lt;")
  .replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;")
  .replace(/'/g, "&#39;")

const parseDateValue = (value) => {
  if (!value) return null
  const trimmed = String(value).trim()
  if (!trimmed) return null
  const isoDate = new Date(trimmed)
  if (!Number.isNaN(isoDate.getTime())) return isoDate
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
  return null
}

const createAdminToken = () => crypto.randomBytes(32).toString("hex")

const getAdminFromToken = async (req) => {
  const token = req.headers["x-admin-token"]
  if (!token) return null
  const session = await getDb(
    "SELECT s.id, s.admin_id, s.created_at, a.user, a.role FROM admin_sessions s JOIN admin_users a ON a.id = s.admin_id WHERE s.token = ?",
    [token]
  )
  if (!session) return null
  const createdAt = new Date(session.created_at)
  const ttlMs = ADMIN_TOKEN_TTL_HOURS * 60 * 60 * 1000
  if (Number.isFinite(ttlMs) && createdAt.getTime() + ttlMs < Date.now()) {
    await runDb("DELETE FROM admin_sessions WHERE id = ?", [session.id])
    return null
  }
  const now = new Date().toISOString()
  await runDb("UPDATE admin_sessions SET last_used = ? WHERE id = ?", [now, session.id])
  return { user: session.user, role: session.role, adminId: session.admin_id, token }
}

const clearAdminSession = async (token) => {
  if (!token) return
  await runDb("DELETE FROM admin_sessions WHERE token = ?", [token])
}

const cleanupAdminSessions = async () => {
  const ttlMs = ADMIN_TOKEN_TTL_HOURS * 60 * 60 * 1000
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) return
  const cutoff = new Date(Date.now() - ttlMs).toISOString()
  await runDb("DELETE FROM admin_sessions WHERE created_at < ?", [cutoff])
}

const validateTicketInput = (body) => {
  const errors = []
  const cleaned = {}
  REQUIRED_FIELDS.forEach((key) => {
    const value = sanitizeString(body?.[key])
    if (!value) {
      errors.push(`Falta ${key}`)
      return
    }
    if (value.length > MAX_FIELD_LEN) {
      errors.push(`${key} supera ${MAX_FIELD_LEN} caracteres`)
      return
    }
    cleaned[key] = value
  })
  const prioridad = normalizeEnum(body?.prioridad, PRIORITY_VALUES)
  if (body?.prioridad && !prioridad) {
    errors.push("Prioridad inválida")
  } else if (prioridad) {
    cleaned.prioridad = prioridad
  }
  const categoria = normalizeEnum(body?.categoria, CATEGORY_VALUES)
  if (body?.categoria && !categoria) {
    errors.push("Categoría inválida")
  } else if (categoria) {
    cleaned.categoria = categoria
  }
  const canal = normalizeEnum(body?.canal, CHANNEL_VALUES)
  if (body?.canal && !canal) {
    errors.push("Canal inválido")
  } else if (canal) {
    cleaned.canal = canal
  }
  const slaDueAt = normalizeIsoDate(body?.sla_due_at)
  if (body?.sla_due_at && !slaDueAt) {
    errors.push("SLA inválido")
  } else if (slaDueAt) {
    cleaned.sla_due_at = slaDueAt
  }
  return { errors, cleaned }
}
const mailer = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
})

function fila(label, value, alt) {
  const safe = escapeHtml(value)
  const bg = alt ? "#f8fafc" : "#ffffff"
  return `
    <tr>
      <td style="padding: 8px 10px; border: 1px solid #d1d5db; background: ${bg}; font-weight: 600; width: 180px;">
        ${escapeHtml(label)}
      </td>
      <td style="padding: 8px 10px; border: 1px solid #d1d5db; background: ${bg};">
        ${safe}
      </td>
    </tr>
  `
}

async function enviarCorreo(ticket) {
  const smtpUser = process.env.SMTP_USER
  const smtpPass = process.env.SMTP_PASS
  const smtpFrom = process.env.SMTP_FROM || smtpUser
  const smtpTo = process.env.SMTP_TO
  if (!smtpUser || !smtpPass || !smtpTo) {
    logToFile("warn", "SMTP incompleto, correo omitido", {
      hasUser: Boolean(smtpUser),
      hasPass: Boolean(smtpPass),
      hasFrom: Boolean(smtpFrom),
      hasTo: Boolean(smtpTo)
    })
    return
  }
  const subject = `Nuevo Ticket #${ticket.id} - ${ticket.titulo || "Sin título"}`
  const safeId = escapeHtml(ticket.id)
  const safeTitle = escapeHtml(ticket.titulo || "Sin título")
  const rows = [
    ["Título", ticket.titulo],
    ["Descripción", ticket.contexto],
    ["Familia", ticket.proyecto],
    ["Número de Serie", ticket.fase],
    ["Prioridad", ticket.prioridad],
    ["Nombre completo", ticket.nombre],
    ["Usuario GDL / Nómina", ticket.empleado],
    ["Estado", ticket.estado || "abierto"],
    ["Hora de creación", ticket.fecha]
  ]
  const text = rows.map(([k, v]) => `${k}: ${v || "—"}`).join("\n")
  const html = `
    <div style="font-family: Arial, sans-serif; color: #111827;">
      <div style="background: #0a7bc2; color: #ffffff; padding: 12px 14px; border-radius: 8px 8px 0 0;">
        <div style="font-size: 18px; font-weight: 700;">Ticket Flex</div>
        <div style="font-size: 13px;">Nuevo Ticket #${safeId}</div>
      </div>
      <div style="border: 1px solid #cfe3f3; border-top: 0; border-radius: 0 0 8px 8px; padding: 12px 14px; background: #f7fbff;">
        <h2 style="margin: 0 0 12px; font-size: 16px; color: #0a7bc2;">${safeTitle}</h2>
        <table cellpadding="0" cellspacing="0" width="100%" border="1" style="border-collapse: collapse; font-size: 14px; border-color: #cfe3f3;">
        <tbody>
          ${rows.map((r, idx) => fila(r[0], r[1], idx % 2 === 0)).join("")}
        </tbody>
      </table>
      </div>
    </div>
  `

  await mailer.sendMail({
    from: smtpFrom,
    to: smtpTo,
    subject,
    text,
    html
  })
}

const requireApiKey = (req, res, next) => {
  const fullPath = req.baseUrl ? `${req.baseUrl}${req.path}` : req.path
  const allowed = ["/login", "/logout", "/me", "/api/login", "/api/logout", "/api/me"]
  if (allowed.includes(req.path) || allowed.includes(fullPath)) {
    return next()
  }
  if (!API_KEY) {
    return next()
  }
  const key = req.headers["x-api-key"]
  if (!key || key !== API_KEY) {
    return res.status(401).json({ error: "No autorizado" })
  }
  return next()
}

const adminRoles = ["admin", "superadmin"]

const requireAdmin = async (req, res, next) => {
  try {
    const admin = await getAdminFromToken(req)
    if (admin && adminRoles.includes(String(admin.role || "").toLowerCase())) {
      req.adminUser = admin
      return next()
    }
  } catch {
    return res.status(500).json({ error: "No se pudo validar sesión" })
  }
  return res.status(403).json({ error: "Solo admins pueden realizar esta acción" })
}

const requireSuperAdmin = async (req, res, next) => {
  try {
    const admin = await getAdminFromToken(req)
    if (admin && String(admin.role || "").toLowerCase() === "superadmin") {
      req.adminUser = admin
      return next()
    }
  } catch {
    return res.status(500).json({ error: "No se pudo validar sesión" })
  }
  return res.status(403).json({ error: "Solo superadmins pueden realizar esta acción" })
}

app.use("/api", apiLimiter, requireApiKey)

app.post("/api/login", loginLimiter, async (req, res) => {
  const user = sanitizeString(req.body?.user)
  const pass = sanitizeString(req.body?.pass)
  if (!user || !pass) {
    return res.status(400).json({ error: "Faltan credenciales" })
  }
  const key = loginKey(req, user, "admin")
  const attempt = getLoginAttempt(key)
  if (attempt.lockedUntil) {
    return res.status(429).json({ error: "Cuenta temporalmente bloqueada. Intenta más tarde." })
  }
  try {
    const current = await getDb(
      "SELECT user, role, pass FROM admin_users WHERE lower(user) = lower(?)",
      [user]
    )
    if (current) {
      const ok = await bcrypt.compare(pass, current.pass)
      if (ok) {
        const token = createAdminToken()
        const now = new Date().toISOString()
        await runDb(
          "INSERT INTO admin_sessions (admin_id, token, created_at, last_used) VALUES ((SELECT id FROM admin_users WHERE lower(user)=lower(?)), ?, ?, ?)",
          [current.user, token, now, now]
        )
        resetLoginAttempts(key)
        await logAudit("login", null, req, { user: current.user })
        return res.status(200).json({ user: current.user, role: current.role || "admin", token })
      }
    }

    registerLoginFailure(key)
    return res.status(401).json({ error: "Credenciales incorrectas" })
  } catch (err) {
    return res.status(401).json({ error: "Credenciales incorrectas" })
  }
})

app.post("/api/logout", (req, res) => {
  const token = req.headers["x-admin-token"]
  clearAdminSession(token)
    .catch(() => { })
    .finally(() => {
      res.status(200).json({ ok: true })
    })
})

app.get("/api/me", (req, res) => {
  getAdminFromToken(req)
    .then((admin) => {
      if (!admin) {
        return res.status(200).json({ logged: false })
      }
      return res.status(200).json({ logged: true, user: admin.user, role: admin.role })
    })
    .catch(() => res.status(500).json({ error: "No se pudo validar sesión" }))
})

app.get("/api/admins", requireSuperAdmin, async (req, res) => {
  try {
    const admins = await allDb("SELECT id, user, role FROM admin_users ORDER BY id ASC")
    res.status(200).json(admins)
  } catch (err) {
    res.status(500).json({ error: "No se pudo cargar admins" })
  }
})


app.post("/api/admins", requireSuperAdmin, async (req, res) => {
  const user = sanitizeString(req.body?.user)
  const pass = sanitizeString(req.body?.pass)
  const role = sanitizeString(req.body?.role) || "admin"
  const normalizedRole = role.toLowerCase()
  if (!adminRoles.includes(normalizedRole)) {
    return res.status(400).json({ error: "Rol inválido" })
  }
  if (!user || !pass) {
    return res.status(400).json({ error: "Faltan datos" })
  }
  const hashed = await hashPassword(pass)
  if (!hashed) {
    return res.status(400).json({ error: "Contraseña inválida" })
  }
  try {
    await runDb("INSERT INTO admin_users (user, pass, role) VALUES (?, ?, ?)", [user, hashed, normalizedRole])
    await logAudit("admin_create", null, req, { user, role: normalizedRole })
    return res.status(200).json({ ok: true })
  } catch (err) {
    return res.status(409).json({ error: "Usuario ya existe" })
  }
})

app.patch("/api/admins/:id/password", requireSuperAdmin, async (req, res) => {
  const adminId = Number(req.params.id)
  const pass = sanitizeString(req.body?.pass)
  if (!Number.isFinite(adminId) || !pass) {
    return res.status(400).json({ error: "Datos inválidos" })
  }
  const hashed = await hashPassword(pass)
  if (!hashed) {
    return res.status(400).json({ error: "Contraseña inválida" })
  }
  try {
    const admin = await getDb("SELECT id FROM admin_users WHERE id = ?", [adminId])
    if (!admin) {
      return res.status(404).json({ error: "Admin no encontrado" })
    }
    await runDb("UPDATE admin_users SET pass = ? WHERE id = ?", [hashed, adminId])
    await logAudit("admin_reset_pass", adminId, req)
    return res.status(200).json({ ok: true })
  } catch (err) {
    return res.status(500).json({ error: "No se pudo actualizar" })
  }
})

app.delete("/api/admins/:id", requireSuperAdmin, async (req, res) => {
  const adminId = Number(req.params.id)
  if (!Number.isFinite(adminId)) {
    return res.status(400).json({ error: "Id inválido" })
  }
  const currentUser = req.adminUser?.user || req.session?.user?.user
  const target = await getDb("SELECT user FROM admin_users WHERE id = ?", [adminId])
  if (!target) {
    return res.status(404).json({ error: "Admin no encontrado" })
  }
  if (target.user === currentUser) {
    return res.status(409).json({ error: "No puedes eliminar tu propio usuario" })
  }
  try {
    await runDb("DELETE FROM admin_users WHERE id = ?", [adminId])
    await logAudit("admin_delete", adminId, req, { user: target.user })
    return res.status(200).json({ ok: true })
  } catch (err) {
    return res.status(500).json({ error: "No se pudo eliminar" })
  }
})

// Obtener tickets
app.get("/api/tickets", async (req, res) => {
  try {
    const tickets = await listTickets()
    res.json(tickets)
  } catch (err) {
    res.status(500).json({ error: "No se pudo leer la base de datos" })
  }
})

app.get("/api/tickets/closed", async (req, res) => {
  const days = Number(req.query?.days || 7)
  if (!Number.isFinite(days) || days <= 0) {
    return res.status(400).json({ error: "Days inválidos" })
  }
  const cappedDays = Math.min(days, 365)
  const cutoffMs = Date.now() - cappedDays * 24 * 60 * 60 * 1000
  const now = new Date()
  try {
    const tickets = await listTickets()
    const closed = tickets
      .filter(t => String(t.estado || "").trim().toLowerCase() === "cerrado")
      .map(t => {
        const base = t.cierre || t.actualizado || t.fecha
        const parsed = parseDateValue(base)
        const date = parsed || now
        if (!parsed && base) {
          logToFile("warn", "Fecha inválida para cerrado, usando fallback", { ticketId: t.id, date: base })
        }
        return { ticket: t, date }
      })
      .filter(entry => entry.date.getTime() >= cutoffMs)
      .sort((a, b) => b.date.getTime() - a.date.getTime())
      .map(entry => entry.ticket)
    res.json(closed)
  } catch (err) {
    res.status(500).json({ error: "No se pudieron cargar tickets cerrados" })
  }
})

app.get("/api/admin/stats", requireAdmin, async (req, res) => {
  const days = Number(req.query?.days || 30)
  if (!Number.isFinite(days) || days <= 0) {
    return res.status(400).json({ error: "Days inválidos" })
  }
  const cappedDays = Math.min(days, 365)
  const cutoffMs = Date.now() - cappedDays * 24 * 60 * 60 * 1000
  try {
    const tickets = await listTickets()
    const ticketMap = new Map(tickets.map(t => [String(t.id), t]))
    const createdInWindow = tickets.filter(t => {
      const created = parseDateValue(t.fecha)
      return created && created.getTime() >= cutoffMs
    })

    const lineCounts = new Map()
    createdInWindow.forEach(t => {
      const key = String(t.proyecto || "Sin proyecto")
      lineCounts.set(key, (lineCounts.get(key) || 0) + 1)
    })
    const topLineas = [...lineCounts.entries()]
      .map(([linea, total]) => ({ linea, total }))
      .sort((a, b) => b.total - a.total)

    const logs = await allDb(
      "SELECT action, ticket_id, actor, created_at FROM audit_logs WHERE action IN ('take','close')"
    )
    const takeLogs = []
    const closeLogs = []
    logs.forEach(log => {
      const ts = parseDateValue(log.created_at)
      if (!ts || ts.getTime() < cutoffMs) return
      const entry = {
        action: log.action,
        ticketId: String(log.ticket_id || ""),
        actor: log.actor || "Sin usuario",
        createdAt: ts
      }
      if (log.action === "take") takeLogs.push(entry)
      if (log.action === "close") closeLogs.push(entry)
    })

    const takesByTicket = new Map()
    takeLogs.forEach(entry => {
      const list = takesByTicket.get(entry.ticketId) || []
      list.push(entry)
      takesByTicket.set(entry.ticketId, list)
    })
    takesByTicket.forEach(list => list.sort((a, b) => a.createdAt - b.createdAt))

    const closeDurations = []
    const adminCloseStats = new Map()
    closeLogs.forEach(entry => {
      const ticket = ticketMap.get(entry.ticketId)
      const takes = takesByTicket.get(entry.ticketId) || []
      const takeBeforeClose = [...takes].reverse().find(t => t.createdAt <= entry.createdAt)
      const start = takeBeforeClose?.createdAt || parseDateValue(ticket?.fecha)
      if (!start) return
      const durationMs = entry.createdAt.getTime() - start.getTime()
      if (durationMs < 0) return
      closeDurations.push(durationMs)
      const current = adminCloseStats.get(entry.actor) || { totalMs: 0, count: 0 }
      current.totalMs += durationMs
      current.count += 1
      adminCloseStats.set(entry.actor, current)
    })

    const adminCloseRanking = [...adminCloseStats.entries()]
      .map(([admin, data]) => ({
        admin,
        count: data.count,
        avgMs: data.count ? Math.round(data.totalMs / data.count) : 0
      }))
      .sort((a, b) => a.avgMs - b.avgMs)

    const takesByAdmin = new Map()
    const takesPerDay = new Map()
    takeLogs.forEach(entry => {
      const day = entry.createdAt.toISOString().slice(0, 10)
      const key = `${entry.actor}|${day}`
      takesPerDay.set(key, (takesPerDay.get(key) || 0) + 1)
      const summary = takesByAdmin.get(entry.actor) || { total: 0, days: new Set() }
      summary.total += 1
      summary.days.add(day)
      takesByAdmin.set(entry.actor, summary)
    })
    const takeRanking = [...takesByAdmin.entries()]
      .map(([admin, data]) => ({
        admin,
        total: data.total,
        days: data.days.size,
        avgPerDay: data.days.size ? Number((data.total / data.days.size).toFixed(2)) : 0
      }))
      .sort((a, b) => b.avgPerDay - a.avgPerDay)

    const sortedDurations = [...closeDurations].sort((a, b) => a - b)
    const medianMs = sortedDurations.length
      ? (sortedDurations.length % 2
        ? sortedDurations[(sortedDurations.length - 1) / 2]
        : Math.round((sortedDurations[sortedDurations.length / 2 - 1] + sortedDurations[sortedDurations.length / 2]) / 2))
      : 0
    const avgMs = closeDurations.length
      ? Math.round(closeDurations.reduce((sum, n) => sum + n, 0) / closeDurations.length)
      : 0

    res.status(200).json({
      windowDays: cappedDays,
      topLineas,
      adminCloseRanking,
      takeRanking,
      globalTiming: {
        avgCloseMs: avgMs,
        medianCloseMs: medianMs,
        totalClosed: closeDurations.length
      }
    })
  } catch (err) {
    res.status(500).json({ error: "No se pudieron cargar estadísticas" })
  }
})

app.get("/api/tickets/:id/comments", async (req, res) => {
  const ticketId = Number(req.params.id)
  if (!Number.isFinite(ticketId)) {
    return res.status(400).json({ error: "Id inválido" })
  }
  try {
    const comments = await listCommentsForTicket(ticketId)
    return res.status(200).json(comments)
  } catch (err) {
    return res.status(500).json({ error: "No se pudieron cargar comentarios" })
  }
})

app.post("/api/tickets/:id/comments", requireAdmin, (req, res) => {
  const ticketId = Number(req.params.id)
  const comentarioResult = enforceMaxLength(req.body?.comentario, "Comentario")
  if (!Number.isFinite(ticketId)) {
    return res.status(400).json({ error: "Id inválido" })
  }
  if (!comentarioResult.ok) {
    return res.status(400).json({ error: comentarioResult.error })
  }
  if (!comentarioResult.value) {
    return res.status(400).json({ error: "Comentario vacío" })
  }
  withDbWrite(async () => {
    const ticket = await getDb("SELECT * FROM tickets WHERE id = ?", [ticketId])
    if (!ticket) {
      return { status: 404 }
    }
    const createdAt = new Date().toISOString()
    const autor = req.adminUser?.user || req.session?.user?.user || null
    await runDb(
      "INSERT INTO ticket_comments (ticket_id, comentario, autor, tipo, created_at) VALUES (?, ?, ?, ?, ?)",
      [ticketId, comentarioResult.value, autor, "nota", createdAt]
    )
    await runDb(
      `UPDATE tickets
       SET comentario = ?,
           actualizado = ?,
           first_response_at = COALESCE(first_response_at, ?),
           first_response_by = COALESCE(first_response_by, ?)
       WHERE id = ?`,
      [comentarioResult.value, createdAt, createdAt, autor, ticketId]
    )
    const allTickets = await listTickets()
    generarExcel(allTickets)
    backupDbIfNeeded()
    await logAudit("comment_add", ticketId, req)
    return { status: 200 }
  })
    .then((result) => {
      if (result.status === 200) {
        return res.status(200).json({ ok: true })
      }
      return res.sendStatus(result.status)
    })
    .catch(() => res.status(500).json({ error: "No se pudo guardar comentario" }))
})

app.get("/api/export", requireSuperAdmin, async (req, res) => {
  try {
    const format = String(req.query?.format || "json").toLowerCase()
    const tickets = await listTickets()
    if (format === "csv") {
      const headers = [
        "id",
        "titulo",
        "contexto",
        "proyecto",
        "fase",
        "nombre",
        "empleado",
        "estado",
        "fecha",
        "actualizado",
        "asignado",
        "comentario",
        "cierre",
        "prioridad",
        "categoria",
        "canal",
        "sla_due_at",
        "first_response_at",
        "first_response_by",
        "last_status_at",
        "last_status_by",
        "reopened_count"
      ]
      const rows = tickets.map(t => ([
        t.id,
        t.titulo,
        t.contexto,
        t.proyecto,
        t.fase,
        t.nombre,
        t.empleado,
        t.estado,
        t.fecha,
        t.actualizado,
        t.asignado,
        t.comentario,
        t.cierre,
        t.prioridad,
        t.categoria,
        t.canal,
        t.sla_due_at,
        t.first_response_at,
        t.first_response_by,
        t.last_status_at,
        t.last_status_by,
        t.reopened_count
      ]).map(toCsvValue).join(","))
      const csvContent = [headers.join(","), ...rows].join("\n")
      res.setHeader("Content-Type", "text/csv; charset=utf-8")
      res.setHeader("Content-Disposition", "attachment; filename=tickets.csv")
      return res.send("\uFEFF" + csvContent)
    }
    res.setHeader("Content-Type", "application/json")
    return res.send(JSON.stringify(tickets, null, 2))
  } catch (err) {
    return res.status(500).json({ error: "No se pudo exportar" })
  }
})

app.post("/api/import", requireSuperAdmin, (req, res) => {
  const payload = req.body
  if (!Array.isArray(payload)) {
    return res.status(400).json({ error: "Se esperaba un arreglo de tickets" })
  }
  const now = new Date().toISOString()
  let created = 0
  let skipped = 0
  withDbWrite(async () => {
    const insertSql = `
      INSERT INTO tickets (
        titulo, contexto, proyecto, fase, nombre, empleado,
        estado, fecha, actualizado, asignado, comentario, cierre,
        prioridad, categoria, canal, sla_due_at,
        first_response_at, first_response_by, last_status_at, last_status_by, reopened_count
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `
    for (const item of payload) {
      const { errors, cleaned } = validateTicketInput(item)
      if (errors.length) {
        skipped += 1
        continue
      }
      const now = new Date().toISOString()
      await runDb(insertSql, [
        cleaned.titulo,
        cleaned.contexto,
        cleaned.proyecto,
        cleaned.fase,
        cleaned.nombre,
        cleaned.empleado,
        sanitizeString(item?.estado) || "abierto",
        sanitizeString(item?.fecha) || now,
        sanitizeString(item?.actualizado) || now,
        sanitizeString(item?.asignado) || null,
        sanitizeString(item?.comentario) || null,
        sanitizeString(item?.cierre) || null,
        cleaned.prioridad || null,
        cleaned.categoria || null,
        cleaned.canal || null,
        cleaned.sla_due_at || null,
        null,
        null,
        now,
        null,
        0
      ])
      created += 1
    }
    const allTickets = await listTickets()
    generarExcel(allTickets)
    backupDbIfNeeded()
    await logAudit("import", null, req, { created, skipped })
    return { created, skipped }
  })
    .then((result) => res.status(200).json(result))
    .catch(() => res.status(500).json({ error: "No se pudo importar" }))
})

// Crear ticket
app.post("/api/tickets", (req, res) => {
  const { errors, cleaned } = validateTicketInput(req.body)
  if (errors.length) {
    return res.status(400).json({ error: "Validación fallida", details: errors })
  }
  withDbWrite(async () => {
    const now = new Date().toISOString()
    const insertSql = `
      INSERT INTO tickets (
        titulo, contexto, proyecto, fase, nombre, empleado,
        estado, fecha, actualizado, asignado, comentario, cierre,
        prioridad, categoria, canal, sla_due_at,
        first_response_at, first_response_by, last_status_at, last_status_by, reopened_count
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `
    const result = await runDb(insertSql, [
      cleaned.titulo,
      cleaned.contexto,
      cleaned.proyecto,
      cleaned.fase,
      cleaned.nombre,
      cleaned.empleado,
      "abierto",
      now,
      now,
      null,
      null,
      null,
      cleaned.prioridad || null,
      cleaned.categoria || null,
      cleaned.canal || null,
      cleaned.sla_due_at || null,
      null,
      null,
      now,
      null,
      0
    ])
    const nuevoTicket = await getDb("SELECT * FROM tickets WHERE id = ?", [result.lastID])
    const allTickets = await listTickets()
    generarExcel(allTickets)
    backupDbIfNeeded()
    await logAudit("create", nuevoTicket?.id, req)
    enviarCorreo(nuevoTicket)
      .catch((err) => {
        logToFile("error", "No se pudo enviar correo", { message: String(err?.message || err || "") })
      })
    return nuevoTicket
  })
    .then((nuevoTicket) => res.status(200).json(nuevoTicket))
    .catch(() => res.status(500).json({ error: "No se pudo guardar el ticket" }))
})

// Tomar ticket (en proceso)
app.post("/api/tomar/:id", requireAdmin, (req, res) => {
  const ticketId = Number(req.params.id)
  const asignadoResult = enforceMaxLength(req.body?.asignado, "Asignado")
  if (!Number.isFinite(ticketId)) {
    return res.status(400).json({ error: "Id inválido" })
  }
  if (!asignadoResult.ok) {
    return res.status(400).json({ error: asignadoResult.error })
  }
  if (!asignadoResult.value) {
    return res.status(400).json({ error: "Falta asignado" })
  }
  withDbWrite(async () => {
    const ticket = await getDb("SELECT * FROM tickets WHERE id = ?", [ticketId])
    if (!ticket) {
      return { status: 404 }
    }
    if (ticket.estado === "cerrado") {
      return { status: 409, error: "El ticket ya está cerrado" }
    }
    if (ticket.estado === "en_proceso" && ticket.asignado) {
      return { status: 409, error: "El ticket ya está en proceso" }
    }
    const updatedAt = new Date().toISOString()
    const actor = req.adminUser?.user || req.session?.user?.user || null
    await runDb(
      `UPDATE tickets
       SET estado = ?,
           asignado = ?,
           actualizado = ?,
           last_status_at = ?,
           last_status_by = ?,
           first_response_at = COALESCE(first_response_at, ?),
           first_response_by = COALESCE(first_response_by, ?)
       WHERE id = ?`,
      [
        "en_proceso",
        asignadoResult.value,
        updatedAt,
        updatedAt,
        actor,
        updatedAt,
        actor,
        ticketId
      ]
    )
    const updated = await getDb("SELECT * FROM tickets WHERE id = ?", [ticketId])
    const allTickets = await listTickets()
    generarExcel(allTickets)
    backupDbIfNeeded()
    await logAudit("take", ticketId, req, { asignado: asignadoResult.value })
    return { status: 200, data: updated }
  })
    .then((result) => {
      if (result.status === 200) {
        return res.status(200).json(result.data)
      }
      if (result.error) {
        return res.status(result.status).json({ error: result.error })
      }
      return res.sendStatus(result.status)
    })
    .catch(() => res.status(500).json({ error: "No se pudo actualizar el ticket" }))
})

// Cerrar ticket y guardar comentario
app.post("/api/cerrar/:id", requireAdmin, (req, res) => {
  const ticketId = Number(req.params.id)
  if (!Number.isFinite(ticketId)) {
    return res.status(400).json({ error: "Id inválido" })
  }
  const comentarioResult = enforceMaxLength(req.body?.comentario, "Comentario")
  if (!comentarioResult.ok) {
    return res.status(400).json({ error: comentarioResult.error })
  }
  const tipoCierre = sanitizeString(req.body?.tipo_cierre)
  const categoria = normalizeEnum(req.body?.categoria, ["incidencia", "mejora", "soporte", "otro"]) || null
  withDbWrite(async () => {
    const ticket = await getDb("SELECT * FROM tickets WHERE id = ?", [ticketId])
    if (!ticket) {
      return { status: 404 }
    }
    const cierre = new Date().toISOString()
    const autor = req.adminUser?.user || req.session?.user?.user || null
    await runDb(
      `UPDATE tickets
       SET estado = ?,
           comentario = ?,
           tipo_cierre = ?,
           categoria = ?,
           cierre = ?,
           actualizado = ?,
           last_status_at = ?,
           last_status_by = ?,
           first_response_at = COALESCE(first_response_at, ?),
           first_response_by = COALESCE(first_response_by, ?)
       WHERE id = ?`,
      [
        "cerrado",
        comentarioResult.value,
        tipoCierre,
        categoria,
        cierre,
        cierre,
        cierre,
        autor,
        cierre,
        autor,
        ticketId
      ]
    )
    if (comentarioResult.value) {
      await runDb(
        "INSERT INTO ticket_comments (ticket_id, comentario, autor, tipo, created_at) VALUES (?, ?, ?, ?, ?)",
        [ticketId, comentarioResult.value, autor, "cierre", cierre]
      )
    }
    const updated = await getDb("SELECT * FROM tickets WHERE id = ?", [ticketId])
    const allTickets = await listTickets()
    generarExcel(allTickets)
    backupDbIfNeeded()
    await logAudit("close", ticketId, req)
    return { status: 200, data: updated }
  })
    .then((result) => {
      if (result.status === 200) {
        return res.status(200).json(result.data)
      }
      if (result.error) {
        return res.status(result.status).json({ error: result.error })
      }
      return res.sendStatus(result.status)
    })
    .catch(() => res.status(500).json({ error: "No se pudo cerrar el ticket" }))
})

const port = Number(process.env.PORT) || 3000

initDb()
  .then(() => {
    app.listen(port, () => console.log("Servidor activo en puerto", port))
  })
  .catch((err) => {
    console.error("No se pudo iniciar la base de datos", err)
    process.exit(1)
  })