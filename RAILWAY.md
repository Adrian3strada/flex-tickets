# Desplegar Ticket Flex en Railway

Pasos para subir el proyecto a [Railway](https://railway.app) y que la base de datos persista.

---

## 1. Subir el código a GitHub

1. Crea un repositorio en GitHub (si aún no lo tienes).
2. En la carpeta del proyecto:

   ```bash
   git init
   git add .
   git commit -m "Preparar despliegue Railway"
   git branch -M main
   git remote add origin https://github.com/TU_USUARIO/TU_REPO.git
   git push -u origin main
   ```

   **Importante:** No subas `.env`. El `.gitignore` ya lo excluye. Si ya habías trackeado `.env` antes:

   ```bash
   git rm --cached .env
   git commit -m "Dejar de trackear .env"
   git push
   ```

---

## 2. Crear proyecto en Railway

1. Entra en [railway.app](https://railway.app) e inicia sesión (con GitHub).
2. **New Project** → **Deploy from GitHub repo**.
3. Elige el repositorio del ticket-system y autoriza a Railway si te lo pide.
4. Railway detectará Node.js y usará `npm install` y `npm start`. No hace falta tocar el build.

---

## 3. Añadir volumen (para que la BD no se borre)

Sin volumen, la base SQLite se pierde en cada despliegue.

1. En tu proyecto Railway, abre el **servicio** (el que se creó al conectar el repo).
2. Pestaña **Variables** (o **Settings** según la vista).
3. Ve a **Volumes** (o **Storage**).
4. **Add Volume** (o **Create Volume**).
5. **Mount path:** pon exactamente: `/data`
6. Guarda. Railway montará el volumen en `/data` y dará la variable `RAILWAY_VOLUME_MOUNT_PATH=/data` (o el path que hayas puesto). El código ya usa esa variable para guardar la BD, backups y logs ahí.

---

## 4. Variables de entorno

En el mismo servicio: **Variables** → **Add Variable** (o **New Variable**). Añade las que uses, por ejemplo:

| Variable | Valor | Obligatorio en producción |
|----------|--------|----------------------------|
| `NODE_ENV` | `production` | Sí |
| `SESSION_SECRET` | Una cadena larga aleatoria (ej: `openssl rand -hex 64`) | Sí |
| `SMTP_USER` | Tu correo SMTP | Si usas correo |
| `SMTP_PASS` | Contraseña de aplicación (Gmail, etc.) | Si usas correo |
| `SMTP_FROM` | `"Ticket Flex <tu@email.com>"` | Opcional |
| `SMTP_TO` | Correo donde recibir notificaciones | Si usas correo |
| `ADMIN_BOOTSTRAP_USER` | Usuario del primer admin | Recomendado |
| `ADMIN_BOOTSTRAP_PASS` | Contraseña del primer admin | Recomendado |
| `TRUST_PROXY` | `1` | Sí (Railway pone un proxy delante) |

No hace falta definir `PORT`: Railway la asigna sola.  
Si montaste el volumen en `/data`, no hace falta `DATA_DIR`; si usaste otro path, define `DATA_DIR` con ese path (ej: `DATA_DIR=/app/data`).

---

## 5. Dominio público

1. En el servicio: **Settings** (o pestaña de configuración).
2. Busca **Networking** o **Generate Domain**.
3. **Generate Domain** (o **Public Networking**). Railway te dará una URL tipo `tu-proyecto.up.railway.app`.
4. Esa URL es la que usarás para entrar a la app (login, etc.).

---

## 6. Desplegar

- Cada `git push` a la rama conectada (p. ej. `main`) dispara un nuevo despliegue.
- O en el dashboard: **Deploy** / **Redeploy**.
- En **Deployments** puedes ver logs y estado.

---

## Resumen rápido

1. Repo en GitHub (sin `.env`).
2. Railway → New Project → Deploy from GitHub → elegir repo.
3. Añadir **Volume** con mount path `/data`.
4. Añadir **Variables** (al menos `NODE_ENV`, `SESSION_SECRET`, `TRUST_PROXY`, y si quieres admin y SMTP).
5. **Generate Domain** y usar la URL que te den.

Si algo falla, revisa los **logs** del servicio en Railway; suelen indicar si falta una variable o si hay error de BD.
