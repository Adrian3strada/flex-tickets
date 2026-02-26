# Pasos para subir a Railway (hazlo en orden)

## Paso 1 – Entrar a Railway
- Abre: **https://railway.app**
- Inicia sesión con **GitHub** (Login with GitHub).

---

## Paso 2 – Crear proyecto desde GitHub
- Clic en **"New Project"**.
- Elige **"Deploy from GitHub repo"**.
- Si te pide, autoriza a Railway para ver tus repos.
- Busca y elige el repo: **Adrian3strada/flex-tickets**.
- Railway creará un servicio y empezará a desplegar (puede tardar 1–2 minutos).

---

## Paso 3 – Añadir volumen (para que no se pierda la base de datos)
- En el proyecto, entra al **servicio** (el cuadro con el nombre del repo).
- Arriba verás pestañas: **Deployments**, **Settings**, **Variables**, etc.
- Entra en **"Variables"** o **"Settings"** y busca la sección **"Volumes"** o **"Storage"**.
- Clic en **"Add Volume"** o **"Create Volume"**.
- En **Mount path** escribe exactamente: **`/data`**
- Guarda.

---

## Paso 4 – Variables de entorno
En el mismo servicio, pestaña **"Variables"** → **"Add Variable"** (o **"New Variable"**).  
Añade **una por una** (nombre y valor):

| Nombre            | Valor (cópialo tal cual o usa el tuyo) |
|-------------------|----------------------------------------|
| `NODE_ENV`        | `production` |
| `SESSION_SECRET`  | `75691feb53e9afe07a50d593356297b78e034a589cb1295306a6ce9cbb61450c27102bff71d34e2e47d5bfb5c42dffa0bd811017738d0ace15a0d8854cc3d297` |
| `TRUST_PROXY`     | `1` |
| `ADMIN_BOOTSTRAP_USER` | El usuario con el que quieres entrar (ej: `Ivan`) |
| `ADMIN_BOOTSTRAP_PASS` | La contraseña del primer admin (ej: una segura que elijas) |

Si quieres que lleguen correos al crear tickets, añade también (con tus datos):

- `SMTP_USER` = tu correo (ej: ivanestrda@gmail.com)
- `SMTP_PASS` = contraseña de aplicación de Gmail
- `SMTP_FROM` = "Ticket Flex <tu@email.com>"
- `SMTP_TO` = correo donde recibir notificaciones

Al guardar las variables, Railway suele **redesplegar** solo.

---

## Paso 5 – Dominio público (URL para entrar)
- En el servicio, entra a **"Settings"**.
- Busca **"Networking"** o **"Public Networking"** o **"Generate Domain"**.
- Clic en **"Generate Domain"** (o **"Create Domain"**).
- Te dará una URL tipo: `flex-tickets-production-xxxx.up.railway.app`
- Esa es la URL de tu app. Ábrela en el navegador.

---

## Paso 6 – Probar
- Abre la URL que te dio Railway.
- Deberías ver la pantalla de **login**.
- Entra con el usuario y contraseña que pusiste en `ADMIN_BOOTSTRAP_USER` y `ADMIN_BOOTSTRAP_PASS`.

Si algo falla, en Railway entra a **Deployments** → clic en el último despliegue → **View Logs** y revisa el error.
