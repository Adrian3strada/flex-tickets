/* =====================
   REFERENCIAS A CAMPOS
===================== */
const MAX_FIELD_LEN = 500;
const titulo   = document.getElementById("titulo");
const contexto = document.getElementById("contexto");
const proyecto = document.getElementById("proyecto"); // Familia
const fase     = document.getElementById("fase");     // Número de Serie
const prioridad = document.getElementById("prioridad");
const nombre   = document.getElementById("nombre");
const empleado = document.getElementById("empleado");
const btnCrear = document.getElementById("btnCrearTicket");

const notify = (message) => (typeof uiAlert === "function" ? uiAlert(message) : alert(message));
const toast = (message) => (typeof showToast === "function" ? showToast(message, "success") : null);

function cargarTickets() {
  const cont = document.getElementById("tickets");
  if (!cont) {
    console.error("No existe el contenedor #tickets");
    return;
  }

  const params = new URLSearchParams(location.search);
  const selectedId = params.get("id");

  fetchTickets()
    .then(data => {
      let list = Array.isArray(data) ? data : [];

      if (selectedId) {
        list = list.filter(t => String(t.id) === String(selectedId));
      }

      cont.innerHTML = list.length
        ? list.map(ticketCard).join("")
        : `<div class="empty">Ticket no encontrado</div>`;
    })
    .catch(err => {
      console.error(err);
      cont.innerHTML = `<div class="empty">Error al cargar tickets</div>`;
    });
}
/* =====================
   ENVIAR TICKET
===================== */
async function enviarTicket() {

  const requiredFields = [
    titulo,
    contexto,
    proyecto,
    fase,
    nombre,
    empleado
  ];

  const missing = requiredFields.some(
    field => !field || !String(field.value || "").trim()
  );

  if (missing) {
    await notify("Completa todos los campos antes de enviar el ticket.");
    return;
  }
  const tooLong = requiredFields.some(
    field => String(field.value || "").trim().length > MAX_FIELD_LEN
  );
  if (tooLong) {
    await notify(`Algún campo supera ${MAX_FIELD_LEN} caracteres.`);
    return;
  }

  // ⚠️ IMPORTANTE:
  // Se guarda como proyecto / fase
  // para NO romper tickets existentes
  const ticket = {
    titulo: titulo.value,
    contexto: contexto.value,
    proyecto: proyecto.value, // Familia
    fase: fase.value,         // Número de Serie
    prioridad: prioridad ? prioridad.value : "",
    nombre: nombre.value,
    empleado: empleado.value,
    estado: "abierto",
    fecha: new Date().toLocaleString()
  };

  try {
    const sender = (typeof fetchWithTimeout === "function") ? fetchWithTimeout : fetch;
    const res = await sender("/api/tickets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(ticket)
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      await notify(err.error || "Error al crear ticket");
      return;
    }

    const creado = await res.json().catch(() => null);

    const successMessage = creado?.id
      ? `Ticket enviado correctamente. ID: ${creado.id}`
      : "Ticket enviado correctamente."
    toast(successMessage)
    await notify(successMessage)

    // LIMPIAR FORM
    titulo.value = "";
    contexto.value = "";
    proyecto.value = "";
    fase.value = "";
    if (prioridad) prioridad.value = "";
    nombre.value = "";
    empleado.value = "";

  } catch (e) {
    await notify("No se pudo conectar con el servidor.");
  }
}

/* =====================
   REFRESCO AUTOMÁTICO
===================== */
function iniciarRefresco(elementId, segundos = 300) {
  const el = document.getElementById(elementId);
  if (!el) return;

  let restante = segundos;

  const timer = setInterval(() => {
    const min = String(Math.floor(restante / 60)).padStart(2, "0");
    const sec = String(restante % 60).padStart(2, "0");
    el.textContent = `La página se refrescará en ${min}:${sec}`;
    restante--;

    if (restante < 0) {
      clearInterval(timer);
      location.reload();
    }
  }, 1000);
}
