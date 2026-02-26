/**
 * Script para eliminar todos los tickets de la base de datos.
 * Ejecutar: node delete-all-tickets.js
 */
const path = require("path");
const sqlite3 = require("sqlite3").verbose();

const rootDir = __dirname;
const dataDir = process.env.DATA_DIR || process.env.RAILWAY_VOLUME_MOUNT_PATH || rootDir;
const dbFile = path.join(dataDir, "database.sqlite");

const db = new sqlite3.Database(dbFile, (err) => {
  if (err) {
    console.error("Error al conectar con la base de datos:", err.message);
    process.exit(1);
  }
});

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

async function deleteAllTickets() {
  try {
    await run("DELETE FROM ticket_comments");
    await run("DELETE FROM audit_logs");
    await run("DELETE FROM tickets");
    console.log("Todos los tickets han sido eliminados correctamente.");
  } catch (err) {
    console.error("Error al eliminar tickets:", err.message);
    process.exit(1);
  } finally {
    db.close();
  }
}

deleteAllTickets();
