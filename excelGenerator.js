const XLSX = require("xlsx")
function generarExcel(data){
  const ws = XLSX.utils.json_to_sheet(data)
  const wb = XLSX.utils.book_new()
  XLSX.utils.book_append_sheet(wb, ws, "Tickets")
  XLSX.writeFile(wb, "tickets.xlsx")
}
module.exports = generarExcel