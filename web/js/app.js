const API_BASE = "http://127.0.0.1:8000";
const statusNode = document.getElementById("scan-status");

async function checkApi() {
  try {
    const response = await fetch(API_BASE + "/api/health");
    const data = await response.json();
    statusNode.textContent = data.status === "ok" ? "Ready" : "Offline";
  } catch {
    statusNode.textContent = "API offline";
  }
}

document.getElementById("scan-button")?.addEventListener("click", () => {
  const target = document.getElementById("target-url").value.trim();
  if (!target) return;
  statusNode.textContent = "Queued";
  // TODO: connect to POST /api/v1/scans after shared request contract is implemented.
  document.getElementById("findings-list").textContent = "Scan orchestration is not connected yet.";
});
checkApi();
