"use strict";

// UI-only milestone. No scan is started without a documented backend contract.
const API_BASE = "http://127.0.0.1:8000";
const $ = (id) => document.getElementById(id);
const conversation = $("conversation");
const chatInput = $("chat-input");
const messages = [];
let approvedScope = null;
let selectedFile = null;

function appendMessage(role, text, actions = []) {
  const row = document.createElement("div");
  row.className = `message ${role}`;
  if (role === "assistant") {
    const avatar = document.createElement("div");
    avatar.className = "message-avatar";
    avatar.textContent = "◈";
    row.append(avatar);
  }
  const body = document.createElement("div");
  body.className = "message-body";
  const content = document.createElement("p");
  content.textContent = text; // never inject user text as HTML
  body.append(content);
  if (actions.length) {
    const bar = document.createElement("div");
    bar.className = "inline-actions";
    for (const action of actions) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "action-button";
      button.textContent = action.label;
      button.addEventListener("click", action.onClick);
      bar.append(button);
    }
    body.append(bar);
  }
  row.append(body);
  $("welcome").hidden = true;
  conversation.append(row);
  conversation.scrollTop = conversation.scrollHeight;
  messages.push({ role, text });
}

function findTarget(text) {
  const match = text.match(/https?:\/\/[^\s<>"']+/i);
  if (!match) return null;
  try {
    const url = new URL(match[0].replace(/[.,;!?]+$/, ""));
    if (!["http:", "https:"].includes(url.protocol)) return null;
    return url.href;
  } catch { return null; }
}

function openAuthorization(url = "") {
  if (url) $("scope-url").value = url;
  $("auth-modal").hidden = false;
  $("scope-url").focus();
}
function closeAuthorization() { $("auth-modal").hidden = true; }

function handleMessage(text) {
  const value = text.trim();
  if (!value) return;
  appendMessage("user", value);
  const target = findTarget(value);
  if (target) {
    appendMessage("assistant", "I can help assess this API. Before any network testing, please confirm your authorization and the exact allowed paths. No scan has been started.", [{ label: "Define authorized scope", onClick: () => openAuthorization(target) }]);
  } else if (/openapi|swagger|specification/i.test(value)) {
    appendMessage("assistant", "Attach an OpenAPI JSON or YAML file using 'Attach spec' below. I'll keep the file selected locally for now. Upload and endpoint parsing require the agreed backend integration.");
  } else if (/report|vapt/i.test(value)) {
    appendMessage("assistant", "A VAPT report requires a completed assessment and verified evidence. Report download will be enabled when the backend exposes the agreed report endpoint. No report is available yet.");
  } else if (/test|scan|owasp|security|vulnerab/i.test(value)) {
    appendMessage("assistant", "To begin, share the target API URL or attach its OpenAPI specification. I'll ask for explicit authorization and allowed scope before a scan can start.");
  } else {
    appendMessage("assistant", "I can help you prepare an authorized API security assessment. Enter an API URL, attach an OpenAPI specification, or ask about a VAPT report. Automated analysis will become available once the backend is connected.");
  }
}

$("chat-form").addEventListener("submit", (event) => {
  event.preventDefault();
  handleMessage(chatInput.value);
  chatInput.value = "";
  chatInput.style.height = "auto";
});
chatInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    $("chat-form").requestSubmit();
  }
});
chatInput.addEventListener("input", () => {
  chatInput.style.height = "auto";
  chatInput.style.height = `${Math.min(chatInput.scrollHeight, 140)}px`;
});
for (const button of document.querySelectorAll("[data-prompt]")) {
  button.addEventListener("click", () => handleMessage(button.dataset.prompt));
}
$("spec-file").addEventListener("change", (event) => {
  const file = event.target.files?.[0];
  if (!file) return;
  if (!/\.(json|yaml|yml)$/i.test(file.name)) {
    appendMessage("assistant", "Please select an OpenAPI .json, .yaml, or .yml file.");
    event.target.value = "";
    return;
  }
  if (file.size > 5 * 1024 * 1024) {
    appendMessage("assistant", "Please choose a specification smaller than 5 MB.");
    event.target.value = "";
    return;
  }
  selectedFile = file;
  $("file-name").textContent = file.name;
  appendMessage("assistant", `Selected ${file.name}. The file is not uploaded yet. Backend upload integration is pending.`);
});
$("auth-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const url = $("scope-url").value.trim();
  const paths = $("scope-paths").value.split(",").map((path) => path.trim()).filter(Boolean);
  if (!$("auth-check").checked || !paths.length || paths.some((path) => !path.startsWith("/"))) {
    window.alert("Confirm authorization and enter valid paths beginning with /.");
    return;
  }
  try {
    const parsed = new URL(url);
    if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("Unsupported protocol");
    approvedScope = { target_url: parsed.href, approved_scope: paths };
    closeAuthorization();
    appendMessage("assistant", `Authorization acknowledged for ${parsed.origin} and paths: ${paths.join(", ")}. This confirmation is local UI state only. No network scan has started; backend validation and scan creation are not yet connected.`);
  } catch {
    window.alert("Enter a valid HTTP or HTTPS API URL.");
  }
});
$("auth-close").addEventListener("click", closeAuthorization);
$("auth-cancel").addEventListener("click", closeAuthorization);
$("auth-modal").addEventListener("click", (event) => { if (event.target === $("auth-modal")) closeAuthorization(); });
document.addEventListener("keydown", (event) => { if (event.key === "Escape") closeAuthorization(); });

function showView(view) {
  for (const name of ["chat", "history", "admin"]) {
    $(`${name}-view`).hidden = name !== view;
    $(`nav-${name}`).classList.toggle("selected", name === view);
  }
  $("page-name").textContent = { chat: "AI Analyst", history: "Recent activity", admin: "Admin dashboard" }[view];
  $("sidebar").classList.remove("open");
  if (view === "history") {
    $("history-content").textContent = messages.length
      ? messages.map((message, index) => `${index + 1}. ${message.role === "user" ? "You" : "AccessLens"}: ${message.text}`).join("\n\n")
      : "No messages in this session yet.";
    $("history-content").style.whiteSpace = "pre-wrap";
  }
}
for (const view of ["chat", "history", "admin"]) {
  $(`nav-${view}`).addEventListener("click", () => showView(view));
}
$("new-chat").addEventListener("click", () => {
  messages.length = 0;
  approvedScope = null;
  selectedFile = null;
  $("spec-file").value = "";
  $("file-name").textContent = "";
  conversation.querySelectorAll(".message").forEach((node) => node.remove());
  $("welcome").hidden = false;
  showView("chat");
  chatInput.focus();
});
$("menu-toggle").addEventListener("click", () => $("sidebar").classList.add("open"));
$("close-sidebar").addEventListener("click", () => $("sidebar").classList.remove("open"));

async function checkApi() {
  const node = $("connection");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 4000);
  try {
    const response = await fetch(`${API_BASE}/api/health`, { signal: controller.signal });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    if (data.status !== "ok") throw new Error("Backend not ready");
    node.textContent = "Backend online";
    node.classList.add("online");
  } catch {
    node.textContent = "Backend offline";
    node.classList.add("offline");
  } finally { clearTimeout(timeout); }
}
checkApi();
