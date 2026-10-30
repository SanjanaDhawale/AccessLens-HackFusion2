"use strict";
(() => {
  const $ = (id) => document.getElementById(id);
  const api = window.AccessLensAPI;
  const state = { messages: [], target: null, targetId: null, specificationId: null, scanId: null, pollTimer: null, selectedFile: null, scanBusy: false };
  const chat = $("messages");
  const input = $("chatInput");
  let toastTimer;

  function toast(message) {
    const el = $("toast"); el.textContent = message; el.classList.add("show");
    clearTimeout(toastTimer); toastTimer = setTimeout(() => el.classList.remove("show"), 3500);
  }
  function safeText(text) { return String(text ?? ""); }
  function appendMessage(role, text, actions = []) {
    $("welcome").hidden = true;
    const row = document.createElement("div"); row.className = "message-row " + role;
    if (role === "assistant") {
      const avatar = document.createElement("div"); avatar.className = "message-avatar"; avatar.textContent = "◈"; row.append(avatar);
    }
    const bubble = document.createElement("div"); bubble.className = "message-bubble";
    const p = document.createElement("p"); p.textContent = safeText(text); bubble.append(p);
    if (actions.length) {
      const bar = document.createElement("div"); bar.className = "inline-actions";
      actions.forEach(action => {
        const btn = document.createElement("button"); btn.type = "button"; btn.textContent = action.label;
        if (action.primary) btn.classList.add("primary");
        btn.addEventListener("click", action.run); bar.append(btn);
      });
      bubble.append(bar);
    }
    row.append(bubble); chat.append(row); $("chatScroll").scrollTop = $("chatScroll").scrollHeight;
    state.messages.push({ role, text: safeText(text) });
  }
  function addFindingCard(finding) {
    const card = document.createElement("div");
    const severity = String(finding.severity || "unknown").toLowerCase();
    card.className = "finding-card " + severity;
    const top = document.createElement("div"); top.className = "finding-top";
    const title = document.createElement("span"); title.textContent = finding.title || finding.owasp_id || "Security finding";
    const level = document.createElement("span"); level.className = "severity"; level.textContent = severity;
    top.append(title, level); card.append(top);
    const detail = document.createElement("p"); detail.textContent = [finding.method, finding.endpoint, finding.rationale].filter(Boolean).join(" · ") || "Review the backend evidence for details.";
    card.append(detail); return card;
  }
  function showFindings(findings) {
    const row = document.createElement("div"); row.className = "message-row assistant";
    const avatar = document.createElement("div"); avatar.className = "message-avatar"; avatar.textContent = "◈";
    const bubble = document.createElement("div"); bubble.className = "message-bubble";
    const intro = document.createElement("p"); intro.textContent = findings.length ? "Here are the findings returned by the security engine:" : "The backend returned no findings for this assessment.";
    bubble.append(intro);
    findings.forEach(f => bubble.append(addFindingCard(f)));
    const bar = document.createElement("div"); bar.className = "inline-actions";
    const explain = document.createElement("button"); explain.textContent = "Explain findings"; explain.addEventListener("click", () => appendMessage("assistant", "These findings are the records returned by the backend. Review each affected endpoint, severity, rationale and remediation guidance. AccessLens does not apply changes to your API."));
    const report = document.createElement("button"); report.textContent = "Generate security report"; report.className = "primary"; report.addEventListener("click", generateReport);
    bar.append(explain, report); bubble.append(bar); row.append(avatar,bubble); chat.append(row);
    $("chatScroll").scrollTop = $("chatScroll").scrollHeight;
  }
  function setView(name) {
    $("chatView").hidden = name !== "chat"; $("historyView").hidden = name !== "history";
    document.querySelectorAll(".nav-item[data-view]").forEach(b => b.classList.toggle("active", b.dataset.view === name));
    if (name === "history") renderHistory();
  }
  function renderHistory() {
    const list = $("historyList"); list.replaceChildren();
    if (!state.messages.length) { const empty=document.createElement("div"); empty.className="empty-state"; empty.textContent="No activity in this session yet."; list.append(empty); return; }
    state.messages.filter(m => m.role === "user").forEach(m => { const item=document.createElement("div"); item.className="history-entry"; item.textContent=m.text; list.append(item); });
  }
  function resetChat() {
    clearTimeout(state.pollTimer); state.messages=[]; state.target=null; state.targetId=null; state.specificationId=null; state.scanId=null; state.scanBusy=false;
    chat.replaceChildren(); $("welcome").hidden=false; $("scanPanel").hidden=true; $("endpointCount").textContent="—"; $("selectedFile").textContent=""; $("specFile").value=""; state.selectedFile=null; input.value=""; setView("chat"); input.focus();
  }
  function findUrl(text) { const m=String(text).match(/https?:\/\/[^\s<>"']+/i); if(!m)return null; try { const u=new URL(m[0].replace(/[),.;!?]+$/,"")); if(!["http:","https:"].includes(u.protocol)||u.username||u.password) return null; return u; } catch{return null;} }
  function isSecretLike(text) { return /\b(api[_-]?key|bearer\s+[a-z0-9._-]{12,}|secret\s*[:=]|password\s*[:=])\b/i.test(text); }
  function askForTarget(url) {
    state.target = url ? url.href : null;
    appendMessage("assistant", url ? "I found an API URL. Before testing, I need to confirm ownership and the exact paths you authorize. No request has been sent to the target yet." : "Let's prepare an authorized API assessment. Share the API base URL or attach an OpenAPI JSON/YAML specification. Do not paste API keys or secrets into chat.", url ? [{label:"Define authorized scope",primary:true,run:()=>openScope(url.href)}] : []);
  }
  function openScope(url) {
    $("targetUrl").value = url || state.target || "";
    updateHost();
    $("scopeModal").hidden=false;
    $("targetUrl").focus();
  }
  function updateHost() {
    try { const u=new URL($("targetUrl").value); $("scopeHost").textContent="AUTHORIZED HOST · "+u.hostname; }
    catch { $("scopeHost").textContent="HOST SCOPE WILL APPEAR HERE"; }
  }
  async function confirmScope(event) {
    event.preventDefault();
    if (!$("authorizationCheck").checked) return toast("Explicit authorization is required.");
    let url;
    try { url=new URL($("targetUrl").value); if(!["http:","https:"].includes(url.protocol)||url.username||url.password||url.search||url.hash) throw new Error(); }
    catch { return toast("Enter a valid base URL without credentials, query parameters or fragments."); }
    const paths=$("allowedPaths").value.split(",").map(p=>p.trim()).filter(Boolean);
    if(!paths.length || paths.some(p=>!p.startsWith("/")||p.startsWith("//"))) return toast("Every allowed path must be an absolute path beginning with /.");
    const button=$("confirmScope"); button.disabled=true; button.textContent="Registering target…";
    try {
      const target=await api.registerTarget({target_url:url.origin+url.pathname.replace(/\/$/,""),authorization_confirmed:true,authorized_hosts:[url.hostname],allowed_paths:paths});
      state.target=url; state.targetId=target.target_id || target.id || target.data?.target_id;
      if(!state.targetId) throw new Error("The backend response did not include a target ID.");
      $("scopeModal").hidden=true;
      appendMessage("assistant","Your authorized target was registered successfully. Target ID: "+state.targetId+". "+(state.selectedFile ? "I'll upload the OpenAPI specification next." : "You can now start the security assessment when ready."),[{label:"Start security assessment",primary:true,run:startAssessment}]);
      if(state.selectedFile) await uploadSpec();
    } catch(err) { appendMessage("assistant","I couldn't register this target with the backend: "+err.message+". No scan was started."); }
    finally { button.disabled=false; button.textContent="Confirm authorized scope"; }
  }
  async function uploadSpec() {
    if(!state.targetId||!state.selectedFile) return;
    const form=new FormData(); form.append("target_id",state.targetId); form.append("authorization_confirmed","true"); form.append("file",state.selectedFile);
    try {
      const result=await api.uploadSpecification(form);
      state.specificationId=result.specification_id || result.id || result.data?.specification_id;
      if(!state.specificationId) throw new Error("The backend did not return a specification ID.");
      const endpoints=Array.isArray(result.endpoints)?result.endpoints:[];
      $("endpointCount").textContent=String(result.total_endpoints ?? endpoints.length ?? "—").padStart(2,"0");
      appendMessage("assistant","OpenAPI specification uploaded and parsed by the backend. "+(result.total_endpoints ?? endpoints.length)+" endpoint(s) were returned. Start the assessment when you're ready.",[{label:"Start security assessment",primary:true,run:startAssessment}]);
    } catch(err) { appendMessage("assistant","The target was registered, but the specification upload failed: "+err.message+". You can retry by attaching the file again."); }
  }
  async function startAssessment() {
    if(state.scanBusy||!state.targetId) return;
    state.scanBusy=true;
    appendMessage("assistant","Starting the authorized assessment through the AccessLens backend. I'll show only status and progress returned by the server.");
    $("scanPanel").hidden=false; $("scanTitle").textContent="Assessment submitted"; $("scanStage").textContent="Waiting for backend response…"; $("scanPercent").textContent="—"; $("scanProgress").style.width="0%";
    try {
      const result=await api.startScan({target_id:state.targetId,authorization_confirmed:true,scan_profile:"OWASP_API_TOP_10_SAFE",...(state.specificationId?{specification_id:state.specificationId}:{})});
      state.scanId=result.scan_id;
      if(!state.scanId) throw new Error("The backend did not return a scan ID.");
      $("scanId").textContent="SCAN "+state.scanId; $("scanStatus").textContent=result.status||"QUEUED";
      applyScanStatus(result); pollScan();
    } catch(err) { state.scanBusy=false; $("scanPanel").hidden=true; appendMessage("assistant","The backend could not start this assessment: "+err.message+". No results have been generated."); }
  }
  function applyScanStatus(data) {
    const status=String(data.status||"UNKNOWN").toUpperCase();
    const stage=data.current_stage||data.message||status;
    const progress=Number(data.progress);
    $("scanTitle").textContent=status==="COMPLETED"?"Assessment complete":status==="FAILED"?"Assessment failed":status==="CANCELLED"?"Assessment cancelled":"Security assessment running";
    $("scanStage").textContent=stage; $("scanStatus").textContent=status;
    if(Number.isFinite(progress)) { const p=Math.max(0,Math.min(100,progress)); $("scanPercent").textContent=Math.round(p)+"%"; $("scanProgress").style.width=p+"%"; }
    if(["COMPLETED","FAILED","CANCELLED"].includes(status)) { state.scanBusy=false; return true; }
    return false;
  }
  async function pollScan() {
    if(!state.scanId)return;
    try {
      const data=await api.scanStatus(state.scanId);
      if(applyScanStatus(data)) {
        if(String(data.status).toUpperCase()==="COMPLETED") await loadFindings();
        else appendMessage("assistant","The assessment ended with status "+data.status+". The backend did not report a completed result.");
        return;
      }
      state.pollTimer=setTimeout(pollScan,1800);
    } catch(err) { state.scanBusy=false; $("scanStage").textContent="Unable to retrieve scan status"; appendMessage("assistant","I lost contact with the backend while checking scan status: "+err.message+". Refresh the assessment status before assuming it completed."); }
  }
  async function loadFindings() {
    try {
      const result=await api.findings(state.scanId);
      const findings=Array.isArray(result)?result:(result.findings||result.items||[]);
      appendMessage("assistant","The backend reports that the assessment is complete. Scan ID: "+state.scanId+". Findings below are loaded from the backend; they are not generated by the chat interface.");
      showFindings(findings);
    } catch(err) { appendMessage("assistant","The scan completed, but findings could not be loaded: "+err.message+"."); }
  }
  async function generateReport() {
    if(!state.scanId)return toast("Complete an assessment before requesting a report.");
    try {
      const result=await api.generateReport(state.scanId);
      appendMessage("assistant","The backend accepted the report-generation request. "+(result.message||"Check the report service response for availability."),[{label:"Download report",primary:true,run:()=>window.open(api.reportDownloadUrl(state.scanId),"_blank","noopener")}]);
    } catch(err) { appendMessage("assistant","Report generation is not available for this assessment yet: "+err.message+"."); }
  }
  function handleMessage(raw) {
    const text=raw.trim(); if(!text)return;
    appendMessage("user",text); input.value=""; input.style.height="auto";
    if(isSecretLike(text)) { appendMessage("assistant","This message may contain an API key, bearer token, password, or secret. For your safety, remove it and rotate the credential if it was real. The current backend does not provide a secure credential-vault integration, so AccessLens will not forward it."); return; }
    if(/report|vapt/i.test(text)&&state.scanId) { appendMessage("assistant","I can request a report for the completed assessment.",[{label:"Generate report",primary:true,run:generateReport}]); return; }
    const url=findUrl(text);
    if(url) { askForTarget(url); return; }
    if(/upload|openapi|swagger|specification/i.test(text)) { appendMessage("assistant",state.selectedFile?"Your OpenAPI file is selected. Share the API base URL and confirm its authorized scope to upload it.":"Attach an OpenAPI .json, .yaml or .yml file using the Upload OpenAPI control."); return; }
    if(/fix|remediat|resolve|change/i.test(text)) { appendMessage("assistant","I can explain remediation recommendations returned with verified findings. This frontend cannot modify a live API or apply fixes. Any future remediation workflow must show proposed changes and require explicit approval."); return; }
    if(/analy|scan|test|security|vulnerab|authentication|authorization/i.test(text)) { askForTarget(null); return; }
    appendMessage("assistant","I can help prepare an authorized API security assessment, explain backend findings, or request a report. Share an API base URL or attach an OpenAPI specification to begin.");
  }
  $("chatForm").addEventListener("submit",e=>{e.preventDefault();handleMessage(input.value);});
  input.addEventListener("keydown",e=>{if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();$("chatForm").requestSubmit();}});
  input.addEventListener("input",()=>{input.style.height="auto";input.style.height=Math.min(input.scrollHeight,130)+"px";});
  document.querySelectorAll("[data-prompt]").forEach(b=>b.addEventListener("click",()=>handleMessage(b.dataset.prompt)));
  $("specFile").addEventListener("change",e=>{
    const file=e.target.files?.[0]; if(!file)return;
    if(!/\.(json|yaml|yml)$/i.test(file.name)||file.size>2*1024*1024){toast("Choose an OpenAPI JSON/YAML file up to 2 MB.");e.target.value="";return;}
    state.selectedFile=file; $("selectedFile").textContent=file.name;
    appendMessage("assistant","Selected "+file.name+". The specification stays in this page until you confirm an authorized API target. It will only be uploaded after target registration.");
  });
  $("addUrl").addEventListener("click",()=>{input.value="Analyze my API at https://";input.focus();input.setSelectionRange(input.value.length,input.value.length);});
  $("targetUrl").addEventListener("input",updateHost);
  $("scopeForm").addEventListener("submit",confirmScope);
  $("cancelScope").addEventListener("click",()=>$("scopeModal").hidden=true);
  $("newChat").addEventListener("click",resetChat);
  document.querySelectorAll(".nav-item[data-view]").forEach(b=>b.addEventListener("click",()=>setView(b.dataset.view)));
  $("openAdmin").addEventListener("click",()=>{toast("Admin preview is separate and currently uses synthetic demo data. Protected admin APIs are not connected.");window.open("dashboard-preview.html","_blank","noopener");});
  $("menuToggle").addEventListener("click",()=>$("sidebar").classList.add("open"));
  $("closeSidebar").addEventListener("click",()=>$("sidebar").classList.remove("open"));
  $("clock").textContent=new Intl.DateTimeFormat(undefined,{month:"short",day:"2-digit",hour:"2-digit",minute:"2-digit"}).format(new Date());
  async function checkBackend(){
    const el=$("connection");
    try { await api.health(); el.innerHTML="<i></i> BACKEND ONLINE"; el.classList.remove("offline"); }
    catch { el.innerHTML="<i></i> BACKEND OFFLINE"; el.classList.add("offline"); }
  }
  checkBackend();
})();