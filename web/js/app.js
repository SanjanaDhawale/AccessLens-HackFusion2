const API_BASE = "http://127.0.0.1:8000";
const modal = document.getElementById("scan-modal");

function openScan() {
  modal.classList.add("open");
  modal.setAttribute("aria-hidden", "false");
  document.getElementById("target-url").focus();
}
function closeScan() {
  modal.classList.remove("open");
  modal.setAttribute("aria-hidden", "true");
}
document.getElementById("open-scan").addEventListener("click", openScan);
document.getElementById("hero-scan").addEventListener("click", openScan);
document.getElementById("close-scan").addEventListener("click", closeScan);
document.getElementById("cancel-scan").addEventListener("click", closeScan);
modal.addEventListener("click", (event) => { if (event.target === modal) closeScan(); });
document.addEventListener("keydown", (event) => { if (event.key === "Escape") closeScan(); });

function showView(name) {
  const validViews = ["overview", "inventory", "matrix", "findings", "evidence", "history", "reports", "settings"];
  if (!validViews.includes(name)) name = "overview";
  document.querySelectorAll(".view").forEach((node) => node.classList.remove("active-view"));
  document.getElementById("view-" + name).classList.add("active-view");
  document.querySelectorAll(".nav-link[data-view]").forEach((node) => node.classList.toggle("active", node.dataset.view === name));
  document.getElementById("breadcrumb-current").textContent = name.replace("-", " ").toUpperCase();
  document.getElementById("sidebar").classList.remove("mobile-open");
  window.scrollTo({ top: 0, behavior: "smooth" });
}
document.querySelectorAll(".nav-link[data-view]").forEach((link) => {
  link.addEventListener("click", (event) => { event.preventDefault(); showView(link.dataset.view); });
});
document.querySelectorAll("[data-goto]").forEach((button) => button.addEventListener("click", () => showView(button.dataset.goto)));
document.getElementById("mobile-menu").addEventListener("click", () => document.getElementById("sidebar").classList.toggle("mobile-open"));

document.getElementById("inventory-upload").addEventListener("click", () => document.getElementById("spec-file").click());
document.getElementById("spec-file").addEventListener("change", (event) => {
  const file = event.target.files?.[0];
  if (file) alert(file.name + " selected. OpenAPI parsing will be connected during backend integration.");
});

async function checkApi() {
  const badge = document.querySelector(".live-badge");
  try {
    const response = await fetch(API_BASE + "/api/health", { signal: AbortSignal.timeout(2500) });
    const data = await response.json();
    badge.innerHTML = data.status === "ok" ? "<i></i> API CONNECTED" : "<i></i> ENGINE STANDBY";
  } catch {
    badge.innerHTML = "<i></i> ENGINE STANDBY";
  }
}
document.getElementById("scan-button").addEventListener("click", () => {
  const input = document.getElementById("target-url");
  const feedback = document.getElementById("scan-feedback");
  let target;
  try {
    target = new URL(input.value.trim());
    if (!["http:", "https:"].includes(target.protocol)) throw new Error("Only HTTP or HTTPS targets are supported.");
    if (target.username || target.password) throw new Error("Credentials must not be embedded in target URLs.");
  } catch (error) {
    feedback.textContent = error.message || "Enter a valid target URL.";
    return;
  }
  feedback.textContent = "Target format valid. Backend scan orchestration is not connected yet; no requests were sent.";
});
checkApi();

// API INVENTORY: local OpenAPI/Swagger inspection; no target requests are sent.
const inv = { endpoints: [] };
const invFile = document.getElementById("spec-file");
const invBody = document.getElementById("endpoint-table-body");
const invSearch = document.getElementById("endpoint-search");
const invMethod = document.getElementById("method-filter");
const invAuth = document.getElementById("auth-filter");
const invFeedback = document.getElementById("inventory-feedback");

function safeText(v){return String(v ?? "").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function yamlLite(text){
  const spec={openapi:"",swagger:"",info:{},paths:{},security:null};let section="",path="",method="";
  for(const raw of text.split(/\r?\n/)){
    const line=raw.replace(/\s+#.*$/,"");if(!line.trim()||/^\s*#/.test(line))continue;
    const n=line.length-line.trimStart().length,m=line.trim().match(/^["']?([^:'"]+)["']?\s*:\s*(.*?)\s*$/);if(!m)continue;
    const k=m[1].trim(),v=m[2].replace(/^["']|["']$/g,"");
    if(n===0){section=k;if(k==="openapi"||k==="swagger")spec[k]=v;continue;}
    if(section==="info"&&n<=2)spec.info[k]=v;
    if(section==="paths"){
      if(n<=2&&k.startsWith("/")){path=k;spec.paths[path]={};method="";}
      else if(path&&n<=4&&["get","post","put","patch","delete","options","head","trace"].includes(k.toLowerCase())){method=k.toUpperCase();spec.paths[path][method]={};}
      else if(path&&method&&n>=6&&["summary","description","operationId"].includes(k))spec.paths[path][method][k]=v;
    }
  }return spec;
}
function readOpenApi(text,name){
  const spec=(name.toLowerCase().endsWith(".json")||text.trim().startsWith("{"))?JSON.parse(text):yamlLite(text);
  if(!spec.paths||typeof spec.paths!=="object")throw Error("No OpenAPI paths object was found.");
  const globalAuth=Array.isArray(spec.security)&&spec.security.length>0,items=[];
  for(const [path,item] of Object.entries(spec.paths)){
    if(!item||typeof item!=="object")continue;
    for(const [verb,op0] of Object.entries(item)){
      if(!["get","post","put","patch","delete","options","head","trace"].includes(verb.toLowerCase()))continue;
      const op=op0||{},params=[...(item.parameters||[]),...(op.parameters||[])];
      const secured=Array.isArray(op.security)?op.security.length>0:globalAuth;
      items.push({id:verb.toUpperCase()+" "+path,method:verb.toUpperCase(),path,summary:op.summary||op.description||"No summary provided",operationId:op.operationId||"—",secured,parameters:params.map(p=>({name:p.name||"unnamed",in:p.in||"unknown",required:!!p.required})),tags:op.tags||[],deprecated:!!op.deprecated,responses:Object.keys(op.responses||{})});
    }
  }
  if(!items.length)throw Error("No HTTP operations were found under paths.");
  return {spec,items};
}
function renderInventory(){
  const q=invSearch.value.trim().toLowerCase(),m=invMethod.value,a=invAuth.value;
  const rows=inv.endpoints.filter(x=>(!q||[x.path,x.summary,x.operationId,x.method].join(" ").toLowerCase().includes(q))&&(m==="ALL"||x.method===m)&&(a==="ALL"||(a==="AUTH"?x.secured:!x.secured)));
  document.getElementById("table-result-count").textContent=rows.length+" result"+(rows.length===1?"":"s");
  if(!rows.length){invBody.innerHTML='<tr class="inventory-empty"><td colspan="6"><div class="empty-state"><span>⌕</span><strong>No matching endpoints</strong><small>Try changing your search or filters.</small></div></td></tr>';return;}
  invBody.innerHTML=rows.map(x=>{const mc=["GET","POST","PUT","PATCH","DELETE"].includes(x.method)?"method-"+x.method:"method-OTHER";return `<tr><td><span class="method-pill ${mc}">${safeText(x.method)}</span></td><td><span class="endpoint-path">${safeText(x.path)}</span><span class="endpoint-summary">${safeText(x.summary)}${x.deprecated?" · DEPRECATED":""}</span></td><td><span class="auth-state ${x.secured?"":"open"}">${x.secured?"Security declared":"No security declared"}</span></td><td><span class="parameter-count">${x.parameters.length}</span></td><td><span class="operation-id">${safeText(x.operationId)}</span></td><td><button class="details-button" data-endpoint-id="${safeText(x.id)}">Inspect ↗</button></td></tr>`;}).join("");
}
async function importSpec(file){
  if(!file)return;invFeedback.textContent="Reading "+file.name+"…";
  try{if(file.size>5*1024*1024)throw Error("File exceeds the 5 MB import limit.");const result=readOpenApi(await file.text(),file.name);inv.endpoints=result.items;
    const methods=[...new Set(inv.endpoints.map(x=>x.method))],auth=inv.endpoints.filter(x=>x.secured).length;
    document.getElementById("inventory-count").textContent=inv.endpoints.length+" ENDPOINTS";
    document.getElementById("stat-endpoints").textContent=inv.endpoints.length;document.getElementById("stat-methods").textContent=methods.length;
    document.getElementById("stat-methods-detail").textContent=methods.join(" · ")||"None";
    document.getElementById("stat-auth").textContent=auth;document.getElementById("stat-version").textContent=result.spec.openapi||(result.spec.swagger?"v"+result.spec.swagger:"Unknown");
    document.getElementById("stat-spec-name").textContent=result.spec.info?.title||file.name;
    document.getElementById("inventory-footer-note").textContent=inv.endpoints.length+" operations extracted from "+file.name+".";
    renderInventory();invFeedback.textContent="Imported "+file.name+": "+inv.endpoints.length+" operations discovered. Local parsing only; no API target was contacted.";
  }catch(e){invFeedback.textContent="Import failed: "+e.message;}
}
document.getElementById("inventory-upload").addEventListener("click",()=>invFile.click());
invFile.addEventListener("change",e=>{importSpec(e.target.files?.[0]);e.target.value="";});
[invSearch,invMethod,invAuth].forEach(el=>el.addEventListener(el===invSearch?"input":"change",renderInventory));
document.getElementById("clear-inventory").addEventListener("click",()=>{
  inv.endpoints=[];["inventory-count","stat-endpoints","stat-methods","stat-auth"].forEach(id=>document.getElementById(id).textContent=id==="inventory-count"?"0 ENDPOINTS":"0");
  document.getElementById("stat-methods-detail").textContent="No methods mapped";document.getElementById("stat-version").textContent="—";document.getElementById("stat-spec-name").textContent="No file imported";document.getElementById("inventory-footer-note").textContent="Endpoint inventory is empty.";invFeedback.textContent="Inventory cleared.";renderInventory();
});
const endpointModal=document.getElementById("endpoint-modal");
function closeEndpoint(){endpointModal.classList.remove("open");endpointModal.setAttribute("aria-hidden","true");}
function showEndpoint(id){
  const x=inv.endpoints.find(e=>e.id===id);if(!x)return;
  const params=x.parameters.length?`<ul>${x.parameters.map(p=>`<li>${safeText(p.name)} · ${safeText(p.in)} · ${p.required?"required":"optional"}</li>`).join("")}</ul>`:"<p class='detail-description'>No parameters declared.</p>";
  document.getElementById("endpoint-detail-content").innerHTML=`<div class="detail-route">${safeText(x.method)} ${safeText(x.path)}</div><div class="detail-grid"><div class="detail-cell"><small>AUTH DECLARATION</small><strong>${x.secured?"Security requirement declared":"No security requirement declared"}</strong></div><div class="detail-cell"><small>OPERATION ID</small><strong>${safeText(x.operationId)}</strong></div><div class="detail-cell"><small>TAGS</small><strong>${safeText(x.tags.join(", ")||"—")}</strong></div><div class="detail-cell"><small>EXPECTED RESPONSES</small><strong>${safeText(x.responses.join(", ")||"Not specified")}</strong></div></div><p class="detail-description">${safeText(x.summary)}</p><div class="detail-params"><h3>DECLARED PARAMETERS (${x.parameters.length})</h3>${params}</div>${x.secured?"":"<div class='detail-warning'>No security requirement is declared in the specification. This is not proof of a missing-authentication vulnerability; runtime verification is required.</div>"}`;
  endpointModal.classList.add("open");endpointModal.setAttribute("aria-hidden","false");
}
invBody.addEventListener("click",e=>{const b=e.target.closest("[data-endpoint-id]");if(b)showEndpoint(b.dataset.endpointId);});
document.getElementById("close-endpoint").addEventListener("click",closeEndpoint);document.getElementById("close-endpoint-footer").addEventListener("click",closeEndpoint);
endpointModal.addEventListener("click",e=>{if(e.target===endpointModal)closeEndpoint();});
document.addEventListener("keydown",e=>{if(e.key==="Escape")closeEndpoint();});

// ACCESS MATRIX: illustrative expected policies only; no live requests are made.
const matrixPolicies = [
 {id:"GET /vehicles",path:"/vehicles",method:"GET",summary:"List vehicles visible to the current identity",category:"VEHICLE",rules:{anonymous:"deny",alice:"allow",bob:"allow",technician:"allow",admin:"allow"},notes:{alice:"Alice may list only vehicles assigned to her account.",bob:"Bob may list only vehicles assigned to his account.",technician:"Technicians may list vehicles within their maintenance assignment.",admin:"Administrators may list all vehicles."}},
 {id:"GET /vehicles/{vin}",path:"/vehicles/{vin}",method:"GET",summary:"Retrieve a vehicle by VIN",category:"VEHICLE",rules:{anonymous:"deny",alice:"own",bob:"own",technician:"own",admin:"allow"},notes:{alice:"Alice may retrieve CAR-A only. Access to Bob's CAR-B should be denied.",bob:"Bob may retrieve CAR-B only. Access to Alice's CAR-A should be denied.",technician:"A technician may retrieve a vehicle only when an active maintenance assignment authorizes access.",admin:"Administrators may retrieve any vehicle."}},
 {id:"POST /vehicles",path:"/vehicles",method:"POST",summary:"Register a vehicle",category:"VEHICLE",rules:{anonymous:"deny",alice:"deny",bob:"deny",technician:"deny",admin:"allow"},notes:{admin:"Only an administrator may register vehicles in this demo policy."}},
 {id:"GET /admin/users",path:"/admin/users",method:"GET",summary:"List user accounts",category:"ADMIN",rules:{anonymous:"deny",alice:"deny",bob:"deny",technician:"deny",admin:"allow"},notes:{admin:"Administrative user listing is restricted to the administrator role."}},
 {id:"POST /admin/users",path:"/admin/users",method:"POST",summary:"Create a user account",category:"ADMIN",rules:{anonymous:"deny",alice:"deny",bob:"deny",technician:"deny",admin:"allow"},notes:{admin:"Creating user accounts is an administrator-only function."}}
];
const roleLabels={anonymous:"Anonymous",alice:"Alice",bob:"Bob",technician:"Technician",admin:"Admin"};
const ruleLabels={allow:"ALLOWED",own:"OWN ONLY",deny:"DENIED"};
function renderMatrix(){
 const q=document.getElementById("matrix-search").value.trim().toLowerCase(),cat=document.getElementById("matrix-category").value,role=document.getElementById("matrix-role").value;
 const rows=matrixPolicies.filter(x=>(!q||(x.path+" "+x.summary).toLowerCase().includes(q))&&(cat==="ALL"||x.category===cat));
 const roles=role==="ALL"?["anonymous","alice","bob","technician","admin"]:[role];
 const head=document.querySelector(".matrix-table thead tr");
 const roleHead={anonymous:'<span class="matrix-col-avatar anonymous">?</span> ANONYMOUS',alice:'<span class="matrix-col-avatar alice">A</span> ALICE',bob:'<span class="matrix-col-avatar bob">B</span> BOB',technician:'<span class="matrix-col-avatar tech">T</span> TECHNICIAN',admin:'<span class="matrix-col-avatar admin">A</span> ADMIN'};
 head.innerHTML="<th>API OPERATION</th>"+roles.map(r=>"<th>"+roleHead[r]+"</th>").join("");
 const body=document.getElementById("matrix-table-body");
 body.innerHTML=rows.length?rows.map(x=>"<tr><td><div class='matrix-endpoint'><strong>"+safeText(x.method+" "+x.path)+"</strong><small>"+safeText(x.summary)+"</small></div></td>"+roles.map(r=>{const v=x.rules[r];return "<td><button type='button' class='policy-cell "+v+"' data-policy-id='"+safeText(x.id)+"' data-policy-role='"+r+"'>"+ruleLabels[v]+"</button></td>";}).join("")+"</tr>").join(""):"<tr><td colspan='"+(roles.length+1)+"'><div class='empty-state'><span>⌕</span><strong>No matching operations</strong><small>Change the search or category filter.</small></div></td></tr>";
 document.getElementById("matrix-row-count").textContent=rows.length+" policy rows · "+(rows.length*roles.length)+" visible expected decisions";
}
["matrix-search","matrix-category","matrix-role"].forEach(id=>document.getElementById(id).addEventListener(id==="matrix-search"?"input":"change",renderMatrix));
renderMatrix();
const policyModal=document.getElementById("policy-modal");
function closePolicy(){policyModal.classList.remove("open");policyModal.setAttribute("aria-hidden","true");}
document.getElementById("matrix-table-body").addEventListener("click",event=>{
 const button=event.target.closest("[data-policy-id]");if(!button)return;
 const row=matrixPolicies.find(x=>x.id===button.dataset.policyId),role=button.dataset.policyRole,value=row.rules[role];
 const explanation=row.notes?.[role]||"This identity is not permitted to perform this operation under the illustrative ConnectedCar policy.";
 document.getElementById("policy-detail-content").innerHTML="<div class='detail-route'>"+safeText(row.method+" "+row.path)+"</div><div class='detail-grid'><div class='detail-cell'><small>IDENTITY</small><strong>"+roleLabels[role]+"</strong></div><div class='detail-cell'><small>EXPECTED POLICY</small><strong><span class='policy-detail-status "+value+"'>"+ruleLabels[value]+"</span></strong></div><div class='detail-cell'><small>POLICY CATEGORY</small><strong>"+row.category+"</strong></div><div class='detail-cell'><small>RUNTIME VERDICT</small><strong>INCONCLUSIVE · NOT TESTED</strong></div></div><p class='detail-description'>"+safeText(explanation)+"</p><div class='detail-warning'>This is an expected policy rule for the synthetic demo, not an observed authorization result. AccessLens must execute a scoped runtime check and compare the actual response before assigning PASS or FAIL.</div>";
 policyModal.classList.add("open");policyModal.setAttribute("aria-hidden","false");
});
document.getElementById("close-policy").addEventListener("click",closePolicy);
document.getElementById("close-policy-footer").addEventListener("click",closePolicy);
policyModal.addEventListener("click",e=>{if(e.target===policyModal)closePolicy();});
document.getElementById("matrix-run-checks").addEventListener("click",()=>{
 const button=document.getElementById("matrix-run-checks");
 button.textContent="Engine integration pending";
 const notice=document.querySelector(".matrix-notice small");
 notice.textContent="Authorization checks are not connected yet. No network requests were sent; all runtime verdicts remain INCONCLUSIVE.";
 setTimeout(()=>button.textContent="Run authorization checks ↗",2600);
});
