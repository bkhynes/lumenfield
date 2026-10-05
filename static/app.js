const findings = JSON.parse(document.getElementById("catalog").textContent);
const list = document.getElementById("list");
const detail = document.getElementById("detail");
const voice = document.getElementById("voice");
let current = findings[0].id;
let query = "";
let last = null;

function visible() {
  const q = query.trim().toLowerCase();
  if (!q) return findings;
  return findings.filter(f => `${f.title} ${f.cve} ${f.vendor} ${f.product} ${f.klass}`.toLowerCase().includes(q));
}

const avg = Math.round(findings.reduce((s, f) => s + f.relevance, 0) / findings.length);
document.getElementById("stats").innerHTML = [
  [findings.length, "Living tests on the board"],
  [findings.filter(f => f.cve.startsWith("CVE")).length, "Tied to a public KEV entry"],
  [avg, "Mean ongoing relevance"],
].map(([n, l]) => `<div class="stat"><b>${n}</b><span>${l}</span></div>`).join("");

function paintList() {
  const rows = visible();
  list.innerHTML = rows.map(f => `
    <li><button data-id="${f.id}" class="${f.id === current ? "on" : ""}">
      <span class="rel">${f.relevance}</span>
      <b>${f.title}</b>
      <small>${f.cve} · ${f.klass} · ${dueLabel(f.due)}</small>
    </button></li>`).join("") || "<li class='fine'>Nothing on the board matches that.</li>";
}

function paintDetail() {
  const f = findings.find(x => x.id === current);
  const body = voice.value === "client" ? f.client_line : f.impact;
  detail.innerHTML = `
    <p class="kicker">${f.status} · added ${f.kev_added} · due ${f.due}</p>
    <h3>${f.title}</h3>
    <div class="pills">
      <span>${f.cve}</span><span>${f.vendor}</span><span>CVSS ${f.cvss}</span>
      <span>${f.exposure}</span><span>Relevance ${f.relevance}</span>
    </div>
    <p class="client-line">${body}</p>
    <h4>Why it is still relevant</h4>
    <p>${f.why_ongoing}</p>
    <h4>Fix to put in front of the client</h4>
    <ul>${f.fix.map(step => `<li>${step}</li>`).join("")}</ul>
    <h4>Defensive check · ${f.check_name}</h4>
    <pre>${f.check.replace(/[&<>]/g, ch => ({"&":"&","<":"<",">":">"}[ch]))}</pre>
    <button type="button" id="copy-line">Copy client line</button>`;
  document.getElementById("copy-line").onclick = () => navigator.clipboard.writeText(f.client_line);
}

list.addEventListener("click", (event) => {
  const btn = event.target.closest("button");
  if (!btn) return;
  current = btn.dataset.id;
  paintList();
  paintDetail();
});
voice.addEventListener("change", paintDetail);
paintList();
paintDetail();

document.getElementById("filter").addEventListener("input", (event) => {
  query = event.target.value;
  const rows = visible();
  if (rows.length && !rows.some(f => f.id === current)) current = rows[0].id;
  paintList();
  if (rows.length) paintDetail();
});

document.getElementById("brief-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.target);
  const data = {
    client: form.get("client"),
    prepared: form.get("prepared"),
    include_scan: form.get("include_scan") === "on",
  };
  localStorage.setItem("lf-client", data.client);
  if (form.get("matches_only") === "on" && last?.findings?.length) {
    data.ids = [...new Set(last.findings.map(hit => hit.id))];
  }
  const res = await fetch("/api/report", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(data),
  });
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "lumenfield-brief.pdf";
  a.click();
});

const stage = document.getElementById("scan-stage");
const result = document.getElementById("scan-result");
const scanBtn = document.getElementById("scan-btn");
const savedClient = localStorage.getItem("lf-client");
if (savedClient) document.querySelector("[name=client]").value = savedClient;

function paintDevices(body) {
  const count = document.getElementById("device-count");
  const list = document.getElementById("device-list");
  if (!body.ok) {
    count.textContent = body.error || "MySQL is not connected.";
    list.innerHTML = "<p class='fine'>The app expects MySQL on 127.0.0.1 as root with an empty password, and will create the lumenfield database itself.</p>";
    return;
  }
  count.textContent = `${body.connected_now} seen in the last 15 minutes · ${body.known} known`;
  list.innerHTML = body.devices.map(device => `<article class="device">
    <div><b>${device.hostname || device.ip}</b><span>${device.ip} · ${device.mac || "no mac"} · ${device.vendor || "vendor unknown"}</span></div>
    <div><span>${device.role || "unclassified"} · ports ${device.ports || "none"}</span><span>${device.evidence || "no banner"}</span></div>
    <div><span>first ${device.first_seen}</span><span>last ${device.last_seen} · seen ${device.times_seen} times</span></div>
  </article>`).join("") || "<p class='fine'>No devices stored yet. Run a scan on a network you are authorised to assess.</p>";
}

fetch("/api/devices").then(r => r.json()).then(paintDevices);
fetch("/api/network").then(r => r.json()).then(net => {
  document.getElementById("cidr").value = net.cidr;
  document.getElementById("lan").textContent = net.private
    ? `This host is ${net.host} on ${net.cidr}. Up to 128 hosts, seven service ports.`
    : "No private range detected. Enter a private CIDR you operate.";
});
fetch("/api/scan").then(r => r.json()).then(body => {
  if (body.cidr) showScan(body);
});

document.getElementById("scan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target));
  data.confirmed = true;
  stage.hidden = false;
  scanBtn.disabled = true;
  const started = Date.now();
  const clock = setInterval(() => {
    stage.querySelector("p").textContent = `Reading banners. ${Math.round((Date.now() - started) / 1000)}s elapsed. No exploit traffic.`;
  }, 500);
  const res = await fetch("/api/scan", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(data),
  });
  clearInterval(clock);
  stage.hidden = true;
  scanBtn.disabled = false;
  const body = await res.json();
  if (!res.ok) {
    result.innerHTML = `<p>${body.error || "Scan refused."}</p>`;
    return;
  }
  showScan(body);
  if (body.devices) paintDevices(body.devices.ok ? body.devices : {ok: false, error: body.devices.error});
});

function dueLabel(due) {
  if (!due || due === "rolling") return "rolling";
  const today = new Date().toISOString().slice(0, 10);
  if (due < today) return "past due";
  return `due ${due}`;
}

function unmatched(body) {
  const matched = new Set((body.findings || []).map(hit => `${hit.host}:${hit.port}`));
  return (body.observations || []).filter(obs => !matched.has(`${obs.host}:${obs.port}`));
}

function deltaLine(body) {
  const delta = body.delta;
  if (!delta || !delta.compared_with) return "First saved scan on this service.";
  if (!delta.new.length && !delta.cleared.length) return `Unchanged since ${delta.compared_with}.`;
  return `${delta.new.length} new, ${delta.cleared.length} cleared since ${delta.compared_with}.`;
}

function inventory(body) {
  const rows = unmatched(body);
  if (!rows.length) return "";
  return `<details class="inventory"><summary>${rows.length} other services answered, not on the board</summary>
    <ul>${rows.map(obs => `<li>${obs.host}:${obs.port} — ${obs.evidence}</li>`).join("")}</ul>
  </details>`;
}

function showScan(body) {
  last = body;
  result.innerHTML = body.clear ? clearField(body) : hitList(body);
}

function clearField(body) {
  const seen = body.observations?.length || 0;
  const motes = Array.from({length: 14}, (_, i) =>
    `<span class="mote" style="left:${8 + i * 6}%; animation-delay:${(i % 5) * 0.35}s"></span>`
  ).join("");
  return `<div class="clear-field">
    ${motes}
    <div class="orbit"></div>
    <div class="orbit inner"></div>
    <div>
      <div class="seal">LF</div>
      <h3>Field is clear.</h3>
      <p>No watched product on ${body.cidr}. ${body.hosts_considered} hosts, ${seen} services answered, none matched the board.</p>
      <p class="fine">${deltaLine(body)} Saved ${body.scanned_at}.</p>
    </div>
  </div>${inventory(body)}`;
}

function hitList(body) {
  return `<p class="kicker">${body.findings.length} match${body.findings.length === 1 ? "" : "es"} on ${body.cidr}</p>` +
    body.findings.map(hit => `<article class="hit">
      <button type="button" data-open="${hit.id}"><b>${hit.title}</b></button>
      <p>${hit.host}:${hit.port} · ${hit.cve} · relevance ${hit.relevance}</p>
      <p>${hit.client_line}</p>
      <p class="fine">${hit.evidence}</p>
    </article>`).join("") +
    `<p class="fine">${deltaLine(body)} Open a match to brief it.</p>${inventory(body)}`;
}

result.addEventListener("click", (event) => {
  const btn = event.target.closest("[data-open]");
  if (!btn) return;
  current = btn.dataset.open;
  query = "";
  document.getElementById("filter").value = "";
  paintList();
  paintDetail();
  document.getElementById("board").scrollIntoView({behavior: "smooth"});
});
