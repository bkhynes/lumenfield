const findings = JSON.parse(document.getElementById("catalog").textContent);
const list = document.getElementById("list");
const detail = document.getElementById("detail");
const voice = document.getElementById("voice");
let current = findings[0].id;

const avg = Math.round(findings.reduce((s, f) => s + f.relevance, 0) / findings.length);
document.getElementById("stats").innerHTML = [
  [findings.length, "Living tests on the board"],
  [findings.filter(f => f.cve.startsWith("CVE")).length, "Tied to a public KEV entry"],
  [avg, "Mean ongoing relevance"],
].map(([n, l]) => `<div class="stat"><b>${n}</b><span>${l}</span></div>`).join("");

function paintList() {
  list.innerHTML = findings.map(f => `
    <li><button data-id="${f.id}" class="${f.id === current ? "on" : ""}">
      <span class="rel">${f.relevance}</span>
      <b>${f.title}</b>
      <small>${f.cve} · ${f.klass}</small>
    </button></li>`).join("");
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
    <pre>${f.check.replace(/[&<>]/g, ch => ({'&':'&','<':'<','>':'>'}[ch]))}</pre>`;
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

document.getElementById("brief-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target));
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
fetch("/api/network").then(r => r.json()).then(net => {
  document.getElementById("cidr").value = net.cidr;
  document.getElementById("lan").textContent = net.private
    ? `This host is ${net.host} on ${net.cidr}`
    : "No private range detected. Enter a private CIDR you operate.";
});

document.getElementById("scan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target));
  data.confirmed = true;
  stage.hidden = false;
  result.innerHTML = "";
  const res = await fetch("/api/scan", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(data),
  });
  const body = await res.json();
  stage.hidden = true;
  if (!res.ok) {
    result.innerHTML = `<p>${body.error || "Scan refused."}</p>`;
    return;
  }
  result.innerHTML = body.clear ? clearField(body) : hitList(body);
});

function clearField(body) {
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
      <p>No watched product was identified on ${body.cidr}. ${body.hosts_considered} hosts read, banners only.</p>
      <p class="fine">Saved ${body.scanned_at}. A clear field is today's result — run it again when the feed moves.</p>
    </div>
  </div>`;
}

function hitList(body) {
  return `<p class="kicker">${body.findings.length} match${body.findings.length === 1 ? "" : "es"} on ${body.cidr}</p>` +
    body.findings.map(hit => `<article class="hit">
      <b>${hit.title}</b>
      <p>${hit.host}:${hit.port} · ${hit.cve} · relevance ${hit.relevance}</p>
      <p>${hit.client_line}</p>
      <p class="fine">${hit.evidence}</p>
    </article>`).join("");
}
