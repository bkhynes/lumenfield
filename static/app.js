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
