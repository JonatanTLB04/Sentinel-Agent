with open("public/dashboard.html", encoding="utf-8") as f:
    c = f.read()

changes = []

# ---------------------------------------------------------------
# 1. Remove the fake animateCount/animateBar/hardcoded-Chart block,
#    replace with real chart init (starts empty, filled by loadData)
# ---------------------------------------------------------------
old_load_block = """window.addEventListener('load', () => {
  function animateCount(el, target, duration) {
    let start = 0;
    const step = target / (duration / 16);
    const timer = setInterval(() => { start += step; if (start >= target) { start = target; clearInterval(timer); } el.textContent = Math.floor(start); }, 16);
  }
  function animateBar(el, width, delay) { setTimeout(() => { el.style.width = width + '%'; }, delay); }
  animateCount(document.getElementById('m1'), 31, 800);
  animateCount(document.getElementById('m2'), 24, 1000);
  animateCount(document.getElementById('m3'), 4, 600);
  animateCount(document.getElementById('m4'), 3, 600);
  animateBar(document.getElementById('b1'), 100, 200);
  animateBar(document.getElementById('b2'), 77, 300);
  animateBar(document.getElementById('b3'), 13, 400);
  animateBar(document.getElementById('b4'), 10, 500);
  const weekCtx = document.getElementById('weekChart').getContext('2d');
  new Chart(weekCtx, {type:'bar',data:{labels:['Mon','Tue','Wed','Thu','Fri','Sat','Sun'],datasets:[{label:'Auto',data:[18,22,15,24,19,8,5],backgroundColor:'#00FFEE30',borderColor:'#00FFEE',borderWidth:1,borderRadius:4},{label:'Escalate',data:[2,3,1,4,2,0,1],backgroundColor:'#FF330030',borderColor:'#FF3300',borderWidth:1,borderRadius:4},{label:'Review',data:[1,2,3,3,1,0,0],backgroundColor:'#FF660030',borderColor:'#FF6600',borderWidth:1,borderRadius:4}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:'#555',font:{size:10}}}},scales:{x:{stacked:true,grid:{color:'#1a1a1a'},ticks:{color:'#555',font:{size:10}}},y:{stacked:true,grid:{color:'#1a1a1a'},ticks:{color:'#555',font:{size:10}}}}}});
  const donutCtx = document.getElementById('donutChart').getContext('2d');
  new Chart(donutCtx, {type:'doughnut',data:{labels:['Auto','Escalate','Review'],datasets:[{data:[24,4,3],backgroundColor:['#00FFEE40','#FF330040','#FF660040'],borderColor:['#00FFEE','#FF3300','#FF6600'],borderWidth:2}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'bottom',labels:{color:'#555',font:{size:10},padding:10}}},cutout:'70%'}});
});"""

new_load_block = """let weekChartInstance = null;
let donutChartInstance = null;

function initCharts() {
  const weekCtx = document.getElementById('weekChart').getContext('2d');
  weekChartInstance = new Chart(weekCtx, {type:'bar',data:{labels:['Mon','Tue','Wed','Thu','Fri','Sat','Sun'],datasets:[{label:'Auto',data:[0,0,0,0,0,0,0],backgroundColor:'#00FFEE30',borderColor:'#00FFEE',borderWidth:1,borderRadius:4},{label:'Escalate',data:[0,0,0,0,0,0,0],backgroundColor:'#FF330030',borderColor:'#FF3300',borderWidth:1,borderRadius:4},{label:'Review',data:[0,0,0,0,0,0,0],backgroundColor:'#FF660030',borderColor:'#FF6600',borderWidth:1,borderRadius:4}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:'#555',font:{size:10}}}},scales:{x:{stacked:true,grid:{color:'#1a1a1a'},ticks:{color:'#555',font:{size:10}}},y:{stacked:true,grid:{color:'#1a1a1a'},ticks:{color:'#555',font:{size:10}}}}}});
  const donutCtx = document.getElementById('donutChart').getContext('2d');
  donutChartInstance = new Chart(donutCtx, {type:'doughnut',data:{labels:['Auto','Escalate','Review'],datasets:[{data:[0,0,0],backgroundColor:['#00FFEE40','#FF330040','#FF660040'],borderColor:['#00FFEE','#FF3300','#FF6600'],borderWidth:2}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'bottom',labels:{color:'#555',font:{size:10},padding:10}}},cutout:'70%'}});
}

function updateCharts(alerts, stats) {
  if (!weekChartInstance || !donutChartInstance) return;
  const dayBuckets = [0,1,2,3,4,5,6].map(() => ({auto:0, escalate:0, review:0}));
  const now = new Date();
  const dayOfWeek = (now.getDay() + 6) % 7;
  const startOfWeek = new Date(now);
  startOfWeek.setDate(now.getDate() - dayOfWeek);
  startOfWeek.setHours(0,0,0,0);
  alerts.forEach(a => {
    const t = new Date(a.timestamp);
    if (t < startOfWeek) return;
    const diffDays = Math.floor((t - startOfWeek) / 86400000);
    if (diffDays < 0 || diffDays > 6) return;
    if (a.decision === "auto_resolve") dayBuckets[diffDays].auto++;
    else if (a.decision === "escalate") dayBuckets[diffDays].escalate++;
    else if (a.decision === "review") dayBuckets[diffDays].review++;
  });
  weekChartInstance.data.datasets[0].data = dayBuckets.map(d => d.auto);
  weekChartInstance.data.datasets[1].data = dayBuckets.map(d => d.escalate);
  weekChartInstance.data.datasets[2].data = dayBuckets.map(d => d.review);
  weekChartInstance.update();
  donutChartInstance.data.datasets[0].data = [stats.auto_resolved || 0, stats.escalated || 0, stats.review || 0];
  donutChartInstance.update();
}

window.addEventListener('load', () => {
  initCharts();
});"""

if old_load_block in c:
    c = c.replace(old_load_block, new_load_block)
    changes.append("Removed fake animation/charts, added real chart init + update functions")
else:
    print("NOT FOUND: fake animation/chart block")

# ---------------------------------------------------------------
# 2. Extend loadData() to also rebuild the other 5 pages + charts,
#    and fix the pre-existing auto_resolve/type-mapping bug
# ---------------------------------------------------------------
old_loaddata = """async function loadData() {
  try {
    const [stats, alerts] = await Promise.all([
      fetch("/api/stats").then(r => r.json()),
      fetch("/api/alerts").then(r => r.json())
    ]);

    // Update metrics
    document.getElementById("m1").textContent = stats.total || 0;
    document.getElementById("m2").textContent = stats.auto_resolved || 0;
    document.getElementById("m3").textContent = stats.escalated || 0;
    document.getElementById("m4").textContent = stats.review || 0;

    // Update bars
    const total = stats.total || 1;
    document.getElementById("b1").style.width = "100%";
    document.getElementById("b2").style.width = ((stats.auto_resolved/total)*100) + "%";
    document.getElementById("b3").style.width = ((stats.escalated/total)*100) + "%";
    document.getElementById("b4").style.width = ((stats.review/total)*100) + "%";

    // Update badge
    const badge = document.querySelector(".badge");
    if (badge) badge.textContent = stats.review || 0;

    // Update recent alerts section
    const recentContainer = document.querySelector("#page-dashboard .section:last-child");
    if (recentContainer && stats.recent && stats.recent.length > 0) {
      const header = recentContainer.querySelector(".section-header");
      recentContainer.innerHTML = "";
      recentContainer.appendChild(header);
      stats.recent.forEach(a => {
        const typeMap = { auto_resolve: "auto", escalate: "escalate", review: "review" };
        const labelMap = { auto_resolve: "AUTO", escalate: "ESCALATE", review: "REVIEW" };
        const iconMap = { auto_resolve: "ti-circle-check", escalate: "ti-alert-triangle", review: "ti-eye" };
        const t = typeMap[a.decision] || "review";
        const time = new Date(a.timestamp).toLocaleTimeString("en-US", {hour:"2-digit",minute:"2-digit"});
        const row = document.createElement("div");
        row.className = "alert-row";
        row.dataset.type = t;
        row.innerHTML = `
          <div class="icon-box ${t === "auto_resolve" ? "auto" : t === "escalate" ? "esc" : "rev"}">
            <i class="ti ${iconMap[a.decision] || "ti-eye"}"></i>
          </div>
          <div class="alert-info">
            <div class="alert-name">${a.ruleName} — ${a.processName}</div>
            <div class="alert-host">${a.hostname} · ${a.organization}</div>
          </div>
          <div class="dec ${t === "auto_resolve" ? "auto" : t === "escalate" ? "esc" : "rev"}">${labelMap[a.decision] || "REVIEW"}</div>
          <div class="alert-time">${time}</div>
          <button class="act-btn">${t === "auto_resolve" ? "View" : "Review"}</button>
        `;
        recentContainer.appendChild(row);
      });
    } else if (recentContainer && (!stats.recent || stats.recent.length === 0)) {
      const header = recentContainer.querySelector(".section-header");
      recentContainer.innerHTML = "";
      recentContainer.appendChild(header);
      const empty = document.createElement("div");
      empty.style.cssText = "padding:24px;color:#444;text-align:center;font-size:13px;";
      empty.textContent = "No alerts processed yet.";
      recentContainer.appendChild(empty);
    }
  } catch(e) {
    console.error("Failed to load data:", e);
  }
}"""

new_loaddata = """function escHtml(v) {
  return String(v == null ? "" : v).replace(/[&<>"\\']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",\'"\':"&quot;","\\'":"&#39;"}[c]));
}

function renderAlertRows(container, list, emptyText) {
  if (!container) return;
  const header = container.querySelector(".section-header");
  container.innerHTML = "";
  if (header) container.appendChild(header);
  if (!list || list.length === 0) {
    const empty = document.createElement("div");
    empty.style.cssText = "padding:24px;color:#444;text-align:center;font-size:13px;";
    empty.textContent = emptyText;
    container.appendChild(empty);
    return;
  }
  const cls = { auto_resolve: "auto", escalate: "esc", review: "rev" };
  const dataType = { auto_resolve: "auto", escalate: "escalate", review: "review" };
  const label = { auto_resolve: "AUTO", escalate: "ESCALATE", review: "REVIEW" };
  const icon = { auto_resolve: "ti-circle-check", escalate: "ti-alert-triangle", review: "ti-eye" };
  const btnText = { auto_resolve: "View", escalate: "Review", review: "Triage" };
  list.forEach(a => {
    const c = cls[a.decision] || "rev";
    const time = new Date(a.timestamp).toLocaleTimeString("en-US", {hour:"2-digit",minute:"2-digit"});
    const row = document.createElement("div");
    row.className = "alert-row";
    row.dataset.type = dataType[a.decision] || "review";
    row.innerHTML =
      \'<div class="icon-box \' + c + \'"><i class="ti \' + (icon[a.decision] || "ti-eye") + \'"></i></div>\' +
      \'<div class="alert-info"><div class="alert-name">\' + escHtml(a.ruleName) + " \\u2014 " + escHtml(a.processName) + \'</div>\' +
      \'<div class="alert-host">\' + escHtml(a.hostname) + " \\u00b7 " + escHtml(a.organization || "Unknown org") + \'</div></div>\' +
      \'<div class="dec \' + c + \'">\' + (label[a.decision] || "REVIEW") + \'</div>\' +
      \'<div class="alert-time">\' + time + \'</div>\' +
      \'<button class="act-btn">\' + (btnText[a.decision] || "Review") + \'</button>\';
    container.appendChild(row);
  });
}

function renderOrganizations(alerts) {
  const section = document.querySelector("#page-orgs .section");
  if (!section) return;
  const header = section.querySelector(".section-header");
  const todayStr = new Date().toDateString();
  const todayAlerts = alerts.filter(a => new Date(a.timestamp).toDateString() === todayStr);
  const orgCounts = {};
  todayAlerts.forEach(a => {
    const org = a.organization || "Unknown";
    orgCounts[org] = (orgCounts[org] || 0) + 1;
  });
  section.innerHTML = "";
  if (header) section.appendChild(header);
  const wrap = document.createElement("div");
  wrap.style.cssText = "padding:16px;display:flex;flex-direction:column;gap:12px;font-family:Arial,sans-serif";
  const orgNames = Object.keys(orgCounts);
  if (orgNames.length === 0) {
    const empty = document.createElement("div");
    empty.style.cssText = "padding:24px;color:#444;text-align:center;font-size:13px;";
    empty.textContent = "No organization activity yet.";
    wrap.appendChild(empty);
  } else {
    orgNames.forEach(org => {
      const row = document.createElement("div");
      row.style.cssText = "display:flex;align-items:center;gap:14px;padding:12px 16px;background:#1a1a1a;border-radius:8px";
      row.innerHTML =
        \'<div class="active-dot"></div>\' +
        \'<div style="flex:1"><div style="color:#fff;font-size:13px">\' + escHtml(org) + \'</div>\' +
        \'<div style="color:#444;font-size:11px;margin-top:2px">\' + orgCounts[org] + \' alert(s) today</div></div>\' +
        \'<div style="color:#00FFEE;font-size:11px">Active</div>\';
      wrap.appendChild(row);
    });
  }
  section.appendChild(wrap);
}

function renderReports(stats, alerts) {
  const section = document.querySelector("#page-reports .section");
  if (!section) return;
  const total = stats.total || 0;
  const autoN = stats.auto_resolved || 0;
  const escN = stats.escalated || 0;
  const revN = stats.review || 0;
  const pct = n => total > 0 ? Math.round((n/total)*100) : 0;
  const todayStr = new Date().toDateString();
  const todayAlerts = alerts.filter(a => new Date(a.timestamp).toDateString() === todayStr);
  const orgCounts = {};
  todayAlerts.forEach(a => {
    const org = a.organization || "Unknown";
    orgCounts[org] = (orgCounts[org] || 0) + 1;
  });
  const orgNames = Object.keys(orgCounts);
  const header = section.querySelector(".section-header");
  section.innerHTML = "";
  if (header) section.appendChild(header);
  const orgHtml = orgNames.length
    ? orgNames.map(o => \'<div>\' + escHtml(o) + \': <span style="color:#fff">\' + orgCounts[o] + \' alert(s)</span></div>\').join("")
    : \'<div style="color:#444">No organization activity today.</div>\';
  const body = document.createElement("div");
  body.style.cssText = "padding:24px;font-family:Arial,sans-serif;color:#555;font-size:13px;line-height:2";
  body.innerHTML =
    \'<div style="display:grid;grid-template-columns:1fr 1fr;gap:24px">\' +
      \'<div>\' +
        \'<div style="color:#fff;font-size:11px;letter-spacing:1px;margin-bottom:12px">SUMMARY (TODAY)</div>\' +
        \'<div>Total alerts processed: <span style="color:#fff">\' + total + \'</span></div>\' +
        \'<div>Auto-resolved by SENTINEL: <span style="color:#00FFEE">\' + autoN + \' (\' + pct(autoN) + \'%)</span></div>\' +
        \'<div>Escalated to IT: <span style="color:#FF3300">\' + escN + \' (\' + pct(escN) + \'%)</span></div>\' +
        \'<div>Pending human review: <span style="color:#FF6600">\' + revN + \' (\' + pct(revN) + \'%)</span></div>\' +
      \'</div>\' +
      \'<div>\' +
        \'<div style="color:#fff;font-size:11px;letter-spacing:1px;margin-bottom:12px">BY ORGANIZATION (TODAY)</div>\' +
        orgHtml +
      \'</div>\' +
    \'</div>\';
  section.appendChild(body);
}

async function loadData() {
  try {
    const [stats, alerts] = await Promise.all([
      fetch("/api/stats").then(r => r.json()),
      fetch("/api/alerts").then(r => r.json())
    ]);

    document.getElementById("m1").textContent = stats.total || 0;
    document.getElementById("m2").textContent = stats.auto_resolved || 0;
    document.getElementById("m3").textContent = stats.escalated || 0;
    document.getElementById("m4").textContent = stats.review || 0;

    const total = stats.total || 1;
    document.getElementById("b1").style.width = "100%";
    document.getElementById("b2").style.width = ((stats.auto_resolved/total)*100) + "%";
    document.getElementById("b3").style.width = ((stats.escalated/total)*100) + "%";
    document.getElementById("b4").style.width = ((stats.review/total)*100) + "%";

    const badge = document.querySelector(".badge");
    if (badge) badge.textContent = stats.review || 0;

    renderAlertRows(document.querySelector("#page-dashboard .section:last-child"), stats.recent, "No alerts processed yet.");

    const pending = alerts.filter(a => a.decision === "escalate" || a.decision === "review");
    renderAlertRows(document.querySelector("#page-alerts .section"), pending, "No pending alerts.");

    const autoResolved = alerts.filter(a => a.decision === "auto_resolve");
    const todayStr = new Date().toDateString();
    const autoToday = autoResolved.filter(a => new Date(a.timestamp).toDateString() === todayStr).length;
    const autoHeader = document.querySelector("#page-auto .section-header span");
    if (autoHeader) autoHeader.textContent = autoToday + " today";
    renderAlertRows(document.querySelector("#page-auto .section"), autoResolved, "No alerts auto-resolved yet.");

    renderOrganizations(alerts);
    renderReports(stats, alerts);
    updateCharts(alerts, stats);
  } catch(e) {
    console.error("Failed to load data:", e);
  }
}"""

if old_loaddata in c:
    c = c.replace(old_loaddata, new_loaddata)
    changes.append("Extended loadData() to rebuild all pages + charts from real data, fixed pre-existing auto_resolve type-mapping bug")
else:
    print("NOT FOUND: loadData() block")

with open("public/dashboard.html", "w", encoding="utf-8") as f:
    f.write(c)

print("Applied:", changes)
