with open("public/dashboard.html", encoding="utf-8") as f:
    html = f.read()

# Add fetch script before </body>
fetch_script = """
<script>
async function loadData() {
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
}

loadData();
setInterval(loadData, 30000);
</script>
"""

html = html.replace("</body>", fetch_script + "\n</body>")

with open("public/dashboard.html", "w", encoding="utf-8") as f:
    f.write(html)
print("Done")
