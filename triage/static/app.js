// タブ切替と、全件表の検索・絞り込み（外部ライブラリなし）
(function () {
  document.documentElement.classList.add("js");

  document.querySelectorAll("[data-tabs]").forEach(function (box) {
    var buttons = box.querySelectorAll(".tabs button");
    function show(id) {
      buttons.forEach(function (b) {
        var on = b.dataset.tab === id;
        b.setAttribute("aria-selected", on ? "true" : "false");
        document.getElementById(b.dataset.tab).hidden = !on;
      });
    }
    buttons.forEach(function (b) {
      b.addEventListener("click", function () {
        show(b.dataset.tab);
        // 読み込み時に書き換えるとその位置まで飛ぶので、クリック時だけ URL に残す
        try { history.replaceState(null, "", "#" + b.dataset.tab); } catch (e) {}
      });
    });
    var hash = location.hash.slice(1);
    show(Array.prototype.some.call(buttons, function (b) { return b.dataset.tab === hash; }) ? hash : buttons[0].dataset.tab);
  });

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function pct(v) { return v == null ? "—" : (v * 100).toFixed(2) + "%"; }
  function delta(v) {
    if (v == null) return "—";
    var pt = v * 100;
    if (Math.abs(pt) < 0.005) return "±0";
    return '<span class="' + (pt > 0 ? "up" : "down") + '">' + (pt > 0 ? "+" : "") + pt.toFixed(2) + "pt</span>";
  }

  document.querySelectorAll("[data-fulltable]").forEach(function (box) {
    var url = box.dataset.fulltable;
    var tbody = box.querySelector("tbody");
    var q = box.querySelector("input[type=search]");
    var tiers = box.querySelectorAll("input[name=tier]");
    var jvnOnly = box.querySelector("input[name=jvn]");
    var countEl = box.querySelector(".count");
    var moreBtn = box.querySelector(".more button");
    var rows = [], limit = 100;

    function render() {
      var words = q.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
      var allowed = {};
      tiers.forEach(function (t) { allowed[t.value] = t.checked; });
      var hit = rows.filter(function (r) {
        if (!allowed[r.tier]) return false;
        if (jvnOnly && jvnOnly.checked && r.jvn !== false) return false;
        if (!words.length) return true;
        var hay = (r.id + " " + (r.summary || "") + " " + (r.cwe || []).join(" ")).toLowerCase();
        return words.every(function (w) { return hay.indexOf(w) >= 0; });
      });
      countEl.textContent = hit.length + " 件";
      tbody.innerHTML = hit.slice(0, limit).map(function (r) {
        var flags = r.jvn === false ? ' <span class="flag">JVN未掲載</span>' : "";
        return "<tr><td class=num>" + r.rank + '</td><td><span class="tier tier-' + r.tier + '">' + r.tier +
          '</span></td><td class=id><a href="https://nvd.nist.gov/vuln/detail/' + esc(r.id) + '" rel="noopener">' + esc(r.id) +
          "</a>" + flags + "</td><td class=num>" + pct(r.epss) + "</td><td class=num>" + delta(r.epss_delta) +
          "</td><td class=num>" + (r.cvss == null ? "—" : esc(r.cvss)) + "</td><td>" + esc((r.cwe || []).join(", ") || "—") +
          "</td><td>" + esc(r.kev || "—") + "</td><td>" + esc(r.poc || "—") + "</td><td>" + esc(r.published || "") +
          "</td><td class=sum>" + esc(r.summary) + "</td></tr>";
      }).join("");
      moreBtn.parentNode.hidden = hit.length <= limit;
    }

    fetch(url).then(function (res) { return res.json(); }).then(function (data) {
      rows = data.map(function (r, i) { r.rank = i + 1; return r; });
      render();
    }).catch(function () {
      countEl.textContent = "全件データを読み込めませんでした";
    });
    q.addEventListener("input", function () { limit = 100; render(); });
    tiers.forEach(function (t) { t.addEventListener("change", function () { limit = 100; render(); }); });
    if (jvnOnly) jvnOnly.addEventListener("change", function () { limit = 100; render(); });
    moreBtn.addEventListener("click", function () { limit += 200; render(); });
  });
})();
