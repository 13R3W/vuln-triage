// タブ切替、期間のプルダウン、全件表の検索・絞り込み・ページ送り（外部ライブラリなし）
(function () {
  document.documentElement.classList.add("js");

  // 選んでいるタブは URL の「#tab=poc」に残す。日・週・月を切り替えても同じタブを開くため。
  // （「#poc」のように要素の id と同じにすると、開いたときにその位置まで飛んでしまうので別の形にする）
  function currentTab() {
    var m = /^#(?:tab=)?([\w-]+)$/.exec(location.hash);
    return m ? m[1] : "";
  }
  function withTab(url) {
    var tab = currentTab();
    return tab ? url.split("#")[0] + "#tab=" + tab : url;
  }

  // 期間のプルダウン：選んだらそのページへ移動（今のタブのまま）
  document.querySelectorAll("select[data-nav]").forEach(function (sel) {
    sel.addEventListener("change", function () { location.href = withTab(sel.value); });
  });
  // 日次・週次・月次のボタン：今のタブのまま移動
  document.querySelectorAll("a[data-keep-tab]").forEach(function (a) {
    a.addEventListener("click", function () { a.href = withTab(a.href); });
  });

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
        try { history.replaceState(null, "", "#tab=" + b.dataset.tab); } catch (e) {}
      });
    });
    var tab = currentTab();
    show(Array.prototype.some.call(buttons, function (b) { return b.dataset.tab === tab; }) ? tab : buttons[0].dataset.tab);
  });

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function nw(s) { return '<span class="nw">' + esc(s) + "</span>"; }
  function pct(v) { return v == null ? "—" : (v * 100).toFixed(2) + "%"; }
  function delta(v) {
    if (v == null) return "—";
    var pt = v * 100;
    if (Math.abs(pt) < 0.005) return "±0";
    return '<span class="' + (pt > 0 ? "up" : "down") + '">' + (pt > 0 ? "+" : "") + pt.toFixed(2) + "pt</span>";
  }
  function num(n) { return n.toLocaleString("ja-JP"); }

  // ページ番号の並び：1 … 4 5 [6] 7 8 … 165
  function pageList(cur, last) {
    var out = [], from = Math.max(2, cur - 2), to = Math.min(last - 1, cur + 2);
    out.push(1);
    if (from > 2) out.push("…");
    for (var i = from; i <= to; i++) out.push(i);
    if (to < last - 1) out.push("…");
    if (last > 1) out.push(last);
    return out;
  }

  var PER_PAGE = 100;

  document.querySelectorAll("[data-fulltable]").forEach(function (box) {
    var url = box.dataset.fulltable;
    var tbody = box.querySelector("tbody");
    var table = box.querySelector(".tablewrap");
    var q = box.querySelector("input[type=search]");
    var tiers = box.querySelectorAll("input[name=tier]");
    var jvnOnly = box.querySelector("input[name=jvn]");
    var pagers = box.querySelectorAll(".pager");
    var rows = [], hit = [], page = 1, loaded = false;

    function filter() {
      var words = q.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
      var allowed = {};
      tiers.forEach(function (t) { allowed[t.value] = t.checked; });
      hit = rows.filter(function (r) {
        if (!allowed[r.tier]) return false;
        if (jvnOnly && jvnOnly.checked && r.jvn !== false) return false;
        if (!words.length) return true;
        var hay = (r.id + " " + (r.summary || "") + " " + (r.cwe || []).join(" ")).toLowerCase();
        return words.every(function (w) { return hay.indexOf(w) >= 0; });
      });
      page = 1;
    }

    function renderPager() {
      var last = Math.max(1, Math.ceil(hit.length / PER_PAGE));
      var from = hit.length ? (page - 1) * PER_PAGE + 1 : 0;
      var to = Math.min(page * PER_PAGE, hit.length);
      var html = '<span class="range">全' + num(hit.length) + "件" + (hit.length ? "中 " + num(from) + "〜" + num(to) + "件" : "") + "</span>";
      if (last > 1) {
        html += '<span class="pages">';
        html += '<button type="button" data-page="' + (page - 1) + '"' + (page === 1 ? " disabled" : "") + ">« 前へ</button>";
        pageList(page, last).forEach(function (p) {
          html += p === "…" ? '<span class="gap">…</span>'
            : '<button type="button" data-page="' + p + '"' + (p === page ? ' class="on" aria-current="page"' : "") + ">" + p + "</button>";
        });
        html += '<button type="button" data-page="' + (page + 1) + '"' + (page === last ? " disabled" : "") + ">次へ »</button>";
        html += "</span>";
      }
      pagers.forEach(function (p) { p.innerHTML = html; });
    }

    function renderRows() {
      var start = (page - 1) * PER_PAGE;
      tbody.innerHTML = hit.slice(start, start + PER_PAGE).map(function (r) {
        var flags = r.jvn === false ? ' <span class="flag">JVN未掲載</span>' : "";
        return "<tr><td class=num>" + r.rank + '</td><td><span class="tier tier-' + r.tier + '">' + r.tier +
          '</span></td><td class=id><a class="cve" href="https://nvd.nist.gov/vuln/detail/' + esc(r.id) + '" rel="noopener">' + esc(r.id) +
          "</a>" + flags + "</td><td class=num>" + pct(r.epss) + "</td><td class=num>" + delta(r.epss_delta) +
          "</td><td class=num>" + (r.cvss == null ? "—" : esc(r.cvss)) + "</td><td>" + ((r.cwe || []).map(nw).join(" ") || "—") +
          "</td><td>" + nw(r.kev || "—") + "</td><td>" + nw(r.poc || "—") + "</td><td>" + nw(r.published || "") +
          "</td><td class=sum>" + esc(r.summary) + "</td></tr>";
      }).join("") || '<tr><td colspan="11" class="empty">' + esc(rows.length ? "該当なし" : (box.dataset.empty || "該当なし")) + "</td></tr>";
    }

    function render() {
      if (!loaded) return;
      renderPager();
      renderRows();
    }

    pagers.forEach(function (p, i) {
      p.addEventListener("click", function (ev) {
        var b = ev.target.closest("button[data-page]");
        if (!b || b.disabled) return;
        page = parseInt(b.dataset.page, 10);
        render();
        // 下側で切り替えたときは表の先頭に戻る
        if (i === pagers.length - 1) pagers[0].scrollIntoView({ block: "start" });
      });
    });

    fetch(url).then(function (res) { return res.json(); }).then(function (data) {
      rows = data.map(function (r, i) { r.rank = i + 1; return r; });
      loaded = true;
      filter();
      render();
    }).catch(function () {
      pagers[0].textContent = "全件データを読み込めませんでした";
    });
    function refilter() { filter(); render(); }
    q.addEventListener("input", refilter);
    tiers.forEach(function (t) { t.addEventListener("change", refilter); });
    if (jvnOnly) jvnOnly.addEventListener("change", refilter);
  });
})();
