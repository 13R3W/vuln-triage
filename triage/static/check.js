// 「自分の環境をチェック」の画面。ファイルは見る人のブラウザの中で読むだけで、どこにも送らない。
// 部品の名前と版だけを OSV.dev に問い合わせる（見る人の通信で行う）。
(function () {
  "use strict";
  var Core = window.CheckCore;
  var box = document.getElementById("check");
  if (!box || !Core) return;

  var OSV = box.dataset.osv || "https://api.osv.dev";
  var ROOT = box.dataset.root || "";
  var BATCH = 1000;        // querybatch 1回あたりの件数（OSV の上限）
  var PARALLEL = 6;        // 詳細の同時取得数
  var MAX_SHOWN = 500;     // 画面に出す最大件数（CSV には全部入る）

  var fileInput = box.querySelector("input[type=file]");
  var drop = box.querySelector(".drop");
  var paste = box.querySelector("textarea");
  var runBtn = box.querySelector("button.run");
  var status = box.querySelector(".status");
  var out = box.querySelector(".results");
  var files = [];

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function pct(v) { return v == null ? "—" : (v * 100).toFixed(2) + "%"; }
  function say(msg, err) { status.textContent = msg; status.className = "status" + (err ? " err" : ""); }

  function setFiles(list) {
    files = Array.prototype.slice.call(list || []);
    drop.querySelector(".names").textContent = files.length
      ? files.map(function (f) { return f.name; }).join("、") : "まだ選ばれていません";
  }
  fileInput.addEventListener("change", function () { setFiles(fileInput.files); });
  ["dragenter", "dragover"].forEach(function (t) {
    drop.addEventListener(t, function (e) { e.preventDefault(); drop.classList.add("over"); });
  });
  ["dragleave", "drop"].forEach(function (t) {
    drop.addEventListener(t, function (e) { e.preventDefault(); drop.classList.remove("over"); });
  });
  drop.addEventListener("drop", function (e) { setFiles(e.dataTransfer.files); });

  function readText(file) {
    return new Promise(function (ok, ng) {
      var r = new FileReader();
      r.onload = function () { ok(String(r.result)); };
      r.onerror = function () { ng(r.error); };
      r.readAsText(file);
    });
  }

  function getJson(url, body) {
    var opt = body ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : {};
    return fetch(url, opt).then(function (res) {
      if (!res.ok) throw new Error(url + "：HTTP " + res.status);
      return res.json();
    });
  }

  // 同時に n 件ずつ処理する
  function pool(items, n, fn) {
    var i = 0, results = new Array(items.length);
    function next() {
      if (i >= items.length) return Promise.resolve();
      var k = i++;
      return fn(items[k]).then(function (v) { results[k] = v; }, function () { results[k] = null; }).then(next);
    }
    var workers = [];
    for (var w = 0; w < Math.min(n, items.length); w++) workers.push(next());
    return Promise.all(workers).then(function () { return results; });
  }

  // 部品の一覧 → OSV.dev で当てはまる脆弱性を調べる
  function queryOsv(pkgs) {
    var batches = [];
    for (var i = 0; i < pkgs.length; i += BATCH) batches.push(pkgs.slice(i, i + BATCH));
    var hits = [];  // [{ pkg, id }]
    return batches.reduce(function (p, batch) {
      return p.then(function () {
        return getJson(OSV + "/v1/querybatch", { queries: batch.map(Core.osvQuery) }).then(function (data) {
          (data.results || []).forEach(function (r, k) {
            (r.vulns || []).forEach(function (v) { hits.push({ pkg: batch[k], id: v.id }); });
          });
        });
      });
    }, Promise.resolve()).then(function () {
      var ids = [];
      hits.forEach(function (h) { if (ids.indexOf(h.id) < 0) ids.push(h.id); });
      say("OSV.dev から脆弱性の詳細を取得しています（" + ids.length + "件）…");
      return pool(ids, PARALLEL, function (id) { return getJson(OSV + "/v1/vulns/" + encodeURIComponent(id)); })
        .then(function (details) {
          var byId = {};
          ids.forEach(function (id, k) { byId[id] = details[k] || { id: id }; });
          return hits.map(function (h) {
            var v = byId[h.id];
            return { id: Core.cveOf(v), pkg: h.pkg, vuln: v };
          });
        });
    });
  }

  // 全CVE索引のうち必要な年だけ読む
  function loadIndex(ids) {
    return Promise.all([getJson(ROOT + "data/index/meta.json"), getJson(ROOT + "data/index/kev.json")])
      .then(function (r) {
        var meta = r[0], kev = r[1], years = {};
        ids.forEach(function (id) {
          var m = /^CVE-(\d{4})-/.exec(id);
          if (m && meta.years.indexOf(m[1]) >= 0) years[m[1]] = true;
        });
        var list = Object.keys(years);
        return Promise.all(list.map(function (y) { return getJson(ROOT + "data/index/" + y + ".json"); }))
          .then(function (parts) {
            var index = {};
            list.forEach(function (y, k) { index[y] = parts[k]; });
            return { meta: meta, kev: kev, index: index };
          });
      });
  }

  function render(results, info) {
    var s = Core.summarize(results);
    var tiles = [[s.total, "見つかった件数"], [s.S, '<span class="tier tier-S">S</span>ティア'],
                 [s.A, '<span class="tier tier-A">A</span>ティア'], [s.B, '<span class="tier tier-B">B</span>ティア'],
                 [s.C, '<span class="tier tier-C">C</span>ティア'], [s.kev, "KEV掲載"], [s.fixable, "修正版あり"]];
    var html = '<div class="summary-row check-tiles">' + tiles.map(function (t) {
      return '<div class="stat"><b>' + t[0] + "</b><span>" + t[1] + "</span></div>";
    }).join("") + "</div>";
    html += '<p class="lead">' + esc(info) + "</p>";
    if (!results.length) {
      out.innerHTML = html + '<p class="empty">当てはまる脆弱性は見つかりませんでした。</p>';
      return;
    }
    html += '<p><button type="button" class="csv">結果をCSVで保存</button></p>';
    html += '<div class="tablewrap"><table><thead><tr><th>ティア</th><th>CVE</th><th>該当する部品・対策</th>' +
      '<th class="num">EPSS</th><th>KEV追加</th><th>PoC初出</th><th>概要</th></tr></thead><tbody>';
    results.slice(0, MAX_SHOWN).forEach(function (r) {
      var idHtml = r.isCve
        ? '<a class="cve" href="https://nvd.nist.gov/vuln/detail/' + esc(r.id) + '" rel="noopener">' + esc(r.id) + "</a>"
        : '<a class="cve" href="https://osv.dev/vulnerability/' + esc(r.id) + '" rel="noopener">' + esc(r.id) + '</a> <span class="flag">CVE番号なし</span>';
      var todo = r.advice.map(esc).join("<br>");
      if (r.kevAction) {
        todo += (todo ? "<br>" : "") + '<span class="kev-act">KEV：期限 <span class="nw">' + esc(r.kevDue || "—") +
          "</span>　" + esc(r.kevAction) + "</span>";
      }
      html += '<tr><td><span class="tier tier-' + r.tier + '">' + r.tier + "</span></td><td class=id>" + idHtml +
        "</td><td>" + (todo || "—") + "</td><td class=num>" + pct(r.epss) +
        '</td><td><span class="nw">' + esc(r.kev || "—") + '</span></td><td><span class="nw">' + esc(r.poc || "—") +
        "</span>" + (r.repos ? "（" + r.repos + "件）" : "") + "</td><td class=sum>" + esc(r.summary) + "</td></tr>";
    });
    html += "</tbody></table></div>";
    if (results.length > MAX_SHOWN) {
      html += '<p class="lead">画面には上位' + MAX_SHOWN + "件だけ出しています。全件はCSVに入っています。</p>";
    }
    out.innerHTML = html;
    out.querySelector("button.csv").addEventListener("click", function () {
      var blob = new Blob([Core.toCsv(results)], { type: "text/csv" });
      var a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "vuln-check.csv";
      document.body.appendChild(a);
      a.click();
      setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
    });
  }

  runBtn.addEventListener("click", function () {
    var inputs = files.map(function (f) { return readText(f).then(function (t) { return { name: f.name, text: t }; }); });
    if (paste.value.trim()) inputs.push(Promise.resolve({ name: "", text: paste.value }));
    if (!inputs.length) { say("ファイルを選ぶか、内容を貼り付けてください。", true); return; }
    runBtn.disabled = true;
    out.innerHTML = "";
    say("ファイルを読んでいます…");
    var pkgs = [], cves = [], formats = [], osvError = null;
    Promise.all(inputs).then(function (list) {
      list.forEach(function (f) {
        var r = Core.parseFile(f.name, f.text);
        formats.push((f.name || "貼り付けた内容") + "：" + r.format +
          (r.packages.length ? "（部品 " + r.packages.length + "件）" : r.cves.length ? "（CVE " + r.cves.length + "件）" : ""));
        pkgs = pkgs.concat(r.packages);
        cves = cves.concat(r.cves);
      });
      if (!pkgs.length && !cves.length) throw new Error("部品の一覧も CVE 番号も見つかりませんでした。対応している形式か確認してください。");
      if (!pkgs.length) return [];
      say("部品 " + pkgs.length + " 件を OSV.dev に問い合わせています…");
      return queryOsv(pkgs).catch(function (e) { osvError = e; return []; });
    }).then(function (findings) {
      say("優先度を計算しています…");
      var ids = cves.concat(findings.map(function (f) { return f.id; }));
      return loadIndex(ids).then(function (ix) {
        var results = Core.buildResults(findings, cves, ix.index, ix.kev, ix.meta.thresholds);
        render(results, "読み込んだファイル：" + formats.join("／") + "。優先度は " + ix.meta.generated_at +
          "（日本時間）時点のデータ（EPSS " + ix.meta.epss_date + "）で判定しています。");
        if (osvError) say("OSV.dev に接続できなかったため、部品の一覧は照合できませんでした（" + osvError.message + "）。", true);
        else say("完了しました。");
      });
    }).catch(function (e) {
      say(e.message || String(e), true);
    }).then(function () { runBtn.disabled = false; });
  });
})();
