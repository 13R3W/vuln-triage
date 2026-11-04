// 「自分の環境をチェック」の中身（画面に関係しない部分）。
// ブラウザでは window.CheckCore として、テスト（Node）では require() で使う。
// ここでは外部に通信しない。通信（OSV.dev・索引の読み込み）は check.js が行う。
(function (root) {
  "use strict";

  var TIER_ORDER = { S: 0, A: 1, B: 2, C: 3 };

  // ---- 部品の一覧を読む（どれも {ecosystem, name, version} の配列を返す） ----

  function uniq(pkgs) {
    var seen = {}, out = [];
    pkgs.forEach(function (p) {
      if (!p || !p.name || !p.version) return;
      var key = p.ecosystem + "|" + p.name + "|" + p.version + "|" + (p.purl || "");
      if (!seen[key]) { seen[key] = true; out.push(p); }
    });
    return out;
  }

  function stripV(v) { return String(v).trim().replace(/^v(?=\d)/, ""); }

  // npm：package-lock.json（v1〜v3）
  function parsePackageLock(obj) {
    var out = [];
    if (obj.packages) {
      Object.keys(obj.packages).forEach(function (key) {
        var p = obj.packages[key];
        if (!key || !p || p.link || !p.version) return;
        var name = p.name || key.split("node_modules/").pop();
        out.push({ ecosystem: "npm", name: name, version: p.version });
      });
    }
    (function walk(deps) {
      if (!deps) return;
      Object.keys(deps).forEach(function (name) {
        var d = deps[name];
        if (d && d.version && !/^(file|link|git|github):/.test(d.version)) {
          out.push({ ecosystem: "npm", name: name, version: d.version });
        }
        walk(d && d.dependencies);
      });
    })(obj.packages ? null : obj.dependencies);
    return out;
  }

  // Python：requirements.txt（== で版を固定している行だけ）
  function parseRequirements(text) {
    var out = [];
    text.split(/\r?\n/).forEach(function (line) {
      line = line.replace(/#.*/, "").trim();
      var m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;,\\]+)/.exec(line);
      if (m) out.push({ ecosystem: "PyPI", name: m[1], version: m[2] });
    });
    return out;
  }

  // TOML の [[package]] 形式（poetry.lock・Cargo.lock）
  function parseTomlPackages(text, ecosystem) {
    var out = [];
    text.split(/\n(?=\[\[package\]\])/).forEach(function (block) {
      if (!/^\[\[package\]\]/.test(block)) return;
      var name = /^name\s*=\s*"([^"]+)"/m.exec(block);
      var version = /^version\s*=\s*"([^"]+)"/m.exec(block);
      if (name && version) out.push({ ecosystem: ecosystem, name: name[1], version: version[1] });
    });
    return out;
  }

  // Python：Pipfile.lock
  function parsePipfileLock(obj) {
    var out = [];
    ["default", "develop"].forEach(function (k) {
      var deps = obj[k] || {};
      Object.keys(deps).forEach(function (name) {
        var v = deps[name] && deps[name].version;
        if (v) out.push({ ecosystem: "PyPI", name: name, version: v.replace(/^==/, "") });
      });
    });
    return out;
  }

  // Go：go.sum・go.mod
  function parseGoSum(text) {
    var out = [];
    text.split(/\r?\n/).forEach(function (line) {
      var m = /^(\S+)\s+(v[^\s/]+)(?:\/go\.mod)?\s+h1:/.exec(line.trim());
      if (m) out.push({ ecosystem: "Go", name: m[1], version: stripV(m[2]) });
    });
    return out;
  }
  function parseGoMod(text) {
    var out = [], inBlock = false;
    text.split(/\r?\n/).forEach(function (raw) {
      var line = raw.replace(/\/\/.*/, "").trim();
      if (/^require\s*\($/.test(line)) { inBlock = true; return; }
      if (inBlock && line === ")") { inBlock = false; return; }
      var m = inBlock ? /^(\S+)\s+(v\S+)$/.exec(line) : /^require\s+(\S+)\s+(v\S+)$/.exec(line);
      if (m) out.push({ ecosystem: "Go", name: m[1], version: stripV(m[2]) });
    });
    return out;
  }

  // Java：pom.xml（版が直接書いてある dependency だけ）
  function parsePom(text) {
    var out = [];
    var re = /<dependency>([\s\S]*?)<\/dependency>/g, m;
    function tag(block, name) {
      var t = new RegExp("<" + name + ">\\s*([^<]+?)\\s*</" + name + ">").exec(block);
      return t ? t[1] : "";
    }
    while ((m = re.exec(text))) {
      var g = tag(m[1], "groupId"), a = tag(m[1], "artifactId"), v = tag(m[1], "version");
      if (g && a && v && v.indexOf("${") < 0) out.push({ ecosystem: "Maven", name: g + ":" + a, version: v });
    }
    return out;
  }

  // Ruby：Gemfile.lock（specs: の下の「名前 (版)」）
  function parseGemfileLock(text) {
    var out = [];
    text.split(/\r?\n/).forEach(function (line) {
      var m = /^ {4}([A-Za-z0-9_.-]+) \(([^)\s]+)\)$/.exec(line);
      if (m) out.push({ ecosystem: "RubyGems", name: m[1], version: m[2].replace(/-[a-z0-9_-]+$/, "") });
    });
    return out;
  }

  // PHP：composer.lock
  function parseComposerLock(obj) {
    return (obj.packages || []).concat(obj["packages-dev"] || []).map(function (p) {
      return { ecosystem: "Packagist", name: p.name, version: stripV(p.version || "") };
    });
  }

  // purl（pkg:npm/%40scope/name@1.2.3 など）→ 部品
  var PURL_ECOSYSTEM = {
    npm: "npm", pypi: "PyPI", maven: "Maven", golang: "Go", gem: "RubyGems", composer: "Packagist",
    cargo: "crates.io", nuget: "NuGet", pub: "Pub", hex: "Hex", swift: "SwiftURL"
  };
  function parsePurl(purl) {
    var m = /^pkg:([^/]+)\/(.+?)@([^?#]+)/.exec(purl || "");
    if (!m) return null;
    var type = m[1].toLowerCase(), path = decodeURIComponent(m[2]), version = decodeURIComponent(m[3]);
    var eco = PURL_ECOSYSTEM[type];
    if (!eco) return { ecosystem: "", name: path, version: version, purl: purl.replace(/[?#].*$/, "") };
    var name = path;
    if (type === "maven") name = path.replace("/", ":");
    if (type === "pypi") name = path.toLowerCase();
    if (type === "golang") version = stripV(version);
    return { ecosystem: eco, name: name, version: version };
  }

  // SBOM：CycloneDX JSON・SPDX JSON
  function parseCycloneDx(obj) {
    var out = [];
    (function walk(list) {
      (list || []).forEach(function (c) {
        var p = parsePurl(c.purl);
        if (p) out.push(p);
        walk(c.components);
      });
    })(obj.components);
    return out;
  }
  function parseSpdx(obj) {
    var out = [];
    (obj.packages || []).forEach(function (pkg) {
      (pkg.externalRefs || []).forEach(function (r) {
        if (/purl/i.test(r.referenceType || "")) {
          var p = parsePurl(r.referenceLocator);
          if (p) out.push(p);
        }
      });
    });
    return out;
  }

  function tryJson(text) {
    try { return JSON.parse(text); } catch (e) { return null; }
  }

  // ファイル名と中身から種類を見分けて読む。
  // 戻り値：{ format: "形式名", packages: [...], cves: [...] }
  function parseFile(filename, text) {
    var base = String(filename || "").split(/[\\/]/).pop().toLowerCase();
    var obj = /^\s*[{\[]/.test(text) ? tryJson(text) : null;
    var format = "", pkgs = [];
    if (obj && !Array.isArray(obj)) {
      if (obj.bomFormat === "CycloneDX") { format = "CycloneDX（SBOM）"; pkgs = parseCycloneDx(obj); }
      else if (obj.spdxVersion) { format = "SPDX（SBOM）"; pkgs = parseSpdx(obj); }
      else if (obj.lockfileVersion !== undefined || base === "package-lock.json") { format = "package-lock.json（npm）"; pkgs = parsePackageLock(obj); }
      else if (obj._meta && (obj["default"] || obj.develop)) { format = "Pipfile.lock（Python）"; pkgs = parsePipfileLock(obj); }
      else if (base === "composer.lock" || (obj.packages && obj["content-hash"])) { format = "composer.lock（PHP）"; pkgs = parseComposerLock(obj); }
    } else if (base === "go.sum" || /\sh1:[A-Za-z0-9+/=]+\s*$/m.test(text)) { format = "go.sum（Go）"; pkgs = parseGoSum(text); }
    else if (base === "go.mod" || /^module\s+\S+/m.test(text) && /^go\s+\d/m.test(text)) { format = "go.mod（Go）"; pkgs = parseGoMod(text); }
    else if (base === "pom.xml" || /<project[\s>]/.test(text) && /<dependency>/.test(text)) { format = "pom.xml（Java）"; pkgs = parsePom(text); }
    else if (base === "gemfile.lock" || /^GEM\s*$/m.test(text) && /^\s+specs:\s*$/m.test(text)) { format = "Gemfile.lock（Ruby）"; pkgs = parseGemfileLock(text); }
    else if (base === "cargo.lock") { format = "Cargo.lock（Rust）"; pkgs = parseTomlPackages(text, "crates.io"); }
    else if (base === "poetry.lock") { format = "poetry.lock（Python）"; pkgs = parseTomlPackages(text, "PyPI"); }
    else if (/requirements.*\.txt$/.test(base) || /^[A-Za-z0-9][A-Za-z0-9._-]*(\[[^\]]*\])?\s*==\s*\S+/m.test(text) && !/CVE-\d{4}-\d{4,}/i.test(text)) {
      format = "requirements.txt（Python）"; pkgs = parseRequirements(text);
    }
    pkgs = uniq(pkgs);
    if (pkgs.length) return { format: format, packages: pkgs, cves: [] };
    // 部品の一覧として読めなければ、中に書いてある CVE 番号を全部拾う（スキャナーの結果など）
    var cves = extractCves(text);
    return { format: cves.length ? "CVE番号の一覧" : (format || "不明"), packages: [], cves: cves };
  }

  function extractCves(text) {
    var seen = {}, out = [], re = /CVE-(\d{4})-(\d{4,})/gi, m;
    while ((m = re.exec(text || ""))) {
      var id = "CVE-" + m[1] + "-" + m[2];
      if (!seen[id]) { seen[id] = true; out.push(id); }
    }
    return out;
  }

  // ---- ティア（triage/tiering.py と同じ規則） ----

  // row：索引の値 [EPSS, KEV追加日, PoC初出日, PoCリポジトリ数]（無い CVE は undefined）
  function tierOf(row, th) {
    row = row || [];
    var epss = row[0], kev = row[1], poc = row[2];
    // PoC は EPSS スコアがある（＝実在する）CVE だけ採用する
    var hasPoc = !!poc && epss !== null && epss !== undefined;
    var score = epss || 0;
    if (kev) return "S";
    if (hasPoc && score >= th.a_epss) return "A";
    if (hasPoc || score >= th.b_epss) return "B";
    return "C";
  }

  function indexRow(index, cve) {
    var m = /^CVE-(\d{4})-(\d+)$/.exec(cve || "");
    if (!m || !index[m[1]]) return undefined;
    return index[m[1]][m[2]];
  }

  // ---- 対策（OSV の「直った版」から作る） ----

  function normName(eco, name) {
    name = String(name || "");
    if (eco === "PyPI") return name.toLowerCase().replace(/[-_.]+/g, "-");
    if (eco === "npm" || eco === "Packagist" || eco === "crates.io" || eco === "NuGet") return name.toLowerCase();
    return name;
  }

  // 数字の並びで比べる簡易な版の比較（1.10.0 > 1.9.2）。各言語の細かい規則までは見ない
  function cmpVersion(a, b) {
    var pa = String(a).split(/[^0-9]+/).filter(Boolean).map(Number);
    var pb = String(b).split(/[^0-9]+/).filter(Boolean).map(Number);
    for (var i = 0; i < Math.max(pa.length, pb.length); i++) {
      var x = pa[i] || 0, y = pb[i] || 0;
      if (x !== y) return x < y ? -1 : 1;
    }
    return 0;
  }

  // OSV の脆弱性1件から、その部品の「直った版」を全部集める
  function fixedVersions(vuln, pkg) {
    var out = [];
    (vuln.affected || []).forEach(function (a) {
      var p = a.package || {};
      if (pkg.ecosystem && (p.ecosystem || "").split(":")[0] !== pkg.ecosystem) return;
      if (pkg.ecosystem && normName(pkg.ecosystem, p.name) !== normName(pkg.ecosystem, pkg.name)) return;
      (a.ranges || []).forEach(function (r) {
        if (r.type === "GIT") return;
        (r.events || []).forEach(function (ev) {
          if (ev.fixed && out.indexOf(ev.fixed) < 0) out.push(ev.fixed);
        });
      });
    });
    return out.sort(cmpVersion);
  }

  // 今の版より新しい「直った版」のうち一番小さいもの（無ければ一番大きいもの）
  function pickFix(fixed, current) {
    if (!fixed.length) return "";
    for (var i = 0; i < fixed.length; i++) {
      if (cmpVersion(fixed[i], current) > 0) return fixed[i];
    }
    return fixed[fixed.length - 1];
  }

  function advice(pkg, fix) {
    return fix ? pkg.name + " を " + fix + " 以上に更新（今は " + pkg.version + "）"
               : pkg.name + " " + pkg.version + "：修正版の情報なし";
  }

  // OSV の脆弱性 → CVE 番号（無ければ GHSA などの ID のまま）
  function cveOf(vuln) {
    if (/^CVE-/.test(vuln.id || "")) return vuln.id;
    var alias = (vuln.aliases || []).filter(function (a) { return /^CVE-\d{4}-\d+$/.test(a); })[0];
    return alias || vuln.id;
  }

  // ---- 結果をまとめる ----

  // findings：[{ id, pkg, vuln }]（部品の照合結果）と CVE 番号の一覧から、1 CVE 1 行の結果を作る
  function buildResults(findings, cveList, index, kevActions, th) {
    var byId = {};
    function get(id) {
      if (!byId[id]) {
        var row = indexRow(index, id) || [];
        var act = (kevActions || {})[id];
        byId[id] = {
          id: id, isCve: /^CVE-/.test(id), tier: tierOf(row, th),
          epss: row[0] === undefined ? null : row[0], kev: row[1] || null, poc: row[2] || null, repos: row[3] || 0,
          kevDue: act ? act[1] : null, kevAction: act ? act[2] : null,
          packages: [], advice: [], summary: "", aliases: []
        };
      }
      return byId[id];
    }
    (findings || []).forEach(function (f) {
      var r = get(f.id);
      var fix = pickFix(fixedVersions(f.vuln, f.pkg), f.pkg.version);
      var label = f.pkg.name + " " + f.pkg.version;
      if (r.packages.indexOf(label) < 0) {
        r.packages.push(label);
        r.advice.push(advice(f.pkg, fix));
      }
      if (!r.summary && f.vuln.summary) r.summary = f.vuln.summary;
      [f.vuln.id].concat(f.vuln.aliases || []).forEach(function (a) {
        if (a && a !== r.id && r.aliases.indexOf(a) < 0) r.aliases.push(a);
      });
    });
    (cveList || []).forEach(function (id) { get(id); });
    var out = Object.keys(byId).map(function (k) { return byId[k]; });
    out.sort(function (a, b) {
      return TIER_ORDER[a.tier] - TIER_ORDER[b.tier]
        || (a.epss === null) - (b.epss === null)
        || (b.epss || 0) - (a.epss || 0)
        || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
    });
    return out;
  }

  function summarize(results) {
    var s = { total: results.length, S: 0, A: 0, B: 0, C: 0, kev: 0, fixable: 0 };
    results.forEach(function (r) {
      s[r.tier]++;
      if (r.kev) s.kev++;
      if (r.advice.some(function (a) { return / 以上に更新/.test(a); })) s.fixable++;
    });
    return s;
  }

  // ---- CSV（Excel で文字化けしないよう先頭に BOM を付ける） ----
  function toCsv(results) {
    function q(v) {
      v = v === null || v === undefined ? "" : String(v);
      return /[",\r\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
    }
    var head = ["ティア", "CVE", "EPSS", "KEV追加日", "KEV対応期限", "KEVで求められる対応", "PoC初出日", "PoCリポジトリ数",
                "該当する部品", "対策", "別名", "概要"];
    var lines = [head.map(q).join(",")];
    results.forEach(function (r) {
      lines.push([r.tier, r.id, r.epss === null ? "" : r.epss, r.kev, r.kevDue, r.kevAction, r.poc, r.repos || "",
                  r.packages.join(" / "), r.advice.join(" / "), r.aliases.join(" "), r.summary].map(q).join(","));
    });
    return "﻿" + lines.join("\r\n") + "\r\n";
  }

  // OSV.dev への問い合わせ1件分
  function osvQuery(pkg) {
    if (pkg.purl) return { package: { purl: pkg.purl } };
    return { package: { name: pkg.name, ecosystem: pkg.ecosystem }, version: pkg.version };
  }

  var api = {
    parseFile: parseFile, parsePurl: parsePurl, extractCves: extractCves, tierOf: tierOf, indexRow: indexRow,
    cmpVersion: cmpVersion, fixedVersions: fixedVersions, pickFix: pickFix, cveOf: cveOf,
    buildResults: buildResults, summarize: summarize, toCsv: toCsv, osvQuery: osvQuery
  };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.CheckCore = api;
})(this);
