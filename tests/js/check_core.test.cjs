// 「自分の環境をチェック」の中身（triage/static/check-core.js）のテスト。
// 実行：node --test tests/js
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const Core = require("../../triage/static/check-core.js");

const FIX = path.join(__dirname, "..", "fixtures", "check");
const TH = { a_epss: 0.1, b_epss: 0.01 };

function parse(name) {
  return Core.parseFile(name, fs.readFileSync(path.join(FIX, name), "utf8"));
}
function names(r) {
  return r.packages.map((p) => `${p.ecosystem}:${p.name}@${p.version}`).sort();
}

test("package-lock.json v3：入れ子・スコープ付きも読む、link は除く", () => {
  const r = parse("package-lock.json");
  assert.match(r.format, /package-lock/);
  assert.deepEqual(names(r), ["npm:@babel/core@7.0.0", "npm:lodash@4.17.15", "npm:minimist@1.2.0"]);
});

test("package-lock.json v1：dependencies を入れ子まで読む、file: は除く", () => {
  const r = parse("package-lock-v1.json");
  assert.deepEqual(names(r), ["npm:axios@0.21.0", "npm:follow-redirects@1.13.0"]);
});

test("requirements.txt：== / === で固定した行だけ", () => {
  const r = parse("requirements.txt");
  assert.deepEqual(names(r), ["PyPI:Django@3.2.0", "PyPI:PyYAML@5.3", "PyPI:requests@2.25.1"]);
});

test("poetry.lock・Cargo.lock", () => {
  assert.deepEqual(names(parse("poetry.lock")), ["PyPI:jinja2@2.11.2", "PyPI:markupsafe@1.1.1"]);
  assert.deepEqual(names(parse("Cargo.lock")), ["crates.io:demo@0.1.0", "crates.io:openssl@0.10.40"]);
});

test("go.sum・go.mod：先頭の v は外す、/go.mod の行と重複はまとめる", () => {
  assert.deepEqual(names(parse("go.sum")), ["Go:github.com/gin-gonic/gin@1.6.0", "Go:golang.org/x/text@0.3.2"]);
  assert.deepEqual(names(parse("go.mod")), [
    "Go:github.com/gin-gonic/gin@1.6.0", "Go:github.com/pkg/errors@0.9.1",
    "Go:golang.org/x/net@0.0.0-20200822124328-c89045814202"]);
});

test("pom.xml：${...} の版は読まない", () => {
  assert.deepEqual(names(parse("pom.xml")), ["Maven:org.apache.logging.log4j:log4j-core@2.14.1"]);
});

test("Gemfile.lock・composer.lock", () => {
  assert.deepEqual(names(parse("Gemfile.lock")), ["RubyGems:nokogiri@1.10.9", "RubyGems:rails@6.0.0"]);
  assert.deepEqual(names(parse("composer.lock")), ["Packagist:guzzlehttp/guzzle@7.4.0", "Packagist:phpunit/phpunit@9.5.0"]);
});

test("CycloneDX：入れ子の components も読み、未対応の種類は purl のまま問い合わせる", () => {
  const r = parse("bom.cdx.json");
  assert.match(r.format, /CycloneDX/);
  assert.deepEqual(names(r), [
    ":debian/openssl@1.1.1n-0", "Maven:org.apache.logging.log4j:log4j-core@2.14.1",
    "npm:@babel/core@7.0.0", "npm:lodash@4.17.15"]);
  const deb = r.packages.find((p) => p.purl);
  assert.deepEqual(Core.osvQuery(deb), { package: { purl: "pkg:deb/debian/openssl@1.1.1n-0" } });
  const npm = r.packages.find((p) => p.name === "lodash");
  assert.deepEqual(Core.osvQuery(npm), { package: { name: "lodash", ecosystem: "npm" }, version: "4.17.15" });
});

test("SPDX", () => {
  assert.deepEqual(names(parse("sbom.spdx.json")), ["Go:github.com/gin-gonic/gin@1.6.0", "PyPI:django@3.2.0"]);
});

test("CVE 番号の一覧：大文字にそろえ、重複はまとめる", () => {
  const r = parse("trivy-result.csv");
  assert.equal(r.format, "CVE番号の一覧");
  assert.deepEqual(r.cves, ["CVE-2020-8203", "CVE-2021-44228", "CVE-2022-0778"]);
  assert.deepEqual(r.packages, []);
});

test("何も読めないファイル", () => {
  const r = Core.parseFile("memo.txt", "こんにちは");
  assert.equal(r.format, "不明");
  assert.deepEqual(r.cves, []);
});

test("ティア：triage/tiering.py と同じ規則", () => {
  assert.equal(Core.tierOf([0.0001, "2024-01-01"], TH), "S");
  assert.equal(Core.tierOf([0.1, null, "2024-01-01", 2], TH), "A");
  assert.equal(Core.tierOf([0.0999, null, "2024-01-01", 2], TH), "B");
  assert.equal(Core.tierOf([0.5], TH), "B");
  assert.equal(Core.tierOf([0.01], TH), "B");
  assert.equal(Core.tierOf([0.0099], TH), "C");
  assert.equal(Core.tierOf([null, null, "2024-01-01", 1], TH), "C");  // EPSS が無い PoC は採用しない
  assert.equal(Core.tierOf(undefined, TH), "C");                     // 索引に無い CVE
});

test("版の比較と「直った版」の選び方", () => {
  assert.equal(Core.cmpVersion("1.10.0", "1.9.2"), 1);
  assert.equal(Core.cmpVersion("4.17.19", "4.17.19"), 0);
  assert.equal(Core.pickFix(["2.3.1", "2.12.2", "2.15.0"], "2.14.1"), "2.15.0");
  assert.equal(Core.pickFix(["1.0.0"], "2.0.0"), "1.0.0");
  assert.equal(Core.pickFix([], "1.0.0"), "");
});

const LODASH_VULN = {
  id: "GHSA-p6mc-m468-83gw", aliases: ["CVE-2020-8203"], summary: "Prototype Pollution in lodash",
  affected: [
    { package: { ecosystem: "npm", name: "lodash" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "3.7.0" }, { fixed: "4.17.19" }] }] },
    { package: { ecosystem: "npm", name: "lodash-es" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.20" }] }] }],
};
const NOFIX_VULN = {
  id: "GHSA-xxxx-yyyy-zzzz", aliases: [], summary: "No fix yet",
  affected: [{ package: { ecosystem: "PyPI", name: "Django" },
               ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }] }] }],
};

test("OSV の脆弱性から CVE 番号と直った版", () => {
  assert.equal(Core.cveOf(LODASH_VULN), "CVE-2020-8203");
  assert.equal(Core.cveOf({ id: "CVE-2021-44228" }), "CVE-2021-44228");
  assert.equal(Core.cveOf(NOFIX_VULN), "GHSA-xxxx-yyyy-zzzz");
  assert.deepEqual(Core.fixedVersions(LODASH_VULN, { ecosystem: "npm", name: "lodash" }), ["4.17.19"]);
  // PyPI は大文字小文字・区切り文字の違いを同じとみなす
  assert.deepEqual(Core.fixedVersions(NOFIX_VULN, { ecosystem: "PyPI", name: "django" }), []);
});

test("結果のまとめ：1 CVE 1 行、優先度順、対策と KEV の対応", () => {
  const index = {
    "2020": { "8203": [0.02, null, "2020-07-01", 3] },
    "2021": { "44228": [0.944, "2021-12-10", "2021-12-10", 400] },
  };
  const kev = { "CVE-2021-44228": ["2021-12-10", "2021-12-24", "Apply updates per vendor instructions."] };
  const findings = [
    { id: "CVE-2020-8203", pkg: { ecosystem: "npm", name: "lodash", version: "4.17.15" }, vuln: LODASH_VULN },
    { id: "CVE-2020-8203", pkg: { ecosystem: "npm", name: "lodash", version: "4.17.15" }, vuln: LODASH_VULN },
    { id: "GHSA-xxxx-yyyy-zzzz", pkg: { ecosystem: "PyPI", name: "Django", version: "3.2.0" }, vuln: NOFIX_VULN },
  ];
  const res = Core.buildResults(findings, ["CVE-2021-44228", "CVE-2020-8203"], index, kev, TH);
  assert.deepEqual(res.map((r) => [r.id, r.tier]), [
    ["CVE-2021-44228", "S"], ["CVE-2020-8203", "B"], ["GHSA-xxxx-yyyy-zzzz", "C"]]);
  assert.deepEqual(res[1].advice, ["lodash を 4.17.19 以上に更新（今は 4.17.15）"]);
  assert.deepEqual(res[1].aliases, ["GHSA-p6mc-m468-83gw"]);
  assert.deepEqual(res[2].advice, ["Django 3.2.0：修正版の情報なし"]);
  assert.equal(res[2].isCve, false);
  assert.equal(res[0].kevDue, "2021-12-24");
  assert.equal(res[0].kevAction, "Apply updates per vendor instructions.");

  const s = Core.summarize(res);
  assert.deepEqual(s, { total: 3, S: 1, A: 0, B: 1, C: 1, kev: 1, fixable: 1 });

  const csv = Core.toCsv(res);
  assert.ok(csv.startsWith("﻿ティア,CVE,"));
  assert.match(csv, /S,CVE-2021-44228,0\.944,2021-12-10,2021-12-24,Apply updates per vendor instructions\./);
  assert.match(csv, /lodash を 4\.17\.19 以上に更新（今は 4\.17\.15）/);
  assert.equal(csv.trim().split("\r\n").length, 4);
});

test("CSV：カンマや改行や引用符を含む値は囲む", () => {
  const csv = Core.toCsv([{ tier: "C", id: "CVE-1", epss: null, kev: null, kevDue: null, kevAction: null, poc: null,
    repos: 0, packages: [], advice: [], aliases: [], summary: 'a,b "c"\nd' }]);
  assert.match(csv, /"a,b ""c""\nd"/);
});
