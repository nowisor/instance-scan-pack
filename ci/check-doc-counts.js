#!/usr/bin/env node
/**
 * check-doc-counts.js — WI-MIRROR-1 Item 2.
 *
 * Two guards over the pack's own documentation. They exist because the public
 * README carried v1.0.0 numbers ("the 26 checks", "27 nowisor checks",
 * "confirm all 26 are active=true") for four months after the pack grew to 49.
 * A count typed into prose is a copy of a fact that lives in manifest.json, and
 * copies go stale silently.
 *
 *   1. COUNT GUARD (README.md). Any integer in the 20..49 band on a line that
 *      talks about checks must be a number the manifest can justify: the total,
 *      or the active count. It deliberately does NOT require the word "checks"
 *      to follow the number -- the worst real line was "confirm all 26 are
 *      `active=true`", which a /<N> checks/ pattern cannot see at all.
 *
 *      Scope is README.md ONLY, on purpose. verification/*.md are dated PDI
 *      transcripts that capture observed output verbatim ("Found 26 active
 *      nowisor checks" on dev265484). Those numbers are evidence of what a run
 *      measured on a date; rewriting them to today's total would falsify the
 *      record rather than fix a stale claim.
 *
 *   2. DEAD-PATH GUARD (whole tree, including verification/). No absolute path
 *      pointing into the archived Google Drive copy abandoned in the 2026-09-23
 *      tree move. A doc that tells a reader to cd there sends them to a tree
 *      that no longer receives commits.
 *
 * Lives in ci/ and not in scripts/ deliberately: scripts/check-*.js is the
 * PUBLISHED ServiceNow scan-check namespace, and release-validation.yml sweeps
 * that glob asserting every match emits NOWISOR_METADATA. Build tooling placed
 * there fails that step and ships to customers looking like a scan check.
 *
 * Usage: node ci/check-doc-counts.js [packRoot]
 * Exit 0 clean, 1 on any violation. No dependencies.
 */

'use strict';

const fs = require('fs');
const path = require('path');

let PACK_ROOT = path.resolve(process.argv[2] || path.join(__dirname, '..'));

const COUNT_RE = /\b(2[0-9]|[3-4][0-9])\b/g;
const CHECK_CONTEXT_RE = /check/i;

// A history section speaks about released versions; everything inside it is a
// true statement about an era, not a claim about the current pack.
const HISTORY_HEADING_RE = /^(#+)\s*(changelog|release notes|history)\b/i;
const HEADING_RE = /^(#+)\s/;

// The one explicit opt-out, for a live section that names its own era anyway
// (the compatibility matrix row for v1.0.0). Deliberately a literal marker and
// not "any line citing a version": a blanket version-citation exemption would
// excuse a future "26 checks in 1.2.1", which is exactly the bug being guarded.
const HISTORICAL_MARKER = 'doc-count:historical';

const DEAD_PATH_RE = /\/Users\/[^\n"'`]*My Drive/;

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', '.now', '.vscode', 'build']);
const MAX_BYTES = 2 * 1024 * 1024;

let failures = [];

function rel(p) {
  return path.relative(PACK_ROOT, p) || path.basename(p);
}

function readManifestCounts() {
  const manifestPath = path.join(PACK_ROOT, 'manifest.json');
  if (!fs.existsSync(manifestPath)) {
    failures.push('manifest.json not found -- cannot establish the expected count');
    return null;
  }
  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  } catch (err) {
    failures.push(`manifest.json is not valid JSON (${err.message})`);
    return null;
  }
  if (!Array.isArray(manifest.checks)) {
    failures.push('manifest.json has no checks array');
    return null;
  }
  const total = manifest.checks.length;
  const active = manifest.checks.filter((c) => c.active !== false).length;
  // Both DERIVED from the manifest, so the oracle never comes from the prose
  // being checked. "47 of the 49 in 1.2.1" is true; "all 26" is not.
  return { total, active, allowed: new Set([total, active]) };
}

function checkCounts(counts) {
  const file = path.join(PACK_ROOT, 'README.md');
  if (!fs.existsSync(file)) {
    failures.push('README.md not found');
    return;
  }
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  let historyDepth = null; // heading depth of the history section we are inside

  lines.forEach((line, i) => {
    const heading = line.match(HEADING_RE);
    if (heading) {
      const depth = heading[1].length;
      if (HISTORY_HEADING_RE.test(line)) historyDepth = depth;
      else if (historyDepth !== null && depth <= historyDepth) historyDepth = null;
    }
    if (historyDepth !== null) return;
    if (line.includes(HISTORICAL_MARKER)) return;
    if (!CHECK_CONTEXT_RE.test(line)) return;

    COUNT_RE.lastIndex = 0;
    let m;
    while ((m = COUNT_RE.exec(line)) !== null) {
      if (line[m.index - 1] === '#') continue; // a check id such as "#27"
      const found = Number(m[1]);
      if (!counts.allowed.has(found)) {
        failures.push(
          `${rel(file)}:${i + 1}: states ${found} on a line about checks, but the ` +
          `manifest justifies only ${counts.total} (total) or ${counts.active} (active)` +
          `\n      ${line.trim().slice(0, 160)}`
        );
      }
    }
  });
}

function walk(dir, visit) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name)) continue;
    if (entry.isDirectory() && entry.name.startsWith('.') && entry.name !== '.github') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, visit);
    else if (entry.isFile()) visit(full);
  }
}

function checkDeadPaths() {
  walk(PACK_ROOT, (file) => {
    let stat;
    try {
      stat = fs.statSync(file);
    } catch {
      return;
    }
    if (stat.size > MAX_BYTES) return;
    // The detector states the pattern it looks for, so it matches itself.
    if (path.resolve(file) === path.resolve(__filename)) return;
    let text;
    try {
      text = fs.readFileSync(file, 'utf8');
    } catch {
      return;
    }
    if (text.includes('\u0000')) return; // binary
    text.split('\n').forEach((line, i) => {
      if (DEAD_PATH_RE.test(line)) {
        failures.push(
          `${rel(file)}:${i + 1}: dead archived path (the retired Drive tree)` +
          `\n      ${line.trim().slice(0, 160)}`
        );
      }
    });
  });
}

/**
 * Run both guards over `root`. Pure: returns the verdict, prints nothing and
 * never exits, so the vitest half can call it in-process. Spawning a node
 * process per fixture measurably slowed the suite -- it pushed three
 * sqlite-migration tests past their 5s timeout -- and the CLI adds nothing the
 * function does not already decide.
 */
function run(root) {
  PACK_ROOT = path.resolve(root);
  failures = [];
  const counts = readManifestCounts();
  if (counts !== null) checkCounts(counts);
  checkDeadPaths();
  return { ok: failures.length === 0, failures: failures.slice(), counts };
}

function cli() {
  const { ok, failures: found, counts } = run(process.argv[2] || path.join(__dirname, '..'));
  if (!ok) {
    console.error(`check-doc-counts: ${found.length} violation(s) in ${PACK_ROOT}\n`);
    for (const f of found) console.error(`  - ${f}`);
    console.error(
      '\nFix the prose. If the line genuinely describes a past release, put it in' +
      `\nthe Changelog section or tag the line "${HISTORICAL_MARKER}".`
    );
    process.exit(1);
  }
  console.log(
    `check-doc-counts: OK (${counts.total} checks in manifest.json, ` +
    `${counts.active} active, no dead paths)`
  );
}

module.exports = { run, HISTORICAL_MARKER };

if (require.main === module) cli();
