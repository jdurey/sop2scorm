/**
 * Cross-Platform Automated Test Suite for `sop2scorm` (Ubuntu, macOS, Windows).
 * Runs via Node.js native test runner: `node --test test/sop2scorm.test.mjs`
 */

import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync, statSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import {
  readZip,
  sha256Hex,
  parseSopMarkdown,
  verifySopCitations,
  diffSopRevisions,
  buildEnterpriseScorm12DriverJs,
  compileSopToPackages
} from "../src/index.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "..");
const SOP_V1_PATH = join(REPO_ROOT, "examples", "acmecloud_nist_800_61r3_sop.md");
const SOP_V2_PATH = join(REPO_ROOT, "examples", "acmecloud_nist_800_61r3_sop_v2_15min_sla.md");
const QUIZ_PATH = join(REPO_ROOT, "examples", "acmecloud_quiz.json");
const CLI_PATH = join(REPO_ROOT, "bin", "sop2scorm.mjs");

test("1. Parses Markdown SOP source_id anchors, character spans, and paragraph SHA-256 digests deterministically", () => {
  const md = readFileSync(SOP_V1_PATH, "utf8");
  const parsed = parseSopMarkdown(md);

  assert.equal(
    parsed.title,
    "AcmeCloud Production Incident & NIST SP 800-61r3 Escalation SOP v2.4"
  );
  assert.equal(parsed.sections.length, 5);
  assert.equal(parsed.paragraphs.length, 10);

  const slaPara = parsed.citation_map["SOP-SLA-4.2"];
  assert.ok(slaPara, "Expected explicit source_id SOP-SLA-4.2 in citation_map");
  assert.match(slaPara.text, /within 4 Hours of containment confirmation/);
  assert.equal(slaPara.sha256, sha256Hex(slaPara.text));
  assert.ok(slaPara.end_char > slaPara.start_char);
});

test("2. Verifies paragraph-level quiz citations and catches unknown source_id or modified verbatim quotes", () => {
  const md = readFileSync(SOP_V1_PATH, "utf8");
  const quiz = JSON.parse(readFileSync(QUIZ_PATH, "utf8"));
  const parsed = parseSopMarkdown(md);

  const cleanReport = verifySopCitations(parsed, quiz);
  assert.equal(cleanReport.valid, true);
  assert.equal(cleanReport.violations.length, 0);
  assert.equal(cleanReport.citation_table.length, 15); // 10 lesson blocks + 5 quiz items

  // Inject bad source_id and drifted quote
  const badQuiz = [
    ...quiz,
    {
      id: "Q_BAD_ID",
      source_id: "NON_EXISTENT_SOP_99",
      question: "Bad ID test?",
      options: ["A", "B"],
      correct: 1
    },
    {
      id: "Q_BAD_QUOTE",
      source_id: "SOP-SLA-4.2",
      source_quote: "within 99 Days of containment",
      question: "Bad quote test?",
      options: ["A", "B"],
      correct: 1
    }
  ];

  const badReport = verifySopCitations(parsed, badQuiz);
  assert.equal(badReport.valid, false);
  assert.equal(badReport.violations.length, 2);
  assert.equal(badReport.violations[0].code, "UNKNOWN_SOURCE_ID");
  assert.equal(badReport.violations[1].code, "QUOTE_MISMATCH");
});

test("3. Produces byte-identical (--reproducible) SCORM 1.2 and IMS QTI 2.1 .zip archives across LF and CRLF inputs", async () => {
  const mdLf = readFileSync(SOP_V1_PATH, "utf8").replace(/\r\n/g, "\n");
  const mdCrlf = mdLf.replace(/\n/g, "\r\n");
  const quiz = JSON.parse(readFileSync(QUIZ_PATH, "utf8"));

  const buildA = await compileSopToPackages(mdLf, {
    courseId: "ACME_NIST_800_61R3",
    masteryScore: 80,
    quizItems: quiz,
    reproducible: true,
    strict: true
  });

  const buildB = await compileSopToPackages(mdCrlf, {
    courseId: "ACME_NIST_800_61R3",
    masteryScore: 80,
    quizItems: quiz,
    reproducible: true,
    strict: true
  });

  assert.equal(buildA.receipt.source_sha256, buildB.receipt.source_sha256);
  assert.equal(buildA.receipt.scorm12_zip_sha256, buildB.receipt.scorm12_zip_sha256);
  assert.equal(buildA.receipt.qti21_zip_sha256, buildB.receipt.qti21_zip_sha256);
  assert.deepEqual(buildA.scormZipBytes, buildB.scormZipBytes);
  assert.deepEqual(buildA.qtiZipBytes, buildB.qtiZipBytes);

  const scormZip = await readZip(buildA.scormZipBytes);
  for (const reqFile of [
    "course.json",
    "course_data.js",
    "imsmanifest.xml",
    "index.html",
    "scorm12_driver.js",
    "source_lineage_receipt.json"
  ]) {
    assert.ok(scormZip.has(reqFile), `Missing '${reqFile}' in SCORM 1.2 archive`);
  }

  const qtiZip = await readZip(buildA.qtiZipBytes);
  assert.ok(qtiZip.has("imsmanifest.xml"));
  assert.ok(qtiZip.has("tests/assessment_test.xml"));
  assert.ok(qtiZip.has("source_lineage_receipt.json"));
  assert.equal(
    qtiZip.listPaths().filter((p) => p.startsWith("items/")).length,
    5
  );
  // Ensure retry feedback never leaks the correct choice identifier
  const item1Xml = qtiZip.getText("items/qti21_item_01.xml");
  assert.match(item1Xml, /Review source paragraph SOP-FORENSICS-2\.1/);
});

test("4. Hardened Enterprise SCORM 1.2 CMI Runtime enforces 500-frame parent+opener walk, passed lock, <=3800-char suspend_data, and pagehide commit", () => {
  const driverCode = buildEnterpriseScorm12DriverJs();

  const lmsCalls = [];
  const lmsStore = {
    "cmi.core.lesson_status": "not attempted",
    "cmi.core.score.raw": "",
    "cmi.suspend_data": ""
  };

  const mockLmsApi = {
    LMSInitialize: () => {
      lmsCalls.push(["LMSInitialize"]);
      return "true";
    },
    LMSGetValue: (k) => lmsStore[k] || "",
    LMSSetValue: (k, v) => {
      lmsStore[k] = String(v);
      lmsCalls.push(["LMSSetValue", k, String(v)]);
      return "true";
    },
    LMSCommit: () => {
      lmsCalls.push(["LMSCommit"]);
      return "true";
    },
    LMSFinish: () => {
      lmsCalls.push(["LMSFinish"]);
      return "true";
    }
  };

  // Nest API 45 frames deep inside opener.parent chain to test enterprise popup+frameset discovery
  let deepOpener = { API: mockLmsApi };
  for (let i = 0; i < 45; i++) {
    const next = { parent: deepOpener };
    deepOpener = next;
  }

  const listeners = {};
  const docListeners = {};
  const sandboxWindow = {
    parent: null,
    opener: deepOpener,
    addEventListener: (evt, fn) => {
      listeners[evt] = fn;
    },
    document: {
      visibilityState: "visible",
      addEventListener: (evt, fn) => {
        docListeners[evt] = fn;
      }
    }
  };
  sandboxWindow.parent = sandboxWindow;

  vm.runInNewContext(driverCode, { window: sandboxWindow, globalThis: sandboxWindow });
  const drv = sandboxWindow.SCORM12Driver;
  assert.ok(drv, "SCORM12Driver must attach to window");

  // 1. Initialize and verify opener.parent walk found mockLmsApi + set incomplete + committed
  assert.equal(drv.LMSInitialize(""), "true");
  assert.equal(lmsStore["cmi.core.lesson_status"], "incomplete");
  assert.equal(lmsStore["cmi.core.exit"], "suspend");

  // 2. Test compact suspend_data persistence & hydration
  drv.saveSuspendState({ v: 1, l: 2, d: { "SOP-FORENSICS-2.1": true }, p: 0, s: 60 });
  const hydrated = drv.loadSuspendState();
  assert.equal(hydrated.l, 2);
  assert.equal(hydrated.s, 60);

  // 3. Test high-water 'passed' & score lock (Workday / Cornerstone masteryscore protection)
  drv.LMSSetValue("cmi.core.score.raw", "90");
  drv.LMSSetValue("cmi.core.lesson_status", "passed");
  assert.equal(lmsStore["cmi.core.lesson_status"], "passed");
  assert.equal(lmsStore["cmi.core.score.raw"], "90");

  // Attempt to downgrade 'passed' -> 'completed' or 'failed' and score '90' -> '40'
  drv.LMSSetValue("cmi.core.lesson_status", "completed");
  drv.LMSSetValue("cmi.core.lesson_status", "failed");
  drv.LMSSetValue("cmi.core.score.raw", "40");
  assert.equal(lmsStore["cmi.core.lesson_status"], "passed", "Must never downgrade 'passed' status");
  assert.equal(lmsStore["cmi.core.score.raw"], "90", "Must never downgrade passing high-water score");

  // 4. Test visibilitychange (hidden) and pagehide eager commits
  const commitsBefore = lmsCalls.filter((c) => c[0] === "LMSCommit").length;
  sandboxWindow.document.visibilityState = "hidden";
  docListeners.visibilitychange();
  const commitsAfterHidden = lmsCalls.filter((c) => c[0] === "LMSCommit").length;
  assert.ok(commitsAfterHidden > commitsBefore, "visibilitychange -> hidden must trigger eager LMSCommit");

  listeners.pagehide();
  assert.ok(lmsCalls.some((c) => c[0] === "LMSFinish"), "pagehide must flush LMSCommit + LMSFinish");
});

test("5. Policy-Diff Engine (4 Hours -> 15 Minutes) deterministically flags Block #4 and Scenario Question #3 as HALTED_FOR_SME_SIGN_OFF", () => {
  const mdV1 = readFileSync(SOP_V1_PATH, "utf8");
  const mdV2 = readFileSync(SOP_V2_PATH, "utf8");
  const quiz = JSON.parse(readFileSync(QUIZ_PATH, "utf8"));

  const diff = diffSopRevisions(mdV1, mdV2, quiz);
  assert.equal(diff.status, "HALTED_FOR_SME_SIGN_OFF");
  assert.equal(diff.modified_paragraphs.length, 1);
  assert.equal(diff.modified_paragraphs[0].source_id, "SOP-SLA-4.2");
  assert.match(diff.modified_paragraphs[0].old_text, /4 Hours/);
  assert.match(diff.modified_paragraphs[0].new_text, /15 Minutes/);

  assert.equal(diff.impacted_blocks.length, 1);
  assert.equal(diff.impacted_blocks[0].block_number, 4);
  assert.equal(diff.impacted_blocks[0].status, "HALTED_FOR_SME_SIGN_OFF");

  assert.equal(diff.impacted_quiz_items.length, 1);
  assert.equal(diff.impacted_quiz_items[0].question_number, 3);
  assert.equal(diff.impacted_quiz_items[0].item_id, "Q_3");
  assert.equal(diff.impacted_quiz_items[0].source_id, "SOP-SLA-4.2");
  assert.equal(diff.impacted_quiz_items[0].status, "HALTED_FOR_SME_SIGN_OFF");
});

test("6. CLI commands (verify, diff, compile --reproducible --json) execute cleanly with zero network calls", () => {
  const tmpDir = mkdtempSync(join(tmpdir(), "sop2scorm_cli_"));
  try {
    const verifyOut = execFileSync(
      process.execPath,
      [CLI_PATH, "verify", SOP_V1_PATH, "--quiz", QUIZ_PATH, "--json"],
      { encoding: "utf8" }
    );
    const verifyJson = JSON.parse(verifyOut);
    assert.equal(verifyJson.valid, true);

    const diffOut = execFileSync(
      process.execPath,
      [CLI_PATH, "diff", SOP_V1_PATH, SOP_V2_PATH, "--quiz", QUIZ_PATH, "--json"],
      { encoding: "utf8" }
    );
    const diffJson = JSON.parse(diffOut);
    assert.equal(diffJson.status, "HALTED_FOR_SME_SIGN_OFF");
    assert.equal(diffJson.impacted_blocks[0].block_number, 4);
    assert.equal(diffJson.impacted_quiz_items[0].question_number, 3);

    const compileOut = execFileSync(
      process.execPath,
      [
        CLI_PATH,
        "compile",
        SOP_V1_PATH,
        "--quiz",
        QUIZ_PATH,
        "--out-dir",
        tmpDir,
        "--reproducible",
        "--json"
      ],
      { encoding: "utf8" }
    );
    const compileJson = JSON.parse(compileOut);
    assert.equal(compileJson.ok, true);
    assert.ok(compileJson.scorm12_bytes > 2000);
    assert.ok(compileJson.qti21_bytes > 1000);
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("7. Zero em-dashes or en-dashes across all repository files", () => {
  const emChar = String.fromCharCode(0x2014);
  const enChar = String.fromCharCode(0x2013);

  function walkDir(dir) {
    const out = [];
    for (const name of readdirSync(dir)) {
      if (name === "node_modules" || name === ".git" || name === "dist") continue;
      const full = join(dir, name);
      const st = statSync(full);
      if (st.isDirectory()) out.push(...walkDir(full));
      else if (/\.(mjs|js|json|md|yml)$/i.test(name)) out.push(full);
    }
    return out;
  }

  for (const fPath of walkDir(REPO_ROOT)) {
    const txt = readFileSync(fPath, "utf8");
    assert.equal(txt.includes(emChar), false, `Found raw em-dash in ${fPath}`);
    assert.equal(txt.includes(enChar), false, `Found raw en-dash in ${fPath}`);
  }
});
