#!/usr/bin/env node
/**
 * CLI for `sop2scorm` - Deterministic Markdown-to-SCORM 1.2 & IMS QTI 2.1 Compiler
 * with paragraph-level `source_id` citation verification, SHA-256 build receipts,
 * and zero-cost Policy-Diff impact analysis.
 *
 * Commands:
 *   sop2scorm compile <sop.md> [--quiz <quiz.json>] [--out-dir <dir>] [--reproducible] [--strict] [--json]
 *   sop2scorm verify  <sop.md> [--quiz <quiz.json>] [--strict] [--json]
 *   sop2scorm diff    <old_sop.md> <new_sop.md> [--quiz <quiz.json>] [--json]
 */

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { resolve, join } from "node:path";
import {
  parseSopMarkdown,
  verifySopCitations,
  diffSopRevisions,
  compileSopToPackages
} from "../src/index.mjs";

function printHelp() {
  console.log(`sop2scorm v1.0.0 - Deterministic Markdown-to-SCORM 1.2 & IMS QTI 2.1 Compiler

Usage:
  sop2scorm compile <sop.md> [options]
  sop2scorm verify  <sop.md> [options]
  sop2scorm diff    <old_sop.md> <new_sop.md> [options]

Options:
  --quiz <path>          Optional JSON file containing source-cited scenario quiz items
  --out-dir <dir>        Output directory for compiled .zip & receipt files (default: ./dist)
  --scorm-out <path>     Explicit path for ADL SCORM 1.2 .zip output
  --qti-out <path>       Explicit path for IMS QTI 2.1 .zip output
  --citations-out <path> Explicit path for source_lineage_receipt.json output
  --course-id <id>       Course identifier (default: SOP_COURSE_001)
  --title <title>        Override course title
  --mastery-score <pct>  Mastery threshold 1-100 (default: 80)
  --reproducible         Force deterministic byte-identical .zip output (default: true)
  --no-strict            Allow compilation even if a quiz item is missing a valid source_id
  --json                 Print machine-readable JSON output to stdout
  -h, --help             Show this help message
`);
}

function parseCliArgs(argv) {
  const positionals = [];
  const flags = {
    reproducible: true,
    strict: true,
    json: false,
    outDir: "./dist",
    courseId: "SOP_COURSE_001",
    masteryScore: 80
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-h" || a === "--help") {
      flags.help = true;
    } else if (a === "--reproducible") {
      flags.reproducible = true;
    } else if (a === "--no-strict") {
      flags.strict = false;
    } else if (a === "--strict") {
      flags.strict = true;
    } else if (a === "--json") {
      flags.json = true;
    } else if (a === "--quiz" && argv[i + 1]) {
      flags.quizPath = argv[++i];
    } else if (a === "--out-dir" && argv[i + 1]) {
      flags.outDir = argv[++i];
    } else if (a === "--scorm-out" && argv[i + 1]) {
      flags.scormOut = argv[++i];
    } else if (a === "--qti-out" && argv[i + 1]) {
      flags.qtiOut = argv[++i];
    } else if (a === "--citations-out" && argv[i + 1]) {
      flags.citationsOut = argv[++i];
    } else if (a === "--course-id" && argv[i + 1]) {
      flags.courseId = argv[++i];
    } else if (a === "--title" && argv[i + 1]) {
      flags.title = argv[++i];
    } else if (a === "--mastery-score" && argv[i + 1]) {
      flags.masteryScore = Number(argv[++i]);
    } else if (!a.startsWith("-")) {
      positionals.push(a);
    }
  }

  return { positionals, flags };
}

async function main() {
  const { positionals, flags } = parseCliArgs(process.argv.slice(2));
  if (flags.help || positionals.length === 0) {
    printHelp();
    process.exit(0);
  }

  const subcmd = positionals[0];
  const quizItems = flags.quizPath
    ? JSON.parse(readFileSync(resolve(flags.quizPath), "utf8"))
    : [];

  if (subcmd === "verify") {
    const sopPath = positionals[1];
    if (!sopPath) {
      console.error("Error: 'sop2scorm verify' requires <sop.md> path.");
      process.exit(1);
    }
    const md = readFileSync(resolve(sopPath), "utf8");
    const parsed = parseSopMarkdown(md, { title: flags.title });
    const report = verifySopCitations(parsed, quizItems);
    if (flags.json) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(`SOP Title:       ${parsed.title}`);
      console.log(`Source SHA-256:  ${report.source_sha256}`);
      console.log(`Sections:        ${report.section_count}`);
      console.log(`Paragraph Spans: ${report.paragraph_count}`);
      console.log(`Quiz Citations:  ${report.quiz_item_count}`);
      console.log(`Verification:    ${report.valid ? "PASS (0 violations)" : `FAIL (${report.violations.length} violations)`}`);
      for (const v of report.violations) {
        console.error(`  - [${v.code}] ${v.message}`);
      }
    }
    if (flags.strict && !report.valid) {
      process.exit(2);
    }
    return;
  }

  if (subcmd === "diff") {
    const oldPath = positionals[1];
    const newPath = positionals[2];
    if (!oldPath || !newPath) {
      console.error("Error: 'sop2scorm diff' requires <old_sop.md> and <new_sop.md>.");
      process.exit(1);
    }
    const oldMd = readFileSync(resolve(oldPath), "utf8");
    const newMd = readFileSync(resolve(newPath), "utf8");
    const diff = diffSopRevisions(oldMd, newMd, quizItems);
    if (flags.json) {
      console.log(JSON.stringify(diff, null, 2));
    } else {
      console.log(`Policy-Diff Status:  ${diff.status}`);
      console.log(`Old Source SHA-256:  ${diff.old_source_sha256}`);
      console.log(`New Source SHA-256:  ${diff.new_source_sha256}`);
      console.log(`Modified Paragraphs: ${diff.modified_paragraphs.length}`);
      for (const mp of diff.modified_paragraphs) {
        console.log(`  * [${mp.source_id}] "${mp.old_text}" -> "${mp.new_text}"`);
      }
      console.log(`Impacted Blocks:     ${diff.impacted_blocks.length}`);
      for (const ib of diff.impacted_blocks) {
        console.log(`  * Block #${ib.block_number} (${ib.section_title}) [${ib.impacted_source_ids.join(", ")}] -> ${ib.status}`);
      }
      console.log(`Impacted Quiz Items: ${diff.impacted_quiz_items.length}`);
      for (const iq of diff.impacted_quiz_items) {
        console.log(`  * Question #${iq.question_number} (${iq.item_id}, cites ${iq.source_id}) -> ${iq.status}`);
      }
    }
    return;
  }

  const sopPath = subcmd === "compile" ? positionals[1] : positionals[0];
  if (!sopPath) {
    console.error("Error: Missing <sop.md> input file.");
    process.exit(1);
  }

  const md = readFileSync(resolve(sopPath), "utf8");
  const compiled = await compileSopToPackages(md, {
    title: flags.title,
    courseId: flags.courseId,
    masteryScore: flags.masteryScore,
    quizItems,
    reproducible: flags.reproducible,
    strict: flags.strict
  });

  const outDir = resolve(flags.outDir);
  mkdirSync(outDir, { recursive: true });
  const scormOutPath = resolve(flags.scormOut || join(outDir, "scorm12_package.zip"));
  const qtiOutPath = resolve(flags.qtiOut || join(outDir, "qti21_bank.zip"));
  const citationsOutPath = resolve(flags.citationsOut || join(outDir, "source_lineage_receipt.json"));

  writeFileSync(scormOutPath, compiled.scormZipBytes);
  writeFileSync(qtiOutPath, compiled.qtiZipBytes);
  writeFileSync(citationsOutPath, JSON.stringify(compiled.receipt, null, 2) + "\n", "utf8");

  const summary = {
    ok: true,
    title: compiled.parsedSop.title,
    course_id: flags.courseId,
    reproducible: flags.reproducible,
    source_sha256: compiled.receipt.source_sha256,
    scorm12_zip: scormOutPath,
    scorm12_bytes: compiled.scormZipBytes.byteLength,
    scorm12_sha256: compiled.receipt.scorm12_zip_sha256,
    qti21_zip: qtiOutPath,
    qti21_bytes: compiled.qtiZipBytes.byteLength,
    qti21_sha256: compiled.receipt.qti21_zip_sha256,
    receipt_json: citationsOutPath
  };

  if (flags.json) {
    console.log(JSON.stringify(summary, null, 2));
  } else {
    console.log(`Compiled Source-Locked SCORM 1.2 + IMS QTI 2.1 Packages:`);
    console.log(`  Course Title:    ${summary.title}`);
    console.log(`  Source SHA-256:  ${summary.source_sha256}`);
    console.log(`  SCORM 1.2 .zip:  ${summary.scorm12_zip} (${summary.scorm12_bytes} bytes, sha256=${summary.scorm12_sha256.slice(0, 16)}...)`);
    console.log(`  IMS QTI 2.1:     ${summary.qti21_zip} (${summary.qti21_bytes} bytes, sha256=${summary.qti21_sha256.slice(0, 16)}...)`);
    console.log(`  Lineage Receipt: ${summary.receipt_json}`);
  }
}

main().catch((err) => {
  console.error(`sop2scorm error: ${err.message || err}`);
  process.exit(1);
});
