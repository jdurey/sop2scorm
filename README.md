# sop2scorm

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](./package.json)
[![Node.js >= 18](https://img.shields.io/badge/node-%3E%3D18.0.0-339933.svg)](./package.json)
[![Reproducible Builds](https://img.shields.io/badge/builds-reproducible-0f766e.svg)](./src/sop_compiler.mjs)

Deterministic, zero-dependency Node.js CLI and ESM library that compiles Markdown Standard Operating Procedures (`SOPs`) and source-cited quiz JSON into **enterprise-hardened ADL SCORM 1.2** `.zip` packages, **IMS QTI 2.1** assessment banks, and **Deterministic Source-Lineage Build Receipts (`SHA-256`)** with paragraph-level citation verification and policy-diff impact analysis.

- **100% Pure JavaScript (`Node >= 18`):** Zero npm install dependencies, zero native C++/Rust bindings, zero network calls. Runs identically on Linux, macOS, and Windows.
- **Byte-Identical Reproducible Archives (`--reproducible`):** Normalizes `CRLF`/`LF` line endings, sorts archive members lexicographically, and pins deterministic ZIP header timestamps so CI pipelines produce identical `SHA-256` output on every OS.
- **Hardened for Workday Learning & Cornerstone OnDemand:** Implements eager `LMSCommit` on `pagehide` and `visibilitychange`, 500-frame cross-origin-safe `window.parent` + `window.opener` API discovery, high-water `passed`/`masteryscore` protection, compact `<= 3,800`-character `cmi.suspend_data` state hydration, accessible WebVTT `<track>` captions + collapsible WCAG 2.1 AA HTML transcript drawers, and zero answer-key leakage on failed attempts.

> [!TIP]
> **Need full PDF/DOCX SOP ingestion, 3-model blind-solved scenario assessments, 1080p30 presenter-bookended diagram walkthrough videos, and Microsoft Word (`.docx`) SME Citation Tables delivered in 48 hours?**
> Inspect the live interactive flagship build and Policy-Diff sandbox at **[scorm.stillhumanacademy.com/pilot](https://scorm.stillhumanacademy.com/pilot?src=github)**.

---

## Quick Start

```bash
git clone https://github.com/jdurey/sop2scorm.git
cd sop2scorm
npm test
```

### 1. Verify Paragraph-Level `source_id` Citations

Every SOP paragraph carries a deterministic `source_id` (e.g., `[SOP-SLA-4.2]` or `{#SOP-SLA-4.2}`), and every scenario question cites an exact `source_id` + verbatim `source_quote`:

```bash
node ./bin/sop2scorm.mjs verify ./examples/acmecloud_nist_800_61r3_sop.md \
  --quiz ./examples/acmecloud_quiz.json
```

Output:

```text
SOP Title:       AcmeCloud Production Incident & NIST SP 800-61r3 Escalation SOP v2.4
Source SHA-256:  c8159c80217b7ab0d814b26f8665d1c0c492d92c46bd7524bf569285be79c6d6
Sections:        5
Paragraph Spans: 10
Quiz Citations:  5
Verification:    PASS (0 violations)
```

### 2. Run Deterministic Policy-Diff Impact Analysis (`$0` API Cost)

When an SOP changes (for example, `SOP-SLA-4.2` changes the Severity-1 escalation SLA from `4 Hours` to `15 Minutes`), `sop2scorm diff` hashes every `source_id` paragraph and halts only the impacted lesson blocks and quiz items for SME sign-off:

```bash
node ./bin/sop2scorm.mjs diff \
  ./examples/acmecloud_nist_800_61r3_sop.md \
  ./examples/acmecloud_nist_800_61r3_sop_v2_15min_sla.md \
  --quiz ./examples/acmecloud_quiz.json
```

Output:

```text
Policy-Diff Status:  HALTED_FOR_SME_SIGN_OFF
Modified Paragraphs: 1
  * [SOP-SLA-4.2] "...within 4 Hours..." -> "...within 15 Minutes..."
Impacted Blocks:     1
  * Block #4 (4. Executive, Legal & Customer Escalation SLAs) [SOP-SLA-4.2] -> HALTED_FOR_SME_SIGN_OFF
Impacted Quiz Items: 1
  * Question #3 (Q_3, cites SOP-SLA-4.2) -> HALTED_FOR_SME_SIGN_OFF
```

### 3. Compile Reproducible SCORM 1.2 + IMS QTI 2.1 + Lineage Receipt

```bash
node ./bin/sop2scorm.mjs compile ./examples/acmecloud_nist_800_61r3_sop.md \
  --quiz ./examples/acmecloud_quiz.json \
  --course-id ACME_NIST_800_61R3 \
  --out-dir ./dist \
  --reproducible
```

Produces three files in `./dist`:
1. `scorm12_package.zip` (Self-contained ADL SCORM 1.2 package ready for Workday, Cornerstone, Docebo, Moodle, or SCORM Cloud)
2. `qti21_bank.zip` (IMS QTI 2.1 assessment package ready for Canvas, Brightspace, or Blackboard)
3. `source_lineage_receipt.json` (Paragraph-level citation table mapping every lesson block and quiz item to character offsets `[start_char, end_char]` and `SHA-256` paragraph digests)

---

## Programmatic ESM Usage

```js
import fs from "node:fs";
import { compileSopToPackages, diffSopRevisions } from "sop2scorm";

const sopMd = fs.readFileSync("./examples/acmecloud_nist_800_61r3_sop.md", "utf8");
const quiz = JSON.parse(fs.readFileSync("./examples/acmecloud_quiz.json", "utf8"));

const { scormZipBytes, qtiZipBytes, receipt } = await compileSopToPackages(sopMd, {
  courseId: "ACME_NIST_800_61R3",
  masteryScore: 80,
  quizItems: quiz,
  reproducible: true,
  strict: true
});
```

---

## License

MIT License. See [LICENSE](./LICENSE).
