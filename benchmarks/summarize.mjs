// Folds repeated benchmark runs (benchmark-results/<name>-run<N>.json) into medians: node benchmarks/summarize.mjs
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

const dir = "benchmark-results";
const median = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : +((s[m - 1] + s[m]) / 2).toFixed(3);
};
const runs = (prefix) =>
  readdirSync(dir)
    .filter((f) => new RegExp(`^${prefix}-run\\d+\\.json$`).test(f))
    .map((f) => JSON.parse(readFileSync(`${dir}/${f}`, "utf8")));

const summary = {};
for (const [name, prefix] of [["append", "append-throughput"], ["appendNpgsql8k", "append-throughput-npgsql-8k"]]) {
  const all = runs(prefix);
  if (!all.length) continue;
  summary[name] = all[0].map((row, i) => ({
    mode: row.mode,
    runs: all.length,
    entriesPerSecond: median(all.map((r) => r[i].entriesPerSecond)),
    entriesPerSecondAllRuns: all.map((r) => r[i].entriesPerSecond),
    latencyMsP50: median(all.map((r) => r[i].latencyMsP50)),
    latencyMsP95: median(all.map((r) => r[i].latencyMsP95)),
    latencyMsP99: median(all.map((r) => r[i].latencyMsP99)),
  }));
}

const proofs = runs("proof-latency");
if (proofs.length) {
  summary.proofs = {
    runs: proofs.length,
    checkpoints: proofs[0].checkpoints.map((c, i) => {
      const out = { treeSize: c.treeSize, inclusionProofHashes: c.inclusionProofHashes };
      for (const k of ["inclusionMsP50", "inclusionMsP95", "inclusionMsP99", "consistencyMsP50", "consistencyMsP95"]) {
        out[k] = median(proofs.map((p) => p.checkpoints[i][k]));
      }
      return out;
    }),
    loadSeconds: median(proofs.map((p) => p.loadSeconds)),
    tableSize: proofs.map((p) => p.tableSize),
    fullAuditSeconds: median(proofs.map((p) => p.fullAudit.seconds)),
    fullAuditRowsPerSecond: median(proofs.map((p) => p.fullAudit.rowsPerSecond)),
    fullAuditClean: proofs.every((p) => p.fullAudit.clean),
  };
}

writeFileSync(`${dir}/summary.json`, JSON.stringify(summary, null, 2));
console.log(JSON.stringify(summary, null, 2));
