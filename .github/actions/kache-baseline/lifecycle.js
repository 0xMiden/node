const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

// The post hook runs after kache's own cleanup, when its local store is idle.
const helper = path.join(__dirname, "baseline.py");
let args;
if (process.env.STATE_baseline) {
  args = [helper, "publish", "--state", process.env.STATE_baseline];
} else {
  const state = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "kache-base-")), "state.json");
  fs.appendFileSync(process.env.GITHUB_STATE, `baseline=${state}\n`);
  args = [helper, "restore", "--state", state];
  for (const name of [
    "job-key",
    "cache-version",
    "binary",
    "config",
    "bucket",
    "region",
    "download-endpoint",
    "writable",
    "cache-dir",
    "runtime-dir",
  ]) {
    const value = process.env[`INPUT_${name.toUpperCase()}`];
    if (value) args.push(`--${name}`, value);
  }
}
const result = spawnSync("python3", args, { stdio: "inherit" });
if (result.error || result.status !== 0) {
  console.log(`::warning::Kache baseline helper failed: ${result.error || result.status}`);
}
