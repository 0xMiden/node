"""Replay a small workload through the benchmark and a real BuildKit builder."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid


@unittest.skipUnless(os.environ.get("DOCKER_THROUGHPUT_INTEGRATION") == "1",
                     "Set DOCKER_THROUGHPUT_INTEGRATION=1 to use Docker")
class BuildKitTest(unittest.TestCase):
    def test_replay_and_cache_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="throughput-test-") as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()

            def git(*args):
                return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()

            git("init", "-b", "fixture")
            git("config", "user.name", "Benchmark fixture")
            git("config", "user.email", "benchmark@example.invalid")
            for name in (".cargo", "bin", "crates", "proto", "xtask/src"):
                (repo / name).mkdir(parents=True, exist_ok=True)
            for name in ("Cargo.toml", "Cargo.lock", ".cargo/config.toml", "bin/input",
                         "crates/input", "proto/input", "xtask/Cargo.toml", "xtask/src/main.rs"):
                (repo / name).write_text("base\n")
            canary = "throughput-canary-" + uuid.uuid4().hex
            (repo / "Dockerfile").write_text('''FROM alpine:3.23 AS control
RUN --mount=type=cache,id=CANARY,target=/cache \\
    touch /cache/control
FROM alpine:3.23 AS build-base
WORKDIR /app
FROM build-base AS builder
ARG BUILD_CACHE_SUFFIX
COPY crates/ crates/
RUN --mount=type=cache,sharing=locked,id=fixture${BUILD_CACHE_SUFFIX},target=/cache \\
    count=0 && \\
    if [ -f /cache/count ]; then count="$(cat /cache/count)"; fi && \\
    count=$((count + 1)) && printf '%s' "$count" > /cache/count && \\
    sleep 2 && printf '%s' "$count" > /app/kache-report.md
FROM scratch AS build-report
COPY --from=builder /app/kache-report.md /kache-report.md
'''.replace("CANARY", canary))
            (repo / "docker-bake.hcl").write_text('''group "validate" { targets = ["build-report"] }
target "build-report" {
  context = "."
  dockerfile = "Dockerfile"
  target = "build-report"
  output = ["type=local,dest=./kache-report"]
}
''')
            subprocess.run(["docker", "buildx", "build", "--target", "control", str(repo)], check=True)
            git("add", ".")
            git("commit", "-m", "Warm-up")
            warmup = git("rev-parse", "HEAD")
            samples = []
            for pr in (1, 2):
                (repo / "crates/input").write_text(f"source revision {pr}\n")
                git("add", ".")
                git("commit", "-m", f"Sample {pr}")
                samples.append(dict(pr=pr, revision=git("rev-parse", "HEAD")))
            workload = root / "workload.json"
            workload.write_text(json.dumps(dict(baseline=warmup, candidate=warmup,
                                                warmup=warmup, samples=samples)))
            architecture = subprocess.check_output(
                ["docker", "version", "--format", "{{.Server.Arch}}"], text=True).strip()
            output = root / "results"
            try:
                subprocess.run([sys.executable, str(Path(__file__).with_name("benchmark.py")),
                                "--repo", str(repo), "--workload", str(workload),
                                "--platform", f"linux/{architecture}", "--rounds", "2",
                                "--output", str(output)], check=True)
                results = json.loads((output / "results.json").read_text())
                self.assertEqual([r["mode"] for r in results],
                                 ["baseline", "candidate", "candidate", "baseline"])
                for trial in results:
                    self.assertTrue(trial["batch"]["success"])
                    for phase in ("warmup", "batch"):
                        for build in trial[phase]["builds"]:
                            self.assertGreaterEqual(build["elapsed_seconds"], 1.9)
                    folder = output / f"{trial['round']}-{trial['mode']}"
                    counts = sorted(int(p.read_text()) for p in
                                    (folder / "measured").glob("*/report/kache-report.md"))
                    self.assertEqual(counts, [2, 3] if trial["mode"] == "baseline" else [2, 2])
                    for report in (folder / "warmup").glob("*/report/kache-report.md"):
                        self.assertEqual(report.read_text(), "1")
                usage = subprocess.check_output(
                    ["docker", "buildx", "du", "--format", "json", "--filter", "type=exec.cachemount"],
                    text=True)
                self.assertIn(canary, usage)
                for dockerfile in output.glob("*/Dockerfile"):
                    namespace = dockerfile.read_text().split("id=docker-benchmark-")[1].split("-" + canary)[0]
                    self.assertNotIn("docker-benchmark-" + namespace, usage)
            finally:
                subprocess.run(["docker", "buildx", "prune", "--force", "--filter",
                                "type=exec.cachemount", "--filter", f"description~={canary}"], check=True)


if __name__ == "__main__":
    unittest.main()
