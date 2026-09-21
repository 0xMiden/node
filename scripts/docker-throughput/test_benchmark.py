"""Check benchmark measurements and cache isolation."""

import json
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

import benchmark


class BenchmarkTests(unittest.TestCase):
    def test_batches_submit_builds_concurrently_and_report_failures(self):
        ready = threading.Barrier(2)

        def fake_build(*args):
            ready.wait(timeout=5)
            return {"exit_code": int(args[-1] == "failed")}

        samples = [{"pr": 1, "revision": "ok"}, {"pr": 2, "revision": "failed"}]
        with tempfile.TemporaryDirectory() as directory, patch.object(benchmark, "build", fake_build):
            result = benchmark.batch(None, None, {"ok": None, "failed": None},
                                     Path(directory) / "batch", "linux/amd64", samples, True)
        self.assertFalse(result["success"])
        self.assertEqual(len(result["builds"]), 2)

    def test_failed_batch_has_no_throughput_ratio(self):
        results = [
            dict(round=1, mode="baseline", batch=dict(elapsed_seconds=10, success=True, builds=[{}])),
            dict(round=1, mode="candidate", batch=dict(elapsed_seconds=5, success=False, builds=[{}])),
        ]
        report = benchmark.summary(results)
        self.assertIn("Failed", report)
        self.assertNotIn("paired throughput ratio", report)

    def test_ratio_compares_total_batch_time(self):
        results = [
            dict(round=1, mode="baseline", batch=dict(elapsed_seconds=20, success=True, builds=[{}, {}])),
            dict(round=1, mode="candidate", batch=dict(elapsed_seconds=10, success=True, builds=[{}, {}])),
        ]
        report = benchmark.summary(results)
        self.assertIn("2.000x", report)
        self.assertIn("720.00", report)

    def test_cleanup_failure_excludes_the_pair(self):
        results = [
            dict(round=1, mode="baseline", batch=dict(elapsed_seconds=20, success=True, builds=[{}])),
            dict(round=1, mode="candidate", error="cleanup failed",
                 batch=dict(elapsed_seconds=10, success=True, builds=[{}])),
        ]
        self.assertNotIn("paired throughput ratio", benchmark.summary(results))

    def test_rejects_unsafe_cache_namespaces(self):
        for invalid in ("", "../other", "test.*", "test|production"):
            with self.assertRaises(ValueError):
                benchmark.prune_command(invalid)
            with self.assertRaises(ValueError):
                benchmark.scoped_dockerfile("", invalid)

    def test_rejects_a_cache_mount_without_an_id(self):
        with self.assertRaises(ValueError):
            benchmark.scoped_dockerfile("RUN --mount=type=cache,target=/cache true", "test-123")

    def test_build_records_a_failed_docker_process(self):
        def failed_process(args, **kwargs):
            kwargs["stdout"].write("compiler failed\n")
            return subprocess.CompletedProcess(args, 17)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            with patch.object(benchmark.subprocess, "run", failed_process):
                record = benchmark.build(path / "bake.hcl", path / "Dockerfile", path,
                                         path / "result", "linux/amd64", "", "revision")
            stored = json.loads((path / "result/timing.json").read_text())
            self.assertEqual(record, stored)
            self.assertEqual(record["exit_code"], 17)
            self.assertIn("compiler failed", (path / "result/build.log").read_text())


if __name__ == "__main__":
    unittest.main()
