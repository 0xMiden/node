import argparse
import contextlib
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import threading
import time
import unittest
from unittest import mock

import baseline


def key(name):
    return hashlib.sha256(name.encode()).hexdigest()


def state(root, branch="next"):
    return {
        "repository": "0xMiden/node",
        "branch": branch,
        "job": "tests",
        "platform": "Linux-X64",
        "cache_version": "test-version",
        "writable": True,
        "cache": str(root / "cache"),
        "runtime": str(root / "runtime"),
        "binary": "/usr/bin/true",
        "config": str(root / "config.toml"),
        "bucket": "test-bucket",
        "region": "eu-north-1",
        "restore_ok": True,
        "workflow": "node/ci",
        "run_number": 2,
    }


def metadata(st, keys, archive=b"archive"):
    digest = hashlib.sha256(archive).hexdigest()
    return baseline.identity(st) | {
        "format": 1,
        "created_at": time.time(),
        "artifact_keys": sorted(keys),
        "archive": f"protected-branch/baselines/v1/archives/{digest}.tar.zst",
        "sha256": digest,
        "archive_bytes": len(archive),
        "workflow": st["workflow"],
        "run_number": st["run_number"],
    }


@contextlib.contextmanager
def cdn():
    objects = {}
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            obj = objects.get(self.path.lstrip("/"))
            if isinstance(obj, tuple):
                self.send_response(302)
                self.send_header("Location", obj[0])
                self.end_headers()
                return
            if obj is None:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(obj)))
            self.send_header("ETag", '"' + hashlib.sha256(obj).hexdigest() + '"')
            self.end_headers()
            self.wfile.write(obj)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", objects, requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def seed_cache(root):
    cache = root / "cache"
    (cache / "store").mkdir(parents=True)
    (cache / "store" / "artifact").write_bytes(b"compiled artifact")
    with contextlib.closing(sqlite3.connect(cache / "index.db")) as db, db:
        db.execute("CREATE TABLE entries (cache_key TEXT, committed INTEGER)")
        db.execute("INSERT INTO entries VALUES (?, 1)", (key("one"),))
    return cache


class PolicyTests(unittest.TestCase):
    def test_branch_baselines_are_separate_and_prs_use_their_target(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.assertNotEqual(
                baseline.metadata_key(state(root)),
                baseline.metadata_key(state(root, "release/v0.18")),
            )
            self.assertNotEqual(
                baseline.metadata_key(state(root, "release/v0.18")),
                baseline.metadata_key(state(root, "release/v0.19")),
            )
            for branch in ["next", "release/v0.18", "release/v0.19"]:
                self.assertEqual(
                    baseline.branch_for({"GITHUB_REF": "refs/heads/" + branch}), branch
                )
                self.assertEqual(
                    baseline.branch_for(
                        {"GITHUB_REF": "refs/pull/123/merge", "GITHUB_BASE_REF": branch}
                    ),
                    branch,
                )
            self.assertEqual(
                baseline.branch_for({"GITHUB_REF": "refs/tags/v0.18.3"}),
                "release/v0.18",
            )
            self.assertEqual(
                baseline.branch_for({"GITHUB_REF": "refs/heads/feature"}), "next"
            )
            event = root / "event.json"
            event.write_text(
                json.dumps({"merge_group": {"base_ref": "refs/heads/release/v0.18"}})
            )
            self.assertEqual(
                baseline.branch_for(
                    {
                        "GITHUB_EVENT_NAME": "merge_group",
                        "GITHUB_EVENT_PATH": str(event),
                    }
                ),
                "release/v0.18",
            )

    def test_only_protected_pushes_publish_their_own_branch(self):
        with tempfile.TemporaryDirectory() as folder:
            for branch in ["next", "release/v0.18"]:
                st = state(Path(folder), branch)
                env = {
                    "GITHUB_EVENT_NAME": "push",
                    "GITHUB_REF_PROTECTED": "true",
                    "GITHUB_REF": "refs/heads/" + branch,
                    "GITHUB_REPOSITORY": "0xMiden/node",
                }
                self.assertTrue(baseline.may_publish(st, env))
                for change in [
                    {"GITHUB_EVENT_NAME": "pull_request"},
                    {"GITHUB_EVENT_NAME": "workflow_dispatch"},
                    {"GITHUB_REF_PROTECTED": "false"},
                    {"GITHUB_REF": "refs/heads/feature"},
                    {"GITHUB_REPOSITORY": "fork/node"},
                ]:
                    self.assertFalse(baseline.may_publish(st, env | change))
                self.assertFalse(baseline.may_publish(st | {"writable": False}, env))

    def test_missing_artifact_and_age_thresholds(self):
        st = state(Path("/tmp"))
        needed = {key(str(i)) for i in range(100)}
        covered = sorted(needed)
        meta = metadata(st, covered[:96])
        now = meta["created_at"]
        self.assertIsNone(baseline.refresh_reason(meta, needed, now))
        self.assertIsNotNone(
            baseline.refresh_reason(meta | {"artifact_keys": covered[:95]}, needed, now)
        )
        self.assertIsNone(baseline.refresh_reason(meta, needed, now + 604799))
        self.assertIsNotNone(baseline.refresh_reason(meta, needed, now + 604800))
        self.assertIsNotNone(baseline.refresh_reason(None, needed, now))
        self.assertIsNone(baseline.refresh_reason(None, set(), now))

    def test_metadata_is_bound_to_branch_job_version_and_archive(self):
        st = state(Path("/tmp"))
        meta = metadata(st, [key("one")])
        self.assertEqual(
            baseline.decode_metadata(json.dumps(meta), st, time.time()), meta
        )
        for change in [
            {"branch": "release/v0.18"},
            {"job": "other"},
            {"cache_version": "old"},
            {"archive": "https://s3.example/file"},
            {"artifact_keys": ["../escape"]},
            {"archive_bytes": -1},
            {"created_at": time.time() + 100},
            {"run_number": "invalid"},
            {"workflow": None},
        ]:
            with self.assertRaises(ValueError):
                baseline.decode_metadata(json.dumps(meta | change), st, time.time())


class DownloadTests(unittest.TestCase):
    def test_reads_use_the_cdn_and_redirects_do_not_escape_it(self):
        with cdn() as (url, objects, requests):
            objects["file"] = b"hello"
            objects["redirect"] = ("http://127.0.0.1:1/s3",)
            remote = baseline.CloudFront(url)
            self.assertEqual(remote.get("file")[0], b"hello")
            self.assertIsNone(remote.get("missing"))
            with self.assertRaises(Exception):
                remote.get("redirect")
            with self.assertRaises(ValueError):
                remote.get("file", size_limit=4)
            self.assertEqual(requests, ["/file", "/missing", "/redirect", "/file"])
        for endpoint in [
            "http://s3.example",
            "https://user:password@cdn.example",
            "https://cdn.example/?q=1",
        ]:
            with self.assertRaises(ValueError):
                baseline.CloudFront(endpoint)


@unittest.skipUnless(shutil.which("zstd"), "zstd is required for archive tests")
class SnapshotTests(unittest.TestCase):
    def test_restore_uses_target_branch_and_rejects_corrupt_archives(self):
        with tempfile.TemporaryDirectory() as folder, cdn() as (url, objects, requests):
            root = Path(folder)
            cache = seed_cache(root)
            checkpoint = root / "checkpoint"
            checkpoint.mkdir()
            archive = root / "snapshot.zst"
            baseline.make_archive(cache, archive, checkpoint)
            st = state(root, "release/v0.18")
            meta = metadata(st, [key("one")], archive.read_bytes())
            objects[baseline.metadata_key(st)] = json.dumps(meta).encode()
            objects[meta["archive"]] = archive.read_bytes()
            output = root / "outputs"
            env = {
                "GITHUB_WORKSPACE": str(root / "workspace"),
                "GITHUB_REPOSITORY": "0xMiden/node",
                "GITHUB_REF": "refs/pull/123/merge",
                "GITHUB_BASE_REF": "release/v0.18",
                "RUNNER_OS": "Linux",
                "RUNNER_ARCH": "X64",
                "GITHUB_OUTPUT": str(output),
            }
            args = argparse.Namespace(
                command="restore",
                state=str(root / "state.json"),
                cache_dir=str(root / "consumer"),
                runtime_dir=str(root / "runtime"),
                cache_version="test-version",
                job_key="tests",
                writable="false",
                binary="unused",
                config="unused",
                bucket="test",
                region="eu-north-1",
                download_endpoint=url,
            )
            baseline.restore(args, env)
            self.assertTrue(json.loads(Path(args.state).read_text())["restore_ok"])
            self.assertEqual(
                requests, ["/" + baseline.metadata_key(st), "/" + meta["archive"]]
            )
            self.assertEqual(
                (root / "consumer" / "store" / "artifact").read_bytes(),
                b"compiled artifact",
            )
            objects[meta["archive"]] = b"corrupt"
            args.cache_dir = str(root / "corrupt-consumer")
            baseline.restore(args, env)
            self.assertFalse(json.loads(Path(args.state).read_text())["restore_ok"])
            self.assertEqual(list(Path(args.cache_dir).iterdir()), [])

    def test_snapshot_restores_database_and_artifacts_without_runtime_or_upload_queue(
        self,
    ):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            cache = seed_cache(root)
            (cache / "store" / "artifact").chmod(0o444)
            (cache / "daemon.sock").write_bytes(b"runtime")
            (cache / "upload-queue").mkdir()
            (cache / "upload-queue" / "pending").write_text("do not replay")
            checkpoint = root / "checkpoint"
            checkpoint.mkdir()
            archive = root / "snapshot.tar.zst"
            self.assertEqual(
                baseline.make_archive(cache, archive, checkpoint), {key("one")}
            )
            restored = root / "restored"
            baseline.extract_archive(archive, restored)
            self.assertEqual(
                (restored / "store" / "artifact").read_bytes(), b"compiled artifact"
            )
            self.assertEqual(
                (restored / "store" / "artifact").stat().st_mode & 0o777, 0o444
            )
            self.assertEqual(
                {p.name for p in restored.iterdir()}, {"store", "index.db"}
            )
            with contextlib.closing(sqlite3.connect(restored / "index.db")) as db:
                self.assertEqual(
                    db.execute("SELECT cache_key FROM entries").fetchone()[0],
                    key("one"),
                )

    def test_unsafe_archives_do_not_create_a_partial_cache(self):
        for name in ["../escape", "/escape", "store/../../escape", "unexpected/file"]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                raw = root / "bad.tar"
                with tarfile.open(raw, "w") as tar:
                    member = tarfile.TarInfo(name)
                    member.size = 1
                    tar.addfile(member, io.BytesIO(b"x"))
                archive = root / "bad.tar.zst"
                subprocess.run(
                    ["zstd", "--quiet", str(raw), "-o", str(archive)], check=True
                )
                with self.assertRaises(ValueError):
                    baseline.extract_archive(archive, root / "restored")
                self.assertFalse((root / "restored").exists())

    def test_unchanged_job_does_not_compress_or_upload(self):
        with tempfile.TemporaryDirectory() as folder, cdn() as (url, objects, requests):
            root = Path(folder)
            st = state(root)
            st["download_endpoint"] = url
            Path(st["runtime"]).mkdir()
            (Path(st["runtime"]) / "events.jsonl").write_text(
                json.dumps({"result": "local_hit", "cache_key": key("one")}) + "\n"
            )
            objects[baseline.metadata_key(st)] = json.dumps(
                metadata(st, [key("one")])
            ).encode()
            saved = root / "state.json"
            saved.write_text(json.dumps(st))
            env = {
                "GITHUB_EVENT_NAME": "push",
                "GITHUB_REF": "refs/heads/next",
                "GITHUB_REF_PROTECTED": "true",
                "GITHUB_REPOSITORY": "0xMiden/node",
            }
            with (
                mock.patch.object(
                    baseline,
                    "make_archive",
                    side_effect=AssertionError("must not compress"),
                ),
                mock.patch.object(
                    baseline.subprocess,
                    "run",
                    side_effect=AssertionError("must not upload"),
                ),
            ):
                baseline.publish(argparse.Namespace(state=str(saved)), env)
            self.assertEqual(requests, ["/" + baseline.metadata_key(st)])

    def test_refresh_uploads_archive_before_conditionally_publishing_metadata(self):
        with tempfile.TemporaryDirectory() as folder, cdn() as (url, objects, requests):
            root = Path(folder)
            seed_cache(root)
            st = state(root)
            st["download_endpoint"] = url
            Path(st["runtime"]).mkdir()
            (Path(st["runtime"]) / "events.jsonl").write_text(
                json.dumps({"result": "local_hit", "cache_key": key("one")}) + "\n"
            )
            saved = root / "state.json"
            saved.write_text(json.dumps(st))
            env = {
                "GITHUB_EVENT_NAME": "push",
                "GITHUB_REF": "refs/heads/next",
                "GITHUB_REF_PROTECTED": "true",
                "GITHUB_REPOSITORY": "0xMiden/node",
                "PATH": os.environ["PATH"],
            }
            calls = []
            original = subprocess.run

            def command(args, **kwargs):
                if args[0] != "aws":
                    return original(args, **kwargs)
                calls.append(args)
                if args[1:3] == ["s3", "cp"]:
                    archive_key = args[4].removeprefix("s3://test-bucket/")
                    objects[archive_key] = Path(args[3]).read_bytes()
                else:
                    self.assertIn("--if-none-match", args)
                    obj = Path(args[args.index("--body") + 1]).read_bytes()
                    meta = json.loads(obj)
                    self.assertIn(meta["archive"], objects)
                    objects[args[args.index("--key") + 1]] = obj
                return subprocess.CompletedProcess(args, 0)

            with mock.patch.object(baseline.subprocess, "run", side_effect=command):
                baseline.publish(argparse.Namespace(state=str(saved)), env)
            self.assertEqual(len(calls), 2)
            meta = baseline.decode_metadata(
                objects[baseline.metadata_key(st)], st, time.time()
            )
            archive = root / "download.tar.zst"
            archive.write_bytes(objects[meta["archive"]])
            baseline.extract_archive(archive, root / "consumer")
            self.assertEqual(
                (root / "consumer" / "store" / "artifact").read_bytes(),
                b"compiled artifact",
            )

    def test_older_run_cannot_replace_a_newer_baseline(self):
        with tempfile.TemporaryDirectory() as folder, cdn() as (url, objects, requests):
            root = Path(folder)
            st = state(root)
            st["download_endpoint"] = url
            newer = metadata(st, [key("newer")]) | {"run_number": 3}
            original = json.dumps(newer).encode()
            objects[baseline.metadata_key(st)] = original
            saved = root / "state.json"
            saved.write_text(json.dumps(st))
            env = {
                "GITHUB_EVENT_NAME": "push",
                "GITHUB_REF": "refs/heads/next",
                "GITHUB_REF_PROTECTED": "true",
                "GITHUB_REPOSITORY": "0xMiden/node",
            }
            with mock.patch.object(
                baseline.subprocess,
                "run",
                side_effect=AssertionError("must not upload"),
            ):
                baseline.publish(argparse.Namespace(state=str(saved)), env)
            self.assertEqual(objects[baseline.metadata_key(st)], original)

    def test_failed_metadata_upload_preserves_previous_baseline(self):
        with tempfile.TemporaryDirectory() as folder, cdn() as (url, objects, requests):
            root = Path(folder)
            seed_cache(root)
            st = state(root)
            st["download_endpoint"] = url
            Path(st["runtime"]).mkdir()
            (Path(st["runtime"]) / "events.jsonl").write_text(
                json.dumps({"result": "local_hit", "cache_key": key("one")}) + "\n"
            )
            old = json.dumps(metadata(st, [key("old")])).encode()
            objects[baseline.metadata_key(st)] = old
            saved = root / "state.json"
            saved.write_text(json.dumps(st))
            env = {
                "GITHUB_EVENT_NAME": "push",
                "GITHUB_REF": "refs/heads/next",
                "GITHUB_REF_PROTECTED": "true",
                "GITHUB_REPOSITORY": "0xMiden/node",
                "PATH": os.environ["PATH"],
            }
            original = subprocess.run
            uploads = []

            def command(args, **kwargs):
                if args[0] != "aws":
                    return original(args, **kwargs)
                uploads.append(args)
                if args[1:3] == ["s3api", "put-object"]:
                    self.assertEqual(
                        args[args.index("--if-match") + 1],
                        '"' + hashlib.sha256(old).hexdigest() + '"',
                    )
                    raise subprocess.CalledProcessError(412, args)
                return subprocess.CompletedProcess(args, 0)

            with (
                mock.patch.object(baseline.subprocess, "run", side_effect=command),
                self.assertRaises(subprocess.CalledProcessError),
            ):
                baseline.publish(argparse.Namespace(state=str(saved)), env)
            self.assertEqual(len(uploads), 2)
            self.assertEqual(objects[baseline.metadata_key(st)], old)


@unittest.skipUnless(
    os.environ.get("KACHE_TEST_BINARY") and shutil.which("zstd"),
    "set KACHE_TEST_BINARY to exercise real Cargo restores",
)
class CargoRestoreTests(unittest.TestCase):
    def test_fresh_store_hits_and_changed_sources_rebuild(self):
        binary = str(Path(os.environ["KACHE_TEST_BINARY"]).resolve())
        with tempfile.TemporaryDirectory(prefix="kache-cargo-") as folder:
            root = Path(folder)
            project = root / "project"
            (project / "src").mkdir(parents=True)
            (project / "Cargo.toml").write_text(
                '[package]\nname="baseline-check"\nversion="0.1.0"\nedition="2024"\n[workspace]\n'
            )
            source = project / "src" / "lib.rs"
            generated = 'include!(concat!(env!("OUT_DIR"), "/generated.rs"));\n'
            source.write_text(generated + "pub fn answer() -> u32 { GENERATED + 42 }\n")
            (project / "build.rs").write_text(
                "fn main() {\n"
                '    println!("cargo:rerun-if-changed=build.rs");\n'
                '    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());\n'
                '    std::fs::write(out.join("generated.rs"), "const GENERATED: u32 = 7;").unwrap();\n'
                "}\n"
            )
            config = root / "kache.toml"
            config.write_text("[cache]\nlocal_only=true\n")
            env = dict(os.environ) | {
                "KACHE_CONFIG": str(config),
                "KACHE_HOST_CONFIG": "",
                "KACHE_CI_BUNDLES": "false",
                "KACHE_CACHE_DIR": str(root / "producer"),
                "KACHE_RUNTIME_DIR": str(root / "producer-run"),
                "KACHE_BASE_DIR": str(project),
                "KACHE_CACHE_EXECUTABLES": "1",
                "CARGO_INCREMENTAL": "0",
                "RUSTC_WRAPPER": binary,
                "RUSTC_WORKSPACE_WRAPPER": "",
            }

            def command(args, current=env):
                subprocess.run(
                    args,
                    env=current,
                    cwd=project,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )

            command([binary, "daemon", "start"])
            try:
                command(["cargo", "build", "--offline"])
            finally:
                command([binary, "daemon", "stop"])
            checkpoint = root / "checkpoint"
            checkpoint.mkdir()
            archive = root / "snapshot.zst"
            baseline.make_archive(root / "producer", archive, checkpoint)
            for changed in [False, True]:
                command(["cargo", "clean"])
                if changed:
                    source.write_text(
                        generated + "pub fn answer() -> u32 { GENERATED + 43 }\n"
                    )
                cache = root / f"consumer-{changed}"
                baseline.extract_archive(archive, cache)
                consumer = env | {
                    "KACHE_CACHE_DIR": str(cache),
                    "KACHE_RUNTIME_DIR": str(root / f"consumer-run-{changed}"),
                }
                command([binary, "daemon", "start"], consumer)
                try:
                    command(["cargo", "build", "--offline"], consumer)
                    report = root / f"report-{changed}.json"
                    command(
                        [
                            binary,
                            "stats",
                            "--full",
                            "--format",
                            "json",
                            "--output",
                            str(report),
                        ],
                        consumer,
                    )
                    summary = json.loads(report.read_text())["summary"]
                    if changed:
                        self.assertGreater(summary["misses"], 0)
                    else:
                        self.assertGreater(summary["local_hits"], 0)
                        self.assertEqual(summary["misses"], 0)
                finally:
                    command([binary, "daemon", "stop"], consumer)


if __name__ == "__main__":
    unittest.main()
