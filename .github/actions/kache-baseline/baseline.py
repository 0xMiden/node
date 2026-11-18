#!/usr/bin/env python3
"""Bootstrap kache from branch-specific local-store snapshots through CloudFront."""

import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


FORMAT = 1
MAX_AGE = 7 * 24 * 60 * 60
MISSING_FRACTION = 0.05
MAX_METADATA = 16 << 20
MAX_ARCHIVE = 64 << 30
MAX_FILES = 500_000
KEY = re.compile(r"[a-f0-9]{64}\Z")
BRANCH = re.compile(r"(?:next|release/v[A-Za-z0-9][A-Za-z0-9._-]*)\Z")


def branch_for(env):
    """Select the target branch whose baseline this job consumes."""
    ref = env.get("GITHUB_BASE_REF") or env.get("GITHUB_REF", "")
    if env.get("GITHUB_EVENT_NAME") == "merge_group":
        event = json.loads(Path(env["GITHUB_EVENT_PATH"]).read_text())
        ref = event.get("merge_group", {}).get("base_ref", ref)
    if ref.startswith("refs/tags/"):
        match = re.fullmatch(r"refs/tags/v(\d+\.\d+)\.\d+(?:[-+].*)?", ref)
        ref = f"release/v{match[1]}" if match else "next"
    ref = ref.removeprefix("refs/heads/")
    return ref if BRANCH.fullmatch(ref) else "next"


def may_publish(state, env):
    return (
        state["writable"]
        and env.get("GITHUB_EVENT_NAME") == "push"
        and env.get("GITHUB_REF_PROTECTED") == "true"
        and env.get("GITHUB_REF") == "refs/heads/" + state["branch"]
        and env.get("GITHUB_REPOSITORY") == state["repository"]
    )


def identity(state):
    return {
        key: state[key]
        for key in ["repository", "branch", "job", "platform", "cache_version"]
    }


def metadata_key(state):
    parts = [
        state[key]
        for key in ["repository", "branch", "job", "platform", "cache_version"]
    ]
    return (
        "protected-branch/baselines/v1/manifests/" + "/".join(parts) + "/current.json"
    )


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


class CloudFront:
    """Reads baseline objects exclusively through the configured CDN endpoint."""

    def __init__(self, endpoint):
        url = urllib.parse.urlsplit(endpoint)
        if url.scheme != "https" and not (
            url.scheme == "http" and url.hostname in {"127.0.0.1", "localhost", "::1"}
        ):
            raise ValueError("baseline downloads require HTTPS")
        if not url.netloc or url.username or url.password or url.query or url.fragment:
            raise ValueError("baseline download endpoint must be a plain base URL")
        self.endpoint = endpoint.rstrip("/")

    def get(self, key, destination=None, size_limit=MAX_METADATA):
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None

        url = self.endpoint + "/" + urllib.parse.quote(key, safe="/")
        opener = urllib.request.build_opener(NoRedirect())
        try:
            response = opener.open(url, timeout=30)
        except urllib.error.HTTPError as error:
            error.close()
            if error.code == 404:
                return None
            raise
        with response:
            advertised = response.headers.get("Content-Length")
            if advertised and int(advertised) > size_limit:
                raise ValueError("baseline object exceeds download limit")
            body = bytearray()
            count = 0
            while chunk := response.read(1 << 20):
                count += len(chunk)
                if count > size_limit:
                    raise ValueError("baseline object exceeds download limit")
                if destination is None:
                    body.extend(chunk)
                else:
                    destination.write(chunk)
            if advertised is not None and count != int(advertised):
                raise ValueError("incomplete baseline download")
            return bytes(body), response.headers.get("ETag"), count


def decode_metadata(body, state, now):
    meta = json.loads(body)
    if (
        not isinstance(meta, dict)
        or meta.get("format") != FORMAT
        or any(meta.get(key) != value for key, value in identity(state).items())
    ):
        raise ValueError("baseline identity or format mismatch")
    keys = meta.get("artifact_keys")
    if (
        not isinstance(keys, list)
        or len(keys) > 100_000
        or any(not isinstance(k, str) or not KEY.fullmatch(k) for k in keys)
    ):
        raise ValueError("invalid baseline artifact keys")
    digest = meta.get("sha256", "")
    expected = f"protected-branch/baselines/v1/archives/{digest}.tar.zst"
    if (
        not isinstance(digest, str)
        or not KEY.fullmatch(digest)
        or meta.get("archive") != expected
    ):
        raise ValueError("invalid baseline archive binding")
    if (
        type(meta.get("archive_bytes")) is not int
        or not 0 < meta["archive_bytes"] <= MAX_ARCHIVE
    ):
        raise ValueError("invalid baseline archive size")
    if (
        not isinstance(meta.get("created_at"), (int, float))
        or not 0 < meta["created_at"] <= now
    ):
        raise ValueError("invalid baseline creation time")
    if (
        not isinstance(meta.get("workflow"), str)
        or type(meta.get("run_number")) is not int
    ):
        raise ValueError("invalid baseline producer")
    return meta


def read_metadata(remote, state):
    result = remote.get(metadata_key(state))
    if result is None:
        return None, None
    body, etag, _ = result
    try:
        return decode_metadata(body, state, time.time()), etag
    except (ValueError, TypeError):
        return None, etag


def used_keys(runtime):
    keys = set()
    path = Path(runtime) / "events.jsonl"
    if path.exists():
        for line in path.read_text().splitlines():
            event = json.loads(line)
            key = event.get("cache_key", "")
            if KEY.fullmatch(key) and event.get("result") in {
                "local_hit",
                "remote_hit",
                "prefetch_hit",
                "miss",
                "dup",
            }:
                keys.add(key)
    return keys


def refresh_reason(meta, needed, now):
    if not needed:
        return None
    if meta is None:
        return "missing or invalid baseline"
    if now - meta["created_at"] >= MAX_AGE:
        return "baseline is at least seven days old"
    missing = len(needed.difference(meta["artifact_keys"]))
    print(
        f"Kache baseline coverage: {len(needed) - missing}/{len(needed)} artifacts; {missing / len(needed):.2%} missing"
    )
    if missing / len(needed) >= MISSING_FRACTION:
        return "at least five percent of needed artifacts are missing"
    return None


def extract_archive(archive, destination):
    """Restores persistent state into a fresh directory with bounded extraction."""

    def cache_filter(member, root):
        safe = tarfile.data_filter(member, root)
        if safe.isfile():
            safe.mode = member.mode & 0o755
        return safe

    destination = Path(destination).resolve()
    if destination.exists() and any(destination.iterdir()):
        raise ValueError("baseline restore needs an empty cache directory")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".kache-restore-", dir=destination.parent
    ) as folder:
        staging = Path(folder) / "cache"
        staging.mkdir()
        process = subprocess.Popen(
            ["zstd", "--decompress", "--stdout", str(archive)], stdout=subprocess.PIPE
        )
        try:
            total = 0
            count = 0
            with tarfile.open(fileobj=process.stdout, mode="r|") as stream:
                for member in stream:
                    path = PurePosixPath(member.name)
                    if (
                        path.is_absolute()
                        or ".." in path.parts
                        or not path.parts
                        or path.parts[0] not in {"store", "index.db"}
                    ):
                        raise ValueError("unexpected baseline archive path")
                    if not (member.isdir() or member.isfile() or member.islnk()):
                        raise ValueError("unsupported baseline archive member")
                    count += 1
                    total += member.size
                    if count > MAX_FILES or total > MAX_ARCHIVE:
                        raise ValueError("baseline expansion limit exceeded")
                    stream.extract(member, path=staging, filter=cache_filter)
            if process.wait() != 0:
                raise ValueError("baseline decompression failed")
            if not (staging / "store").is_dir() or not (staging / "index.db").is_file():
                raise ValueError("baseline is missing its persistent store")
            with closing(
                sqlite3.connect((staging / "index.db").as_uri() + "?mode=ro", uri=True)
            ) as db:
                if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise ValueError("baseline database is corrupt")
            if destination.exists():
                destination.rmdir()
            staging.rename(destination)
        finally:
            process.stdout.close()
            if process.poll() is None:
                process.kill()
            process.wait()


def make_archive(cache, archive, checkpoint):
    """Snapshots the idle database and compresses only persistent cache files."""
    cache = Path(cache)
    checkpoint = Path(checkpoint)
    with closing(
        sqlite3.connect((cache / "index.db").resolve().as_uri() + "?mode=ro", uri=True)
    ) as source:
        with closing(sqlite3.connect(checkpoint / "index.db")) as target:
            source.backup(target)
            keys = {
                row[0]
                for row in target.execute(
                    "SELECT cache_key FROM entries WHERE committed = 1"
                )
            }
    with tempfile.TemporaryFile() as errors, Path(archive).open("wb") as output:
        tar = subprocess.Popen(
            [
                "tar",
                "-cf",
                "-",
                "-C",
                str(cache),
                "store",
                "-C",
                str(checkpoint),
                "index.db",
            ],
            stdout=subprocess.PIPE,
            stderr=errors,
            env=os.environ | {"COPYFILE_DISABLE": "1"},
        )
        try:
            compressed = subprocess.run(
                ["zstd", "-T2", "-3", "--stdout"],
                stdin=tar.stdout,
                stdout=output,
                check=False,
            )
            tar.stdout.close()
            if compressed.returncode != 0 or tar.wait() != 0:
                errors.seek(0)
                raise RuntimeError(
                    "baseline snapshot failed: "
                    + errors.read().decode(errors="replace")
                )
        finally:
            if tar.poll() is None:
                tar.kill()
            tar.wait()
    if not 0 < Path(archive).stat().st_size <= MAX_ARCHIVE:
        raise ValueError("baseline archive exceeds size limit")
    return keys


def restore(args, env):
    workspace = Path(env["GITHUB_WORKSPACE"])
    cache = (
        Path(args.cache_dir) if args.cache_dir else workspace.parent / ".kache-cache"
    )
    runtime = (
        Path(args.runtime_dir)
        if args.runtime_dir
        else Path(tempfile.mkdtemp(prefix="kache-run-"))
    )
    runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
    state = {
        **vars(args),
        "branch": branch_for(env),
        "job": args.job_key,
        "repository": env["GITHUB_REPOSITORY"],
        "platform": env["RUNNER_OS"] + "-" + env["RUNNER_ARCH"],
        "cache_version": args.cache_version,
        "cache": str(cache),
        "runtime": str(runtime),
        "writable": args.writable == "true",
        "restore_ok": False,
        "workflow": env.get("GITHUB_WORKFLOW_REF"),
        "run_number": int(env.get("GITHUB_RUN_NUMBER", "0")),
    }
    try:
        remote = CloudFront(args.download_endpoint)
        meta, etag = read_metadata(remote, state)
        state["restored_etag"] = etag
        if meta:
            with tempfile.TemporaryDirectory(prefix="kache-download-") as folder:
                archive = Path(folder) / "baseline.tar.zst"
                with archive.open("wb") as output:
                    response = remote.get(
                        meta["archive"], output, meta["archive_bytes"]
                    )
                if (
                    response is None
                    or archive.stat().st_size != meta["archive_bytes"]
                    or sha256(archive) != meta["sha256"]
                ):
                    raise ValueError(
                        "baseline archive is missing or has an invalid checksum"
                    )
                extract_archive(archive, cache)
            state["restore_ok"] = True
            print(
                f"Restored kache baseline for {state['branch']}/{state['job']}: {len(meta['artifact_keys'])} artifacts"
            )
        else:
            print(
                f"No valid kache baseline for {state['branch']}/{state['job']}; using individual artifact downloads"
            )
    except Exception as error:
        print(f"::warning::Kache baseline restore skipped: {error}")
    finally:
        cache.mkdir(parents=True, exist_ok=True)
        Path(args.state).write_text(json.dumps(state) + "\n")
        with open(env["GITHUB_OUTPUT"], "a") as output:
            output.write(f"cache-dir={cache}\nruntime-dir={runtime}\n")


def publish(args, env):
    state = json.loads(Path(args.state).read_text())
    if not may_publish(state, env):
        print(
            "Kache baseline publication skipped: only successful protected next/release pushes publish"
        )
        return
    remote = CloudFront(state["download_endpoint"])
    meta, etag = read_metadata(remote, state)
    if (
        meta
        and meta.get("workflow") == state["workflow"]
        and meta.get("run_number", 0) > state["run_number"]
    ):
        print("A newer run already published this baseline")
        return
    needed = used_keys(state["runtime"])
    reason = refresh_reason(meta, needed, time.time())
    if needed and not state["restore_ok"] and etag == state.get("restored_etag"):
        reason = "baseline could not be restored"
    if reason is None:
        print("Kache baseline is current; no archive or metadata upload needed")
        return
    cache_env = env | {
        "KACHE_CONFIG": state["config"],
        "KACHE_CACHE_DIR": state["cache"],
        "KACHE_RUNTIME_DIR": state["runtime"],
        "KACHE_CI_BUNDLES": "false",
    }
    subprocess.run([state["binary"], "daemon", "stop"], env=cache_env, check=True)
    print("Refreshing kache baseline: " + reason)
    with tempfile.TemporaryDirectory(prefix="kache-snapshot-") as folder:
        root = Path(folder)
        archive = root / "baseline.tar.zst"
        keys = make_archive(state["cache"], archive, root)
        digest = sha256(archive)
        archive_key = f"protected-branch/baselines/v1/archives/{digest}.tar.zst"
        metadata = identity(state) | {
            "format": FORMAT,
            "created_at": time.time(),
            "archive": archive_key,
            "sha256": digest,
            "archive_bytes": archive.stat().st_size,
            "artifact_keys": sorted(keys),
            "workflow": state["workflow"],
            "run_number": state["run_number"],
        }
        body = root / "current.json"
        body.write_text(json.dumps(metadata, separators=(",", ":")) + "\n")
        if body.stat().st_size > MAX_METADATA:
            raise ValueError("baseline metadata is too large")
        subprocess.run(
            [
                "aws",
                "s3",
                "cp",
                str(archive),
                f"s3://{state['bucket']}/{archive_key}",
                "--region",
                state["region"],
                "--only-show-errors",
                "--cache-control",
                "public,max-age=31536000,immutable",
            ],
            check=True,
        )
        condition = ["--if-match", etag] if etag else ["--if-none-match", "*"]
        subprocess.run(
            [
                "aws",
                "s3api",
                "put-object",
                "--bucket",
                state["bucket"],
                "--key",
                metadata_key(state),
                "--body",
                str(body),
                "--region",
                state["region"],
                "--content-type",
                "application/json",
                "--cache-control",
                "no-cache",
                *condition,
            ],
            check=True,
        )
        print(
            f"Published complete kache baseline: {len(keys)} artifacts, {archive.stat().st_size} compressed bytes"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["restore", "publish"])
    parser.add_argument("--state", required=True)
    for name in [
        "job-key",
        "cache-version",
        "binary",
        "config",
        "bucket",
        "region",
        "download-endpoint",
        "cache-dir",
        "runtime-dir",
    ]:
        parser.add_argument("--" + name, default="")
    parser.add_argument("--writable", choices=["true", "false"], default="false")
    args = parser.parse_args()
    try:
        (restore if args.command == "restore" else publish)(args, dict(os.environ))
    except Exception as error:
        print(f"::warning::Kache baseline {args.command} skipped: {error}")


if __name__ == "__main__":
    main()
