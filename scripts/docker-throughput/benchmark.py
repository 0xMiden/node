#!/usr/bin/env python3
"""Compare one-slot and two-slot Docker builds on the selected BuildKit builder."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import re
import statistics
import subprocess
import tarfile
import tempfile
import time
import uuid


BUILD_INPUTS = (
    "Cargo.toml", "Cargo.lock", ".cargo/config.toml", "bin", "crates", "proto",
    "xtask/Cargo.toml", "xtask/src/main.rs",
)


def command(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def git(repo, *args):
    return command(["git", "-C", str(repo), *args], stdout=subprocess.PIPE).stdout


def validate_workload(repo, workload, fetch=False):
    revisions = [workload[key] for key in ("baseline", "candidate", "warmup")]
    samples = workload["samples"]
    if not 2 <= len(samples) <= 12:
        raise ValueError("Use between two and twelve source revisions")
    revisions.extend(sample["revision"] for sample in samples)
    for revision in revisions:
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ValueError("Each revision must be a full commit SHA")
    if fetch:
        git(repo, "fetch", "--no-tags", "origin", *dict.fromkeys(revisions))
    for revision in revisions:
        git(repo, "cat-file", "-e", f"{revision}^{{commit}}")
    if len({sample["pr"] for sample in samples}) != len(samples):
        raise ValueError("Sample PR numbers must be unique")
    if {sample["pr"] % 2 for sample in samples} != {0, 1}:
        raise ValueError("The samples must use both cache slots")
    fingerprints = set()
    for revision in [workload["warmup"], *(s["revision"] for s in samples)]:
        fingerprint = git(repo, "rev-parse", *(f"{revision}:{p}" for p in BUILD_INPUTS))
        if fingerprint in fingerprints:
            raise ValueError("Build inputs must differ to prevent BuildKit from combining samples")
        fingerprints.add(fingerprint)
    for sample in samples:
        git(repo, "merge-base", "--is-ancestor", workload["warmup"], sample["revision"])


def scoped_dockerfile(text, namespace):
    if not re.fullmatch(r"[a-z0-9-]+", namespace):
        raise ValueError("Invalid benchmark cache namespace")
    lines = []
    mounts = 0
    command_pending = False
    for line in text.splitlines(keepends=True):
        if "--mount=type=cache," in line:
            if not line.rstrip().endswith("\\"):
                raise ValueError("Put cache mount flags on separate continued lines")
            line, count = re.subn(r"(?<=,)id=([^,\s]+)",
                                 rf"id=docker-benchmark-{namespace}-\1", line)
            if count != 1:
                raise ValueError("Each cache mount must have one explicit ID")
            mounts += count
            command_pending = True
        elif command_pending:
            # Change the BuildKit operation without changing the compiler environment.
            lines.append(f"    : docker-benchmark-{namespace} && \\\n")
            command_pending = False
        lines.append(line)
    if not mounts:
        raise ValueError("The Dockerfile has no cache mounts")
    return "".join(lines)


def prune_command(namespace):
    if not re.fullmatch(r"[a-z0-9-]+", namespace):
        raise ValueError("Invalid benchmark cache namespace")
    return ["docker", "buildx", "prune", "--force", "--filter", "type=exec.cachemount",
            "--filter", f"description~=docker-benchmark-{namespace}-"]


def snapshot(path):
    with path.open("w") as output:
        command(["docker", "buildx", "du", "--format", "json"], stdout=output)


def build(bake, dockerfile, context, output, platform, slot, revision):
    output.mkdir()
    args = [
        "docker", "buildx", "bake", "--file", str(bake), "--progress", "plain",
        "--allow", f"fs.read={context}", "--allow", f"fs.read={dockerfile.parent}",
        "--allow", f"fs.write={output}", "--provenance=false",
        "--metadata-file", str(output / "metadata.json"),
        "--set", f"*.context={context}", "--set", f"*.dockerfile={dockerfile}",
        "--set", f"*.platform={platform}",
        "--set", f"*.args.BUILD_CACHE_SUFFIX={slot}",
        "--set", f"*.args.COMMIT={revision}", "--set", "*.args.VERSION=benchmark",
        "--set", "*.args.CREATED=2026-09-21T00:00:00Z",
        "--set", f"build-report.output=type=local,dest={output / 'report'}", "validate",
    ]
    print(f"Starting {output.name} ({slot or 'slot-0'})", flush=True)
    started = time.monotonic()
    started_at = datetime.now(timezone.utc).isoformat()
    with (output / "build.log").open("w") as log:
        result = subprocess.run(args, stdout=log, stderr=subprocess.STDOUT)
    elapsed = time.monotonic() - started
    record = dict(revision=revision, slot=slot or "slot-0", started_at=started_at,
                  elapsed_seconds=elapsed, exit_code=result.returncode)
    (output / "timing.json").write_text(json.dumps(record, indent=2) + "\n")
    print(f"Finished {output.name}: {elapsed:.1f}s, exit {result.returncode}", flush=True)
    if result.returncode:
        print((output / "build.log").read_text()[-6000:], flush=True)
    return record


def batch(bake, dockerfile, contexts, output, platform, samples, two_slots):
    output.mkdir()
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=len(samples)) as executor:
        futures = [executor.submit(
            build, bake, dockerfile, contexts[sample["revision"]],
            output / f"pr-{sample['pr']}", platform,
            "-slot-1" if two_slots and sample["pr"] % 2 else "", sample["revision"],
        ) for sample in samples]
        results = [future.result() for future in futures]
    elapsed = time.monotonic() - started
    return dict(elapsed_seconds=elapsed, builds=results,
                success=all(result["exit_code"] == 0 for result in results))


def summary(results):
    lines = ["## Docker throughput benchmark", "",
             "Warm-up time is excluded. Each batch submits all source revisions together.", "",
             "| Round | Configuration | Batch time | Successful builds/hour | Result |",
             "|---|---|---:|---:|---|"]
    for trial in results:
        batch_result = trial.get("batch")
        if batch_result is None:
            lines.append(f"| {trial['round']} | {trial['mode']} | — | — | Incomplete |")
            continue
        seconds = batch_result["elapsed_seconds"]
        success = batch_result["success"] and not trial.get("error")
        rate = f"{len(batch_result['builds']) * 3600 / seconds:.2f}" if success else "—"
        lines.append(f"| {trial['round']} | {trial['mode']} | {seconds:.1f}s | {rate} | "
                     f"{'Passed' if success else 'Failed'} |")
    ratios = []
    for number in sorted({trial["round"] for trial in results}):
        pair = {trial["mode"]: trial for trial in results if trial["round"] == number}
        if set(pair) != {"baseline", "candidate"}:
            continue
        if all(t.get("batch", {}).get("success") and not t.get("error") for t in pair.values()):
            ratios.append(pair["baseline"]["batch"]["elapsed_seconds"] /
                          pair["candidate"]["batch"]["elapsed_seconds"])
    if ratios:
        lines += ["", f"Median paired throughput ratio: **{statistics.median(ratios):.3f}x** "
                  "(candidate / baseline; greater than 1 is faster)."]
    lines += ["", "A failed or incomplete batch is excluded from the comparison.",
              "Other builds on the same worker invalidate a controlled comparison.",
              "Disk snapshots are not peak measurements. Inspect worker CPU and memory telemetry separately."]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workload", type=Path, default=Path(__file__).with_name("workload.json"))
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--platform", choices=["linux/amd64", "linux/arm64"], default="linux/amd64")
    parser.add_argument("--rounds", type=int, choices=range(1, 4), default=1)
    parser.add_argument("--fetch", action="store_true", help="Fetch the pinned workload commits from origin")
    args = parser.parse_args()
    workload = json.loads(args.workload.read_text())
    validate_workload(args.repo, workload, args.fetch)
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "workload.json").write_text(json.dumps(workload, indent=2) + "\n")
    with (args.output / "builder.txt").open("w") as output:
        command(["docker", "buildx", "inspect", "--bootstrap"], stdout=output)
    results = []
    failed = False
    run_id = uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="docker-throughput-") as directory:
        scratch = Path(directory)
        contexts = {}
        for revision in {workload["warmup"], *(s["revision"] for s in workload["samples"])}:
            context = scratch / revision
            context.mkdir()
            archive = git(args.repo, "archive", revision)
            with tarfile.open(fileobj=io.BytesIO(archive)) as files:
                files.extractall(context, filter="data")
            contexts[revision] = context
        try:
            for number in range(1, args.rounds + 1):
                modes = ["baseline", "candidate"] if number % 2 else ["candidate", "baseline"]
                for mode in modes:
                    namespace = f"{run_id}-{number}-{mode}"
                    trial_dir = args.output / f"{number}-{mode}"
                    trial_dir.mkdir()
                    trial = dict(round=number, mode=mode, configuration=workload[mode])
                    results.append(trial)
                    try:
                        dockerfile = trial_dir / "Dockerfile"
                        text = git(args.repo, "show", f"{workload[mode]}:Dockerfile").decode()
                        dockerfile.write_text(scoped_dockerfile(text, namespace))
                        bake = trial_dir / "docker-bake.hcl"
                        bake.write_bytes(git(args.repo, "show", f"{workload[mode]}:docker-bake.hcl"))
                        warmup = [dict(pr=slot, revision=workload["warmup"])
                                  for slot in range(2 if mode == "candidate" else 1)]
                        trial["warmup"] = batch(bake, dockerfile, contexts, trial_dir / "warmup",
                                                args.platform, warmup, mode == "candidate")
                        if not trial["warmup"]["success"]:
                            raise RuntimeError("Warm-up failed")
                        snapshot(trial_dir / "disk-before.jsonl")
                        trial["batch"] = batch(bake, dockerfile, contexts, trial_dir / "measured",
                                               args.platform, workload["samples"], mode == "candidate")
                        snapshot(trial_dir / "disk-after.jsonl")
                        if not trial["batch"]["success"]:
                            raise RuntimeError("A measured build failed")
                    except Exception as error:
                        trial["error"] = str(error)
                        failed = True
                        raise
                    finally:
                        with (trial_dir / "prune.log").open("w") as log:
                            cleanup = subprocess.run(prune_command(namespace), stdout=log, stderr=subprocess.STDOUT)
                            if cleanup.returncode:
                                failed = True
                                trial["error"] = "Benchmark cache cleanup failed"
                        if cleanup.returncode:
                            print((trial_dir / "prune.log").read_text()[-6000:], flush=True)
                        (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
                        (args.output / "summary.md").write_text(summary(results))
                    if failed:
                        raise RuntimeError("Benchmark cache cleanup failed")
        finally:
            print(summary(results), flush=True)
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
