"""Hash the workspace settings and locked dependencies used by xtask."""

import hashlib
import json
from pathlib import Path
import tomllib


def fingerprint(root, manifest, lock):
    workspace = root["workspace"]
    packages = lock["package"]

    def identity(package):
        return (package["name"], package["version"], package.get("source", ""))

    def resolve(reference):
        parts = reference.split(" ", 2)
        matches = [
            package
            for package in packages
            if package["name"] == parts[0]
            and (len(parts) < 2 or package["version"] == parts[1])
            and (len(parts) < 3 or package.get("source") == parts[2].strip("()"))
        ]
        if len(matches) != 1:
            raise ValueError(f"Cannot resolve locked dependency: {reference}")
        return matches[0]

    pending = [resolve("xtask")]
    selected = {}
    while pending:
        package = pending.pop()
        key = identity(package)
        if key in selected:
            continue
        if package["name"] != "xtask" and "source" not in package:
            raise ValueError("Local xtask dependencies need source files in the cache key")
        dependencies = [resolve(ref) for ref in package.get("dependencies", [])]
        # Normalize references because unrelated packages can add version qualifiers.
        selected[key] = {
            **package,
            "dependencies": sorted(identity(dependency) for dependency in dependencies),
        }
        pending.extend(dependencies)

    inherited_dependencies = {}
    tables = [manifest, *manifest.get("target", {}).values()]
    for table in tables:
        for kind in ("dependencies", "build-dependencies", "dev-dependencies"):
            for name, dependency in table.get(kind, {}).items():
                if isinstance(dependency, dict) and dependency.get("workspace"):
                    inherited_dependencies[name] = workspace["dependencies"][name]

    inputs = {
        "packages": [selected[key] for key in sorted(selected)],
        "workspace-package": {
            name: workspace["package"][name]
            for name, value in manifest["package"].items()
            if isinstance(value, dict) and value.get("workspace")
        },
        "workspace-dependencies": inherited_dependencies,
        "resolver": workspace.get("resolver"),
        "lints": workspace.get("lints") if manifest.get("lints", {}).get("workspace") else None,
        # Root build settings can affect xtask and its transitive dependencies.
        "build-settings": {name: root.get(name) for name in ("profile", "patch", "replace")},
    }
    return hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest()


if __name__ == "__main__":
    def read_toml(path):
        return tomllib.loads(Path(path).read_text())

    print(fingerprint(read_toml("Cargo.toml"), read_toml("xtask/Cargo.toml"), read_toml("Cargo.lock")))
