import copy
import unittest

from cache_key import fingerprint


class CacheKeyTests(unittest.TestCase):
    def setUp(self):
        self.root = {
            "workspace": {
                "package": {"version": "1.0.0", "edition": "2024"},
                "dependencies": {"direct": {"version": "1"}, "unrelated": {"version": "1"}},
                "resolver": "2",
            }
        }
        self.manifest = {
            "package": {"name": "xtask", "version": {"workspace": True}},
            "dependencies": {"direct": {"workspace": True}},
        }
        self.lock = {
            "package": [
                {"name": "xtask", "version": "1.0.0", "dependencies": ["direct"]},
                self.package("direct", dependencies=["transitive"]),
                self.package("transitive"),
                self.package("unrelated"),
            ]
        }
        self.original = self.key()

    @staticmethod
    def package(name, **fields):
        return {"name": name, "version": "1.0.0", "source": "registry+example", **fields}

    def key(self):
        return fingerprint(self.root, self.manifest, self.lock)

    def test_unrelated_manifest_and_lock_changes_reuse_binary(self):
        self.root["workspace"]["dependencies"]["unrelated"]["version"] = "2"
        self.root["workspace"]["package"]["edition"] = "2021"
        self.root["workspace"]["members"] = ["xtask", "new-member"]
        self.lock["package"][-1]["version"] = "2.0.0"
        self.lock["package"].append(self.package("new-dependency"))
        self.assertEqual(self.original, self.key())

    def test_changed_direct_or_transitive_dependency_invalidates_binary(self):
        changes = (("version", "2.0.0"), ("source", "git+example#commit"), ("checksum", "new"))
        for name in ("direct", "transitive"):
            for field, value in changes:
                with self.subTest(package=name, field=field):
                    lock = copy.deepcopy(self.lock)
                    package = next(item for item in lock["package"] if item["name"] == name)
                    package[field] = value
                    self.assertNotEqual(self.original, fingerprint(self.root, self.manifest, lock))

    def test_inherited_features_invalidate_binary(self):
        self.root["workspace"]["dependencies"]["direct"]["features"] = ["extra"]
        self.assertNotEqual(self.original, self.key())

    def test_inherited_package_settings_invalidate_binary(self):
        self.root["workspace"]["package"]["version"] = "2.0.0"
        self.assertNotEqual(self.original, self.key())

    def test_build_settings_invalidate_binary(self):
        self.root["profile"] = {"dev": {"opt-level": 2}}
        self.assertNotEqual(self.original, self.key())

    def test_added_transitive_dependency_invalidates_binary(self):
        self.lock["package"][1]["dependencies"].append("unrelated")
        self.assertNotEqual(self.original, self.key())

    def test_unrelated_duplicate_versions_and_sources_reuse_binary(self):
        self.lock["package"].append(self.package("direct", version="2.0.0"))
        self.lock["package"][0]["dependencies"] = ["direct 1.0.0"]
        self.assertEqual(self.original, self.key())
        self.lock["package"].append(self.package("direct", source="git+example#commit"))
        self.lock["package"][0]["dependencies"] = ["direct 1.0.0 (registry+example)"]
        self.assertEqual(self.original, self.key())

    def test_reordering_packages_reuses_binary(self):
        self.lock["package"].reverse()
        self.assertEqual(self.original, self.key())

    def test_missing_dependency_fails(self):
        self.lock["package"][1]["dependencies"] = ["missing"]
        with self.assertRaisesRegex(ValueError, "Cannot resolve"):
            self.key()

    def test_local_dependency_requires_source_hashing(self):
        del self.lock["package"][1]["source"]
        with self.assertRaisesRegex(ValueError, "source files"):
            self.key()


if __name__ == "__main__":
    unittest.main()
