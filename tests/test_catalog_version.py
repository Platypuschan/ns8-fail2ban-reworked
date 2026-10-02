import importlib.machinery
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECK_SCRIPT = ROOT / ".github/scripts/check-catalog-version"
PREVIOUS_SCRIPT = ROOT / ".github/scripts/previous-release"


def load_script(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


check_version = load_script("check_catalog_version", CHECK_SCRIPT)
previous_release = load_script("previous_release", PREVIOUS_SCRIPT)


class VersionParsingTest(unittest.TestCase):
    def test_orders_semver_versions(self):
        ordered = ["0.1.0-alpha", "0.1.0-alpha.1", "0.1.0-beta", "0.1.0", "0.1.1", "0.2.0", "1.0.0"]
        keys = [check_version.parse_version(value) for value in ordered]
        self.assertEqual(keys, sorted(keys))
        self.assertLess(check_version.parse_version("0.1.0-2"), check_version.parse_version("0.1.0-10"))

    def test_rejects_non_semver_tags(self):
        for value in ("latest", "v0.1.0", "0.1", "01.0.0", "0.1.0-01"):
            with self.subTest(value=value):
                with self.assertRaises(check_version.VersionError):
                    check_version.parse_version(value)


class ReleaseCheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        self.git("init", "--quiet", "--initial-branch=main")
        self.git("config", "user.email", "test@example.test")
        self.git("config", "user.name", "Test")
        self.write("CATALOG_VERSION", "0.1.0\n")
        self.write("imageroot/actions/example", "one\n")
        self.write("README.md", "docs\n")
        self.commit("initial release")
        self.git("switch", "--quiet", "--create", "feature")

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *args):
        subprocess.run(("git",) + args, cwd=self.repo, check=True, capture_output=True)

    def write(self, name, content):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def commit(self, message):
        self.git("add", "--all")
        self.git("commit", "--quiet", "--message", message)

    def check(self, base=None):
        return check_version.check(base, cwd=self.repo)

    def test_documentation_change_needs_no_bump(self):
        self.write("README.md", "more docs\n")
        self.commit("docs")
        self.assertEqual(self.check("main"), [])
        self.assertEqual(self.check(), [])

    def test_image_change_without_bump_fails(self):
        self.write("imageroot/actions/example", "two\n")
        self.commit("change image")
        self.assertEqual(len(self.check("main")), 1)
        self.assertIn("imageroot/actions/example", self.check()[0])

    def test_image_change_with_bump_passes(self):
        self.write("imageroot/actions/example", "two\n")
        self.write("CATALOG_VERSION", "0.1.1\n")
        self.commit("release 0.1.1")
        self.assertEqual(self.check("main"), [])
        self.assertEqual(self.check(), [])

    def test_merge_commit_counts_as_the_version_bump(self):
        self.write("CATALOG_VERSION", "0.1.1\n")
        self.commit("bump first")
        self.write("imageroot/actions/example", "two\n")
        self.commit("change image afterwards")
        self.git("switch", "--quiet", "main")
        self.git("merge", "--quiet", "--no-ff", "--no-edit", "feature")
        self.assertEqual(self.check(), [])

    def test_version_must_increase(self):
        self.write("imageroot/actions/example", "two\n")
        self.write("CATALOG_VERSION", "0.1.0-rc.1\n")
        self.commit("lower version")
        self.assertEqual(len(self.check("main")), 1)

    def test_invalid_version_is_rejected(self):
        self.write("CATALOG_VERSION", "latest\n")
        self.commit("invalid")
        with self.assertRaises(check_version.VersionError):
            self.check("main")


class PreviousReleaseTest(unittest.TestCase):
    TAGS = ["latest", "main", "sha256-abc", "0.1.0", "0.2.0", "0.2.1", "0.3.0-rc.1", "0.10.0"]

    def test_unpublished_version_starts_from_newest_release(self):
        self.assertEqual(previous_release.newest_release(self.TAGS, "0.2.2"), "0.2.1")

    def test_published_version_is_its_own_baseline(self):
        self.assertEqual(previous_release.newest_release(self.TAGS, "0.2.1"), "0.2.1")

    def test_orders_numerically_and_skips_newer_and_prereleases(self):
        self.assertEqual(previous_release.newest_release(self.TAGS, "0.3.0"), "0.2.1")
        self.assertEqual(previous_release.newest_release(self.TAGS, "1.0.0"), "0.10.0")

    def test_no_release_returns_none(self):
        self.assertIsNone(previous_release.newest_release(["latest", "0.3.0"], "0.2.0"))


if __name__ == "__main__":
    unittest.main()
