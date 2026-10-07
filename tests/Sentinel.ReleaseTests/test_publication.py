"""Publication safeguards run without network access or GitHub credentials."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "publish-release.py"
specification = importlib.util.spec_from_file_location("sentinel_publish_release", SCRIPT)
release = importlib.util.module_from_spec(specification)
specification.loader.exec_module(release)

GATES = ["silent-install", "service-boundaries", "desktop-first-launch", "same-version-upgrade",
         "silent-uninstall", "public-v1.0-baseline-hash", "public-v1.0-demo-settings-dpapi-seed",
         "v1.0-to-v1.1-in-place-upgrade", "v1.0-data-settings-secret-and-audit-bytes-preserved",
         "v1.1-reads-original-v1.0-demo-settings-and-dpapi", "installed-desktop-functional-and-rendered-acceptance",
         "upgraded-silent-uninstall-preserves-evidence"]


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.source = "a" * 40
        for name in release.FILES:
            (self.directory / name).write_bytes(("fixture:" + name).encode())
        assembly_hash = "d" * 64
        (self.directory / "release-manifest.json").write_text(json.dumps({"sourceCommit": self.source, "version": "1.1.0", "files": [{"path": "../../artifacts/publish/Desktop/Sentinel.Desktop.dll", "sha256": assembly_hash}]}))
        (self.directory / "verification-results.json").write_text(json.dumps({"checks": [{"name": name, "status": "passed"} for name in GATES]}))
        (self.directory / "desktop-verification-results.json").write_text(json.dumps({"status": "passed", "failed": 0, "quick": False, "renders": [{}] * 360, "dispatcherFailures": [], "desktopAssemblySha256": assembly_hash, "checks": [{"Name": "render-matrix-physical-screenshot-completeness", "Status": "passed"}]}))
        checksums = "\n".join(release.digest(self.directory / name) + "  " + name for name in [release.EXE, release.ZIP])
        (self.directory / "SHA256SUMS.txt").write_text(checksums, encoding="ascii")
        self.state = {"id": 42, "tag_name": release.TAG, "name": release.TITLE, "prerelease": True,
                      "draft": True, "assets": [], "html_url": "https://github.com/test/sentinel/releases/tag/v1.1.0"}
        self.uploads = []
        self.downloads = []
        self.mutations = []

    def api(self, endpoint):
        if endpoint.endswith("git/ref/tags/v1.1.0"):
            return {"object": {"type": "commit", "sha": self.source}}
        self.assertEqual(endpoint, "repos/test/sentinel/releases/42")
        return self.state.copy()

    def mutate(self, endpoint, method, payload):
        self.mutations.append((method, endpoint))
        if method == "POST":
            self.assertEqual(endpoint, "repos/test/sentinel/releases")
            self.assertTrue(payload["draft"])
        elif method == "PATCH":
            self.assertEqual(len(self.downloads), len(release.FILES), "Draft became public before every asset was verified")
            self.state["draft"] = False
        else:
            self.fail("Unexpected mutation: " + method)
        return self.state.copy()

    def upload(self, repository, release_id, name, path):
        self.assertEqual(repository, "test/sentinel")
        self.assertEqual(release_id, 42)
        self.assertTrue(self.state["draft"])
        self.uploads.append(name)
        asset = {"id": 100 + len(self.uploads), "name": name,
                 "browser_download_url": self.state["html_url"].replace("tag/", "download/") + "/" + name}
        self.state["assets"].append(asset)
        return asset

    def download(self, repository, asset, destination):
        self.downloads.append(asset["name"])
        destination.write_bytes((self.directory / asset["name"]).read_bytes())

    def perform(self, existing=None, download=None):
        with patch.object(release, "find_release", return_value=existing) as find, \
             patch.object(release, "api", side_effect=self.api), \
             patch.object(release, "mutate", side_effect=self.mutate), \
             patch.object(release, "upload", side_effect=self.upload), \
             patch.object(release, "download", side_effect=download or self.download), \
             patch.dict(release.os.environ, {"GITHUB_STEP_SUMMARY": ""}):
            result = release.publish(self.directory, "test/sentinel", self.source)
            self.assertEqual(find.call_count, 1, "New draft discovery relied on an eventually-consistent collection")
            return result

    def test_create_response_id_survives_stale_release_collection(self):
        result = self.perform()
        self.assertFalse(result["draft"])
        self.assertEqual(self.uploads, release.FILES)
        self.assertEqual([method for method, _ in self.mutations], ["POST", "PATCH"])

    def test_existing_different_asset_is_never_overwritten_or_published(self):
        self.state["assets"] = [{"id": 3, "name": release.EXE}]
        def altered(repository, asset, destination):
            destination.write_bytes(b"different previously uploaded bytes")
        with self.assertRaisesRegex(RuntimeError, "Nothing was overwritten"):
            self.perform(self.state.copy(), altered)
        self.assertEqual(self.uploads, [])
        self.assertEqual(self.mutations, [])
        self.assertTrue(self.state["draft"])

    def test_corrupt_round_trip_leaves_draft_private(self):
        def corrupted(repository, asset, destination):
            destination.write_bytes(b"corrupted download")
        with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
            self.perform(download=corrupted)
        self.assertEqual(len(self.uploads), 1)
        self.assertTrue(self.state["draft"])
        self.assertEqual([method for method, _ in self.mutations], ["POST"])

    def test_moved_tag_does_not_create_release(self):
        def moved(endpoint):
            return {"object": {"type": "commit", "sha": "b" * 40}}
        with patch.object(release, "api", side_effect=moved), \
             patch.object(release, "mutate") as mutate:
            with self.assertRaisesRegex(RuntimeError, "tag moved"):
                release.publish(self.directory, "test/sentinel", self.source)
            mutate.assert_not_called()

    def test_bad_binary_checksum_fails_before_github(self):
        (self.directory / release.EXE).write_bytes(b"changed after QA")
        with patch.object(release, "api") as api:
            with self.assertRaisesRegex(RuntimeError, "checksums"):
                release.publish(self.directory, "test/sentinel", self.source)
            api.assert_not_called()

    def test_missing_installed_upgrade_gate_fails_before_github(self):
        (self.directory / "verification-results.json").write_text(json.dumps({"checks": [{"name": "silent-install", "status": "passed"}]}))
        with patch.object(release, "api") as api:
            with self.assertRaisesRegex(RuntimeError, "required installation"):
                release.publish(self.directory, "test/sentinel", self.source)
            api.assert_not_called()

    def test_read_only_refresh_waits_for_uploaded_asset_visibility(self):
        empty = self.state.copy()
        complete = self.state.copy()
        complete["assets"] = [{"name": release.EXE}]
        with patch.object(release, "api", side_effect=[empty, empty, complete]), \
             patch.object(release.time, "sleep") as sleep:
            result = release.refresh("test/sentinel", 42, {release.EXE})
        self.assertEqual(result["assets"], complete["assets"])
        self.assertEqual(sleep.call_count, 2)

    def test_missing_distribution_file_does_not_publish(self):
        (self.directory / release.ZIP).unlink()
        with self.assertRaisesRegex(RuntimeError, "Missing distribution file"):
            self.perform()
        self.assertEqual(self.mutations, [])

    def test_quick_desktop_matrix_is_insufficient_for_release(self):
        path = self.directory / "desktop-verification-results.json"
        result = json.loads(path.read_text())
        result["quick"] = True
        result["renders"] = result["renders"][:40]
        path.write_text(json.dumps(result))
        with self.assertRaisesRegex(RuntimeError, "complete installed desktop"):
            self.perform()
        self.assertEqual(self.mutations, [])

    def test_acceptance_of_different_desktop_payload_is_rejected(self):
        path = self.directory / "desktop-verification-results.json"
        result = json.loads(path.read_text())
        result["desktopAssemblySha256"] = "e" * 64
        path.write_text(json.dumps(result))
        with self.assertRaisesRegex(RuntimeError, "assembly in this installer"):
            self.perform()
        self.assertEqual(self.mutations, [])


if __name__ == "__main__":
    unittest.main()
