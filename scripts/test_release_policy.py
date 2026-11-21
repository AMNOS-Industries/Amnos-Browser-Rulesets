import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).with_name("verify_append_only.py")
SPEC = importlib.util.spec_from_file_location("feed_guard", MODULE)
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


class ReleaseHistoryGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.git("init", "-b", "main")
        self.git("config", "user.name", "AMNOS QA")
        self.git("config", "user.email", "qa@example.invalid")
        (self.repo / "README.md").write_text("test\n")
        self.commit("Initial test baseline")
        self.old_root = GUARD.ROOT
        GUARD.ROOT = self.repo
        self.addCleanup(lambda: setattr(GUARD, "ROOT", self.old_root))

    def git(self, *args):
        proc = subprocess.run(["git", "-C", str(self.repo), *args],
                              capture_output=True, check=True)
        return proc.stdout.decode().strip()

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-m", message)
        return self.git("rev-parse", "HEAD")

    def signed_metadata(self, n):
        return json.dumps({"schema_version": 1, "ruleset_version": n})

    def test_append_only_original_and_new_qa_fixture(self):
        old = self.git("rev-parse", "HEAD")
        p = self.repo / "qa/example/release.json"
        p.parent.mkdir(parents=True)
        p.write_text('{"version":1}')
        self.commit("Add QA release")
        GUARD.verify(old)

    def test_previous_qa_payload_modification_rejected(self):
        p = self.repo / "qa/example/release.json"
        p.parent.mkdir(parents=True)
        p.write_text('{"version":1}')
        old = self.commit("Original QA release")
        p.write_text('{"version":2}')
        self.commit("Mutate already released QA content")
        with self.assertRaisesRegex(RuntimeError, "altered"):
            GUARD.verify(old)

    def test_public_key_replacement_rejected(self):
        key = self.repo / "trust/public.pem"
        key.parent.mkdir(parents=True)
        key.write_text("PUBLIC-KEY-1")
        old = self.commit("Pin initial public key")
        key.write_text("PUBLIC-KEY-2")
        self.commit("Replace pinned public key")
        with self.assertRaisesRegex(RuntimeError, "altered"):
            GUARD.verify(old)

    def test_existing_license_removal_rejected(self):
        lic = self.repo / "compliance/licenses/source.txt"
        lic.parent.mkdir(parents=True)
        lic.write_text("Original license grant")
        old = self.commit("Add licensed source")
        lic.unlink()
        self.commit("Remove license")
        with self.assertRaisesRegex(RuntimeError, "altered"):
            GUARD.verify(old)

    def test_new_manifest_sequence_must_advance(self):
        manifest = self.repo / "latest.manifest.json"
        manifest.write_text(self.signed_metadata(2))
        old = self.commit("Current signed release 2")
        manifest.write_text(self.signed_metadata(3))
        self.commit("Advance to signed release 3")
        GUARD.verify(old)

    def test_manifest_rollback_rejected(self):
        manifest = self.repo / "latest.manifest.json"
        manifest.write_text(self.signed_metadata(3))
        old = self.commit("Current signed release 3")
        manifest.write_text(self.signed_metadata(2))
        self.commit("Attempt rollback")
        with self.assertRaisesRegex(RuntimeError, "strictly increase"):
            GUARD.verify(old)

    def test_same_sequence_replacement_rejected(self):
        manifest = self.repo / "latest.manifest.json"
        manifest.write_text(self.signed_metadata(2))
        old = self.commit("Current signed release 2")
        manifest.write_text(self.signed_metadata(2) + "\n")
        self.commit("Replace same sequence bytes")
        with self.assertRaisesRegex(RuntimeError, "strictly increase"):
            GUARD.verify(old)

    def test_active_manifest_deletion_rejected(self):
        manifest = self.repo / "latest.manifest.json"
        manifest.write_text(self.signed_metadata(2))
        old = self.commit("Current signed release")
        manifest.unlink()
        self.commit("Remove signed manifest")
        with self.assertRaisesRegex(RuntimeError, "removed"):
            GUARD.verify(old)


if __name__ == "__main__":
    unittest.main()
