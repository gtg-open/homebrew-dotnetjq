"""Behavioral privacy regressions; all sensitive-looking inputs are invented."""
import gzip
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from check import Scanner


SCRIPT = Path(__file__).with_name("check.py").resolve()
SYNTHETIC_HOME = "/" + "home" + "/invented-contributor/project"
SYNTHETIC_TOKEN = "gh" + "p_" + "1234567890AbCdEfGhIjKlMnOpQrStUvWxYz0123"


class PrivacyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = os.environ.copy()
        self.env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                         "GIT_AUTHOR_NAME": "GtG Open Maintainer", "GIT_COMMITTER_NAME": "GtG Open Maintainer",
                         "GIT_AUTHOR_EMAIL": "325667272+gtg-open-maintainer@users.noreply.github.com",
                         "GIT_COMMITTER_EMAIL": "325667272+gtg-open-maintainer@users.noreply.github.com"})
        self.git("init", "--quiet")

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.root), *args], env=self.env,
                              capture_output=True, check=True).stdout

    def write(self, name, data):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data.encode() if isinstance(data, str) else data)

    def scan(self, *args):
        return subprocess.run([sys.executable, "-B", str(SCRIPT), "--repo", str(self.root), *args],
                              env=self.env, capture_output=True, text=True)

    def test_staged_blob_is_checked_even_if_worktree_was_cleaned(self):
        self.write("settings.txt", SYNTHETIC_HOME)
        self.git("add", "settings.txt")
        self.write("settings.txt", "upstream/jq")
        result = self.scan("--staged")
        self.assertEqual(result.returncode, 1)
        self.assertIn("workstation-home-path", result.stderr)
        self.assertNotIn("invented-contributor", result.stderr)
        self.assertEqual(self.scan("--worktree").returncode, 0)

    def test_clean_staged_data_is_not_replaced_by_unstaged_sensitive_content(self):
        self.write("settings.txt", "upstream/jq")
        self.git("add", "settings.txt")
        self.write("settings.txt", SYNTHETIC_HOME)
        self.assertEqual(self.scan("--staged").returncode, 0)
        self.assertEqual(self.scan("--worktree").returncode, 1)

    def test_unsafe_names_and_symlink_targets_are_scanned_without_following(self):
        name = "evidence/" + SYNTHETIC_TOKEN + ".txt"
        self.write(name, "ordinary data")
        os.symlink(SYNTHETIC_HOME, self.root / "upstream-link")
        self.git("add", ".")
        result = self.scan()
        self.assertEqual(result.returncode, 1)
        self.assertIn("redacted-name:", result.stderr)
        self.assertNotIn(SYNTHETIC_TOKEN, result.stderr)
        self.assertIn("workstation-home-path", result.stderr)

    def test_nested_nuget_binary_symbols_and_zip_comments_are_inspected(self):
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as archive:
            archive.writestr("lib/net10.0/library.pdb", SYNTHETIC_HOME.encode("utf-16-le"))
            archive.comment = SYNTHETIC_TOKEN.encode()
        outer = self.root / "release.zip"
        with zipfile.ZipFile(outer, "w") as archive:
            archive.writestr("tool.1.0.0.nupkg", inner.getvalue())
        result = self.scan("--output", str(outer))
        self.assertEqual(result.returncode, 1)
        self.assertIn("workstation-home-path", result.stderr)
        self.assertIn("github-token", result.stderr)

    def test_tar_links_headers_and_gzip_contents_are_inspected_without_extraction(self):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w") as archive:
            member = tarfile.TarInfo("../../escape")
            member.type = tarfile.SYMTYPE
            member.linkname = SYNTHETIC_HOME
            member.pax_headers = {"comment": SYNTHETIC_TOKEN}
            archive.addfile(member)
        output = self.root / "release.tar.gz"
        output.write_bytes(gzip.compress(data.getvalue()))
        result = self.scan("--output", str(output))
        self.assertEqual(result.returncode, 1)
        self.assertIn("unsafe-archive-name", result.stderr)
        self.assertIn("github-token", result.stderr)
        self.assertFalse((self.root.parent / "escape").exists())

    def test_bad_and_oversized_archives_fail_closed(self):
        self.write("broken.nupkg", "this is not an archive")
        result = self.scan("--output", str(self.root / "broken.nupkg"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("archive-unreadable", result.stderr)
        scanner = Scanner()
        with patch("check.MAX_MEMBER", 8):
            scanner.blob("large.bin", b"0123456789")
        self.assertIn(("large.bin", "inspection-size-limit"), scanner.findings)

    def test_private_denylist_does_not_enter_diagnostics(self):
        private_term = "invented-confidential-project"
        denylist = self.root / "private-checks.txt"
        denylist.write_text(private_term)
        self.write("notes.md", private_term)
        self.git("add", "notes.md")
        result = self.scan("--denylist", str(denylist))
        self.assertEqual(result.returncode, 1)
        self.assertIn("private-denylist-match", result.stderr)
        self.assertNotIn(private_term, result.stdout + result.stderr)

    def test_licenses_and_public_identity_are_preserved(self):
        self.write("LICENSE", "Copyright Example Contributor <contributor@example.org>\nMIT License\n")
        self.write("config.md", "Use ${UPSTREAM_ROOT}, upstream/jq, or /home/<user>/source.\n")
        self.git("add", ".")
        self.git("commit", "-qm", "Add portable source and attribution")
        self.assertEqual(self.scan("--metadata", "--history").returncode, 0)

    def test_unapproved_commit_identity_and_sensitive_ancestor_are_rejected(self):
        self.write("notes.txt", SYNTHETIC_HOME)
        self.git("add", ".")
        self.git("commit", "-qm", "Initial source")
        self.write("notes.txt", "portable source")
        self.git("add", ".")
        self.git("commit", "-qm", "Clean current source")
        self.assertEqual(self.scan("--metadata").returncode, 0)
        self.assertEqual(self.scan("--history").returncode, 1)
        self.env["GIT_COMMITTER_EMAIL"] = "private-person@example.invalid"
        self.git("commit", "--allow-empty", "-qm", "Record change")
        result = self.scan("--metadata")
        self.assertEqual(result.returncode, 1)
        self.assertIn("unapproved-git-identity", result.stderr)
        self.assertNotIn(self.env["GIT_COMMITTER_EMAIL"], result.stderr)

    def test_common_credentials_and_private_endpoints_are_rejected(self):
        cases = [SYNTHETIC_TOKEN, "-----BEGIN " + "PRIVATE KEY-----",
                 "https://" + "testuser:invented-password@service.example",
                 "Authorization: " + "Bearer " + "a1B2c3D4e5F6g7H8i9J0k1L2",
                 "Server=database;" + "Password=" + "invented-password;",
                 "https://service." + "internal/", "192." + "168.27.9"]
        for value in cases:
            with self.subTest(kind=value[:8]):
                scanner = Scanner()
                scanner.blob("fixture.txt", value.encode())
                self.assertTrue(scanner.findings)

    def test_generic_config_filename_and_build_root_do_not_hide_home_paths(self):
        scanner = Scanner()
        scanner.text("fixture.txt", "/" + "home/.jq\nC:/build-fixture/Temp/first\nfilesystem/search/home/cancellation/resource")
        self.assertFalse(scanner.findings)
        scanner.text("fixture.txt", "C:/" + "Users/runner/Temp/first")
        self.assertTrue(scanner.findings)

    def test_missing_output_fails_instead_of_claiming_a_clean_scan(self):
        result = self.scan("--output", str(self.root / "missing.zip"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("input-unreadable", result.stderr)

    def test_public_email_cannot_mask_an_unapproved_personal_commit_name(self):
        self.write("source.txt", "portable content")
        self.git("add", ".")
        self.env["GIT_AUTHOR_NAME"] = "Invented Private Person"
        self.git("commit", "-qm", "Add source")
        result = self.scan("--metadata")
        self.assertEqual(result.returncode, 1)
        self.assertIn("unapproved-git-identity", result.stderr)
        self.assertNotIn("Invented Private Person", result.stderr)


if __name__ == "__main__":
    unittest.main()
