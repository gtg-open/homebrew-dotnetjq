"""Offline adversarial tests for immutable-release formula authentication."""

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

import verify_formula as verifier


def formula(version="1.2.3"):
    return ('class Dotnetjq < Formula\n  version "' + version + '"\nend\n').encode()


def release_fixture(content, version="1.2.3"):
    return {
        "tag_name": "v" + version, "draft": False, "prerelease": False,
        "immutable": True, "published_at": "2026-09-08T10:00:00Z",
        "assets": [{
            "name": "dotnetjq.rb", "state": "uploaded", "size": len(content),
            "digest": "sha256:" + hashlib.sha256(content).hexdigest(),
            "browser_download_url": "https://github.com/gtg-open/dotnetjq/releases/download/v" + version + "/dotnetjq.rb",
        }],
    }


class FakeNetwork:
    def __init__(self, content=None, version="1.2.3"):
        self.content = content if content is not None else formula(version)
        self.release = release_fixture(self.content, version)
        self.calls = []
        self.api_bytes = None

    def __call__(self, url, limit, token=None):
        self.calls.append((url, limit, token))
        if url.startswith("https://api.github.com/"):
            return self.api_bytes if self.api_bytes is not None else json.dumps(self.release).encode()
        return self.content


class CheckoutTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.run_git("init", "-q")
        self.network = FakeNetwork()
        self.commit_candidate()

    def run_git(self, *arguments):
        return subprocess.run(
            ["git", "-C", str(self.root), *arguments], check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout.decode().strip()

    def put_formula(self, content=None):
        destination = self.root / verifier.FORMULA
        destination.parent.mkdir(exist_ok=True)
        destination.write_bytes(content if content is not None else formula())
        return destination

    def commit_baseline(self, content=None):
        self.put_formula(content)
        self.run_git("add", verifier.FORMULA)
        self.run_git(
            "-c", "user.name=Verifier Test", "-c", "user.email=verifier@example.invalid",
            "-c", "commit.gpgsign=false", "commit", "-qm", "test baseline",
        )
        return self.run_git("rev-parse", "HEAD")

    def commit_candidate(self):
        self.run_git("add", "--all")
        self.run_git(
            "-c", "user.name=Verifier Test", "-c", "user.email=verifier@example.invalid",
            "-c", "commit.gpgsign=false", "commit", "--allow-empty", "-qm", "test candidate",
        )
        return self.run_git("rev-parse", "HEAD")

    def verify(self, base="", candidate=None):
        if candidate is None:
            candidate = self.commit_candidate()
        return verifier.verify(
            self.root, base, token="fixture-token", fetcher=self.network,
            candidate_revision=candidate,
        )

    def test_bootstrap_empty_repository(self):
        self.assertEqual("bootstrap", self.verify())
        self.assertEqual([], self.network.calls)

    def test_bootstrap_zero_revision(self):
        self.assertEqual("bootstrap", self.verify("0" * 40))

    def test_bootstrap_existing_commit_without_formula(self):
        (self.root / "README.md").write_text("Tap\n")
        self.run_git("add", "README.md")
        self.run_git("-c", "user.name=Verifier Test", "-c", "user.email=verifier@example.invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "bootstrap")
        self.assertEqual("bootstrap", self.verify(self.run_git("rev-parse", "HEAD")))

    def test_published_formula(self):
        self.put_formula()
        self.assertEqual("verified", self.verify())
        self.assertEqual("fixture-token", self.network.calls[0][2])
        self.assertIsNone(self.network.calls[1][2])
        self.assertEqual("https://api.github.com/repos/gtg-open/dotnetjq/releases/tags/v1.2.3", self.network.calls[0][0])

    def test_same_version_identical_formula(self):
        base = self.commit_baseline()
        self.assertEqual("verified", self.verify(base))

    def test_newer_version(self):
        base = self.commit_baseline(formula("1.2.2"))
        self.put_formula()
        self.assertEqual("verified", self.verify(base))

    def test_semver_numeric_comparison(self):
        base = self.commit_baseline(formula("1.2.9"))
        self.put_formula(formula("1.2.10"))
        self.network = FakeNetwork(version="1.2.10")
        self.assertEqual("verified", self.verify(base))

    def test_downgrade(self):
        base = self.commit_baseline(formula("1.3.0"))
        self.put_formula()
        with self.assertRaisesRegex(verifier.VerificationError, "downgrade"):
            self.verify(base)
        self.assertEqual([], self.network.calls)

    def test_same_version_mutation(self):
        base = self.commit_baseline()
        self.put_formula(formula() + b"# changed\n")
        with self.assertRaisesRegex(verifier.VerificationError, "same-version"):
            self.verify(base)

    def test_deleted_base_formula(self):
        base = self.commit_baseline()
        self.run_git("rm", "-q", verifier.FORMULA)
        with self.assertRaisesRegex(verifier.VerificationError, "deleting"):
            self.verify(base)

    def test_missing_tracked_formula(self):
        self.put_formula()
        candidate = self.commit_candidate()
        (self.root / verifier.FORMULA).unlink()
        with self.assertRaisesRegex(verifier.VerificationError, "working formula differs"):
            self.verify(candidate=candidate)

    def test_unexpected_ruby_paths(self):
        for filename in ("evil.rb", "Formula/other.rb", "lib/exploit.RB"):
            with self.subTest(filename=filename):
                path = self.root / filename
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("raise 'must not run'\n")
                self.run_git("add", filename)
                with self.assertRaisesRegex(verifier.VerificationError, "unexpected committed Ruby"):
                    self.verify()
                self.run_git("rm", "--cached", "-q", filename)

    def test_symlink_formula(self):
        target = self.root / "payload"
        target.write_bytes(formula())
        (self.root / "Formula").mkdir()
        (self.root / verifier.FORMULA).symlink_to(target)
        with self.assertRaisesRegex(verifier.VerificationError, "regular"):
            self.verify()

    def test_symlink_directory(self):
        target = self.root / "elsewhere"
        target.mkdir()
        (target / "dotnetjq.rb").write_bytes(formula())
        (self.root / "Formula").symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(verifier.VerificationError, "real directory"):
            self.verify()

    def test_nonregular_formula(self):
        (self.root / verifier.FORMULA).mkdir(parents=True)
        with self.assertRaisesRegex(verifier.VerificationError, "regular"):
            self.verify()

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFO")
    def test_fifo_formula_rejected_without_opening(self):
        (self.root / "Formula").mkdir()
        os.mkfifo(self.root / verifier.FORMULA)
        with self.assertRaisesRegex(verifier.VerificationError, "regular"):
            verifier.read_candidate(self.root)

    def test_oversized_formula(self):
        self.put_formula(b"x" * (verifier.MAX_FORMULA_BYTES + 1))
        with self.assertRaisesRegex(verifier.VerificationError, "size limit"):
            self.verify()

    def test_bad_base_revisions(self):
        for revision in ("HEAD", "--help", "1234", "a" * 40):
            with self.subTest(revision=revision):
                with self.assertRaises(verifier.VerificationError):
                    self.verify(revision)

    def test_symlink_base_formula(self):
        (self.root / "Formula").mkdir()
        (self.root / verifier.FORMULA).symlink_to("../payload")
        self.run_git("add", verifier.FORMULA)
        self.run_git("-c", "user.name=Verifier Test", "-c", "user.email=verifier@example.invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "bad base")
        base = self.run_git("rev-parse", "HEAD")
        (self.root / verifier.FORMULA).unlink()
        self.put_formula()
        self.run_git("add", verifier.FORMULA)
        with self.assertRaisesRegex(verifier.VerificationError, "base formula must be regular"):
            self.verify(base)

    def test_cli_bootstrap_output(self):
        output = io.StringIO()
        with patch.object(Path, "cwd", return_value=self.root), contextlib.redirect_stdout(output):
            self.assertEqual(0, verifier.main(["--base-revision", "", "--candidate-revision", self.run_git("rev-parse", "HEAD")]))
        self.assertEqual("bootstrap\n", output.getvalue())

    def test_cli_failure_has_no_stdout(self):
        output, errors = io.StringIO(), io.StringIO()
        self.put_formula(b"invalid")
        candidate = self.commit_candidate()
        with patch.object(Path, "cwd", return_value=self.root), contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            self.assertEqual(1, verifier.main(["--candidate-revision", candidate]))
        self.assertEqual("", output.getvalue())
        self.assertIn("Formula verification failed", errors.getvalue())

    def test_candidate_revision_is_required_by_cli(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            verifier.main([])
        self.assertEqual(2, error.exception.code)

    def test_candidate_requires_exact_commit_sha(self):
        for revision in ("", "0" * 40, "HEAD", "--help", "a" * 40):
            with self.subTest(revision=revision), self.assertRaises(verifier.VerificationError):
                self.verify(candidate=revision)

    def test_candidate_must_equal_head(self):
        candidate = self.commit_candidate()
        self.put_formula()
        self.commit_candidate()
        with self.assertRaisesRegex(verifier.VerificationError, "HEAD does not match"):
            self.verify(candidate=candidate)

    def test_committed_malicious_bytes_cannot_be_replaced_in_worktree(self):
        self.put_formula(formula() + b"system('malicious')\n")
        candidate = self.commit_candidate()
        self.put_formula()
        with self.assertRaisesRegex(verifier.VerificationError, "working formula differs"):
            self.verify(candidate=candidate)
        self.assertEqual([], self.network.calls)

    def test_committed_malicious_bytes_cannot_be_replaced_in_index_and_worktree(self):
        self.put_formula(formula() + b"system('malicious')\n")
        candidate = self.commit_candidate()
        self.put_formula()
        self.run_git("add", verifier.FORMULA)
        with self.assertRaisesRegex(verifier.VerificationError, "Ruby index differs"):
            self.verify(candidate=candidate)
        self.assertEqual([], self.network.calls)

    def test_rm_cached_cannot_disguise_existing_formula_as_bootstrap(self):
        self.put_formula(formula() + b"system('malicious')\n")
        candidate = self.commit_candidate()
        self.run_git("rm", "--cached", "-q", verifier.FORMULA)
        (self.root / verifier.FORMULA).unlink()
        with self.assertRaisesRegex(verifier.VerificationError, "Ruby index differs"):
            self.verify(candidate=candidate)
        self.assertEqual([], self.network.calls)

    def test_hidden_committed_extra_ruby_is_rejected(self):
        extra = self.root / "extra.rb"
        extra.write_bytes(b"system('malicious')\n")
        candidate = self.commit_candidate()
        self.run_git("rm", "-q", "extra.rb")
        with self.assertRaisesRegex(verifier.VerificationError, "unexpected committed Ruby"):
            self.verify(candidate=candidate)

    def test_added_index_formula_cannot_change_bootstrap(self):
        candidate = self.commit_candidate()
        self.put_formula()
        self.run_git("add", verifier.FORMULA)
        with self.assertRaisesRegex(verifier.VerificationError, "Ruby index differs"):
            self.verify(candidate=candidate)

    def test_additional_untracked_ruby_rejected(self):
        self.put_formula()
        candidate = self.commit_candidate()
        (self.root / "extra.rb").write_bytes(b"system('malicious')\n")
        with self.assertRaisesRegex(verifier.VerificationError, "unexpected untracked Ruby"):
            self.verify(candidate=candidate)

    def test_additional_ignored_ruby_rejected(self):
        self.put_formula()
        (self.root / ".gitignore").write_text("extra.rb\n")
        candidate = self.commit_candidate()
        (self.root / "extra.rb").write_bytes(b"system('malicious')\n")
        with self.assertRaisesRegex(verifier.VerificationError, "unexpected untracked Ruby"):
            self.verify(candidate=candidate)


class FormulaTests(unittest.TestCase):
    def test_valid_versions(self):
        for version in ("0.0.0", "1.2.3", "10.20.300"):
            self.assertEqual(version, verifier.formula_version(formula(version)))

    def test_bad_versions(self):
        for version in ("1.0", "01.2.3", "1.02.3", "1.2.03", "1.2.3-beta", "1.2.3+build", "-1.2.3", "1.2.3;system('evil')", "9" * 11 + ".0.0"):
            with self.subTest(version=version), self.assertRaises(verifier.VerificationError):
                verifier.formula_version(formula(version))

    def test_invalid_utf8(self):
        with self.assertRaisesRegex(verifier.VerificationError, "UTF-8"):
            verifier.formula_version(formula() + b"\xff")

    def test_nul(self):
        with self.assertRaisesRegex(verifier.VerificationError, "NUL"):
            verifier.formula_version(formula() + b"\0")

    def test_bad_class(self):
        for content in (formula().replace(b"Dotnetjq", b"Unexpected"), formula().replace(b"< Formula", b"< Object"), formula() + b"class Evil < Formula\nend\n", formula().replace(b"class Dotnetjq < Formula", b"class Dotnetjq < Formula; system('bad')")):
            with self.subTest(content=content), self.assertRaises(verifier.VerificationError):
                verifier.formula_version(content)

    def test_duplicate_or_missing_version(self):
        for content in (formula() + b'  version "1.2.3"\n', b"class Dotnetjq < Formula\nend\n"):
            with self.assertRaises(verifier.VerificationError):
                verifier.formula_version(content)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.network = FakeNetwork()

    def verify(self):
        verifier.verify_release(formula(), "1.2.3", token="fixture-token", fetcher=self.network)

    def test_published_immutable_release(self):
        self.verify()
        self.assertEqual(2, len(self.network.calls))

    def test_nonpublished_or_unstable_or_mutable(self):
        for field, values in {"draft": [True, None, 0], "prerelease": [True, None, 0], "immutable": [False, None, 1]}.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    self.network = FakeNetwork()
                    self.network.release[field] = value
                    with self.assertRaises(verifier.VerificationError):
                        self.verify()

    def test_wrong_tag(self):
        self.network.release["tag_name"] = "v1.2.4"
        with self.assertRaisesRegex(verifier.VerificationError, "tag"):
            self.verify()

    def test_bad_publication_timestamp(self):
        for timestamp in (None, "", "yesterday", "2026-09-08T10:00:00"):
            with self.subTest(timestamp=timestamp):
                self.network.release["published_at"] = timestamp
                with self.assertRaises(verifier.VerificationError):
                    self.verify()

    def test_invalid_api_json(self):
        for data in (b"invalid", b"\xff", b"[]", b"null"):
            self.network.api_bytes = data
            with self.subTest(data=data), self.assertRaises(verifier.VerificationError):
                self.verify()

    def test_missing_duplicate_or_invalid_assets(self):
        asset = self.network.release["assets"][0]
        for assets in (None, {}, [], [asset, asset], [{"name": "other.rb"}]):
            self.network.release["assets"] = assets
            with self.subTest(assets=assets), self.assertRaises(verifier.VerificationError):
                self.verify()

    def test_unuploaded_asset(self):
        self.network.release["assets"][0]["state"] = "new"
        with self.assertRaisesRegex(verifier.VerificationError, "uploaded"):
            self.verify()

    def test_invalid_asset_size(self):
        for size in (None, True, 0, -1, verifier.MAX_FORMULA_BYTES + 1, len(formula()) + 1, str(len(formula()))):
            self.network.release["assets"][0]["size"] = size
            with self.subTest(size=size), self.assertRaises(verifier.VerificationError):
                self.verify()

    def test_invalid_or_mismatching_digest(self):
        for digest in (None, "", "md5:" + "0" * 32, "sha256:" + "0" * 64):
            self.network.release["assets"][0]["digest"] = digest
            with self.subTest(digest=digest), self.assertRaises(verifier.VerificationError):
                self.verify()

    def test_asset_url_must_be_exact(self):
        url = self.network.release["assets"][0]["browser_download_url"]
        for bad_url in (url.replace("https:", "http:"), url.replace("gtg-open/", "attacker/"), url + "?download=1", url.replace("v1.2.3", "v1.2.4"), "https://example.invalid/formula.rb"):
            self.network.release["assets"][0]["browser_download_url"] = bad_url
            with self.subTest(url=bad_url), self.assertRaises(verifier.VerificationError):
                self.verify()
        self.assertTrue(all(call[0].startswith("https://api.github.com/") for call in self.network.calls))

    def test_download_differs_from_candidate(self):
        self.network.content = formula().replace(b"1.2.3", b"9.9.9")
        with self.assertRaisesRegex(verifier.VerificationError, "downloaded formula digest"):
            self.verify()

    def test_download_size_mismatch(self):
        self.network.content += b"\n"
        with self.assertRaisesRegex(verifier.VerificationError, "downloaded formula size"):
            self.verify()


class FakeResponse:
    status = 200

    def __init__(self, data=b"abc", length=None):
        self.stream = io.BytesIO(data)
        self.headers = {} if length is None else {"Content-Length": length}

    def __enter__(self):
        return self

    def __exit__(self, *_arguments):
        return False

    def read1(self, size):
        return self.stream.read(size)


class NetworkTests(unittest.TestCase):
    API = "https://api.github.com/repos/gtg-open/dotnetjq/releases/tags/v1.2.3"
    ASSET = "https://github.com/gtg-open/dotnetjq/releases/download/v1.2.3/dotnetjq.rb"

    def test_api_authorization_only(self):
        with patch.object(urllib.request, "build_opener") as opener:
            opener.return_value.open.return_value = FakeResponse()
            self.assertEqual(b"abc", verifier.fetch(self.API, 10, token="fixture-token"))
            request = opener.return_value.open.call_args.args[0]
            self.assertEqual("Bearer fixture-token", request.get_header("Authorization"))
            self.assertEqual(verifier.NETWORK_TIMEOUT, opener.return_value.open.call_args.kwargs["timeout"])
            opener.return_value.open.return_value = FakeResponse()
            verifier.fetch(self.ASSET, 10)
            self.assertFalse(opener.return_value.open.call_args.args[0].has_header("Authorization"))

    def test_credentials_refused_for_asset(self):
        with self.assertRaisesRegex(verifier.VerificationError, "credentials"):
            verifier.fetch(self.ASSET, 10, token="fixture-token")

    def test_response_size_is_bounded(self):
        for response in (FakeResponse(b"abcd"), FakeResponse(b"abc", "100"), FakeResponse(b"abc", "-1")):
            with patch.object(urllib.request, "build_opener") as opener:
                opener.return_value.open.return_value = response
                with self.assertRaises(verifier.VerificationError):
                    verifier.fetch(self.API, 3)

    def test_exact_limit_allowed(self):
        with patch.object(urllib.request, "build_opener") as opener:
            opener.return_value.open.return_value = FakeResponse(b"abc", "3")
            self.assertEqual(b"abc", verifier.fetch(self.API, 3))

    def test_truncated_response(self):
        with patch.object(urllib.request, "build_opener") as opener:
            opener.return_value.open.return_value = FakeResponse(b"abc", "4")
            with self.assertRaisesRegex(verifier.VerificationError, "truncated"):
                verifier.fetch(self.API, 10)

    def test_network_failure_closed(self):
        with patch.object(urllib.request, "build_opener") as opener:
            opener.return_value.open.side_effect = urllib.error.URLError("fixture failure")
            with self.assertRaisesRegex(verifier.VerificationError, "network request failed"):
                verifier.fetch(self.API, 10)

    def test_deadline(self):
        with patch.object(urllib.request, "build_opener") as opener, patch.object(verifier.time, "monotonic", side_effect=[0, verifier.NETWORK_DEADLINE + 1]):
            opener.return_value.open.return_value = FakeResponse()
            with self.assertRaisesRegex(verifier.VerificationError, "deadline"):
                verifier.fetch(self.API, 10)

    def test_api_redirect_always_rejected(self):
        handler = verifier.RestrictedRedirects(False)
        request = urllib.request.Request(self.API, headers={"Authorization": "Bearer fixture-token"})
        with self.assertRaisesRegex(verifier.VerificationError, "API redirects"):
            handler.redirect_request(request, None, 302, "Found", {}, self.API)

    def test_asset_redirect_allowed_anonymously(self):
        handler = verifier.RestrictedRedirects(True)
        request = urllib.request.Request(self.ASSET)
        target = "https://release-assets.githubusercontent.com/github-production-release-asset/123?token=public"
        redirected = handler.redirect_request(request, None, 302, "Found", {}, target)
        self.assertEqual(target, redirected.full_url)
        self.assertFalse(redirected.has_header("Authorization"))

    def test_unsafe_asset_redirects(self):
        handler = verifier.RestrictedRedirects(True)
        request = urllib.request.Request(self.ASSET)
        for target in ("http://github.com/asset", "https://github.com.attacker.invalid/asset", "https://evil.invalid/asset", "https://user@github.com/asset", "https://github.com:444/asset"):
            with self.subTest(target=target), self.assertRaises(verifier.VerificationError):
                handler.redirect_request(request, None, 302, "Found", {}, target)

    def test_authenticated_asset_redirect_rejected(self):
        handler = verifier.RestrictedRedirects(True)
        request = urllib.request.Request(self.ASSET, headers={"Authorization": "Bearer fixture-token"})
        with self.assertRaisesRegex(verifier.VerificationError, "anonymous"):
            handler.redirect_request(request, None, 302, "Found", {}, "https://github.com/asset")


if __name__ == "__main__":
    unittest.main()
