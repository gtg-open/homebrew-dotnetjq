#!/usr/bin/env python3
"""Authenticate Formula/dotnetjq.rb against its immutable GitHub release.

Run from the tap root with --candidate-revision COMMIT and --base-revision
COMMIT (empty/40 zeroes means bootstrap). The candidate must be HEAD, and its
committed Ruby inventory and formula bytes must match the index and worktree.
GH_TOKEN optionally authorizes only the fixed GitHub API request;
the public release asset is always downloaded without Authorization. No Ruby is
evaluated. Standard output is exactly ``bootstrap`` or ``verified`` on success.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


FORMULA = "Formula/dotnetjq.rb"
REPOSITORY = "gtg-open/dotnetjq"
MAX_FORMULA_BYTES = 1024 * 1024
MAX_API_BYTES = 4 * 1024 * 1024
NETWORK_TIMEOUT = 15
NETWORK_DEADLINE = 30
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")


class VerificationError(Exception):
    """An untrusted input failed a required check."""


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def git(root, *arguments):
    """Run a bounded, read-only Git command without a shell."""
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", "--no-optional-locks", "-C", str(root), *arguments], check=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise VerificationError("cannot inspect Git repository") from error
    require(result.returncode == 0, "cannot inspect Git repository")
    return result.stdout


def indexed_ruby_files(root):
    """Return Ruby index modes/blob IDs, rejecting unexpected paths or conflicts."""
    found = {}
    for entry in git(root, "ls-files", "--stage", "-z").split(b"\0"):
        if not entry:
            continue
        metadata, name = entry.split(b"\t", 1)
        mode, object_id, stage = metadata.split()
        require(stage == b"0", "unmerged index entries are not allowed")
        if name.lower().endswith(b".rb"):
            require(name == FORMULA.encode(), "unexpected tracked Ruby file")
            require(mode in (b"100644", b"100755"), "formula must be a regular file")
            found[name] = (mode, object_id)
    return found


def candidate_ruby_files(root, revision):
    """Return the allowed Ruby inventory from the exact immutable candidate tree."""
    found = {}
    for entry in git(root, "ls-tree", "--full-tree", "-r", "-z", revision).split(b"\0"):
        if not entry:
            continue
        metadata, name = entry.split(b"\t", 1)
        mode, kind, object_id = metadata.split()
        if name.lower().endswith(b".rb"):
            require(name == FORMULA.encode(), "unexpected committed Ruby file")
            require(mode in (b"100644", b"100755") and kind == b"blob", "committed formula must be regular")
            found[name] = (mode, object_id)
    return found


def exact_commit(root, revision, label):
    """Accept a full commit object ID only, not a ref, tag, or replacement object."""
    require(isinstance(revision, str) and re.fullmatch(r"[0-9a-fA-F]{40}", revision), label + " revision must be a full commit SHA")
    resolved = git(root, "rev-parse", "--verify", revision + "^{commit}").decode("ascii").strip()
    require(resolved == revision.lower(), label + " revision must identify a commit directly")
    return resolved


def read_candidate(root):
    """Read a bounded regular formula without following directory/file symlinks."""
    directory = root / "Formula"
    try:
        directory_mode = directory.lstat().st_mode
    except FileNotFoundError:
        return None
    require(stat.S_ISDIR(directory_mode), "Formula must be a real directory")
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            info = os.stat("dotnetjq.rb", dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return None
        require(stat.S_ISREG(info.st_mode), "formula must be a regular file")
        require(info.st_size <= MAX_FORMULA_BYTES, "formula exceeds size limit")
        candidate = os.open(
            "dotnetjq.rb", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=descriptor,
        )
        with os.fdopen(candidate, "rb") as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode), "formula must be a regular file")
            require(info.st_size <= MAX_FORMULA_BYTES, "formula exceeds size limit")
            content = stream.read(MAX_FORMULA_BYTES + 1)
            require(len(content) <= MAX_FORMULA_BYTES, "formula exceeds size limit")
            return content
    finally:
        os.close(descriptor)


def read_committed_formula(root, revision, label):
    """Read bounded formula bytes from a validated commit, never working files."""
    entry = git(root, "ls-tree", "-z", "-l", revision, "--", FORMULA)
    if not entry:
        return None
    require(entry.endswith(b"\0") and entry.count(b"\0") == 1, "invalid " + label + " formula entry")
    metadata, name = entry[:-1].split(b"\t", 1)
    mode, kind, object_id, size = metadata.split()
    require(name == FORMULA.encode(), "invalid " + label + " formula path")
    require(mode in (b"100644", b"100755") and kind == b"blob", label + " formula must be regular")
    require(size.isdigit() and int(size) <= MAX_FORMULA_BYTES, label + " formula exceeds size limit")
    content = git(root, "cat-file", "blob", object_id.decode("ascii"))
    require(len(content) == int(size), label + " formula size mismatch")
    return content


def read_baseline(root, revision):
    """Read the optional base formula from a full commit SHA."""
    if not revision or revision == "0" * 40:
        return None
    return read_committed_formula(root, exact_commit(root, revision, "base"), "base")


def bound_candidate(root, revision):
    """Bind verification to HEAD and reject worktree/index substitutions."""
    revision = exact_commit(root, revision, "candidate")
    head = git(root, "rev-parse", "--verify", "HEAD^{commit}").decode("ascii").strip()
    require(head == revision, "HEAD does not match candidate revision")
    working = read_candidate(root)
    committed_ruby = candidate_ruby_files(root, revision)
    require(indexed_ruby_files(root) == committed_ruby, "Ruby index differs from candidate commit")
    # Do not honor .gitignore: ignored Ruby would still be executable by Homebrew.
    for name in git(root, "ls-files", "--others", "-z").split(b"\0"):
        require(not name.lower().endswith(b".rb"), "unexpected untracked Ruby file")
    committed = read_committed_formula(root, revision, "candidate")
    require(working == committed, "working formula differs from candidate commit")
    return committed


def formula_version(content):
    """Extract one canonical stable SemVer and the expected class without Ruby."""
    require(len(content) <= MAX_FORMULA_BYTES, "formula exceeds size limit")
    try:
        source = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise VerificationError("formula must be valid UTF-8") from error
    require("\0" not in source, "formula contains a NUL byte")
    classes = re.findall(r"^[ \t]*class\b[^\r\n]*", source, re.MULTILINE)
    require(classes == ["class Dotnetjq < Formula"], "formula must declare only class Dotnetjq < Formula")
    declarations = re.findall(r"^[ \t]*version\b[^\r\n]*", source, re.MULTILINE)
    require(len(declarations) == 1, "formula must have exactly one version declaration")
    match = re.fullmatch(r'[ \t]*version "([^"\r\n]+)"[ \t]*', declarations[0])
    require(match is not None and VERSION.fullmatch(match[1]), "formula version must be stable SemVer")
    # Bound individual components before int() to avoid pathological decimal work.
    require(all(len(part) <= 10 for part in match[1].split(".")), "version component is too large")
    return match[1]


class RestrictedRedirects(urllib.request.HTTPRedirectHandler):
    """Never redirect an authenticated API call; restrict anonymous asset hosts."""

    def __init__(self, allow_asset_redirects):
        super().__init__()
        self.allow_asset_redirects = allow_asset_redirects

    def redirect_request(self, request, response, code, message, headers, new_url):
        target = urllib.parse.urlsplit(new_url)
        require(self.allow_asset_redirects, "GitHub API redirects are not allowed")
        require(
            target.scheme == "https"
            and target.hostname in {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}
            and target.port in (None, 443)
            and target.username is None and target.password is None,
            "release asset redirect is not an allowed HTTPS GitHub URL",
        )
        require(not request.has_header("Authorization"), "asset request must be anonymous")
        return super().redirect_request(request, response, code, message, headers, new_url)


def fetch(url, limit, token=None):
    """Fetch at most limit bytes; API credentials cannot reach release redirects."""
    api = url.startswith("https://api.github.com/repos/" + REPOSITORY + "/releases/tags/v")
    require(token is None or api, "credentials are allowed only for the release API")
    headers = {"User-Agent": "dotnetjq-homebrew-release-verifier", "Accept-Encoding": "identity"}
    if api:
        headers.update({"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, headers=headers)
    opener = urllib.request.build_opener(RestrictedRedirects(not api))
    deadline = time.monotonic() + NETWORK_DEADLINE
    try:
        with opener.open(request, timeout=NETWORK_TIMEOUT) as response:
            require(response.status == 200, "release download did not return HTTP 200")
            length = response.headers.get("Content-Length")
            if length is not None:
                require(length.isdigit() and int(length) <= limit, "release response exceeds size limit")
            chunks = []
            size = 0
            while True:
                require(time.monotonic() < deadline, "release download exceeded deadline")
                chunk = response.read1(min(65536, limit + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                require(size <= limit, "release response exceeds size limit")
                chunks.append(chunk)
            if length is not None:
                require(size == int(length), "release response was truncated")
            return b"".join(chunks)
    except (OSError, ValueError, urllib.error.URLError) as error:
        raise VerificationError("release network request failed") from error


def verify_release(content, version, token=None, fetcher=fetch):
    """Require a published immutable release and byte-identical SHA-256 asset."""
    tag = "v" + version
    api_url = "https://api.github.com/repos/" + REPOSITORY + "/releases/tags/" + tag
    try:
        release = json.loads(fetcher(api_url, MAX_API_BYTES, token=token))
    except (ValueError, UnicodeDecodeError) as error:
        raise VerificationError("invalid release API JSON") from error
    require(isinstance(release, dict), "release API must return an object")
    require(release.get("tag_name") == tag, "release tag does not match formula version")
    require(release.get("draft") is False and release.get("prerelease") is False, "release must be published and stable")
    require(release.get("immutable") is True, "release must be immutable")
    published = release.get("published_at")
    require(isinstance(published, str), "release must have a publication timestamp")
    try:
        timestamp = datetime.datetime.fromisoformat(published.replace("Z", "+00:00"))
    except ValueError as error:
        raise VerificationError("release publication timestamp is invalid") from error
    require(timestamp.tzinfo is not None, "release publication timestamp must include timezone")
    assets = release.get("assets")
    require(isinstance(assets, list), "release must contain an asset list")
    matches = [asset for asset in assets if isinstance(asset, dict) and asset.get("name") == "dotnetjq.rb"]
    require(len(matches) == 1, "release must contain exactly one dotnetjq.rb asset")
    asset = matches[0]
    require(asset.get("state") == "uploaded", "formula asset is not uploaded")
    size = asset.get("size")
    require(type(size) is int and 0 < size <= MAX_FORMULA_BYTES, "formula asset size is invalid")
    require(size == len(content), "formula size does not match release asset")
    digest = asset.get("digest")
    require(isinstance(digest, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", digest), "formula asset must have a SHA-256 digest")
    expected = "sha256:" + hashlib.sha256(content).hexdigest()
    require(digest == expected, "formula digest does not match release asset")
    url = "https://github.com/" + REPOSITORY + "/releases/download/" + tag + "/dotnetjq.rb"
    require(asset.get("browser_download_url") == url, "formula asset URL is not the exact public release URL")
    published_content = fetcher(url, MAX_FORMULA_BYTES, token=None)
    require(len(published_content) == size, "downloaded formula size mismatch")
    require("sha256:" + hashlib.sha256(published_content).hexdigest() == digest, "downloaded formula digest mismatch")
    require(published_content == content, "candidate formula differs from published release asset")


def verify(root, base_revision="", token=None, fetcher=fetch, *, candidate_revision):
    """Verify a checkout and return its single-word CI state without evaluating it."""
    root = Path(root)
    baseline = read_baseline(root, base_revision)
    candidate = bound_candidate(root, candidate_revision)
    if candidate is None:
        require(baseline is None, "deleting an existing formula is not allowed")
        return "bootstrap"
    version = formula_version(candidate)
    if baseline is not None:
        old_version = formula_version(baseline)
        current = tuple(map(int, version.split(".")))
        previous = tuple(map(int, old_version.split(".")))
        require(current >= previous, "formula version downgrade is not allowed")
        require(current != previous or candidate == baseline, "same-version formula mutation is not allowed")
    verify_release(candidate, version, token=token, fetcher=fetcher)
    return "verified"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-revision", default="", help="full base commit SHA; empty or 40 zeroes for bootstrap")
    parser.add_argument("--candidate-revision", required=True, help="full candidate commit SHA; must equal checked-out HEAD")
    arguments = parser.parse_args(argv)
    try:
        result = verify(Path.cwd(), arguments.base_revision, os.environ.get("GH_TOKEN"), candidate_revision=arguments.candidate_revision)
    except (VerificationError, OSError) as error:
        print("Formula verification failed: " + str(error), file=sys.stderr)
        return 1
    print(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
