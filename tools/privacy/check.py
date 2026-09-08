#!/usr/bin/env python3
"""Fail-closed privacy checks for Git inputs and explicitly selected publications.

No files are changed, no archive is extracted, and no network request is made.
Matching values and unsafe filenames are never included in diagnostics.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
import zipfile


RULES = (
    ("workstation-home-path", re.compile(r"(?i)(?<![A-Za-z0-9_])(?:/(?:home|Users)/|[A-Z]:[\\/]+Users[\\/]+)(?![<$]|\.jq(?:[\s\"']|$))[^\s/\\\"'<>;,:]+")),
    ("private-key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b")),
    ("cloud-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("credential-in-url", re.compile(r"(?i)\b(?:https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s/@:]+:[^\s/@]+@")),
    ("literal-authorization", re.compile(r"(?i)\bAuthorization[\"']?\s*[:=]\s*[\"']?(?:Bearer|Basic)\s+[A-Za-z0-9+/=_-]{20,}")),
    ("private-network-address", re.compile(r"(?<![\d.])(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?![\d.])")),
    ("private-network-endpoint", re.compile(r"(?i)\b(?:https?|ssh|postgres(?:ql)?|mysql|redis)://[^\s/]+\.(?:internal|corp|lan)(?=[:/\s]|$)")),
    ("connection-password", re.compile(r"(?i)\b(?:Password|Pwd)\s*=\s*(?![<$])[^\s;\"']{8,}")),
)
APPROVED_IDENTITIES = frozenset({
    ("GtG Open Maintainer", "325667272+gtg-open-maintainer@users.noreply.github.com"),
    ("gtg-open-maintainer", "325667272+gtg-open-maintainer@users.noreply.github.com"),
    ("GitHub", "noreply@github.com"),
    ("github-actions[bot]", "41898282+github-actions[bot]@users.noreply.github.com"),
    ("dependabot[bot]", "49699333+dependabot[bot]@users.noreply.github.com"),
})
MAX_MEMBER = 256 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
MAX_DEPTH = 4


class ScanError(Exception):
    """An input could not be completely inspected; details remain private."""


def git(root: Path, *args: str) -> bytes:
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True)
    if result.returncode:
        raise ScanError("git-input-unavailable")
    return result.stdout


class Scanner:
    def __init__(self, denied: tuple[str, ...] = ()):
        self.denied = denied
        self.findings: set[tuple[str, str]] = set()
        self.inputs = 0
        self.total = 0

    def matches(self, text: str) -> set[str]:
        found = {name for name, pattern in RULES if pattern.search(text)}
        if any(value.casefold() in text.casefold() for value in self.denied):
            found.add("private-denylist-match")
        return found

    def add(self, location: str, rule: str) -> None:
        if self.matches(location) or any(ord(char) < 32 for char in location):
            location = "redacted-name:" + hashlib.sha256(location.encode("utf-8", "replace")).hexdigest()[:12]
        self.findings.add((location, rule))

    def text(self, location: str, text: str) -> None:
        for rule in self.matches(text):
            self.add(location, rule)

    def blob(self, location: str, data: bytes, *, depth: int = 0) -> None:
        self.inputs += 1
        self.total += len(data)
        if len(data) > MAX_MEMBER or self.total > MAX_TOTAL:
            self.add(location, "inspection-size-limit")
            return
        self.text(location, location)
        # Scan bytes as text, including readable paths embedded in binaries/PDBs.
        self.text(location, data.decode("utf-8", "replace"))
        if b"\x00" in data:
            self.text(location, data.decode("utf-16-le", "replace"))
            self.text(location, data.decode("utf-16-be", "replace"))
        lower = location.lower()
        if lower.endswith((".7z", ".rar", ".xz", ".bz2", ".zst", ".br")):
            self.add(location, "unsupported-compressed-format")
        kind = ("zip" if data.startswith((b"PK\x03\x04", b"PK\x05\x06")) or lower.endswith((".zip", ".nupkg", ".snupkg"))
                else "gzip" if data.startswith(b"\x1f\x8b") or lower.endswith((".gz", ".tgz"))
                else "tar" if lower.endswith(".tar") or data[257:262] == b"ustar"
                else None)
        if kind:
            if depth >= MAX_DEPTH:
                self.add(location, "archive-depth-limit")
                return
            try:
                self.archive(location, data, kind, depth)
            except (OSError, ValueError, RuntimeError, EOFError, zipfile.BadZipFile, tarfile.TarError):
                self.add(location, "archive-unreadable")

    def member_name(self, location: str, name: str) -> str:
        result = location + "!" + name
        self.text(result, name)
        normalized = name.replace("\\", "/")
        if PurePosixPath(normalized).is_absolute() or ".." in PurePosixPath(normalized).parts or re.match(r"^[A-Za-z]:", normalized):
            self.add(result, "unsafe-archive-name")
        return result

    def archive(self, location: str, data: bytes, kind: str, depth: int) -> None:
        if kind == "gzip":
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                content = stream.read(MAX_MEMBER + 1)
            self.blob(location + "!uncompressed.tar" if location.lower().endswith((".tar.gz", ".tgz")) else location + "!uncompressed", content, depth=depth + 1)
        elif kind == "zip":
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                self.text(location + "!comment", archive.comment.decode("utf-8", "replace"))
                for member in archive.infolist():
                    target = self.member_name(location, member.filename)
                    self.text(target, member.comment.decode("utf-8", "replace"))
                    if member.flag_bits & 1:
                        self.add(target, "encrypted-archive-member")
                    elif member.file_size > MAX_MEMBER or self.total + member.file_size > MAX_TOTAL:
                        self.add(target, "inspection-size-limit")
                    elif not member.is_dir():
                        self.blob(target, archive.read(member), depth=depth + 1)
        else:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
                for member in archive:
                    target = self.member_name(location, member.name)
                    self.text(target, json.dumps(member.pax_headers))
                    self.text(target, member.uname + "\n" + member.gname + "\n" + member.linkname)
                    if member.issym() or member.islnk():
                        self.member_name(target, member.linkname)
                    elif member.isfile():
                        if member.size > MAX_MEMBER or self.total + member.size > MAX_TOTAL:
                            self.add(target, "inspection-size-limit")
                        else:
                            stream = archive.extractfile(member)
                            if stream is None:
                                self.add(target, "archive-unreadable")
                            else:
                                self.blob(target, stream.read(MAX_MEMBER + 1), depth=depth + 1)
                    elif not member.isdir():
                        self.add(target, "unsupported-archive-member")

    def file(self, path: Path, location: str) -> None:
        self.text(location, location)
        try:
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                self.text(location, os.readlink(path))
            elif stat.S_ISREG(mode):
                with path.open("rb") as stream:
                    self.blob(location, stream.read(MAX_MEMBER + 1))
            else:
                self.add(location, "unsupported-input-type")
        except OSError:
            self.add(location, "input-unreadable")

    def repository(self, root: Path, mode: str) -> None:
        changed = set(git(root, "diff", "--cached", "--name-only", "--diff-filter=ACMRT", "-z").split(b"\0")) if mode == "staged" else None
        for record in git(root, "ls-files", "--stage", "-z").split(b"\0"):
            if not record:
                continue
            info, name = record.split(b"\t", 1)
            file_mode, oid, stage = info.split()
            location = name.decode("utf-8", "replace")
            if changed is not None and name not in changed:
                continue
            if stage != b"0":
                self.add(location, "unresolved-index-entry")
            elif file_mode == b"160000":
                self.add(location, "submodule-needs-separate-scan")
            elif mode == "worktree":
                path = root / os.fsdecode(name)
                if path.exists() or path.is_symlink():
                    self.file(path, location)
            else:
                self.blob(location, git(root, "cat-file", "blob", oid.decode()))

    def metadata(self, root: Path, history: bool) -> None:
        revisions = git(root, "rev-list", "--all" if history else "HEAD").splitlines() if history else [b"HEAD"]
        inspected_blobs: set[tuple[bytes, bytes]] = set()
        for revision in revisions:
            commit = git(root, "cat-file", "commit", revision.decode())
            location = "commit:" + hashlib.sha256(commit).hexdigest()[:12]
            self.text(location, commit.decode("utf-8", "replace"))
            for name, email in re.findall(rb"^(?:author|committer) ([^\n]*) <([^>]+)> \d+ [+-]\d+", commit, re.M):
                if (name.decode("utf-8", "replace"), email.decode("utf-8", "replace")) not in APPROVED_IDENTITIES:
                    self.add(location, "unapproved-git-identity")
            if history:
                for record in git(root, "ls-tree", "-r", "-z", revision.decode()).split(b"\0"):
                    if not record:
                        continue
                    info, name = record.split(b"\t", 1)
                    _, object_type, oid = info.split()
                    if object_type == b"blob" and (oid, name) not in inspected_blobs:
                        inspected_blobs.add((oid, name))
                        # Retain repository-relative filenames for the same
                        # narrow fixture handling as the current index scan.
                        self.blob(name.decode("utf-8", "replace"), git(root, "cat-file", "blob", oid.decode()))
                    elif object_type != b"blob":
                        self.add(location, "submodule-needs-separate-scan")
        for oid in git(root, "for-each-ref", "--format=%(objectname)", "refs/tags").splitlines():
            if git(root, "cat-file", "-t", oid.decode()).strip() == b"tag":
                tag = git(root, "cat-file", "tag", oid.decode())
                location = "tag:" + oid.decode()[:12]
                self.text(location, tag.decode("utf-8", "replace"))
                for name, email in re.findall(rb"^tagger ([^\n]*) <([^>]+)> \d+ [+-]\d+", tag, re.M):
                    if (name.decode("utf-8", "replace"), email.decode("utf-8", "replace")) not in APPROVED_IDENTITIES:
                        self.add(location, "unapproved-git-identity")
        self.text("git-ref-names", git(root, "for-each-ref", "--format=%(refname)").decode("utf-8", "replace"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--staged", action="store_true", help="inspect changed index blobs, never unstaged replacements")
    modes.add_argument("--worktree", action="store_true", help="inspect present tracked working files before staging")
    parser.add_argument("--metadata", action="store_true", help="inspect HEAD/tag messages and approved author identities")
    parser.add_argument("--history", action="store_true", help="inspect metadata of every locally reachable commit")
    parser.add_argument("--output", action="append", type=Path, default=[], help="also inspect this exact generated file/directory/archive (repeatable)")
    parser.add_argument("--denylist", type=Path, help="private UTF-8 file of literal strings, one per line; never commit this file")
    args = parser.parse_args()
    try:
        denied = tuple(value.strip() for value in args.denylist.read_text(encoding="utf-8").splitlines() if value.strip()) if args.denylist else ()
        if any(len(value) < 4 for value in denied):
            raise ScanError("denylist-entry-too-short")
        scanner = Scanner(denied)
        scanner.repository(args.repo, "staged" if args.staged else "worktree" if args.worktree else "index")
        if args.metadata or args.history:
            scanner.metadata(args.repo, args.history)
        for index, output in enumerate(args.output, 1):
            label = f"output[{index}]"
            scanner.text(label, output.name)
            if output.is_dir() and not output.is_symlink():
                for directory, folders, files in os.walk(output, followlinks=False, onerror=lambda _: (_ for _ in ()).throw(ScanError("output-unreadable"))):
                    for name in folders[:]:
                        child = Path(directory) / name
                        scanner.text(label + "/" + child.relative_to(output).as_posix(), name)
                        if child.is_symlink():
                            scanner.file(child, label + "/" + child.relative_to(output).as_posix())
                            folders.remove(name)
                    for name in files:
                        child = Path(directory) / name
                        scanner.file(child, label + "/" + child.relative_to(output).as_posix())
            else:
                scanner.file(output, label + "/" + output.name)
        for location, rule in sorted(scanner.findings):
            print(f"PRIVACY {rule}: {location}", file=sys.stderr)
        print(f"Privacy scan: {scanner.inputs} inputs inspected; {len(scanner.findings)} findings.")
        return 1 if scanner.findings else 0
    except (OSError, UnicodeError, ScanError):
        print("Privacy scan could not inspect every selected input; no publication is permitted.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
