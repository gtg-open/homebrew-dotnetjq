# Privacy checks

Run `python3 -B tools/privacy/check.py --staged` immediately before committing.
The scanner reads the exact changed blobs in Git's index; an unstaged clean
replacement cannot hide a staged disclosure. Run without `--staged` to inspect
every index blob, or use `--worktree` to inspect tracked working files before
staging. Deleted working files are absent from the worktree scan; the index scan
still checks any version that would be committed. Untracked files are inspected
once staged or when explicitly selected as outputs.

Before publication, run the following with the actual directory or archive
selected for upload:

```sh
python3 -B tools/privacy/check.py --metadata --output artifacts/release
```

Repeat `--output` for additional release assets, symbols, logs, and reports. The
scanner inspects files, filenames, symlink targets, ZIP/NuGet contents and
comments, tar headers and members, and gzip contents. Archives are never
extracted and symlinks are never followed. UTF-8 and UTF-16 text embedded in
binaries is checked. Oversized, encrypted, malformed, excessively nested, or
unsupported archive members fail rather than silently passing. The default
limits are 256 MiB per member, 1 GiB total bytes inspected, and four archive
layers. Larger publications need an explicitly reviewed inspection strategy.

`--metadata` checks current commit and local tag messages, ref names, and the
approved public maintainer/bot name and email pairs. `--history` also inspects every
locally reachable commit's tree and metadata, deduplicating identical blobs at
the same filename. It does not fetch remote refs. Hosting-service surfaces must
be audited separately when removing an earlier disclosure. The CI checkout
fetches full history so an unsafe ancestor cannot be reintroduced unnoticed.

The generic checks detect concrete home-directory paths, common token formats,
private keys, credentials embedded in URLs or authorization headers, private
network endpoints, and connection passwords. Use `--denylist` with a private
UTF-8 file outside the repository for additional literal identities, usernames,
hosts, or confidential terms. Diagnostics include the rule and a safe file
location, never the matching value; sensitive filenames are represented by a
short digest. Do not put real private examples in tests or exceptions.

This is a preventive check, not proof that all private information is absent.
Arbitrary secrets, personal names, encoded/compressed debug formats other than
the supported archives, private hostnames without a recognizable suffix, and
remote logs/caches may require manual or specialist inspection. Legitimate
third-party names, email attribution, and license notices are retained. Inspect
the staged diff and generated outputs as well as running the scanner. A passing
workflow does not itself authorize publishing.
