# Maintainer rules

Before every commit or publication, inspect the exact staged contents and any generated outputs, including filenames, symlink targets, archives, debug information, and commit/tag metadata. Never expose personal or private information, workstation paths, credentials, or private connection setup. Use repository-relative paths, documented environment configuration, and generic examples. Run the repository privacy check before committing and before publishing generated artifacts. Keep private audit evidence outside tracked repositories and public comments. Preserve legitimate third-party attribution, licenses, and approved public maintainer identities. Never restore removed history from an old checkout or backup.

Formula changes must retain their upstream release provenance and pass the tap's checks. Use ordinary commits and merge commits for normal maintenance; history replacement requires explicit authorization.

Run `python3 -B tools/privacy/check.py --staged` before committing. Before publishing, run `python3 -B tools/privacy/check.py --metadata --history` and add `--output` for each generated directory or archive that will be public. See [privacy check usage and limitations](tools/privacy/README.md). Keep any additional private denylist outside the repository.
