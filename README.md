# DotNetJq Homebrew tap

Homebrew packaging for [DotNetJq](https://github.com/gtg-open/dotnetjq), a managed
jq 1.8.2-compatible library and command-line tool.

This repository contains packaging metadata, not a second copy of the product.
Source, binaries, release notes, and product issues remain in
[gtg-open/dotnetjq](https://github.com/gtg-open/dotnetjq).

The first stable DotNetJq release will add the verified Homebrew formula. Until
then, this tap intentionally contains no installable package or placeholder
download.

## Installation

After the first stable release's formula pull request has been merged:

```sh
brew install gtg-open/dotnetjq/dotnetjq
```

Homebrew adds this tap automatically. Subsequent updates use `brew update` and
`brew upgrade gtg-open/dotnetjq/dotnetjq`.

The package installs the NativeAOT CLI; a separate .NET runtime is not required.
Supported targets are macOS and glibc-based Linux on x64 and ARM64. Linux needs
glibc 2.39 or newer; the formula installs its ICU dependency. See the product's
[installation guide](https://github.com/gtg-open/dotnetjq/blob/main/docs/installation.md)
for platform details, Windows/PowerShell, NuGet, and direct downloads. For jq
syntax, use the [canonical jq manual](https://jqlang.org/manual/v1.8/).

## Publication and verification

The source repository's
[release workflow](https://github.com/gtg-open/dotnetjq/blob/main/.github/workflows/release-cli.yml)
generates the formula from tested release binaries and their checksums. After
publishing an immutable stable release, it opens a pull request here. Release
candidates do not update this tap.

Tap CI runs on GitHub, with these gates:

1. Unit-test the formula verifier, including rejection of altered, deleted,
   downgraded, or untrusted formula metadata.
2. Before executing formula Ruby, compare its bytes with `dotnetjq.rb` from the
   matching published, immutable release in `gtg-open/dotnetjq`.
3. On macOS/Linux x64/ARM64, load the tap, install the release, run its Homebrew
   package test, and check the CLI version.

Before the first release, CI verifies the tooling and loads the empty tap on all
four platforms; package installation is explicitly skipped, not reported as a
successful installation test. Product correctness, performance, and all eight
AOT build targets are tested by the source repository before publication.

Changes use pull requests and merge commits. The required `Homebrew tap gate`
must pass; published history is never amended or force-pushed. Formula updates
are reviewed and merged after CI, not pushed directly to `main`.

## Maintenance

- Do not hand-edit `Formula/dotnetjq.rb`. Change the generator in the source
  repository and publish a new product version when a packaging fix is needed.
- Keep GitHub App keys and other publishing credentials out of this repository.
  The narrowly scoped publisher App is installed on this tap; its private key
  is a protected secret in the source repository's `release` environment.
- Report product issues in
  [DotNetJq's issue tracker](https://github.com/gtg-open/dotnetjq/issues).
  Report security vulnerabilities through
  [private vulnerability reporting](https://github.com/gtg-open/dotnetjq/security/advisories/new).
- Homebrew's [tap documentation](https://docs.brew.sh/Taps) explains the naming
  convention. This is a project-owned tap, not inclusion in `homebrew-core`.

## License

The packaging metadata in this repository is MIT-licensed. The distributed
DotNetJq binaries have their own
[license and third-party notices](https://github.com/gtg-open/dotnetjq/blob/main/LICENSES.md).
