# Prebuilt NativeAOT formula for the project's custom tap; not homebrew/core.
class Dotnetjq < Formula
  desc "jq 1.8.2-compatible command-line JSON processor"
  homepage "https://github.com/gtg-open/dotnetjq"
  version "1.0.0"
  # The NativeAOT executable includes the .NET runtime's complete third-party
  # notice set in addition to DotNetJq's mixed-license components. Homebrew's
  # SPDX expression cannot represent that complete per-file boundary.
  license :cannot_represent

  on_macos do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/gtg-open/dotnetjq/releases/download/v1.0.0/dotnetjq-1.0.0-osx-arm64.tar.gz"
      sha256 "94bd08d9b94bfd1dbee992b19be14e126e38a8c51fe859b75931b00f04e8d195"
    elsif Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/gtg-open/dotnetjq/releases/download/v1.0.0/dotnetjq-1.0.0-osx-x64.tar.gz"
      sha256 "0907768fc627982fd9b780f0c4584e567395fd4d118a5959fafff40d16ce2a9e"
    else
      odie "dotnetjq supports only 64-bit ARM and Intel hosts"
    end
  end

  on_linux do
    # The prebuilt glibc archive has an Ubuntu 24.04 / glibc 2.39 baseline.
    # Hosts with an older libc must use a different distribution mechanism.
    depends_on "icu4c@78"

    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/gtg-open/dotnetjq/releases/download/v1.0.0/dotnetjq-1.0.0-linux-arm64.tar.gz"
      sha256 "26dc668e02b794c916d458d99e9d85c7ddc083442b9a6b87c12ebbc4f1e44614"
    elsif Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/gtg-open/dotnetjq/releases/download/v1.0.0/dotnetjq-1.0.0-linux-x64.tar.gz"
      sha256 "18c351b3fe4f1fe7b86d9cbcc511ec1154c2d6401019ea91ebf3a3e5890fc762"
    else
      odie "dotnetjq supports only 64-bit ARM and Intel hosts"
    end
  end

  resource "corresponding_source" do
    url "https://github.com/gtg-open/dotnetjq/releases/download/v1.0.0/dotnetjq-aot-source-1.0.0.tar.gz"
    sha256 "cf7d32e4da1a2081d15b239760e24b4e1c0bff2f949b33bef9510e2566b56fe0"
  end

  def install
    if OS.linux?
      # icu4c@78 is keg-only. Keep the executable itself unmodified under
      # libexec and expose the dependency only to this command's loader.
      libexec.install "dotnetjq"
      (bin/"dotnetjq").write_env_script libexec/"dotnetjq",
                                               LD_LIBRARY_PATH: Formula["icu4c@78"].opt_lib
    else
      bin.install "dotnetjq"
    end
    pkgshare.install "COPYING", "COPYING.LIB", "LICENSE.DotNetJq", "LICENSES.md",
                     "THIRD_PARTY_NOTICES.md", "LICENSE.TXT", "THIRD-PARTY-NOTICES.TXT"
    pkgshare.install "THIRD_PARTY_LICENSES"
    resource("corresponding_source").stage do
      (pkgshare/"aot-source").install Dir["*"]
    end
  end

  test do
    assert_equal "2\n", pipe_output("#{bin}/dotnetjq '. + 1'", "1\n")
  end
end
