# Template for yyasar21/homebrew-mooring (Casks/mooring.rb).
# .github/workflows/release-homebrew.yml renders it on every published release by replacing
# @VERSION@, @SHA256_ARM@, @SHA256_INTEL@ and @IDENTIFIER@ (bundle identifier from
# src-tauri/tauri.conf.json); the result is pushed to the tap.
# Lint locally: brew audit --cask --strict --online yyasar21/mooring/mooring
cask "mooring" do
  arch arm: "aarch64", intel: "x64"

  version "@VERSION@"
  sha256 arm:   "@SHA256_ARM@",
         intel: "@SHA256_INTEL@"

  url "https://github.com/yyasar21/Mooring/releases/download/v#{version}/Mooring_#{version}_#{arch}.dmg",
      verified: "github.com/yyasar21/Mooring/"
  name "Mooring"
  desc "Security-first remote access manager for SSH, RDP and VNC"
  homepage "https://github.com/yyasar21/Mooring"

  livecheck do
    url :url
    strategy :github_latest
  end

  auto_updates false
  depends_on macos: ">= :big_sur"

  app "Mooring.app"

  zap trash: [
    "~/Library/Application Support/@IDENTIFIER@",
    "~/Library/Caches/@IDENTIFIER@",
    "~/Library/Logs/@IDENTIFIER@",
    "~/Library/Preferences/@IDENTIFIER@.plist",
    "~/Library/Saved Application State/@IDENTIFIER@.savedState",
    "~/Library/WebKit/@IDENTIFIER@",
  ]
end
