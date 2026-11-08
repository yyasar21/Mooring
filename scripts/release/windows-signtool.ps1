# Authenticode-sign files with the OV certificate that release.yml's sign-windows job imported
# from WINDOWS_CERTIFICATE (ADR-0018 A1, the fallback when Azure Artifact Signing is not set up).
#
#   pwsh -NoProfile -File scripts/release/windows-signtool.ps1 <file> [<file> ...]
#
# WINDOWS_CERT_THUMBPRINT names the certificate in Cert:\CurrentUser\My (not a secret). RFC 3161
# timestamp, SHA-256 file and timestamp digests. Prints file names only.
param([Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)][string[]]$Files)
$ErrorActionPreference = 'Stop'

$thumb = $env:WINDOWS_CERT_THUMBPRINT
if ($thumb -notmatch '^[0-9A-Fa-f]{40}$') { throw 'WINDOWS_CERT_THUMBPRINT is not a certificate thumbprint' }
$kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
$signtool = Get-ChildItem -Path $kits -Directory |
  Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' -and (Test-Path (Join-Path $_.FullName 'x64\signtool.exe')) } |
  Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
if (-not $signtool) { throw "signtool.exe not found under $kits" }
$exe = Join-Path $signtool.FullName 'x64\signtool.exe'

foreach ($f in $Files) {
  if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { throw "$f not found" }
  & $exe sign /sha1 $thumb /fd sha256 /tr 'http://timestamp.digicert.com' /td sha256 `
    /d 'Mooring' /du 'https://github.com/yyasar21/Mooring' $f | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "signtool failed for $(Split-Path -Leaf $f)" }
  Write-Output "signed $(Split-Path -Leaf $f)"
}
