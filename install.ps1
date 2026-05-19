# capframe installer (Windows) — https://capframe.ai
# Usage:
#   iwr -useb https://capframe.ai/install.ps1 | iex
$ErrorActionPreference = 'Stop'

$Repo    = 'capframe/capframe'
$Version = if ($env:CAPFRAME_VERSION) { $env:CAPFRAME_VERSION } else { 'latest' }
$Install = if ($env:CAPFRAME_INSTALL) { $env:CAPFRAME_INSTALL } else { Join-Path $env:LOCALAPPDATA 'capframe' }

function Info($msg) { Write-Host "::" -ForegroundColor Green -NoNewline; Write-Host " $msg" }
function Die($msg)  { Write-Host "!! $msg" -ForegroundColor Red; exit 1 }

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { 'x86_64' }
    'ARM64' { 'aarch64' }
    default { Die "unsupported arch: $env:PROCESSOR_ARCHITECTURE" }
}
$target = "$arch-pc-windows-msvc"

if ($Version -eq 'latest') {
    $rel = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest"
    $Version = $rel.tag_name
}
Info "Installing capframe $Version for $target"

$tmp = New-Item -ItemType Directory -Force -Path (Join-Path $env:TEMP "capframe-install-$([guid]::NewGuid())")
try {
    $zip = "capframe-$Version-$target.zip"
    $base = "https://github.com/$Repo/releases/download/$Version"

    Info "downloading $zip"
    Invoke-WebRequest "$base/$zip"        -OutFile (Join-Path $tmp $zip)
    Invoke-WebRequest "$base/$zip.sha256" -OutFile (Join-Path $tmp "$zip.sha256")

    $expected = (Get-Content (Join-Path $tmp "$zip.sha256")).Split()[0].ToLower()
    $actual   = (Get-FileHash (Join-Path $tmp $zip) -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $expected) { Die "checksum mismatch (expected $expected, got $actual)" }
    Info "checksum verified"

    $binDir = Join-Path $Install 'bin'
    New-Item -ItemType Directory -Force -Path $binDir | Out-Null
    # Release archive contains capframe-<ver>-<target>/capframe.exe;
    # extract then locate the .exe regardless of folder name.
    Expand-Archive -Path (Join-Path $tmp $zip) -DestinationPath $tmp -Force
    $found = Get-ChildItem -Path $tmp -Recurse -Filter 'capframe.exe' | Select-Object -First 1
    if (-not $found) { Die "capframe.exe not found inside $zip" }
    Move-Item -Force $found.FullName (Join-Path $binDir 'capframe.exe')
    Info "installed to $binDir\capframe.exe"

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($userPath -notlike "*$binDir*") {
        [Environment]::SetEnvironmentVariable('Path', "$binDir;$userPath", 'User')
        Info "added $binDir to user PATH (open a new terminal to pick it up)"
    }
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "  capframe is ready." -ForegroundColor Green
Write-Host "  Try: capframe find --help"
Write-Host "  Docs: https://capframe.ai/docs"
Write-Host ""
