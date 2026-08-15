param(
    [Parameter(Mandatory = $true)]
    [string]$Installer,
    [ValidateSet("x86_64", "arm64")]
    [string]$ExpectedArchitecture = "x86_64",
    [string]$EvidenceFile = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$installerPath = (Resolve-Path -LiteralPath $Installer).Path
$registryRoots = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
$installedExecutable = $null
$uninstaller = $null

function Get-ShieldUninstallEntry {
    foreach ($root in $registryRoots) {
        Get-ItemProperty -Path $root -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -eq "Vollcrypt Shield" } |
            Select-Object -First 1
    }
}

function Get-PeArchitecture {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        $reader = [System.IO.BinaryReader]::new($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) {
            throw "installed Viewer is not a PE executable"
        }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadUInt32()
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            throw "installed Viewer has an invalid PE signature"
        }
        $machine = $reader.ReadUInt16()
        switch ($machine) {
            0x8664 { return "x86_64" }
            0xAA64 { return "arm64" }
            default { return "unknown-0x{0:X4}" -f $machine }
        }
    }
    finally {
        $stream.Dispose()
    }
}

try {
    $signature = Get-AuthenticodeSignature -LiteralPath $installerPath
    if ($env:VOLLCRYPT_REQUIRE_AUTHENTICODE -eq "1" -and $signature.Status -ne "Valid") {
        throw "installer Authenticode signature is not valid: $($signature.Status)"
    }

    $install = Start-Process -FilePath $installerPath -ArgumentList "/S" -Wait -PassThru
    if ($install.ExitCode -ne 0) {
        throw "installer exited with code $($install.ExitCode)"
    }

    $entry = Get-ShieldUninstallEntry | Select-Object -First 1
    if ($null -eq $entry) {
        throw "Vollcrypt Shield uninstall registration was not created"
    }

    if ($entry.InstallLocation) {
        $candidate = Join-Path $entry.InstallLocation "vollcrypt-shield-viewer.exe"
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $installedExecutable = $candidate
        }
    }
    if ($null -eq $installedExecutable -and $entry.DisplayIcon) {
        $candidate = ($entry.DisplayIcon -replace '^"|"$|,\d+$', '')
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $installedExecutable = $candidate
        }
    }
    if ($null -eq $installedExecutable) {
        throw "installed Viewer executable could not be resolved from the uninstall registration"
    }

    $actualArchitecture = Get-PeArchitecture -Path $installedExecutable
    if ($actualArchitecture -ne $ExpectedArchitecture) {
        throw "installed Viewer architecture is $actualArchitecture, expected $ExpectedArchitecture"
    }

    if ($entry.UninstallString -and $entry.UninstallString -match '^"([^\"]+)"') {
        $uninstaller = $Matches[1]
    } elseif ($entry.InstallLocation) {
        $candidate = Join-Path $entry.InstallLocation "uninstall.exe"
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $uninstaller = $candidate
        }
    }
    if ($null -eq $uninstaller -or -not (Test-Path -LiteralPath $uninstaller -PathType Leaf)) {
        throw "registered Shield uninstaller could not be resolved"
    }

    $result = [ordered]@{
        status = "passed"
        installer = [System.IO.Path]::GetFileName($installerPath)
        installerSha256 = (Get-FileHash -LiteralPath $installerPath -Algorithm SHA256).Hash.ToLowerInvariant()
        authenticodeStatus = $signature.Status.ToString()
        authenticodeSigner = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
        installedExecutable = $installedExecutable
        architecture = $actualArchitecture
        version = [Diagnostics.FileVersionInfo]::GetVersionInfo($installedExecutable).FileVersion
    }
    if ($EvidenceFile) {
        $evidencePath = [System.IO.Path]::GetFullPath($EvidenceFile)
        New-Item -ItemType Directory -Path ([System.IO.Path]::GetDirectoryName($evidencePath)) -Force | Out-Null
        $result | ConvertTo-Json | Set-Content -LiteralPath $evidencePath -Encoding Utf8
    }
    $result | ConvertTo-Json
}
finally {
    if ($null -ne $uninstaller -and (Test-Path -LiteralPath $uninstaller -PathType Leaf)) {
        $uninstall = Start-Process -FilePath $uninstaller -ArgumentList "/S" -Wait -PassThru
        if ($uninstall.ExitCode -ne 0) {
            throw "uninstaller exited with code $($uninstall.ExitCode)"
        }
        for ($attempt = 0; $attempt -lt 20 -and (Test-Path -LiteralPath $installedExecutable -PathType Leaf); $attempt++) {
            Start-Sleep -Milliseconds 250
        }
        if ($null -ne $installedExecutable -and (Test-Path -LiteralPath $installedExecutable -PathType Leaf)) {
            throw "Viewer executable remains after silent uninstall"
        }
    }
}
