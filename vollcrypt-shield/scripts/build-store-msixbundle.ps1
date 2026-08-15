param(
    [Parameter(Mandatory = $true)]
    [string[]]$Packages,
    [Parameter(Mandatory = $true)]
    [string]$Output,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedIdentityName,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedPublisher,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedVersion,
    [string]$EvidenceFile = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Find-WindowsSdkTool {
    param([Parameter(Mandatory = $true)][string]$Name)

    $sdkRoot = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
    $preferredArchitecture = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "x64" }
    $tool = Get-ChildItem -LiteralPath $sdkRoot -Filter $Name -Recurse -File |
        Where-Object { $_.Directory.Name -eq $preferredArchitecture } |
        Sort-Object FullName -Descending |
        Select-Object -First 1
    if ($null -eq $tool) {
        $tool = Get-ChildItem -LiteralPath $sdkRoot -Filter $Name -Recurse -File |
            Where-Object { $_.Directory.Name -eq "x64" } |
            Sort-Object FullName -Descending |
            Select-Object -First 1
    }
    if ($null -eq $tool) { throw "$Name was not found in the Windows SDK" }
    return $tool.FullName
}

if ($Packages.Count -lt 2) { throw "at least two architecture packages are required" }
$makeAppx = Find-WindowsSdkTool -Name "makeappx.exe"
$layout = Join-Path ([System.IO.Path]::GetTempPath()) ("vollcrypt-shield-msixbundle-" + [guid]::NewGuid().ToString("N"))
$outputPath = [System.IO.Path]::GetFullPath($Output)
$architectures = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

try {
    New-Item -ItemType Directory -Path $layout -Force | Out-Null
    foreach ($package in $Packages) {
        $packagePath = (Resolve-Path -LiteralPath $package).Path
        $unpack = Join-Path $layout ("inspect-" + [guid]::NewGuid().ToString("N"))
        & $makeAppx unpack /p $packagePath /d $unpack /o
        if ($LASTEXITCODE -ne 0) { throw "MakeAppx could not inspect $packagePath" }
        [xml]$manifest = Get-Content -LiteralPath (Join-Path $unpack "AppxManifest.xml") -Raw
        $namespace = [System.Xml.XmlNamespaceManager]::new($manifest.NameTable)
        $namespace.AddNamespace("f", "http://schemas.microsoft.com/appx/manifest/foundation/windows10")
        $identity = $manifest.SelectSingleNode("/f:Package/f:Identity", $namespace)
        if ($identity.Name -ne $ExpectedIdentityName) { throw "package identity name does not match" }
        if ($identity.Publisher -ne $ExpectedPublisher) { throw "package publisher does not match" }
        if ($identity.Version -ne $ExpectedVersion) { throw "package version does not match" }
        if (-not $architectures.Add([string]$identity.ProcessorArchitecture)) {
            throw "duplicate package architecture: $($identity.ProcessorArchitecture)"
        }
        Remove-Item -LiteralPath $unpack -Recurse -Force
        $architectureDirectory = Join-Path $layout ([string]$identity.ProcessorArchitecture)
        New-Item -ItemType Directory -Path $architectureDirectory -Force | Out-Null
        Copy-Item -LiteralPath $packagePath -Destination (Join-Path $architectureDirectory ([System.IO.Path]::GetFileName($packagePath)))
    }
    if (-not $architectures.SetEquals(@("x64", "arm64"))) {
        throw "the Store bundle must contain exactly x64 and arm64 packages"
    }

    New-Item -ItemType Directory -Path ([System.IO.Path]::GetDirectoryName($outputPath)) -Force | Out-Null
    & $makeAppx bundle /d $layout /p $outputPath /o
    if ($LASTEXITCODE -ne 0) { throw "MakeAppx could not build the Store bundle" }
    $validationDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("vollcrypt-shield-msixbundle-validation-" + [guid]::NewGuid().ToString("N"))
    try {
        & $makeAppx unbundle /p $outputPath /d $validationDirectory /o
        if ($LASTEXITCODE -ne 0 -or @(Get-ChildItem -LiteralPath $validationDirectory -Filter '*.msix' -File).Count -ne 2) {
            throw "MakeAppx validation failed for the Store bundle"
        }
    }
    finally {
        if (Test-Path -LiteralPath $validationDirectory) {
            Remove-Item -LiteralPath $validationDirectory -Recurse -Force
        }
    }

    $result = [ordered]@{
        status = "passed"
        bundle = [System.IO.Path]::GetFileName($outputPath)
        bundleSha256 = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash.ToLowerInvariant()
        identityName = $ExpectedIdentityName
        publisher = $ExpectedPublisher
        version = $ExpectedVersion
        architectures = @($architectures | Sort-Object)
        commit = $env:GITHUB_SHA
    }
    if ($EvidenceFile) {
        $evidencePath = [System.IO.Path]::GetFullPath($EvidenceFile)
        New-Item -ItemType Directory -Path ([System.IO.Path]::GetDirectoryName($evidencePath)) -Force | Out-Null
        $result | ConvertTo-Json | Set-Content -LiteralPath $evidencePath -Encoding Utf8
    }
    $result | ConvertTo-Json
}
finally {
    if (Test-Path -LiteralPath $layout) {
        Remove-Item -LiteralPath $layout -Recurse -Force
    }
}
