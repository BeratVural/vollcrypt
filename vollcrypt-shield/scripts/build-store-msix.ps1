param(
    [Parameter(Mandatory = $true)]
    [string]$Executable,
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,
    [Parameter(Mandatory = $true)]
    [ValidateSet("x64", "arm64")]
    [string]$Architecture,
    [Parameter(Mandatory = $true)]
    [string]$IdentityName,
    [Parameter(Mandatory = $true)]
    [string]$Publisher,
    [string]$PublisherDisplayName = "Vollcrypt",
    [string]$DisplayName = "Vollcrypt Shield",
    [string]$Version = "1.0.0.0",
    [string]$EvidenceFile = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($IdentityName -cnotmatch '^[A-Za-z0-9.\-]{3,50}$') {
    throw "IdentityName must contain 3-50 ASCII letters, digits, dots, or hyphens"
}
if ($Version -cnotmatch '^\d{1,5}\.\d{1,5}\.\d{1,5}\.\d{1,5}$') {
    throw "Version must use the four-part MSIX form, for example 1.0.0.0"
}
foreach ($part in $Version.Split('.')) {
    if ([int]$part -gt 65535) {
        throw "each MSIX version component must be at most 65535"
    }
}
if ($Publisher -cnotmatch '^(CN|O|OU|L|S|C)=') {
    throw "Publisher must be the exact distinguished name assigned by Partner Center"
}

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
    if ($null -eq $tool) {
        throw "$Name was not found in the Windows SDK"
    }
    return $tool.FullName
}

function Get-PeArchitecture {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $reader = [System.IO.BinaryReader]::new($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) { throw "Viewer is not a PE executable" }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadUInt32()
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) { throw "Viewer has an invalid PE signature" }
        switch ($reader.ReadUInt16()) {
            0x8664 { return "x64" }
            0xAA64 { return "arm64" }
            default { throw "Viewer has an unsupported PE architecture" }
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Export-Logo {
    param(
        [Parameter(Mandatory = $true)][System.Drawing.Image]$Source,
        [Parameter(Mandatory = $true)][int]$Size,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    $bitmap = [System.Drawing.Bitmap]::new($Size, $Size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    try {
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
        try {
            $graphics.Clear([System.Drawing.Color]::Transparent)
            $graphics.CompositingMode = [System.Drawing.Drawing2D.CompositingMode]::SourceCopy
            $graphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
            $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
            $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
            $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
            $graphics.DrawImage($Source, 0, 0, $Size, $Size)
        }
        finally {
            $graphics.Dispose()
        }
        $bitmap.Save($Destination, [System.Drawing.Imaging.ImageFormat]::Png)
    }
    finally {
        $bitmap.Dispose()
    }
}

$executablePath = (Resolve-Path -LiteralPath $Executable).Path
if ((Get-PeArchitecture -Path $executablePath) -ne $Architecture) {
    throw "Viewer PE architecture does not match the requested MSIX architecture"
}
$shieldRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$manifestTemplate = Join-Path $shieldRoot "packaging\windows\AppxManifest.xml"
$iconPath = Join-Path $shieldRoot "desktop-app\src-tauri\icons\128x128@2x.png"
$outputPath = [System.IO.Path]::GetFullPath($OutputDirectory)
$stage = Join-Path ([System.IO.Path]::GetTempPath()) ("vollcrypt-shield-msix-" + [guid]::NewGuid().ToString("N"))
$assets = Join-Path $stage "Assets"
$packageName = "VollcryptShield_$($Version)_$Architecture.msix"
$packagePath = Join-Path $outputPath $packageName

try {
    New-Item -ItemType Directory -Path $assets -Force | Out-Null
    New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
    Copy-Item -LiteralPath $executablePath -Destination (Join-Path $stage "vollcrypt-shield-viewer.exe")

    Add-Type -AssemblyName System.Drawing
    $sourceImage = [System.Drawing.Image]::FromFile($iconPath)
    try {
        Export-Logo -Source $sourceImage -Size 44 -Destination (Join-Path $assets "Square44x44Logo.png")
        Export-Logo -Source $sourceImage -Size 50 -Destination (Join-Path $assets "StoreLogo.png")
        Export-Logo -Source $sourceImage -Size 150 -Destination (Join-Path $assets "Square150x150Logo.png")
    }
    finally {
        $sourceImage.Dispose()
    }

    [xml]$manifest = Get-Content -LiteralPath $manifestTemplate -Raw
    $namespace = [System.Xml.XmlNamespaceManager]::new($manifest.NameTable)
    $namespace.AddNamespace("f", "http://schemas.microsoft.com/appx/manifest/foundation/windows10")
    $namespace.AddNamespace("uap", "http://schemas.microsoft.com/appx/manifest/uap/windows10")
    $identity = $manifest.SelectSingleNode("/f:Package/f:Identity", $namespace)
    $identity.SetAttribute("Name", $IdentityName)
    $identity.SetAttribute("Publisher", $Publisher)
    $identity.SetAttribute("Version", $Version)
    $identity.SetAttribute("ProcessorArchitecture", $Architecture)
    $manifest.SelectSingleNode("/f:Package/f:Properties/f:DisplayName", $namespace).InnerText = $DisplayName
    $manifest.SelectSingleNode("/f:Package/f:Properties/f:PublisherDisplayName", $namespace).InnerText = $PublisherDisplayName
    $visualElements = $manifest.SelectSingleNode("/f:Package/f:Applications/f:Application/uap:VisualElements", $namespace)
    if ($null -eq $visualElements) { throw "manifest template is missing uap:VisualElements" }
    $visualElements.SetAttribute("DisplayName", $DisplayName)

    $settings = [System.Xml.XmlWriterSettings]::new()
    $settings.Encoding = [System.Text.UTF8Encoding]::new($false)
    $settings.Indent = $true
    $writer = [System.Xml.XmlWriter]::Create((Join-Path $stage "AppxManifest.xml"), $settings)
    try {
        $manifest.Save($writer)
    }
    finally {
        $writer.Dispose()
    }

    $makeAppx = Find-WindowsSdkTool -Name "makeappx.exe"
    & $makeAppx pack /d $stage /p $packagePath /o
    if ($LASTEXITCODE -ne 0) {
        throw "MakeAppx failed to build $packageName"
    }
    $validationDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("vollcrypt-shield-msix-validation-" + [guid]::NewGuid().ToString("N"))
    try {
        & $makeAppx unpack /p $packagePath /d $validationDirectory /o
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath (Join-Path $validationDirectory "AppxManifest.xml") -PathType Leaf)) {
            throw "MakeAppx validation failed for $packageName"
        }
    }
    finally {
        if (Test-Path -LiteralPath $validationDirectory) {
            Remove-Item -LiteralPath $validationDirectory -Recurse -Force
        }
    }

    $result = [ordered]@{
        status = "passed"
        package = $packageName
        packageSha256 = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash.ToLowerInvariant()
        identityName = $IdentityName
        publisher = $Publisher
        publisherDisplayName = $PublisherDisplayName
        version = $Version
        architecture = $Architecture
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
    if (Test-Path -LiteralPath $stage) {
        Remove-Item -LiteralPath $stage -Recurse -Force
    }
}
