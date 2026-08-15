param(
    [Parameter(Mandatory = $true)]
    [string]$Package,
    [Parameter(Mandatory = $true)]
    [ValidateSet("x64", "arm64")]
    [string]$ExpectedArchitecture,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedIdentityName,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedPublisher,
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

$packagePath = (Resolve-Path -LiteralPath $Package).Path
$unpackDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("vollcrypt-shield-msix-smoke-" + [guid]::NewGuid().ToString("N"))
$certificate = $null
$certificateTrusted = $false
$certificateFile = Join-Path ([System.IO.Path]::GetTempPath()) ("vollcrypt-shield-msix-" + [guid]::NewGuid().ToString("N") + ".cer")
$installedPackage = $null

try {
    $makeAppx = Find-WindowsSdkTool -Name "makeappx.exe"
    $signTool = Find-WindowsSdkTool -Name "signtool.exe"
    & $makeAppx unpack /p $packagePath /d $unpackDirectory /o
    if ($LASTEXITCODE -ne 0) { throw "MakeAppx could not unpack the package" }

    [xml]$manifest = Get-Content -LiteralPath (Join-Path $unpackDirectory "AppxManifest.xml") -Raw
    $namespace = [System.Xml.XmlNamespaceManager]::new($manifest.NameTable)
    $namespace.AddNamespace("f", "http://schemas.microsoft.com/appx/manifest/foundation/windows10")
    $identity = $manifest.SelectSingleNode("/f:Package/f:Identity", $namespace)
    if ($identity.Name -ne $ExpectedIdentityName) { throw "MSIX identity name does not match" }
    if ($identity.Publisher -ne $ExpectedPublisher) { throw "MSIX publisher does not match" }
    if ($identity.ProcessorArchitecture -ne $ExpectedArchitecture) { throw "MSIX architecture does not match" }
    $executable = Join-Path $unpackDirectory "vollcrypt-shield-viewer.exe"
    if ((Get-PeArchitecture -Path $executable) -ne $ExpectedArchitecture) {
        throw "packaged Viewer architecture does not match the manifest"
    }

    $certificate = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $ExpectedPublisher `
        -CertStoreLocation Cert:\CurrentUser\My `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -NotAfter ([DateTime]::UtcNow.AddDays(1))
    Export-Certificate -Cert $certificate -FilePath $certificateFile -Force | Out-Null
    & certutil.exe -addstore -f TrustedPeople $certificateFile | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "qualification certificate import failed" }
    $certificateTrusted = $true

    & $signTool sign /sha1 $certificate.Thumbprint /fd SHA256 $packagePath
    if ($LASTEXITCODE -ne 0) { throw "SignTool could not apply the qualification signature" }
    $signature = Get-AuthenticodeSignature -LiteralPath $packagePath
    if ($null -eq $signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) {
        throw "qualification signature signer does not match the ephemeral certificate"
    }

    Add-AppxPackage -Path $packagePath -ForceApplicationShutdown
    $installedPackage = Get-AppxPackage -Name $ExpectedIdentityName | Select-Object -First 1
    if ($null -eq $installedPackage) { throw "installed MSIX registration was not found" }
    $installedExecutable = Join-Path $installedPackage.InstallLocation "vollcrypt-shield-viewer.exe"
    if (-not (Test-Path -LiteralPath $installedExecutable -PathType Leaf)) {
        throw "installed Viewer executable was not found"
    }
    if ((Get-PeArchitecture -Path $installedExecutable) -ne $ExpectedArchitecture) {
        throw "installed Viewer architecture does not match"
    }

    $result = [ordered]@{
        status = "passed"
        package = [System.IO.Path]::GetFileName($packagePath)
        packageSha256 = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash.ToLowerInvariant()
        identityName = $installedPackage.Name
        publisher = $installedPackage.Publisher
        version = $installedPackage.Version.ToString()
        architecture = $ExpectedArchitecture
        signature = "ephemeral-qualification-only"
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
    if ($null -ne $installedPackage) {
        Remove-AppxPackage -Package $installedPackage.PackageFullName -Confirm:$false
    }
    if ($null -ne $certificate) {
        Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $certificate.Thumbprint) -Force -ErrorAction SilentlyContinue
    }
    if ($certificateTrusted) {
        & certutil.exe -delstore -f TrustedPeople $certificate.Thumbprint | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "qualification certificate cleanup failed: $($certificate.Thumbprint)"
        }
    }
    if (Test-Path -LiteralPath $certificateFile) {
        Remove-Item -LiteralPath $certificateFile -Force
    }
    if (Test-Path -LiteralPath $unpackDirectory) {
        Remove-Item -LiteralPath $unpackDirectory -Recurse -Force
    }
}
