param(
    [string]$TauriConfig = "",
    [string[]]$Files = @()
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$encoded = $env:VOLLCRYPT_WINDOWS_CERTIFICATE_BASE64
$plainPassword = $env:VOLLCRYPT_WINDOWS_CERTIFICATE_PASSWORD
if ([string]::IsNullOrWhiteSpace($encoded) -or [string]::IsNullOrWhiteSpace($plainPassword)) {
    throw "trusted Windows release signing requires the certificate and password secrets"
}

$pfxPath = Join-Path $env:RUNNER_TEMP ("vollcrypt-shield-signing-" + [guid]::NewGuid().ToString("N") + ".pfx")
try {
    [System.IO.File]::WriteAllBytes($pfxPath, [Convert]::FromBase64String($encoded))
    $password = ConvertTo-SecureString -String $plainPassword -AsPlainText -Force
    $imported = @(Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation Cert:\CurrentUser\My -Password $password)
    $certificate = $imported |
        Where-Object {
            $_.HasPrivateKey -and
            $_.NotBefore -le [DateTime]::UtcNow -and
            $_.NotAfter -gt [DateTime]::UtcNow -and
            ($_.EnhancedKeyUsageList.ObjectId.Value -contains "1.3.6.1.5.5.7.3.3")
        } |
        Select-Object -First 1
    if ($null -eq $certificate) {
        throw "the PFX does not contain a currently valid code-signing certificate with a private key"
    }

    if ($TauriConfig) {
        $configPath = [System.IO.Path]::GetFullPath($TauriConfig)
        New-Item -ItemType Directory -Path ([System.IO.Path]::GetDirectoryName($configPath)) -Force | Out-Null
        @{
            bundle = @{
                windows = @{
                    certificateThumbprint = $certificate.Thumbprint
                    digestAlgorithm = "sha256"
                    timestampUrl = "https://timestamp.digicert.com"
                }
            }
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $configPath -Encoding Utf8
    }

    if ($Files.Count -gt 0) {
        $architecture = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "x64" }
        $signTool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Filter signtool.exe -Recurse |
            Where-Object { $_.Directory.Name -eq $architecture } |
            Sort-Object FullName -Descending |
            Select-Object -First 1
        if ($null -eq $signTool) {
            throw "Windows SDK SignTool for $architecture was not found"
        }
        foreach ($file in $Files) {
            $path = (Resolve-Path -LiteralPath $file).Path
            & $signTool.FullName sign /sha1 $certificate.Thumbprint /fd SHA256 /tr https://timestamp.digicert.com /td SHA256 $path
            if ($LASTEXITCODE -ne 0) {
                throw "SignTool failed for $([System.IO.Path]::GetFileName($path))"
            }
            $signature = Get-AuthenticodeSignature -LiteralPath $path
            if ($signature.Status -ne "Valid") {
                throw "Authenticode validation failed for $([System.IO.Path]::GetFileName($path)): $($signature.Status)"
            }
        }
    }
}
finally {
    if (Test-Path -LiteralPath $pfxPath) {
        Remove-Item -LiteralPath $pfxPath -Force
    }
    $encoded = $null
    $plainPassword = $null
}
