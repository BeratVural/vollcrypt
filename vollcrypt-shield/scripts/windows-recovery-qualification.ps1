param(
    [Parameter(Mandatory = $true)]
    [string]$EvidenceDirectory
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Windows recovery qualification requires an elevated administrator token"
}

$evidence = [System.IO.Path]::GetFullPath($EvidenceDirectory)
New-Item -ItemType Directory -Path $evidence -Force | Out-Null
$work = Join-Path $env:RUNNER_TEMP ("vollcrypt-shield-windows-qualification-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $work | Out-Null
$vhd = Join-Path $work "secondary.vhdx"
$diskpartCreate = Join-Path $work "create-vhd.txt"
$diskpartDetach = Join-Path $work "detach-vhd.txt"
$driveLetter = $null
$transcriptStarted = $false

function Invoke-LoggedCargoTest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $log = Join-Path $evidence "$Name.log"
    & cargo @Arguments 2>&1 | Tee-Object -FilePath $log
    if ($LASTEXITCODE -ne 0) {
        throw "cargo $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

try {
    Start-Transcript -Path (Join-Path $evidence "host-transcript.log") | Out-Null
    $transcriptStarted = $true

    $usedLetters = @(Get-PSDrive -PSProvider FileSystem | ForEach-Object { $_.Name.ToUpperInvariant() })
    foreach ($candidate in @('R', 'Q', 'P', 'O', 'N', 'M', 'L', 'K', 'J', 'I', 'H', 'G', 'F', 'E', 'D')) {
        if ($usedLetters -notcontains $candidate) {
            $driveLetter = $candidate
            break
        }
    }
    if ($null -eq $driveLetter) {
        throw "no free drive letter is available for the secondary NTFS qualification volume"
    }

    @(
        "create vdisk file=`"$vhd`" maximum=512 type=expandable"
        "select vdisk file=`"$vhd`""
        "attach vdisk"
        "create partition primary"
        "format fs=ntfs label=SHIELDQUAL quick"
        "assign letter=$driveLetter"
    ) | Set-Content -LiteralPath $diskpartCreate -Encoding Ascii
    & diskpart.exe /s $diskpartCreate 2>&1 | Tee-Object -FilePath (Join-Path $evidence "diskpart-create.log")
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath "${driveLetter}:\" -PathType Container)) {
        throw "failed to provision the secondary NTFS qualification volume"
    }

    $os = Get-CimInstance Win32_OperatingSystem
    $computer = Get-CimInstance Win32_ComputerSystem
    $volumes = Get-Volume | Sort-Object DriveLetter | Select-Object DriveLetter, FileSystem, FileSystemLabel, Path, Size, SizeRemaining, UniqueId
    $privileges = (& whoami.exe /priv /fo csv | ConvertFrom-Csv)
    $requiredPrivileges = @('SeBackupPrivilege', 'SeRestorePrivilege', 'SeSecurityPrivilege')
    foreach ($required in $requiredPrivileges) {
        if ($privileges.'Privilege Name' -notcontains $required) {
            throw "required service-account privilege is absent: $required"
        }
    }

    [ordered]@{
        commit = (& git rev-parse HEAD).Trim()
        osCaption = $os.Caption
        osVersion = $os.Version
        osBuild = $os.BuildNumber
        architecture = $env:PROCESSOR_ARCHITECTURE
        systemType = $computer.SystemType
        runnerName = $env:RUNNER_NAME
        qualificationVolume = "${driveLetter}:\"
        volumes = @($volumes)
        requiredPrivileges = $requiredPrivileges
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $evidence "host.json") -Encoding Utf8
    $privileges | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $evidence "privileges.json") -Encoding Utf8

    $env:VOLLCRYPT_SHIELD_WINDOWS_ACTIVE_QUALIFICATION = "1"
    Invoke-LoggedCargoTest -Name "windows-platform" -Arguments @(
        "test", "--locked", "-p", "vollcrypt-shield-windows", "--", "--nocapture", "--test-threads=1"
    )
    Invoke-LoggedCargoTest -Name "filesystem-recovery" -Arguments @(
        "test", "--locked", "-p", "vollcrypt-shield-fs", "vault::tests::", "--", "--nocapture", "--test-threads=1"
    )

    [ordered]@{
        status = "passed"
        completedAtUtc = [DateTime]::UtcNow.ToString("o")
        strictQualification = $true
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence "result.json") -Encoding Utf8
}
finally {
    Remove-Item Env:VOLLCRYPT_SHIELD_WINDOWS_ACTIVE_QUALIFICATION -ErrorAction SilentlyContinue
    if ($transcriptStarted) {
        Stop-Transcript | Out-Null
    }
    if (Test-Path -LiteralPath $vhd -PathType Leaf) {
        @(
            "select vdisk file=`"$vhd`""
            "detach vdisk"
        ) | Set-Content -LiteralPath $diskpartDetach -Encoding Ascii
        & diskpart.exe /s $diskpartDetach *> (Join-Path $evidence "diskpart-detach.log")
    }
    if (Test-Path -LiteralPath $work -PathType Container) {
        $resolvedWork = [System.IO.Path]::GetFullPath($work)
        $resolvedRunnerTemp = [System.IO.Path]::GetFullPath($env:RUNNER_TEMP)
        if (-not $resolvedWork.StartsWith($resolvedRunnerTemp, [StringComparison]::OrdinalIgnoreCase)) {
            throw "refusing to remove qualification work directory outside RUNNER_TEMP"
        }
        Remove-Item -LiteralPath $resolvedWork -Recurse -Force
    }
}
