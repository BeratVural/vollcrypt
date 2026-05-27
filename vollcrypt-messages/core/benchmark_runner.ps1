# Hardware Info Gathering
Write-Host "Gathering Hardware Specifications..." -ForegroundColor Cyan

$cpu = (Get-CimInstance Win32_Processor).Name
$os = (Get-CimInstance Win32_OperatingSystem).Caption
$total_mem_kb = (Get-CimInstance Win32_OperatingSystem).TotalVisibleMemorySize
$total_mem_gb = [math]::Round($total_mem_kb / 1024 / 1024, 2)
$gpu = (Get-CimInstance Win32_VideoController).Name
if (-not $gpu) {
    try {
        $gpu_nvidia = (nvidia-smi --query-gpu=name --format=csv,noheader).Trim()
        if ($gpu_nvidia) { $gpu = $gpu_nvidia }
    } catch {
        $gpu = "N/A"
    }
}

$disks = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.Size -gt 0 } | ForEach-Object {
    $size_gb = [math]::Round($_.Size / 1024 / 1024 / 1024, 1)
    $free_gb = [math]::Round($_.FreeSpace / 1024 / 1024 / 1024, 1)
    "$($_.DeviceID) ($($_.VolumeName)) $size_gb GB total, $free_gb GB free"
}

$formatted_disks = ""
foreach ($disk in $disks) {
    $formatted_disks += "    *   $disk`n"
}

Write-Host "Hardware info collected successfully." -ForegroundColor Green

# Launching Cargo process in background
Write-Host "Launching Cargo Benchmark Suite..." -ForegroundColor Cyan

$processInfo = New-Object System.Diagnostics.ProcessStartInfo
$processInfo.FileName = "cargo"
# Enable AES-NI acceleration for release run
$processInfo.EnvironmentVariables["RUSTFLAGS"] = "-C target-cpu=native -C target-feature=+aes,+ssse3"
$processInfo.Arguments = "run --manifest-path vollcrypt-messages/core/Cargo.toml --release --features fast-aes --bin perf"
$processInfo.RedirectStandardOutput = $true
$processInfo.RedirectStandardError = $true
$processInfo.UseShellExecute = $false
$processInfo.CreateNoWindow = $true

$process = New-Object System.Diagnostics.Process
$process.StartInfo = $processInfo

$cpu_history = [System.Collections.Generic.List[float]]::new()
$ram_history = [System.Collections.Generic.List[float]]::new()
$gpu_history = [System.Collections.Generic.List[float]]::new()
$disk_read_history = [System.Collections.Generic.List[float]]::new()
$disk_write_history = [System.Collections.Generic.List[float]]::new()

$startTime = [DateTime]::Now

$process.Start() | Out-Null

Write-Host "Benchmark running. Monitoring system resource utilization..." -ForegroundColor Yellow

while (-not $process.HasExited) {
    try {
        # Query CPU utilization
        $cpu_val = (Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'").PercentProcessorTime
        $cpu_history.Add([float]$cpu_val)

        # Query RAM utilization
        $os_mem = Get-CimInstance Win32_OperatingSystem
        $total = $os_mem.TotalVisibleMemorySize
        $free = $os_mem.FreePhysicalMemory
        $used_percent = (($total - $free) / $total) * 100
        $ram_history.Add([float]$used_percent)

        # Query GPU utilization
        $gpu_val = 0
        try {
            $gpu_out = (nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader,nounits).Trim()
            $gpu_val = [float]$gpu_out
        } catch {}
        $gpu_history.Add([float]$gpu_val)

        # Query Disk activity (MB/s)
        $disk = Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -Filter "Name='_Total'"
        $read_mbs = [float]$disk.DiskReadBytesPerSec / 1024 / 1024
        $write_mbs = [float]$disk.DiskWriteBytesPerSec / 1024 / 1024
        $disk_read_history.Add($read_mbs)
        $disk_write_history.Add($write_mbs)
    } catch {
        # Suppress query glitches during start or exit
    }

    Start-Sleep -Milliseconds 150
}

# Capture outputs
$stdout = $process.StandardOutput.ReadToEnd()
$stderr = $process.StandardError.ReadToEnd()
$process.WaitForExit()

Write-Host "Benchmark completed." -ForegroundColor Green

# Calculation Helper
function Get-Stats($list) {
    if ($list.Count -eq 0) {
        return @{ Min = 0.0; Max = 0.0; Avg = 0.0 }
    }
    $min = ($list | Measure-Object -Minimum).Minimum
    $max = ($list | Measure-Object -Maximum).Maximum
    $sum = 0
    foreach ($val in $list) { $sum += $val }
    $avg = $sum / $list.Count
    return @{ Min = $min; Max = $max; Avg = $avg }
}

$cpu_stats = Get-Stats $cpu_history
$ram_stats = Get-Stats $ram_history
$gpu_stats = Get-Stats $gpu_history
$disk_read_stats = Get-Stats $disk_read_history
$disk_write_stats = Get-Stats $disk_write_history

$duration_sec = ([math]::Round(([DateTime]::Now - $startTime).TotalSeconds, 2))

# Pre-format all metrics
$cpu_min = [math]::Round($cpu_stats.Min, 1)
$cpu_max = [math]::Round($cpu_stats.Max, 1)
$cpu_avg = [math]::Round($cpu_stats.Avg, 1)

$ram_min = [math]::Round($ram_stats.Min, 1)
$ram_max = [math]::Round($ram_stats.Max, 1)
$ram_avg = [math]::Round($ram_stats.Avg, 1)

$gpu_min = [math]::Round($gpu_stats.Min, 1)
$gpu_max = [math]::Round($gpu_stats.Max, 1)
$gpu_avg = [math]::Round($gpu_stats.Avg, 1)

$read_min = [math]::Round($disk_read_stats.Min, 2)
$read_max = [math]::Round($disk_read_stats.Max, 2)
$read_avg = [math]::Round($disk_read_stats.Avg, 2)

$write_min = [math]::Round($disk_write_stats.Min, 2)
$write_max = [math]::Round($disk_write_stats.Max, 2)
$write_avg = [math]::Round($disk_write_stats.Avg, 2)

$stderr_section = ""
if ($stderr.Trim()) {
    $stderr_section = "
### Compilation/Error Output
[BACKTICKS]text
$stderr
[BACKTICKS]
"
}

# Output Formatting as Markdown
$report = "# Vollcrypt Core Performance and Resource Monitoring Report

This report presents the execution results of the Vollcrypt Messages cryptographic core benchmark suite, along with real-time hardware resource consumption tracked during the run.

## System Specifications
*   **Operating System (OS):** $os
*   **Processor (CPU):** $cpu
*   **System Memory (RAM):** $total_mem_gb GB
*   **Graphics Controller (GPU):** $gpu
*   **Disk Volumes:**
$formatted_disks
---

## Cryptographic Benchmarks

[BACKTICKS]text
$stdout
[BACKTICKS]

$stderr_section

---

## Resource Utilization Report
*   **Total Test Duration:** $duration_sec seconds

| Resource / Metric | Minimum (Min) | Maximum (Max) | Average (Avg) |
| :--- | :---: | :---: | :---: |
| **System CPU Utilization** | $cpu_min% | $cpu_max% | $cpu_avg% |
| **Memory Utilization (RAM)** | $ram_min% | $ram_max% | $ram_avg% |
| **Graphics Card Utilization (GPU)** | $gpu_min% | $gpu_max% | $gpu_avg% |
| **Disk Read Speed** | $read_min MB/s | $read_max MB/s | $read_avg MB/s |
| **Disk Write Speed** | $write_min MB/s | $write_max MB/s | $write_avg MB/s |

*Note: Since cryptographic operations are entirely CPU-bound, GPU utilization is near zero as expected. Disk I/O remains minimal since encryption/decryption are processed entirely in memory, with disk operations limited to writing standard output logs.*"

# Replace backtick placeholders with actual backticks
$report = $report.Replace("[BACKTICKS]", '```')

$report_file = "C:\Users\iTopya\Desktop\Project\vollcrypt\vollcrypt-messages\core\performance_report_optimized.md"
[System.IO.File]::WriteAllText($report_file, $report, [System.Text.Encoding]::UTF8)
Write-Host "Resource utilization and performance report saved to $report_file." -ForegroundColor Green
