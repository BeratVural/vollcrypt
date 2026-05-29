use sysinfo::System;

#[derive(Debug, Clone)]
pub struct HwInfo {
    pub cpu_brand: String,
    pub cpu_cores_physical: usize,
    pub cpu_cores_logical: usize,
    pub cpu_freq_mhz: u64,
    pub cpu_features: CpuFeatures,
    pub total_memory_gb: f64,
    pub available_memory_gb: f64,
    pub os: String,
    pub kernel: String,
    pub rust_version: String,
    pub gpu_brand: String,
    pub disk_info: String,
}

#[derive(Debug, Clone, Copy)]
pub struct CpuFeatures {
    pub aes_ni: bool,
    pub avx: bool,
    pub avx2: bool,
    pub avx512: bool,
    pub sha_ni: bool,
    pub pclmulqdq: bool,
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn detect_cpu_features() -> CpuFeatures {
    use raw_cpuid::CpuId;
    let cpuid = CpuId::new();

    let (aes_ni, avx, pclmulqdq) = cpuid
        .get_feature_info()
        .map(|f| (f.has_aesni(), f.has_avx(), f.has_pclmulqdq()))
        .unwrap_or((false, false, false));

    let (avx2, avx512, sha_ni) = cpuid
        .get_extended_feature_info()
        .map(|f| (f.has_avx2(), f.has_avx512f(), f.has_sha()))
        .unwrap_or((false, false, false));

    CpuFeatures {
        aes_ni,
        avx,
        avx2,
        avx512,
        sha_ni,
        pclmulqdq,
    }
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn detect_cpu_features() -> CpuFeatures {
    CpuFeatures {
        aes_ni: false,
        avx: false,
        avx2: false,
        avx512: false,
        sha_ni: false,
        pclmulqdq: false,
    }
}

fn detect_gpu_brand() -> String {
    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("powershell")
            .args(&[
                "-NoProfile",
                "-Command",
                "Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name",
            ])
            .output()
        {
            let gpu = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !gpu.is_empty() {
                return gpu.replace("\r", "").replace("\n", ", ");
            }
        }
        if let Ok(output) = std::process::Command::new("wmic")
            .args(&["path", "win32_VideoController", "get", "name"])
            .output()
        {
            let gpu_out = String::from_utf8_lossy(&output.stdout);
            let lines = gpu_out
                .lines()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty() && *s != "Name");
            let gpus: Vec<_> = lines.collect();
            if !gpus.is_empty() {
                return gpus.join(", ");
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = std::process::Command::new("sh")
            .args(&["-c", "lspci | grep -i vga"])
            .output()
        {
            let lspci_out = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !lspci_out.is_empty() {
                return lspci_out;
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("system_profiler")
            .args(&["SPDisplaysDataType"])
            .output()
        {
            let sp_out = String::from_utf8_lossy(&output.stdout);
            for line in sp_out.lines() {
                if line.contains("Chipset Model:") {
                    return line.replace("Chipset Model:", "").trim().to_string();
                }
            }
        }
    }
    "Unknown GPU / Integrated Graphics".to_string()
}

fn detect_disk_info() -> String {
    let disks = sysinfo::Disks::new_with_refreshed_list();
    if disks.is_empty() {
        return "Unknown Disk".to_string();
    }
    disks
        .iter()
        .map(|d| {
            let kind_str = match d.kind() {
                sysinfo::DiskKind::SSD => "SSD",
                sysinfo::DiskKind::HDD => "HDD",
                _ => "Unknown Type",
            };
            format!(
                "{} [{}] ({:.1} GB free / {:.1} GB total)",
                d.mount_point().to_string_lossy(),
                kind_str,
                d.available_space() as f64 / 1_073_741_824.0,
                d.total_space() as f64 / 1_073_741_824.0
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

pub fn detect() -> HwInfo {
    let mut sys = System::new_all();
    sys.refresh_all();

    let cpus = sys.cpus();
    let cpu_brand = cpus
        .first()
        .map(|cpu| cpu.brand().trim().to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    let cpu_freq_mhz = cpus.first().map(|cpu| cpu.frequency()).unwrap_or(0);

    let cpu_cores_physical = sys.physical_core_count().unwrap_or(1);
    let cpu_cores_logical = cpus.len();

    let total_memory_gb = sys.total_memory() as f64 / 1_073_741_824.0;
    let available_memory_gb = sys.available_memory() as f64 / 1_073_741_824.0;

    let os = System::name().unwrap_or_else(|| "Unknown OS".to_string());
    let kernel = System::kernel_version().unwrap_or_else(|| "Unknown Kernel".to_string());

    let rust_version = std::process::Command::new("rustc")
        .arg("-V")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .unwrap_or_else(|| "Unknown".to_string())
        .trim()
        .to_string();

    HwInfo {
        cpu_brand,
        cpu_cores_physical,
        cpu_cores_logical,
        cpu_freq_mhz,
        cpu_features: detect_cpu_features(),
        total_memory_gb,
        available_memory_gb,
        os,
        kernel,
        rust_version,
        gpu_brand: detect_gpu_brand(),
        disk_info: detect_disk_info(),
    }
}

pub fn render_markdown(info: &HwInfo) -> String {
    let features = info.cpu_features;
    let mut accel = Vec::new();
    if features.aes_ni {
        accel.push("AES-NI");
    }
    if features.avx {
        accel.push("AVX");
    }
    if features.avx2 {
        accel.push("AVX2");
    }
    if features.avx512 {
        accel.push("AVX512");
    }
    if features.sha_ni {
        accel.push("SHA-NI");
    }
    if features.pclmulqdq {
        accel.push("PCLMULQDQ");
    }
    let accel_str = if accel.is_empty() {
        "None".to_string()
    } else {
        accel.join(", ")
    };

    format!(
        "| Component | Detail |\n\
         | --- | --- |\n\
         | CPU | {} ({} physical cores, {} logical threads) @ {:.2} GHz |\n\
         | GPU | {} |\n\
         | RAM | {:.2} GB ({:.2} GB available) |\n\
         | Disk | {} |\n\
         | OS | {} {} |\n\
         | Hardware Acceleration | {} |\n\
         | Rust Version | {} |",
        info.cpu_brand,
        info.cpu_cores_physical,
        info.cpu_cores_logical,
        info.cpu_freq_mhz as f64 / 1000.0,
        info.gpu_brand,
        info.total_memory_gb,
        info.available_memory_gb,
        info.disk_info,
        info.os,
        info.kernel,
        accel_str,
        info.rust_version
    )
}
