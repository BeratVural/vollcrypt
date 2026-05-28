pub mod hwinfo;

use sysinfo::System;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

pub fn get_current_rss_mb() -> f64 {
    let mut sys = System::new();
    let pid = sysinfo::get_current_pid().ok();
    if let Some(pid) = pid {
        sys.refresh_process(pid);
        if let Some(process) = sys.process(pid) {
            return process.memory() as f64 / 1_048_576.0;
        }
    }
    0.0
}

#[derive(Default, Clone)]
pub struct MonitorSamples {
    pub ram_usage_pct: Vec<f64>,
    pub cpu_usage_pct: Vec<f64>,
    pub disk_read_bytes_per_sec: Vec<f64>,
    pub disk_write_bytes_per_sec: Vec<f64>,
}

pub struct SystemMonitor {
    stop_signal: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    samples: Arc<Mutex<MonitorSamples>>,
}

impl SystemMonitor {
    pub fn start() -> Self {
        let stop_signal = Arc::new(AtomicBool::new(false));
        let samples = Arc::new(Mutex::new(MonitorSamples::default()));
        
        let stop_signal_clone = Arc::clone(&stop_signal);
        let samples_clone = Arc::clone(&samples);
        
        let handle = std::thread::spawn(move || {
            let mut sys = System::new_all();
            sys.refresh_all();
            
            let pid = sysinfo::get_current_pid().ok();
            
            while !stop_signal_clone.load(Ordering::Relaxed) {
                sys.refresh_memory();
                sys.refresh_cpu();
                
                let total_mem = sys.total_memory() as f64;
                let used_mem = sys.used_memory() as f64;
                let ram_pct = if total_mem > 0.0 { (used_mem / total_mem) * 100.0 } else { 0.0 };
                
                let cpu_pct = sys.global_cpu_info().cpu_usage() as f64;
                
                let mut read_bytes = 0.0;
                let mut write_bytes = 0.0;
                
                if let Some(pid) = pid {
                    sys.refresh_process(pid);
                    if let Some(process) = sys.process(pid) {
                        let du = process.disk_usage();
                        read_bytes = du.read_bytes as f64;
                        write_bytes = du.written_bytes as f64;
                    }
                }
                
                {
                    let mut s = samples_clone.lock().unwrap();
                    s.ram_usage_pct.push(ram_pct);
                    s.cpu_usage_pct.push(cpu_pct);
                    s.disk_read_bytes_per_sec.push(read_bytes);
                    s.disk_write_bytes_per_sec.push(write_bytes);
                }
                
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        });
        
        SystemMonitor {
            stop_signal,
            handle: Some(handle),
            samples,
        }
    }
    
    pub fn stop(mut self) -> (f64, f64, f64, f64, f64, f64, f64, f64, f64, f64, f64, f64) {
        self.stop_signal.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        
        let s = self.samples.lock().unwrap();
        
        let avg = |v: &[f64]| if v.is_empty() { 0.0 } else { v.iter().sum::<f64>() / v.len() as f64 };
        let min = |v: &[f64]| if v.is_empty() { 0.0 } else { *v.iter().min_by(|a, b| a.partial_cmp(b).unwrap()).unwrap() };
        let max = |v: &[f64]| if v.is_empty() { 0.0 } else { *v.iter().max_by(|a, b| a.partial_cmp(b).unwrap()).unwrap() };
        
        (
            min(&s.ram_usage_pct), max(&s.ram_usage_pct), avg(&s.ram_usage_pct),
            min(&s.cpu_usage_pct), max(&s.cpu_usage_pct), avg(&s.cpu_usage_pct),
            min(&s.disk_read_bytes_per_sec), max(&s.disk_read_bytes_per_sec), avg(&s.disk_read_bytes_per_sec),
            min(&s.disk_write_bytes_per_sec), max(&s.disk_write_bytes_per_sec), avg(&s.disk_write_bytes_per_sec)
        )
    }
}
