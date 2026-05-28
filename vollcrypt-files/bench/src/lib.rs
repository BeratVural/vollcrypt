pub mod hwinfo;

use sysinfo::System;

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
