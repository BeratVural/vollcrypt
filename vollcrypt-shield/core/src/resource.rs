use std::thread;
use std::time::{Duration, Instant};

use crate::policy::ScanProfile;

#[derive(Debug)]
pub struct ResourceGovernor {
    profile: ScanProfile,
    processed: usize,
    started: Instant,
    work_time: Duration,
    work_started: Instant,
}

impl ResourceGovernor {
    pub fn new(profile: ScanProfile) -> Self {
        let now = Instant::now();
        Self {
            profile,
            processed: 0,
            started: now,
            work_time: Duration::ZERO,
            work_started: now,
        }
    }

    pub fn max_threads(&self) -> usize {
        self.profile.max_threads
    }

    pub fn before_item(&mut self) {
        self.work_started = Instant::now();
    }

    pub fn after_item(&mut self) {
        self.work_time += self.work_started.elapsed();
        self.processed += 1;
        if !self
            .processed
            .is_multiple_of(self.profile.io_yield_every_files)
        {
            return;
        }

        thread::yield_now();
        if self.profile.max_cpu_percent >= 100 {
            return;
        }

        let elapsed = self.started.elapsed();
        let desired_total = self
            .work_time
            .mul_f64(100.0 / f64::from(self.profile.max_cpu_percent));
        if desired_total > elapsed {
            thread::sleep((desired_total - elapsed).min(Duration::from_secs(1)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_bounded_parallelism() {
        let governor = ResourceGovernor::new(ScanProfile::incremental_default());
        assert_eq!(governor.max_threads(), 2);
    }
}
