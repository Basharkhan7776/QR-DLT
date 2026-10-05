use std::fs;

/// Telemetry and memory profiling helpers for empirical evaluations.
pub struct ProcessMetrics;

impl ProcessMetrics {
    /// Returns the process Resident Set Size (RSS) in megabytes on Linux bare-metal.
    pub fn get_rss_mb() -> Option<f64> {
        let statm = fs::read_to_string("/proc/self/statm").ok()?;
        let parts: Vec<&str> = statm.split_whitespace().collect();
        if parts.len() >= 2 {
            let pages: usize = parts[1].parse().ok()?;
            let page_size_kb = 4; // Standard 4KB page on Linux x86_64
            Some((pages * page_size_kb) as f64 / 1024.0)
        } else {
            None
        }
    }
}
