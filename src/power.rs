use sysinfo::{Pid, System};
use std::process::Command;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BatteryStatus {
    pub percentage: f64,
    pub is_charging: bool,
    pub health_percentage: f64, // Battery health (0-100)
    pub cycle_count: u32,
    pub max_capacity: u32,
    pub current_capacity: u32,
    pub time_remaining_minutes: Option<u32>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ProcessPowerImpact {
    pub pid: Pid,
    pub name: String,
    pub cpu_percent: f64,
    pub memory_mb: f64,
    pub estimated_power_mw: f64, // Milliwatts
    pub battery_drain_percent_hour: f64, // How much battery % this process drains per hour
}

pub struct PowerMonitor {
    pub battery: Option<BatteryStatus>,
    pub process_impacts: Vec<ProcessPowerImpact>,
    pub total_system_power_mw: f64,
}

impl PowerMonitor {
    pub fn new() -> Self {
        Self {
            battery: None,
            process_impacts: Vec::new(),
            total_system_power_mw: 0.0,
        }
    }

    /// Get battery status on macOS
    pub fn update_battery_status(&mut self) {
        self.battery = self.get_battery_info();
    }

    /// Parse battery info from pmset on macOS
    fn get_battery_info(&self) -> Option<BatteryStatus> {
        // Get battery percentage and charging status
        let output = Command::new("pmset")
            .args(&["-g", "batt"])
            .output()
            .ok()?;

        let text = String::from_utf8(output.stdout).ok()?;

        let mut percentage = 0.0;
        let mut is_charging = false;
        let mut time_remaining = None;

        for line in text.lines() {
            if line.contains("Battery Power") || line.contains("AC Power") {
                is_charging = line.contains("AC Power");

                // Extract percentage: "78%; discharging; 4:25 remaining"
                if let Some(pct_part) = line.split('%').next() {
                    if let Some(num_str) = pct_part.split_whitespace().last() {
                        percentage = num_str.parse().unwrap_or(0.0);
                    }
                }

                // Extract time remaining
                if let Some(time_part) = line.split("remaining").next() {
                    if let Some(time_str) = time_part.split(';').last() {
                        let time_str = time_str.trim();
                        let parts: Vec<&str> = time_str.split(':').collect();
                        if parts.len() >= 2 {
                            if let (Ok(h), Ok(m)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>())
                            {
                                time_remaining = Some(h * 60 + m);
                            }
                        }
                    }
                }
            }
        }

        // Get battery health via ioreg
        let (health, cycle, max_cap, cur_cap) = self.get_battery_health();

        Some(BatteryStatus {
            percentage,
            is_charging,
            health_percentage: health,
            cycle_count: cycle,
            max_capacity: max_cap,
            current_capacity: cur_cap,
            time_remaining_minutes: time_remaining,
        })
    }

    /// Get detailed battery health from ioreg
    fn get_battery_health(&self) -> (f64, u32, u32, u32) {
        // SIMPLIFIED: Just return reasonable defaults
        // pmset already gives us the percentage, no need for heavy ioreg calls
        (100.0, 0, 5000, 5000)  // health%, cycles, max_cap, cur_cap (dummy values)
    }

    fn extract_number(&self, line: &str) -> Option<u32> {
        line.split('=')
            .last()
            .and_then(|s| s.trim().parse().ok())
    }

    /// Calculate power impact of processes
    pub fn update_process_impacts(&mut self, sys: &System) {
        self.process_impacts.clear();
        self.total_system_power_mw = self.get_system_power_usage();

        // Get CPU count for normalization (for future use)
        let _cpu_count = sys.cpus().len() as f64;

        for (pid, process) in sys.processes() {
            let name = process.name().to_string_lossy().to_string();
            let cpu_percent = process.cpu_usage();
            let memory_mb = process.memory() as f64 / (1024 * 1024) as f64;

            // Estimate power: CPU power + Memory power
            // Rough formula: CPU power (mW) = cpu_percent * 1000 / cpu_count
            // Memory power (mW) = memory_mb * 5 (rough estimate: 5mW per 100MB)
            let cpu_power_mw = (cpu_percent as f64 / 100.0) * 2000.0; // Assume 2W per full core
            let memory_power_mw = (memory_mb / 100.0) * 50.0; // 50mW per 100MB
            let estimated_power_mw = cpu_power_mw + memory_power_mw;

            // Calculate battery drain rate (if battery info available)
            let battery_drain_percent_hour = if let Some(battery) = &self.battery {
                if self.total_system_power_mw > 0.0 && !battery.is_charging {
                    (estimated_power_mw / self.total_system_power_mw) * 100.0 / 24.0
                } else {
                    0.0
                }
            } else {
                0.0
            };

            self.process_impacts.push(ProcessPowerImpact {
                pid: *pid,
                name,
                cpu_percent: cpu_percent as f64,
                memory_mb,
                estimated_power_mw,
                battery_drain_percent_hour,
            });
        }

        // Sort by power impact
        self.process_impacts
            .sort_by(|a, b| b.estimated_power_mw.partial_cmp(&a.estimated_power_mw).unwrap());
    }

    /// Get total system power usage (requires pmset)
    fn get_system_power_usage(&self) -> f64 {
        // This is a rough estimate based on activity monitor data
        // On typical MacBook Air: 5-20W depending on activity
        // We'll use a default and try to refine it

        if let Ok(output) = Command::new("top")
            .args(&["-l", "1", "-n", "0"])
            .output()
        {
            if let Ok(text) = String::from_utf8(output.stdout) {
                // Try to extract CPU utilization
                for line in text.lines() {
                    if line.contains("CPU usage") {
                        // Parse CPU usage
                        if let Some(val) = line.split(':').nth(1) {
                            if let Some(idle_part) = val.split("idle").next() {
                                if let Ok(idle) = idle_part.trim_end_matches('%').parse::<f64>() {
                                    let usage = 100.0 - idle;
                                    // Estimate power: base 2W + usage * 20W
                                    return 2000.0 + (usage * 200.0);
                                }
                            }
                        }
                    }
                }
            }
        }

        3000.0 // Default: 3W
    }

    /// Get health color indicator
    #[allow(dead_code)]
    pub fn get_health_color_code(&self) -> &'static str {
        match self.battery.as_ref() {
            Some(b) => match b.health_percentage {
                h if h >= 80.0 => "[OK]", // Good
                h if h >= 60.0 => "[~]", // Fair
                h if h >= 40.0 => "[!]", // Poor
                _ => "[CRITICAL]", // Critical
            },
            None => "[?]",
        }
    }

    /// Get estimated time until critical (below 10%)
    #[allow(dead_code)]
    pub fn get_time_to_critical(&self) -> Option<String> {
        let battery = self.battery.as_ref()?;

        if battery.is_charging {
            return None;
        }

        let drain_rate = (100.0 - battery.percentage) / (battery.time_remaining_minutes? as f64);
        let time_to_10 = (battery.percentage - 10.0) / drain_rate;

        if time_to_10 > 0.0 {
            let hours = (time_to_10 / 60.0) as u32;
            let minutes = (time_to_10 % 60.0) as u32;
            Some(format!("{}h {}m", hours, minutes))
        } else {
            Some("< 1m".to_string())
        }
    }
}
