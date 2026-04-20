use sysinfo::{Pid, System};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ProcessSignature {
    pub is_apple_signed: bool,
    pub is_notarized: bool,
    pub signature_valid: bool,
    pub signer: String,
}

impl Default for ProcessSignature {
    fn default() -> Self {
        Self {
            is_apple_signed: false,
            is_notarized: false,
            signature_valid: false,
            signer: String::new(),
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ProcessHistory {
    pub pid: Pid,
    pub name: String,
    pub first_seen: u64, // Unix timestamp
    pub last_seen: u64,
    pub duration_ms: u64,
    pub max_cpu_usage: f64,
    pub max_memory: u64,
    pub network_activity: bool,
}

#[derive(Debug, Clone)]
pub struct ProcessThreat {
    pub is_suspicious: bool,
    pub risk_score: u8, // 0-100
}

pub struct ProcessMonitor {
    pub processes_history: HashMap<Pid, ProcessHistory>,
    pub threats: Vec<ProcessThreat>,
    pub last_scan: u64,
}

impl ProcessMonitor {
    pub fn new() -> Self {
        Self {
            processes_history: HashMap::new(),
            threats: Vec::new(),
            last_scan: 0,
        }
    }

    /// Scan current processes and check signatures
    pub fn scan(&mut self, sys: &System) {
        let now = Self::get_current_timestamp();
        self.last_scan = now;
        self.threats.clear();

        // Get all processes and sort by resource usage (most important first)
        let mut processes: Vec<_> = sys.processes().iter().collect();
        processes.sort_by(|a, b| {
            let score_a = a.1.cpu_usage() as f64 + (a.1.memory() as f64 / (1024 * 1024) as f64);
            let score_b = b.1.cpu_usage() as f64 + (b.1.memory() as f64 / (1024 * 1024) as f64);
            score_b.partial_cmp(&score_a).unwrap_or(std::cmp::Ordering::Equal)
        });

        // Only check signatures for top 30 processes + any that were previously suspicious
        let check_limit = 30;
        let mut checked_count = 0;

        for (pid, process) in processes {
            let name = process.name().to_string_lossy().to_string();
            let should_check_signature = checked_count < check_limit 
                || self.processes_history.get(pid).map_or(false, |h| {
                    // Re-check if this was previously suspicious
                    self.calculate_risk_score(&ProcessSignature::default(), h, 0.0, 0) > 50
                });

            // Check code signature (macOS specific) - but only for important processes
            let signature = if should_check_signature {
                self.check_code_signature(&name)
            } else {
                // Skip signature check for less important processes - assume safe
                ProcessSignature {
                    is_apple_signed: true,
                    is_notarized: true,
                    signature_valid: true,
                    signer: "skipped".to_string(),
                }
            };

            if should_check_signature {
                checked_count += 1;
            }

            // Get or create history
            let history = self
                .processes_history
                .entry(*pid)
                .or_insert_with(|| ProcessHistory {
                    pid: *pid,
                    name: name.clone(),
                    first_seen: now,
                    last_seen: now,
                    duration_ms: 0,
                    max_cpu_usage: 0.0,
                    max_memory: 0,
                    network_activity: false,
                });

            // Update history
            history.last_seen = now;
            history.duration_ms = (now - history.first_seen) * 1000;
            history.max_cpu_usage = history.max_cpu_usage.max(process.cpu_usage() as f64);
            history.max_memory = history.max_memory.max(process.memory());

            // Clone history before we lose mutable borrow
            let history_clone = history.clone();

            // Calculate risk score
            let risk_score = self.calculate_risk_score(
                &signature,
                &history_clone,
                process.cpu_usage() as f64,
                process.memory(),
            );

            let is_suspicious = risk_score > 50;

            self.threats.push(ProcessThreat {
                is_suspicious,
                risk_score,
            });
        }

        // Clean up old processes (not seen for more than 1 hour)
        let one_hour_ago = now - 3600;
        self.processes_history
            .retain(|_, h| h.last_seen > one_hour_ago);

        // Sort threats: suspicious first, then by risk score
        self.threats.sort_by(|a, b| {
            if a.is_suspicious != b.is_suspicious {
                b.is_suspicious.cmp(&a.is_suspicious)
            } else {
                b.risk_score.cmp(&a.risk_score)
            }
        });
    }

    /// Check if a process is signed with valid Apple code signature
    /// SIMPLIFIED: Uses path heuristic instead of system calls (codesign/spctl are too slow)
    fn check_code_signature(&self, process_name: &str) -> ProcessSignature {
        // Quick heuristic: if process name contains known Apple/safe prefixes, consider it signed
        let is_likely_system = process_name.starts_with("kernel") 
            || process_name.starts_with("launchd")
            || process_name.starts_with("com.apple.")
            || process_name.starts_with("kernel_task")
            || process_name.starts_with("WindowServer")
            || process_name.starts_with("Finder")
            || process_name.contains("System")
            || process_name.contains("Apple");

        // System processes are assumed to be signed
        if is_likely_system {
            return ProcessSignature {
                is_apple_signed: true,
                is_notarized: true,
                signature_valid: true,
                signer: "Apple".to_string(),
            };
        }

        // For other processes, quick path check (no system calls)
        let common_safe_prefixes = [
            "/System", "/Applications", "/usr/bin", "/usr/local/bin",
            "/opt/homebrew", "/Library", "/var", "/tmp", "/dev",
        ];

        let looks_trusted = common_safe_prefixes.iter().any(|prefix| {
            process_name.starts_with(prefix)
        });

        if looks_trusted {
            return ProcessSignature {
                is_apple_signed: true,
                is_notarized: true,
                signature_valid: true,
                signer: "System".to_string(),
            };
        }

        // Unknown processes: assume not verified
        ProcessSignature {
            is_apple_signed: false,
            is_notarized: false,
            signature_valid: false,
            signer: "Unknown".to_string(),
        }
    }

    /// Calculate risk score for a process (SIMPLIFIED: focus only on behavior, not signatures)
    fn calculate_risk_score(
        &self,
        _signature: &ProcessSignature,
        history: &ProcessHistory,
        cpu_usage: f64,
        memory: u64,
    ) -> u8 {
        let mut score = 0u8;

        // ONLY FLAG REAL THREATS: Dropper malware pattern
        // Dropper: process that exits very quickly after doing something
        let very_short_lifespan = history.duration_ms < 2000; // Less than 2 seconds
        let high_activity = cpu_usage > 50.0 || memory > (100 * 1024 * 1024); // 100MB+

        if very_short_lifespan && high_activity {
            // Classic dropper signature
            score = 75;
        } else if history.duration_ms < 1000 && cpu_usage > 30.0 {
            // Extremely short lived with some activity
            score = 60;
        }

        // Don't over-flag based on signatures or CPU alone
        // Most legitimate processes will have score 0

        score
    }

    fn get_current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}
