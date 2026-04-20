use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct RemoteConnection {
    pub remote_ip: String,
    pub remote_port: u16,
    pub local_port: u16,
    pub protocol: String, // "tcp" or "udp"
    pub pid: u32,
    pub process_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct GeoLocation {
    pub ip: String,
    pub country: String,
    pub country_code: String,
    pub city: String,
    pub latitude: f64,
    pub longitude: f64,
    pub is_risky: bool, // True if from suspicious countries
}

#[derive(Debug, Clone)]
pub struct NetworkThreat {
    pub connection: RemoteConnection,
    pub geo: Option<GeoLocation>,
    pub is_whitelisted: bool,
    pub is_suspicious: bool,
}

pub struct NetworkMonitor {
    pub connections: Vec<RemoteConnection>,
    pub geo_cache: HashMap<String, GeoLocation>,
    pub whitelist: HashSet<String>, // IPs to whitelist
    pub threats: Vec<NetworkThreat>,
}

impl NetworkMonitor {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            connections: Vec::new(),
            geo_cache: HashMap::new(),
            whitelist: {
                let mut set = HashSet::new();
                // Pre-whitelist common safe IPs
                set.insert("127.0.0.1".to_string());
                set.insert("localhost".to_string());
                set.insert("::1".to_string());
                set
            },
            threats: Vec::new(),
        }
    }

    /// Get local network connections using netstat
    pub fn scan_connections(&mut self) {
        self.connections.clear();

        // Use lsof to get all network connections with PID and process name
        if let Ok(output) = Command::new("lsof")
            .args(&["-i", "-P", "-n"])
            .output()
        {
            if let Ok(text) = String::from_utf8(output.stdout) {
                for line in text.lines().skip(1) {
                    // Format: COMMAND PID ... NAME (where NAME has IP:port->IP:port info)
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 9 {
                        if let Ok(pid) = parts[1].parse::<u32>() {
                            let process_name = parts[0].to_string();
                            let name_info = parts[8..].join(" "); // NAME column may have spaces

                            if let Some(conn) = Self::parse_lsof_connection(
                                &name_info,
                                pid,
                                &process_name,
                            ) {
                                self.connections.push(conn);
                            }
                        }
                    }
                }
            }
        }
    }

    // Parse lsof NAME column: 192.168.1.1:52898->8.8.8.8:443 (TCP) or similar
    fn parse_lsof_connection(
        name_info: &str,
        pid: u32,
        process_name: &str,
    ) -> Option<RemoteConnection> {
        // Skip LISTEN, IPv6 addresses (start with [), and non-connected states
        // NOTE: We KEEP private IPs (192.168, 10.x) to show all connections
        if name_info.contains("LISTEN")
            || name_info.starts_with('[')  // IPv6 addresses in brackets
            || !name_info.contains("->")
        {
            return None;
        }

        // Format: "192.168.1.1:52898->8.8.8.8:443 (TCP)"
        let parts: Vec<&str> = name_info.split("->").collect();
        if parts.len() != 2 {
            return None;
        }

        // Parse local address: IP:port
        let local_addr = parts[0].trim();
        let local_port = local_addr.rsplit(':').next()
            .and_then(|p| p.parse::<u16>().ok())?;

        // Parse remote address: IP:port (state)
        let remote_part = parts[1];
        let remote_addr = remote_part.split(' ').next().unwrap_or("");
        
        // Extract IP and port from remote_addr (format: IP:port)
        let remote_parts: Vec<&str> = remote_addr.rsplit(':').collect();
        if remote_parts.is_empty() {
            return None;
        }

        let remote_port = remote_parts[0].parse::<u16>().ok()?;
        let remote_ip = if remote_parts.len() > 1 {
            // Rejoin the IP parts (handles IPv4 with dots)
            remote_parts[1..].iter().rev().copied().collect::<Vec<_>>().join(":")
        } else {
            return None;
        };

        // Skip only localhost
        if remote_ip == "127.0.0.1" || remote_ip.is_empty() {
            return None;
        }

        let protocol = if remote_part.contains("TCP") {
            "tcp"
        } else if remote_part.contains("UDP") {
            "udp"
        } else {
            "tcp"
        };

        Some(RemoteConnection {
            remote_ip,
            remote_port,
            local_port,
            protocol: protocol.to_string(),
            pid,
            process_name: Self::decode_process_name(process_name),
        })
    }

    /// Decode lsof process names (replace \x20 with spaces, etc)
    fn decode_process_name(name: &str) -> String {
        let mut result = String::new();
        let mut chars = name.chars().peekable();
        
        while let Some(c) = chars.next() {
            if c == '\\' && chars.peek() == Some(&'x') {
                // Parse \xHH format
                chars.next(); // consume 'x'
                let mut hex = String::new();
                for _ in 0..2 {
                    if let Some(h) = chars.next() {
                        hex.push(h);
                    }
                }
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                } else {
                    result.push('\\');
                    result.push('x');
                    result.push_str(&hex);
                }
            } else {
                result.push(c);
            }
        }
        
        result
    }

    /// Add IP to whitelist
    #[allow(dead_code)]
    pub fn add_to_whitelist(&mut self, ip: &str) {
        self.whitelist.insert(ip.to_string());
    }

    /// Remove IP from whitelist
    #[allow(dead_code)]
    pub fn remove_from_whitelist(&mut self, ip: &str) {
        self.whitelist.remove(ip);
    }

    /// Check if IP is in whitelist
    pub fn is_whitelisted(&self, ip: &str) -> bool {
        self.whitelist.contains(ip)
    }

    /// Async function to get geolocation via IP-API (requires tokio runtime)
    #[allow(dead_code)]
    pub fn get_geolocation(&mut self, ip: &str) -> Option<GeoLocation> {
        // Check cache first
        if let Some(geo) = self.geo_cache.get(ip) {
            return Some(geo.clone());
        }

        // Fetch from API synchronously (blocking)
        let url = format!(
            "http://ip-api.com/json/{}?fields=status,country,countryCode,city,lat,lon",
            ip
        );

        // Use a blocking client with timeout
        match reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
        {
            Ok(client) => match client.get(&url).send() {
                Ok(response) => match response.text() {
                    Ok(text) => {
                        if let Ok(data) = serde_json::from_str::<serde_json::Value>(&text) {
                            if data["status"].as_str() == Some("success") {
                                let geo = GeoLocation {
                                    ip: ip.to_string(),
                                    country: data["country"]
                                        .as_str()
                                        .unwrap_or("Unknown")
                                        .to_string(),
                                    country_code: data["countryCode"]
                                        .as_str()
                                        .unwrap_or("XX")
                                        .to_string(),
                                    city: data["city"]
                                        .as_str()
                                        .unwrap_or("Unknown")
                                        .to_string(),
                                    latitude: data["lat"].as_f64().unwrap_or(0.0),
                                    longitude: data["lon"].as_f64().unwrap_or(0.0),
                                    is_risky: Self::is_risky_country(
                                        data["countryCode"].as_str().unwrap_or("XX"),
                                    ),
                                };
                                self.geo_cache.insert(ip.to_string(), geo.clone());
                                return Some(geo);
                            }
                        }
                    }
                    Err(_) => return None,
                },
                Err(_) => return None,
            },
            Err(_) => return None,
        }

        None
    }

    /// Check if country is in high-risk list
    #[allow(dead_code)]
    fn is_risky_country(country_code: &str) -> bool {
        matches!(country_code, "RU" | "CN" | "IR" | "NK" | "SY" | "KP")
    }

    /// Analyze connections for threats
    pub fn analyze_threats(&mut self) {
        self.threats.clear();

        // First pass: collect IPs that need geolocation
        let mut ips_to_fetch: Vec<String> = Vec::new();
        for conn in &self.connections {
            if !self.geo_cache.contains_key(&conn.remote_ip) 
                && !conn.remote_ip.contains(":")  // Skip IPv6
                && conn.remote_ip != "127.0.0.1"
                && !conn.remote_ip.starts_with("192.168.")
                && !conn.remote_ip.starts_with("10.")
            {
                ips_to_fetch.push(conn.remote_ip.clone());
            }
        }

        // Fetch geolocation for uncached IPs (mutable borrow)
        for ip in ips_to_fetch {
            let _ = self.get_geolocation(&ip); // Side effect: populates cache
        }

        // Second pass: build threat list (immutable borrow)
        for conn in &self.connections {
            let is_whitelisted = self.is_whitelisted(&conn.remote_ip);
            let geo = self.geo_cache.get(&conn.remote_ip).cloned();
            let is_suspicious = geo.as_ref().map_or(false, |g| g.is_risky) && !is_whitelisted;

            self.threats.push(NetworkThreat {
                connection: conn.clone(),
                geo,
                is_whitelisted,
                is_suspicious,
            });
        }

        // Sort: suspicious first
        self.threats.sort_by_key(|t| !t.is_suspicious);
    }

    /// Get summary stats
    pub fn get_summary(&self) -> (usize, usize, usize) {
        let total = self.threats.len();
        let suspicious = self.threats.iter().filter(|t| t.is_suspicious).count();
        let whitelisted = self.threats.iter().filter(|t| t.is_whitelisted).count();
        (total, suspicious, whitelisted)
    }
}
