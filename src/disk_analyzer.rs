use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub struct FolderEntry {
    pub path: PathBuf,
    pub size: u64,
    pub name: String,
}

/// Disk analyzer for hierarchical folder size scanning
pub struct DiskAnalyzer {
    pub current_path: PathBuf,
    pub folders: Vec<FolderEntry>,
    pub parent_path: Option<PathBuf>,
}

impl DiskAnalyzer {
    pub fn new(start_path: &str) -> Self {
        let path = PathBuf::from(start_path);
        let mut analyzer = Self {
            current_path: path.clone(),
            folders: Vec::new(),
            parent_path: None,
        };
        analyzer.scan();
        analyzer
    }

    /// Scan current directory for immediate subdirectories and their sizes
    pub fn scan(&mut self) {
        self.folders.clear();
        
        // Get parent path
        self.parent_path = self.current_path.parent().map(|p| p.to_path_buf());

        // Scan immediate subdirectories
        if let Ok(entries) = fs::read_dir(&self.current_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                
                // Skip hidden files/folders
                if path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|s| s.starts_with('.'))
                    .unwrap_or(false)
                {
                    continue;
                }

                if path.is_dir() {
                    let name = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("Unknown")
                        .to_string();

                    // Calculate total size of directory (recursive, non-blocking)
                    let size = Self::calculate_dir_size(&path);

                    self.folders.push(FolderEntry {
                        path,
                        size,
                        name,
                    });
                }
            }
        }

        // Sort by size descending
        self.folders.sort_by(|a, b| b.size.cmp(&a.size));
    }

    /// Recursively calculate directory size (with permission error handling)
    fn calculate_dir_size(path: &Path) -> u64 {
        WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter_map(|e| e.metadata().ok())
            .filter(|m| m.is_file())
            .map(|m| m.len())
            .sum()
    }

    /// Navigate into a subdirectory
    pub fn enter_folder(&mut self, index: usize) {
        if index < self.folders.len() {
            self.current_path = self.folders[index].path.clone();
            self.scan();
        }
    }

    /// Navigate to parent directory
    pub fn go_back(&mut self) {
        if let Some(parent) = &self.parent_path {
            self.current_path = parent.clone();
            self.scan();
        }
    }

    /// Get current path as string
    pub fn current_path_str(&self) -> String {
        self.current_path.to_string_lossy().to_string()
    }

    /// Get total size of all folders in current view
    pub fn total_size(&self) -> u64 {
        self.folders.iter().map(|f| f.size).sum()
    }
}

/// Format bytes to human readable format
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;

    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }

    if unit_idx == 0 {
        format!("{} {}", size as u64, UNITS[unit_idx])
    } else {
        format!("{:.2} {}", size, UNITS[unit_idx])
    }
}

/// Calculate percentage of total
pub fn calc_percentage(value: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        (value as f64 / total as f64) * 100.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytes(512), "512 B");
    }

    #[test]
    fn test_calc_percentage() {
        assert_eq!(calc_percentage(50, 100), 50.0);
        assert_eq!(calc_percentage(0, 0), 0.0);
    }
}
