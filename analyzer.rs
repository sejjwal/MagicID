use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use crate::signatures::{get_signatures, Category, Signature};

const READ_BYTES: usize = 512;

#[derive(Debug)]
pub struct AnalysisResult {
    pub path: String,
    pub file_extension: String,
    pub detected: Option<DetectedType>,
    pub extension_mismatch: bool,
    pub hex_preview: String,
    pub file_size: u64,
}

#[derive(Debug, Clone)]
pub struct DetectedType {
    pub extension: String,
    pub mime_type: String,
    pub description: String,
    pub category: Category,
}

pub fn analyze_file(path: &Path) -> io::Result<AnalysisResult> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    let file_size = metadata.len();

    let mut buffer = vec![0u8; READ_BYTES.min(file_size as usize)];
    let bytes_read = file.read(&mut buffer)?;
    buffer.truncate(bytes_read);

    // Hex preview (first 16 bytes)
    let hex_preview = buffer
        .iter()
        .take(16)
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ");

    // Actual file extension (lowercased)
    let file_extension = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    // Match against signatures
    let signatures = get_signatures();
    let detected = find_match(&buffer, &signatures);

    // Check for mismatch
    let extension_mismatch = if let Some(ref d) = detected {
        !file_extension.is_empty() && file_extension != d.extension
    } else {
        false
    };

    Ok(AnalysisResult {
        path: path.to_string_lossy().into_owned(),
        file_extension,
        detected,
        extension_mismatch,
        hex_preview,
        file_size,
    })
}

fn find_match(buffer: &[u8], signatures: &[Signature]) -> Option<DetectedType> {
    // Sort by magic length descending so longer (more specific) matches win
    let mut sigs = signatures.to_vec();
    sigs.sort_by(|a, b| b.magic.len().cmp(&a.magic.len()));

    for sig in &sigs {
        let start = sig.offset;
        let end = start + sig.magic.len();

        if buffer.len() >= end {
            if &buffer[start..end] == sig.magic {
                return Some(DetectedType {
                    extension: sig.extension.to_string(),
                    mime_type: sig.mime_type.to_string(),
                    description: sig.description.to_string(),
                    category: sig.category.clone(),
                });
            }
        }
    }
    None
}

pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
