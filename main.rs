mod signatures;
mod analyzer;

use std::path::{Path, PathBuf};
use std::process;

use clap::{Parser, Subcommand};
use colored::*;
use walkdir::WalkDir;

use analyzer::{analyze_file, format_size};

/// MagicID — File Type Identifier using Magic Number Signatures
#[derive(Parser)]
#[command(
    name = "magicid",
    version = "1.0.0",
    author = "MagicID Project",
    about = "Identify file types by their magic bytes, detect mismatches, and scan directories",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Identify a single file
    Identify {
        /// Path to the file
        file: PathBuf,

        /// Show raw hex preview of header bytes
        #[arg(short = 'x', long)]
        hex: bool,

        /// Output result as JSON
        #[arg(short, long)]
        json: bool,
    },

    /// Scan a directory for all files
    Scan {
        /// Directory to scan
        dir: PathBuf,

        /// Only report files with extension mismatches
        #[arg(short, long)]
        mismatches_only: bool,

        /// Maximum recursion depth (default: unlimited)
        #[arg(short, long)]
        depth: Option<usize>,

        /// Filter by category (image, video, audio, archive, document, executable, etc.)
        #[arg(short, long)]
        category: Option<String>,
    },

    /// List all supported file signatures in the database
    List {
        /// Filter by category
        #[arg(short, long)]
        category: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Identify { file, hex, json } => {
            cmd_identify(&file, hex, json);
        }
        Commands::Scan { dir, mismatches_only, depth, category } => {
            cmd_scan(&dir, mismatches_only, depth, category.as_deref());
        }
        Commands::List { category } => {
            cmd_list(category.as_deref());
        }
    }
}

// ── identify ────────────────────────────────────────────────────────────────

fn cmd_identify(path: &Path, show_hex: bool, json: bool) {
    if !path.exists() {
        eprintln!("{} File not found: {}", "✗".red().bold(), path.display());
        process::exit(1);
    }

    match analyze_file(path) {
        Ok(result) => {
            if json {
                print_json(&result);
                return;
            }

            println!();
            println!("{} {}", "File:".cyan().bold(), result.path);
            println!("{} {}", "Size:".cyan().bold(), format_size(result.file_size));

            if show_hex {
                println!("{} {}", "Header:".cyan().bold(), result.hex_preview.yellow());
            }

            match &result.detected {
                Some(d) => {
                    println!("{} {} ({})", "Type:".cyan().bold(), d.description.green().bold(), d.mime_type);
                    println!("{} {}", "Category:".cyan().bold(), d.category.to_string().blue());
                    println!("{} .{}", "True Ext:".cyan().bold(), d.extension.green());
                }
                None => {
                    println!("{} {}", "Type:".cyan().bold(), "Unknown / No signature match".yellow());
                }
            }

            if result.extension_mismatch {
                println!(
                    "\n{} Extension {} does not match detected type .{}",
                    "⚠  MISMATCH:".red().bold(),
                    format!(".{}", result.file_extension).red(),
                    result.detected.as_ref().map(|d| d.extension.as_str()).unwrap_or("?").green()
                );
            } else if !result.file_extension.is_empty() {
                println!("{} Extension matches detected type.", "✓".green().bold());
            }
            println!();
        }
        Err(e) => {
            eprintln!("{} {}: {}", "✗".red().bold(), path.display(), e);
            process::exit(1);
        }
    }
}

fn print_json(result: &analyzer::AnalysisResult) {
    let detected_json = match &result.detected {
        Some(d) => format!(
            r#"{{"extension":"{}","mime_type":"{}","description":"{}","category":"{}"}}"#,
            d.extension, d.mime_type, d.description, d.category
        ),
        None => "null".to_string(),
    };

    println!(
        r#"{{"path":"{}","file_size":{},"file_extension":"{}","hex_preview":"{}","detected":{},"extension_mismatch":{}}}"#,
        result.path,
        result.file_size,
        result.file_extension,
        result.hex_preview,
        detected_json,
        result.extension_mismatch
    );
}

// ── scan ────────────────────────────────────────────────────────────────────

fn cmd_scan(dir: &Path, mismatches_only: bool, depth: Option<usize>, category_filter: Option<&str>) {
    if !dir.exists() || !dir.is_dir() {
        eprintln!("{} Not a valid directory: {}", "✗".red().bold(), dir.display());
        process::exit(1);
    }

    let mut walker = WalkDir::new(dir).follow_links(false);
    if let Some(d) = depth {
        walker = walker.max_depth(d);
    }

    let mut total = 0usize;
    let mut matched = 0usize;
    let mut mismatches = 0usize;
    let mut unknown = 0usize;

    println!("\n{} {}\n", "Scanning:".cyan().bold(), dir.display());

    for entry in walker.into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        total += 1;

        match analyze_file(path) {
            Ok(result) => {
                // Category filter
                if let Some(cat) = category_filter {
                    if let Some(ref d) = result.detected {
                        if !d.category.to_string().to_lowercase().contains(cat) {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }

                let show = if mismatches_only { result.extension_mismatch } else { true };

                if show {
                    let name = path.file_name().unwrap_or_default().to_string_lossy();
                    let size_str = format_size(result.file_size);

                    if result.extension_mismatch {
                        mismatches += 1;
                        println!(
                            "  {} {} ({}) — claimed .{} but is {}",
                            "⚠".red().bold(),
                            name.bold(),
                            size_str.dimmed(),
                            result.file_extension.red(),
                            result.detected.as_ref().map(|d| format!(".{}", d.extension)).unwrap_or_default().green()
                        );
                    } else if let Some(ref d) = result.detected {
                        matched += 1;
                        println!(
                            "  {} {} ({}) — {}",
                            "✓".green(),
                            name,
                            size_str.dimmed(),
                            d.description.blue()
                        );
                    } else {
                        unknown += 1;
                        println!(
                            "  {} {} ({}) — {}",
                            "?".yellow(),
                            name,
                            size_str.dimmed(),
                            "Unknown".yellow()
                        );
                    }
                }
            }
            Err(_) => {}
        }
    }

    println!();
    println!("{}", "─".repeat(50).dimmed());
    println!(
        "{} {} files scanned  {} identified  {} mismatches  {} unknown",
        "Summary:".cyan().bold(),
        total.to_string().bold(),
        matched.to_string().green().bold(),
        mismatches.to_string().red().bold(),
        unknown.to_string().yellow().bold()
    );
    println!();
}

// ── list ────────────────────────────────────────────────────────────────────

fn cmd_list(category_filter: Option<&str>) {
    let sigs = signatures::get_signatures();
    println!("\n{}\n", "MagicID Signature Database".cyan().bold());
    println!(
        "  {:<8} {:<12} {:<14} {}",
        "Category".bold(),
        "Extension".bold(),
        "Hex Offset".bold(),
        "Description".bold()
    );
    println!("  {}", "─".repeat(70).dimmed());

    for sig in &sigs {
        let cat = sig.category.to_string();
        if let Some(f) = category_filter {
            if !cat.to_lowercase().contains(f) {
                continue;
            }
        }

        let magic_hex: String = sig.magic.iter().take(6).map(|b| format!("{:02X} ", b)).collect();

        println!(
            "  {:<8} .{:<11} {:<14} {}",
            cat.blue(),
            sig.extension.green(),
            magic_hex.yellow().dimmed(),
            sig.description
        );
    }

    println!("\n  Total: {} signatures\n", sigs.len().to_string().bold());
}
