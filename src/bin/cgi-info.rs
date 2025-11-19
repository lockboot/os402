#!/usr/bin/env rust-script
//! Simple CGI binary that prints process information and environment variables
//!
//! This demonstrates a minimal CGI script that:
//! - Outputs CGI headers (Content-Type)
//! - Prints process information (PID, PPID, UID, GID)
//! - Lists all environment variables
//! - Shows stdin content

use std::env;
use std::fs;
use std::io::{self, Read};
use std::process;
use std::thread;
use std::time::Duration;

fn main() {
    // Check for sleep parameter in QUERY_STRING
    if let Ok(query_string) = env::var("QUERY_STRING") {
        for param in query_string.split('&') {
            if let Some(value) = param.strip_prefix("sleep=") {
                if let Ok(seconds) = value.parse::<u64>() {
                    thread::sleep(Duration::from_secs(seconds));
                }
            }
        }
    }

    // CGI scripts must output headers before content
    println!("Content-Type: text/plain");
    println!(); // Blank line separates headers from body

    // Print process information
    println!("=== Process Information ===");
    println!("PID: {}", process::id());

    // Get current user info (Unix-specific)
    #[cfg(unix)]
    {
        use std::os::unix::process::parent_id;
        println!("PPID: {}", parent_id());

        unsafe {
            println!("UID: {}", libc::getuid());
            println!("GID: {}", libc::getgid());
            println!("EUID: {}", libc::geteuid());
            println!("EGID: {}", libc::getegid());
        }
    }

    println!();

    // Print CGI environment variables (sorted)
    println!("=== CGI Environment Variables ===");
    let mut env_vars: Vec<(String, String)> = env::vars().collect();
    env_vars.sort_by(|a, b| a.0.cmp(&b.0));

    for (key, value) in env_vars {
        println!("{} = {}", key, value);
    }

    println!();

    // List root directory
    println!("=== Directory Listing: / ===");
    match fs::read_dir("/") {
        Ok(entries) => {
            let mut paths: Vec<_> = entries
                .filter_map(|e| e.ok())
                .collect();
            paths.sort_by_key(|e| e.path());

            for entry in paths {
                let path = entry.path();
                let metadata = entry.metadata();

                match metadata {
                    Ok(meta) => {
                        let file_type = if meta.is_dir() { "d" }
                                       else if meta.is_symlink() { "l" }
                                       else { "-" };
                        let size = meta.len();
                        println!("{} {:>10} {}", file_type, size, path.display());
                    }
                    Err(e) => {
                        println!("? {:>10} {} (error: {})", "?", path.display(), e);
                    }
                }
            }
        }
        Err(e) => {
            println!("Failed to read /: {}", e);
        }
    }

    println!();

    // List subdirectories in root
    println!("=== Directory Listing: /*/ ===");
    if let Ok(entries) = fs::read_dir("/") {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_dir() {
                println!("\n--- {} ---", path.display());
                match fs::read_dir(&path) {
                    Ok(sub_entries) => {
                        let mut sub_paths: Vec<_> = sub_entries
                            .filter_map(|e| e.ok())
                            .take(10) // Limit to first 10 entries per directory
                            .collect();
                        sub_paths.sort_by_key(|e| e.path());

                        for sub_entry in sub_paths {
                            let sub_path = sub_entry.path();
                            let file_name = sub_path.file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("?");

                            if let Ok(meta) = sub_entry.metadata() {
                                let file_type = if meta.is_dir() { "d" }
                                               else if meta.is_symlink() { "l" }
                                               else { "-" };
                                println!("{} {:>10} {}", file_type, meta.len(), file_name);
                            } else {
                                println!("? {:>10} {}", "?", file_name);
                            }
                        }
                    }
                    Err(e) => {
                        println!("Failed to read: {}", e);
                    }
                }
            }
        }
    }

    println!();

    // Read and print stdin (request body)
    println!("=== Standard Input (Request Body) ===");
    let mut stdin_content = String::new();
    match io::stdin().read_to_string(&mut stdin_content) {
        Ok(bytes_read) => {
            println!("Bytes read: {}", bytes_read);
            if bytes_read > 0 {
                println!("Content:");
                println!("{}", stdin_content);
            } else {
                println!("(empty)");
            }
        }
        Err(e) => {
            eprintln!("Error reading stdin: {}", e);
        }
    }
}
