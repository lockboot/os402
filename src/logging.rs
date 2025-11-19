//! Tracing/logging configuration for os402
//!
//! Supports:
//! - Multiple verbosity levels: default (WARN), verbose (INFO), quiet (ERROR), silent (off)
//! - Pretty (colored) or JSON output formats
//! - File logging at DEBUG level while terminal shows configured level

use std::path::PathBuf;
use std::sync::OnceLock;

use tracing::Level;
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
    Layer, Registry,
};

/// Log output format
#[derive(Clone, Debug, Default, clap::ValueEnum, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Colored human-readable output
    #[default]
    Pretty,
    /// Structured JSON output (one JSON object per line)
    Json,
    /// Compact single-line format
    Compact,
}

/// Tracing configuration built from CLI args
pub struct TracingConfig {
    /// Verbose mode (INFO level)
    pub verbose: bool,
    /// Debug mode (DEBUG level)
    pub debug: bool,
    /// Quiet mode (ERROR only)
    pub quiet: bool,
    /// Silent mode (no terminal output)
    pub silent: bool,
    /// Output format
    pub format: LogFormat,
    /// Optional log file path (writes DEBUG+ regardless of terminal level)
    pub log_file: Option<PathBuf>,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            verbose: false,
            debug: false,
            quiet: false,
            silent: false,
            format: LogFormat::Pretty,
            log_file: None,
        }
    }
}

/// Global flag to track if tracing has been initialized
static TRACING_INITIALIZED: OnceLock<()> = OnceLock::new();

/// Boxed layer type alias for Registry
type BoxedLayer = Box<dyn Layer<Registry> + Send + Sync + 'static>;

/// Create a boxed terminal layer with the given format and filter
fn make_terminal_layer(format: &LogFormat, filter: EnvFilter) -> BoxedLayer {
    match format {
        LogFormat::Pretty => fmt::layer()
            .with_ansi(true)
            .with_target(false)
            .with_thread_ids(false)
            .with_file(false)
            .with_line_number(false)
            .with_writer(std::io::stderr)
            .with_filter(filter)
            .boxed(),
        LogFormat::Json => fmt::layer()
            .json()
            .with_writer(std::io::stderr)
            .with_filter(filter)
            .boxed(),
        LogFormat::Compact => fmt::layer()
            .compact()
            .with_writer(std::io::stderr)
            .with_filter(filter)
            .boxed(),
    }
}

/// Initialize tracing with the given configuration.
///
/// This should be called early in main() after CLI args are parsed.
/// If called multiple times, subsequent calls are ignored.
pub fn init_tracing(config: TracingConfig) {
    // Only initialize once
    if TRACING_INITIALIZED.get().is_some() {
        return;
    }

    // Determine terminal log level
    // In release builds, DEBUG/TRACE are compiled out (release_max_level_info),
    // so clamp to INFO to avoid tracing-subscriber warnings
    let terminal_level = if config.silent {
        None
    } else if config.quiet {
        Some(Level::ERROR)
    } else if config.debug {
        if cfg!(debug_assertions) {
            Some(Level::DEBUG)
        } else {
            Some(Level::INFO) // DEBUG compiled out in release
        }
    } else if config.verbose {
        Some(Level::INFO)
    } else {
        Some(Level::WARN)
    };

    // Build env filter - CLI args take precedence over RUST_LOG
    let make_filter = |level: Level, cli_specified: bool| {
        if cli_specified {
            // CLI args were explicitly set - use them, ignore RUST_LOG
            EnvFilter::new(format!("os402={},warn", level.as_str().to_lowercase()))
        } else {
            // No CLI args - fall back to RUST_LOG if set, otherwise use default level
            EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                EnvFilter::new(format!("os402={},warn", level.as_str().to_lowercase()))
            })
        }
    };

    // Check if any CLI logging flag was explicitly set
    let cli_log_level_specified = config.verbose || config.debug || config.quiet || config.silent;

    // Collect layers into a Vec so we can add them all at once
    let mut layers: Vec<BoxedLayer> = Vec::new();

    // Handle file logging if configured
    if let Some(log_path) = &config.log_file {
        // Create file for debug logging
        let file = match std::fs::File::create(log_path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("Warning: Failed to create log file {:?}: {}", log_path, e);
                // Fall through to terminal-only logging
                init_terminal_only(terminal_level, &config.format, cli_log_level_specified);
                let _ = TRACING_INITIALIZED.set(());
                return;
            }
        };

        // In release builds, debug is compiled out (release_max_level_info), so use info
        let file_filter = if cfg!(debug_assertions) {
            EnvFilter::new("os402=debug,warn")
        } else {
            EnvFilter::new("os402=info,warn")
        };

        // File layer - max available level (debug in dev, info in release), no ANSI colors
        let file_layer: BoxedLayer = fmt::layer()
            .with_ansi(false)
            .with_target(true)
            .with_thread_ids(false)
            .with_file(true)
            .with_line_number(true)
            .with_span_events(FmtSpan::CLOSE)
            .with_writer(file)
            .with_filter(file_filter)
            .boxed();

        layers.push(file_layer);
    }

    // Add terminal layer if not silent
    if let Some(level) = terminal_level {
        let terminal_filter = make_filter(level, cli_log_level_specified);
        let terminal_layer = make_terminal_layer(&config.format, terminal_filter);
        layers.push(terminal_layer);
    }

    // Initialize with all layers
    if layers.is_empty() {
        // Silent mode with no file - install a no-op subscriber
        let subscriber = tracing_subscriber::registry();
        let _ = tracing::subscriber::set_global_default(subscriber);
    } else {
        tracing_subscriber::registry()
            .with(layers)
            .init();
    }

    let _ = TRACING_INITIALIZED.set(());
}

/// Initialize terminal-only logging (fallback when log file creation fails)
fn init_terminal_only(level: Option<Level>, format: &LogFormat, cli_specified: bool) {
    let Some(level) = level else {
        // Silent mode - install a no-op subscriber
        let subscriber = tracing_subscriber::registry();
        let _ = tracing::subscriber::set_global_default(subscriber);
        return;
    };

    let filter = if cli_specified {
        // CLI args were explicitly set - use them, ignore RUST_LOG
        EnvFilter::new(format!("os402={},warn", level.as_str().to_lowercase()))
    } else {
        // No CLI args - fall back to RUST_LOG if set, otherwise use default level
        EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            EnvFilter::new(format!("os402={},warn", level.as_str().to_lowercase()))
        })
    };

    match format {
        LogFormat::Pretty => {
            tracing_subscriber::fmt()
                .with_ansi(true)
                .with_target(false)
                .with_thread_ids(false)
                .with_file(false)
                .with_line_number(false)
                .with_writer(std::io::stderr)
                .with_env_filter(filter)
                .init();
        }
        LogFormat::Json => {
            tracing_subscriber::fmt()
                .json()
                .with_writer(std::io::stderr)
                .with_env_filter(filter)
                .init();
        }
        LogFormat::Compact => {
            tracing_subscriber::fmt()
                .compact()
                .with_writer(std::io::stderr)
                .with_env_filter(filter)
                .init();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_format_default() {
        let format = LogFormat::default();
        assert!(matches!(format, LogFormat::Pretty));
    }

    #[test]
    fn test_tracing_config_default() {
        let config = TracingConfig::default();
        assert!(!config.verbose);
        assert!(!config.debug);
        assert!(!config.quiet);
        assert!(!config.silent);
        assert!(config.log_file.is_none());
    }
}
