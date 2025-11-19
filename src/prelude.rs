use std::sync::Arc;
use tokio::sync::RwLock;

/// Type alias for Arc<RwLock<T>>, a common pattern for shared mutable state
pub type RwArc<T> = Arc<RwLock<T>>;

/// Macro to create a new SHA-256 hasher with optional data to hash
///
/// Usage:
/// - `sha256!()` - creates a new hasher
/// - `sha256!(data)` - creates a hasher and updates it with data
/// - `sha256!(data1, data2, ...)` - creates a hasher and updates it with multiple values
#[macro_export]
macro_rules! sha256 {
    () => {
        sha2::Sha256::new()
    };
    ($($data:expr),+ $(,)?) => {{
        let mut hasher = sha2::Sha256::new();
        $(
            hasher.update($data);
        )+
        hasher
    }};
}

/// Domain-separated SHA256 hash for cryptographic namespacing
///
/// Computes: H(domain || H(arg1 || arg2 || ...))
///
/// This prevents confusion between different hash purposes by prefixing
/// with a domain tag. The inner hash binds all context data together.
///
/// Usage:
/// ```ignore
/// let hash = sha256_namespaced!(
///     b"os402.task.stdout",
///     &server_owner,
///     &task_id,
///     &content_hash
/// );
/// ```
#[macro_export]
macro_rules! sha256_namespaced {
    ($domain:expr, $($data:expr),+ $(,)?) => {{
        use sha2::Digest;
        // First compute inner hash of all context/content data
        let mut inner = sha2::Sha256::new();
        $(
            inner.update($data);
        )+
        let inner_hash = inner.finalize();

        // Then compute outer hash with domain prefix
        let mut outer = sha2::Sha256::new();
        outer.update($domain);
        outer.update(&inner_hash);
        outer.finalize()
    }};
}

/// Parse a human-friendly size string into bytes.
///
/// Supports formats like:
/// - "1024" (plain bytes)
/// - "8kb" or "8KB" or "8k" (kilobytes)
/// - "2mb" or "2MB" or "2m" (megabytes)
/// - "1gb" or "1GB" or "1g" (gigabytes)
///
/// Returns the size in bytes as u64.
pub fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim().to_lowercase();

    // Find where digits end and suffix begins
    let (num_part, suffix) = if let Some(pos) = s.find(|c: char| !c.is_ascii_digit() && c != '.') {
        (&s[..pos], s[pos..].trim())
    } else {
        (s.as_str(), "")
    };

    let num: f64 = num_part.parse()
        .map_err(|_| format!("Invalid number: {}", num_part))?;

    let multiplier: u64 = match suffix {
        "" | "b" => 1,
        "k" | "kb" => 1024,
        "m" | "mb" => 1024 * 1024,
        "g" | "gb" => 1024 * 1024 * 1024,
        _ => return Err(format!("Unknown size suffix: {}. Use b, kb, mb, or gb", suffix)),
    };

    Ok((num * multiplier as f64) as u64)
}

/// Parse a human-friendly size string into kilobytes.
///
/// Same as parse_size but returns KB instead of bytes.
pub fn parse_size_kb(s: &str) -> Result<u32, String> {
    let bytes = parse_size(s)?;
    Ok((bytes / 1024) as u32)
}
