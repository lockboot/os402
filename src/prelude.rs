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
