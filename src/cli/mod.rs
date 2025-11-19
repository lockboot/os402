pub mod config;
pub mod curl;
pub mod key;
pub mod mcp;
pub mod pay;
pub mod run;
pub mod sandbox;
pub mod offer;
pub mod shared;
pub mod task;

pub use shared::{run_shared, SharedCommands};

/// Get version string with build details
pub fn version(name: &str) -> String {
    let build_type = if cfg!(debug_assertions) { "debug" } else { "release" };
    let panic_mode = if cfg!(panic = "abort") { "panic=abort" } else { "panic=unwind" };
    let link_mode = if cfg!(target_feature = "crt-static") { "static" } else { "dynamic" };
    let target_env = if cfg!(target_env = "gnu") { "gnu" }
        else if cfg!(target_env = "musl") { "musl" }
        else if cfg!(target_env = "msvc") { "msvc" }
        else { "unknown" };

    format!("{} {} {} {} {} {} {} {}",
        name,
        env!("CARGO_PKG_VERSION"),
        std::env::consts::ARCH,
        std::env::consts::OS,
        target_env,
        link_mode,
        build_type,
        panic_mode,
    )
}
