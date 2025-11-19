//! Background cleanup task for expired offers and orphaned executables.
//!
//! This module provides automatic garbage collection for:
//! - Expired offers (where `valid_until < now`)
//! - Associated secrets and name mappings
//! - Orphaned executables (no longer referenced by any offer)

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use crate::os::ExecutableRef;
use super::AppState;

/// Run the cleanup loop indefinitely
///
/// This task periodically removes:
/// 1. Expired offers
/// 2. Associated secrets and name mappings
/// 3. Executables with zero references
pub async fn cleanup_loop(state: AppState, interval: Duration) {
    loop {
        tokio::time::sleep(interval).await;
        cleanup_expired(&state).await;
    }
}

/// Perform a single cleanup sweep
async fn cleanup_expired(state: &AppState) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // 1. Find expired offers
    let expired_offer_hashes: Vec<String> = {
        let offers = state.offers.read().await;
        offers.iter()
            .filter(|(_, offer)| offer.payload.valid_until < now)
            .map(|(hash, _)| hash.clone())
            .collect()
    };

    if expired_offer_hashes.is_empty() {
        return;
    }

    // 2. Remove expired offers and collect executable hashes to decrement
    let mut exe_hashes_to_decrement: Vec<String> = Vec::new();

    for offer_hash in &expired_offer_hashes {
        // Remove offer and collect its executable references
        if let Some(offer) = state.offers.write().await.remove(offer_hash) {
            // Collect all executable hashes this offer references
            for (_, exe_info) in &offer.payload.stage2.variants {
                exe_hashes_to_decrement.push(exe_info.sha256.clone());
            }

            // Remove associated secrets
            state.offer_secrets.write().await.remove(offer_hash);

            // Remove name mapping only if it still points to this offer
            // (a newer offer with the same name might have been uploaded)
            if let Some(name) = &offer.payload.name {
                let mut offers_by_name = state.offers_by_name.write().await;
                if offers_by_name.get(name) == Some(offer_hash) {
                    offers_by_name.remove(name);
                }
            }
        }
    }

    // 3. Decrement reference counts and identify orphaned executables
    let orphaned_exe_hashes: Vec<String> = {
        let mut refs = state.executable_refs.write().await;
        let mut orphaned = Vec::new();

        for hash in &exe_hashes_to_decrement {
            if let Some(count) = refs.get_mut(hash) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    orphaned.push(hash.clone());
                    refs.remove(hash);
                }
            }
        }
        orphaned
    };

    // 4. Remove orphaned executables
    if !orphaned_exe_hashes.is_empty() {
        let mut exes = state.executables.write().await;
        for hash in &orphaned_exe_hashes {
            if let Some(exe_ref) = exes.remove(hash) {
                // If it's a file, delete it from disk
                if let ExecutableRef::File(path) = exe_ref {
                    if let Err(e) = std::fs::remove_file(&path) {
                        tracing::warn!(path = ?path, error = %e, "Failed to delete cached executable");
                    } else {
                        tracing::debug!(sha256 = %hash, path = ?path, "Deleted orphaned executable file");
                    }
                } else {
                    tracing::debug!(sha256 = %hash, "Removed orphaned executable (memfd)");
                }
            }
        }
    }

    // Log details at debug level
    for offer_hash in &expired_offer_hashes {
        tracing::debug!(offer_hash = %offer_hash, "Removed expired offer");
    }

    tracing::info!(
        expired_offers = expired_offer_hashes.len(),
        orphaned_executables = orphaned_exe_hashes.len(),
        "Cleanup completed"
    );
}
