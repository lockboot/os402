//! Offer business logic
//!
//! This module contains pure business logic for working with offers,
//! separate from HTTP handlers. Functions return anyhow::Result for
//! better composability and error handling.

use std::{collections::HashMap, sync::Arc};

use anyhow::{Result, bail};

use crate::os::{TaskInput, TaskSecrets};

use super::{SignedOffer, AppState, Stage2Config};

/// Validate task duration against offer requirements
pub fn validate_duration(
    num_seconds: u32,
    min_duration: u32,
    max_duration: Option<u32>
) -> Result<()> {
    if num_seconds < min_duration {
        bail!(
            "Duration {} seconds is below the minimum of {} seconds",
            num_seconds, min_duration
        );
    }

    if let Some(md) = max_duration {
        if num_seconds > md {
            bail!(
                "Duration {} seconds is above the maximum of {} seconds",
                num_seconds, md
            );
        }
    }

    Ok(())
}

/// Apply offer restrictions to user-provided args, env, and stdin
///
/// If args_extendable: offer args are used as prefix, user args are appended
/// If !args_extendable: only offer args are used, user args are ignored
///
/// If env_extendable: offer env is used as base, user env can override/extend
/// If !env_extendable: only offer env is used, user env is ignored
///
/// If stdin_appendable: offer stdin is used as prefix, user stdin is appended
/// If !stdin_appendable: only offer stdin is used, user stdin is ignored
pub fn apply_offer_restrictions(
    stage2: &Stage2Config,
    //signed_offer: &SignedOffer,
    user_args: Vec<String>,
    user_env: HashMap<String, String>,
    user_stdin: Vec<u8>,
) -> (Vec<String>, HashMap<String, String>, Vec<u8>) {
    // Handle args
    let final_args = if stage2.args_extendable {
        // Extendable: start with offer args (if any), then append user args
        let mut args = stage2.args.clone().unwrap_or_default();
        args.extend(user_args);
        args
    } else {
        // Not extendable: use only offer args, ignore user args
        stage2.args.clone().unwrap_or_default()
    };

    // Handle env
    let final_env = if stage2.env_extendable {
        // Extendable: start with user env, then overlay offer env (offer has priority)
        // This ensures offer-defined env vars cannot be overridden by users
        let mut env = user_env;
        env.extend(stage2.env.clone().unwrap_or_default());
        env
    } else {
        // Not extendable: use only offer env, ignore user env
        stage2.env.clone().unwrap_or_default()
    };

    // Handle stdin (binary-safe)
    let final_stdin = if stage2.stdin_appendable {
        // Appendable: start with offer stdin (if any), then append user stdin
        let mut stdin = stage2.stdin.clone().unwrap_or_default();
        stdin.extend(user_stdin);
        stdin
    } else {
        // Not appendable: use only offer stdin, ignore user stdin
        stage2.stdin.clone().unwrap_or_default()
    };

    (final_args, final_env, final_stdin)
}

/// Prepare TaskInput and TaskSecrets for execution
///
/// This function:
/// 1. Applies offer restrictions (merges user input with offer config from Stage2)
/// 2. Loads private secrets from server storage into TaskSecrets
/// 3. Returns TaskInput (public data) and TaskSecrets (private data) separately
///
/// IMPORTANT: Private secrets are NOT merged into TaskInput to prevent leakage.
/// The merge happens at execution time in TaskManager::execute().
pub async fn prepare_task_input(
    state: &AppState,
    signed_offer: &Arc<SignedOffer>,
    user_args: Vec<String>,
    user_env: HashMap<String, String>,
    user_stdin: Vec<u8>,
) -> Result<(TaskInput, TaskSecrets)> {
    // Apply offer restrictions (merge args, env, and stdin based on extendable flags)
    // This only merges public data from Stage2Config, NOT private secrets
    let (final_args, final_env, final_stdin) = apply_offer_restrictions(
        &signed_offer.payload.stage2,
        user_args,
        user_env,
        user_stdin,
    );

    // Load private env and stdin from server storage if they exist for this offer
    let task_secrets = {
        let secrets_map = state.offer_secrets.read().await;
        secrets_map.get(&signed_offer.sha256).cloned()
            .unwrap_or_else(|| TaskSecrets {
                env: None,
                stdin: None,
            })
    };

    // Create TaskInput with public data only (owner-agnostic for content-addressable caching)
    // Private secrets remain in TaskSecrets and are merged at execution time
    let task_input = TaskInput {
        stdin: final_stdin,
        args: final_args,
        env: final_env.into_iter().collect(),
    };

    Ok((task_input, task_secrets))
}
