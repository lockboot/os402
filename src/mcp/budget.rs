//! Budget tracking for MCP gateway
//!
//! Tracks spending limits per session and per call to prevent runaway costs.
//!
//! Supports both simple USD limits and granular per-token/network limits via MaxSpendLimit.

use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

use crate::x402::prefs::MaxSpendLimit;

// ============================================================================
// Budget Error
// ============================================================================

/// Errors that can occur during budget enforcement
#[derive(Debug, thiserror::Error)]
pub enum BudgetError {
    #[error("Session budget exceeded: spent ${spent:.6}, limit ${limit:.6}")]
    SessionLimitExceeded { spent: f64, limit: f64 },

    #[error("Per-call limit exceeded: ${amount:.6} > ${limit:.6}")]
    PerCallLimitExceeded { amount: f64, limit: f64 },

    #[error("Token session limit exceeded: {token} spent ${spent:.6}, limit ${limit:.6}")]
    TokenSessionLimitExceeded { token: String, spent: f64, limit: f64 },

    #[error("Token per-call limit exceeded: {token} ${amount:.6} > ${limit:.6}")]
    TokenPerCallLimitExceeded { token: String, amount: f64, limit: f64 },

    #[error("Token/network session limit exceeded: {token}@{network} spent ${spent:.6}, limit ${limit:.6}")]
    TokenNetworkSessionLimitExceeded { token: String, network: String, spent: f64, limit: f64 },

    #[error("Token/network per-call limit exceeded: {token}@{network} ${amount:.6} > ${limit:.6}")]
    TokenNetworkPerCallLimitExceeded { token: String, network: String, amount: f64, limit: f64 },
}

// ============================================================================
// Spending Record
// ============================================================================

/// Record of a single spending event
#[derive(Debug, Clone, Serialize)]
pub struct SpendingRecord {
    /// Unix timestamp of the spend
    pub timestamp: u64,

    /// Tool that incurred the spend
    pub tool_name: String,

    /// Amount spent in USD
    pub amount_usd: f64,

    /// Token used for payment (e.g., "USDC")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,

    /// Network used for payment (e.g., "base-sepolia")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,

    /// Backend URL that was called
    pub backend_url: String,

    /// Whether the call was successful
    pub success: bool,

    /// Optional transaction hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction: Option<String>,
}

// ============================================================================
// Session Budget
// ============================================================================

/// Thread-safe budget tracker for a gateway session
///
/// Uses atomic operations for the spend counter to avoid lock contention
/// on the critical path (checking if spend is allowed).
///
/// Supports both simple USD limits and granular per-token/network limits.
#[derive(Debug)]
pub struct SessionBudget {
    /// Global limit in micro-USD (1e-6 USD) for precision
    /// Extracted from MaxSpendLimit::Global or default
    limit_micro_usd: u64,

    /// Current spent amount in micro-USD (global across all tokens)
    spent_micro_usd: AtomicU64,

    /// Global per-call limit in micro-USD
    per_call_limit_micro_usd: u64,

    /// Session limits from --max (stored for per-token checking)
    session_limits: Vec<MaxSpendLimit>,

    /// Per-call limits from --per-call-max (stored for per-token checking)
    per_call_limits: Vec<MaxSpendLimit>,

    /// Spending per token (token -> micro-USD spent)
    spent_per_token: RwLock<HashMap<String, u64>>,

    /// Spending per token+network ((token, network) -> micro-USD spent)
    spent_per_token_network: RwLock<HashMap<(String, String), u64>>,

    /// Warning threshold as fraction (e.g., 0.8 = warn at 80%)
    warn_threshold: f64,

    /// Spending records for audit trail
    records: RwLock<Vec<SpendingRecord>>,

    /// Whether we've already emitted a warning
    warned: AtomicU64, // 0 = not warned, 1 = warned
}

/// Convert USD to micro-USD (millionths of a dollar)
fn usd_to_micro(usd: f64) -> u64 {
    (usd * 1_000_000.0) as u64
}

/// Convert micro-USD back to USD
fn micro_to_usd(micro: u64) -> f64 {
    micro as f64 / 1_000_000.0
}

impl SessionBudget {
    /// Create a budget tracker from MaxSpendLimit configurations
    ///
    /// Extracts global limits for fast checking and stores per-token limits
    /// for granular enforcement.
    ///
    /// # Arguments
    /// * `session_limits` - Session-level limits from --max
    /// * `per_call_limits` - Per-call limits from --per-call-max
    /// * `warn_at` - Fraction at which to emit a warning (0.0-1.0)
    pub fn from_limits(
        session_limits: Vec<MaxSpendLimit>,
        per_call_limits: Vec<MaxSpendLimit>,
        warn_at: f64,
    ) -> Self {
        // Extract global limits from the configurations
        let global_session = session_limits.iter()
            .find_map(|l| match l {
                MaxSpendLimit::Global { amount } => Some(*amount),
                _ => None,
            })
            .unwrap_or(f64::MAX); // No global limit = unlimited

        let global_per_call = per_call_limits.iter()
            .find_map(|l| match l {
                MaxSpendLimit::Global { amount } => Some(*amount),
                _ => None,
            })
            .unwrap_or(f64::MAX); // No global limit = unlimited

        Self {
            limit_micro_usd: usd_to_micro(global_session),
            spent_micro_usd: AtomicU64::new(0),
            per_call_limit_micro_usd: usd_to_micro(global_per_call),
            session_limits,
            per_call_limits,
            spent_per_token: RwLock::new(HashMap::new()),
            spent_per_token_network: RwLock::new(HashMap::new()),
            warn_threshold: warn_at.clamp(0.0, 1.0),
            records: RwLock::new(Vec::new()),
            warned: AtomicU64::new(0),
        }
    }

    /// Check if an amount is within budget
    ///
    /// This does NOT reserve or spend the amount - it only checks.
    /// Call `record_spend` after a successful payment.
    pub fn can_spend(&self, amount_usd: f64) -> Result<(), BudgetError> {
        let amount_micro = usd_to_micro(amount_usd);

        // Check per-call limit
        if amount_micro > self.per_call_limit_micro_usd {
            return Err(BudgetError::PerCallLimitExceeded {
                amount: amount_usd,
                limit: micro_to_usd(self.per_call_limit_micro_usd),
            });
        }

        // Check session limit
        let current_spent = self.spent_micro_usd.load(Ordering::Relaxed);
        if current_spent + amount_micro > self.limit_micro_usd {
            return Err(BudgetError::SessionLimitExceeded {
                spent: micro_to_usd(current_spent),
                limit: micro_to_usd(self.limit_micro_usd),
            });
        }

        Ok(())
    }

    /// Record a spending event
    ///
    /// This should be called after a successful payment to update the budget.
    /// Optionally includes token/network info for per-token tracking.
    pub async fn record_spend(
        &self,
        tool_name: &str,
        amount_usd: f64,
        backend_url: &str,
        success: bool,
        transaction: Option<String>,
    ) {
        self.record_spend_with_token(tool_name, amount_usd, None, None, backend_url, success, transaction).await;
    }

    /// Record a spending event with token/network information
    ///
    /// This enables per-token budget tracking and enforcement.
    pub async fn record_spend_with_token(
        &self,
        tool_name: &str,
        amount_usd: f64,
        token: Option<&str>,
        network: Option<&str>,
        backend_url: &str,
        success: bool,
        transaction: Option<String>,
    ) {
        let amount_micro = usd_to_micro(amount_usd);

        // Update global atomic counter
        self.spent_micro_usd.fetch_add(amount_micro, Ordering::Relaxed);

        // Update per-token tracking if token is specified
        if let Some(tok) = token {
            let mut per_token = self.spent_per_token.write().await;
            *per_token.entry(tok.to_string()).or_insert(0) += amount_micro;

            // Update per-token-network tracking if network is also specified
            if let Some(net) = network {
                let mut per_token_network = self.spent_per_token_network.write().await;
                *per_token_network.entry((tok.to_string(), net.to_string())).or_insert(0) += amount_micro;
            }
        }

        // Create spending record
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let record = SpendingRecord {
            timestamp,
            tool_name: tool_name.to_string(),
            amount_usd,
            token: token.map(String::from),
            network: network.map(String::from),
            backend_url: backend_url.to_string(),
            success,
            transaction,
        };

        // Add to records
        let mut records = self.records.write().await;
        records.push(record);
    }

    /// Check if a specific amount for a token/network is within limits
    ///
    /// This checks both global limits and per-token/network limits.
    pub async fn can_spend_token(
        &self,
        amount_usd: f64,
        token: &str,
        network: &str,
    ) -> Result<(), BudgetError> {
        // First check global limits
        self.can_spend(amount_usd)?;

        let amount_micro = usd_to_micro(amount_usd);

        // Check per-token session limits
        for limit in &self.session_limits {
            match limit {
                MaxSpendLimit::PerToken { token: limit_token, amount } if limit_token == token => {
                    let spent = self.spent_per_token.read().await;
                    let token_spent = spent.get(token).copied().unwrap_or(0);
                    let limit_micro = usd_to_micro(*amount);
                    if token_spent + amount_micro > limit_micro {
                        return Err(BudgetError::TokenSessionLimitExceeded {
                            token: token.to_string(),
                            spent: micro_to_usd(token_spent),
                            limit: *amount,
                        });
                    }
                }
                MaxSpendLimit::PerTokenNetwork { token: limit_token, network: limit_network, amount }
                    if limit_token == token && limit_network == network =>
                {
                    let spent = self.spent_per_token_network.read().await;
                    let key = (token.to_string(), network.to_string());
                    let tn_spent = spent.get(&key).copied().unwrap_or(0);
                    let limit_micro = usd_to_micro(*amount);
                    if tn_spent + amount_micro > limit_micro {
                        return Err(BudgetError::TokenNetworkSessionLimitExceeded {
                            token: token.to_string(),
                            network: network.to_string(),
                            spent: micro_to_usd(tn_spent),
                            limit: *amount,
                        });
                    }
                }
                _ => {}
            }
        }

        // Check per-token per-call limits
        for limit in &self.per_call_limits {
            match limit {
                MaxSpendLimit::PerToken { token: limit_token, amount } if limit_token == token => {
                    if amount_usd > *amount {
                        return Err(BudgetError::TokenPerCallLimitExceeded {
                            token: token.to_string(),
                            amount: amount_usd,
                            limit: *amount,
                        });
                    }
                }
                MaxSpendLimit::PerTokenNetwork { token: limit_token, network: limit_network, amount }
                    if limit_token == token && limit_network == network =>
                {
                    if amount_usd > *amount {
                        return Err(BudgetError::TokenNetworkPerCallLimitExceeded {
                            token: token.to_string(),
                            network: network.to_string(),
                            amount: amount_usd,
                            limit: *amount,
                        });
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Get current spending in USD
    pub fn spent_usd(&self) -> f64 {
        micro_to_usd(self.spent_micro_usd.load(Ordering::Relaxed))
    }

    /// Get remaining budget in USD
    pub fn remaining_usd(&self) -> f64 {
        let spent = self.spent_micro_usd.load(Ordering::Relaxed);
        micro_to_usd(self.limit_micro_usd.saturating_sub(spent))
    }

    /// Get session limit in USD
    pub fn limit_usd(&self) -> f64 {
        micro_to_usd(self.limit_micro_usd)
    }

    /// Get per-call limit in USD
    pub fn per_call_limit_usd(&self) -> f64 {
        micro_to_usd(self.per_call_limit_micro_usd)
    }

    /// Get spending for a specific token
    pub async fn spent_for_token(&self, token: &str) -> f64 {
        let spent = self.spent_per_token.read().await;
        micro_to_usd(spent.get(token).copied().unwrap_or(0))
    }

    /// Get spending for a specific token/network combination
    pub async fn spent_for_token_network(&self, token: &str, network: &str) -> f64 {
        let spent = self.spent_per_token_network.read().await;
        let key = (token.to_string(), network.to_string());
        micro_to_usd(spent.get(&key).copied().unwrap_or(0))
    }

    /// Check if we should emit a budget warning
    ///
    /// Returns true only once when crossing the threshold.
    pub fn should_warn(&self) -> bool {
        let spent = self.spent_micro_usd.load(Ordering::Relaxed);
        let threshold = (self.limit_micro_usd as f64 * self.warn_threshold) as u64;

        if spent >= threshold {
            // Try to set warned flag - only returns true if we're the first
            self.warned.compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed).is_ok()
        } else {
            false
        }
    }

    /// Get all spending records
    pub async fn get_records(&self) -> Vec<SpendingRecord> {
        self.records.read().await.clone()
    }

    /// Get summary statistics
    pub async fn summary(&self) -> BudgetSummary {
        let records = self.records.read().await;
        let successful_calls = records.iter().filter(|r| r.success).count();
        let failed_calls = records.iter().filter(|r| !r.success).count();

        BudgetSummary {
            spent_usd: self.spent_usd(),
            remaining_usd: self.remaining_usd(),
            limit_usd: self.limit_usd(),
            per_call_limit_usd: self.per_call_limit_usd(),
            total_calls: records.len(),
            successful_calls,
            failed_calls,
        }
    }
}

/// Budget summary for reporting
#[derive(Debug, Clone, Serialize)]
pub struct BudgetSummary {
    pub spent_usd: f64,
    pub remaining_usd: f64,
    pub limit_usd: f64,
    pub per_call_limit_usd: f64,
    pub total_calls: usize,
    pub successful_calls: usize,
    pub failed_calls: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a budget with simple global limits
    fn budget(limit: f64, per_call: f64, warn_at: f64) -> SessionBudget {
        SessionBudget::from_limits(
            vec![MaxSpendLimit::Global { amount: limit }],
            vec![MaxSpendLimit::Global { amount: per_call }],
            warn_at,
        )
    }

    #[tokio::test]
    async fn test_basic_budget() {
        let budget = budget(10.0, 1.0, 0.8);

        // Should be able to spend within limits
        assert!(budget.can_spend(0.5).is_ok());
        assert!(budget.can_spend(1.0).is_ok());

        // Should reject over per-call limit
        assert!(matches!(
            budget.can_spend(1.5),
            Err(BudgetError::PerCallLimitExceeded { .. })
        ));
    }

    #[tokio::test]
    async fn test_session_limit() {
        let budget = budget(1.0, 0.5, 0.8);

        // Spend some
        budget.record_spend("test", 0.4, "http://example.com", true, None).await;
        budget.record_spend("test", 0.4, "http://example.com", true, None).await;

        // Now we've spent 0.8, remaining is 0.2
        assert!((budget.spent_usd() - 0.8).abs() < 0.0001);
        assert!((budget.remaining_usd() - 0.2).abs() < 0.0001);

        // Should reject 0.3 (would exceed session limit)
        assert!(matches!(
            budget.can_spend(0.3),
            Err(BudgetError::SessionLimitExceeded { .. })
        ));

        // But 0.1 should be fine
        assert!(budget.can_spend(0.1).is_ok());
    }

    #[tokio::test]
    async fn test_warning_threshold() {
        let budget = budget(10.0, 5.0, 0.8);

        // Spend below threshold
        budget.record_spend("test", 7.0, "http://example.com", true, None).await;
        assert!(!budget.should_warn()); // 70% < 80%

        // Cross threshold
        budget.record_spend("test", 1.5, "http://example.com", true, None).await;
        assert!(budget.should_warn()); // 85% >= 80%, returns true first time

        // Second call should return false
        assert!(!budget.should_warn());
    }

    #[tokio::test]
    async fn test_summary() {
        let budget = budget(10.0, 1.0, 0.8);

        budget.record_spend("tool1", 0.5, "http://a.com", true, None).await;
        budget.record_spend("tool2", 0.3, "http://b.com", false, None).await;
        budget.record_spend("tool1", 0.2, "http://a.com", true, None).await;

        let summary = budget.summary().await;
        assert_eq!(summary.total_calls, 3);
        assert_eq!(summary.successful_calls, 2);
        assert_eq!(summary.failed_calls, 1);
        assert!((summary.spent_usd - 1.0).abs() < 0.0001);
    }

    #[tokio::test]
    async fn test_from_limits() {
        let session_limits = vec![
            MaxSpendLimit::Global { amount: 10.0 },
            MaxSpendLimit::PerToken { token: "USDC".to_string(), amount: 5.0 },
        ];
        let per_call_limits = vec![
            MaxSpendLimit::Global { amount: 1.0 },
            MaxSpendLimit::PerToken { token: "USDC".to_string(), amount: 0.5 },
        ];

        let budget = SessionBudget::from_limits(session_limits, per_call_limits, 0.8);

        // Global limits should work
        assert!(budget.can_spend(0.5).is_ok());
        assert!(budget.can_spend(1.0).is_ok());
        assert!(matches!(
            budget.can_spend(1.5),
            Err(BudgetError::PerCallLimitExceeded { .. })
        ));
    }

    #[tokio::test]
    async fn test_per_token_limits() {
        let session_limits = vec![
            MaxSpendLimit::Global { amount: 10.0 },
            MaxSpendLimit::PerToken { token: "USDC".to_string(), amount: 1.0 },
        ];
        let per_call_limits = vec![
            MaxSpendLimit::Global { amount: 2.0 },
            MaxSpendLimit::PerToken { token: "USDC".to_string(), amount: 0.5 },
        ];

        let budget = SessionBudget::from_limits(session_limits, per_call_limits, 0.8);

        // Should allow $0.3 for USDC (under per-call limit of $0.5)
        assert!(budget.can_spend_token(0.3, "USDC", "base").await.is_ok());

        // Should reject $0.6 for USDC (over per-call limit of $0.5)
        assert!(matches!(
            budget.can_spend_token(0.6, "USDC", "base").await,
            Err(BudgetError::TokenPerCallLimitExceeded { .. })
        ));

        // Record some USDC spending
        budget.record_spend_with_token("test", 0.4, Some("USDC"), Some("base"), "http://x.com", true, None).await;
        budget.record_spend_with_token("test", 0.4, Some("USDC"), Some("base"), "http://x.com", true, None).await;

        // Now USDC is at $0.8, session limit is $1.0, so $0.3 should fail
        assert!(matches!(
            budget.can_spend_token(0.3, "USDC", "base").await,
            Err(BudgetError::TokenSessionLimitExceeded { .. })
        ));

        // But $0.1 should be OK (0.8 + 0.1 = 0.9 < 1.0)
        assert!(budget.can_spend_token(0.1, "USDC", "base").await.is_ok());

        // Different token (USDT) should have no per-token limit
        assert!(budget.can_spend_token(1.5, "USDT", "base").await.is_ok());
    }

    #[tokio::test]
    async fn test_per_token_tracking() {
        let budget = budget(10.0, 5.0, 0.8);

        budget.record_spend_with_token("test", 1.0, Some("USDC"), Some("base"), "http://x.com", true, None).await;
        budget.record_spend_with_token("test", 2.0, Some("USDC"), Some("ethereum"), "http://x.com", true, None).await;
        budget.record_spend_with_token("test", 0.5, Some("USDT"), Some("base"), "http://x.com", true, None).await;

        // Check token spending
        assert!((budget.spent_for_token("USDC").await - 3.0).abs() < 0.0001);
        assert!((budget.spent_for_token("USDT").await - 0.5).abs() < 0.0001);

        // Check token+network spending
        assert!((budget.spent_for_token_network("USDC", "base").await - 1.0).abs() < 0.0001);
        assert!((budget.spent_for_token_network("USDC", "ethereum").await - 2.0).abs() < 0.0001);

        // Global total
        assert!((budget.spent_usd() - 3.5).abs() < 0.0001);
    }
}
