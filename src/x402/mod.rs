//! x402 payment protocol integration
//!
//! This module contains all x402-related functionality including:
//! - Payment middleware for HTTP clients
//! - Payment gate for HTTP servers
//! - Payment preferences and limits
//! - Client builder utilities

pub mod client;
pub mod middleware;
pub mod paygate;
pub mod payment_page;
pub mod prefs;
pub mod auth;
pub mod headers;

pub mod facilitator;
pub mod layer;
pub mod timestamp;
pub mod types;

pub use facilitator::{Facilitator, FacilitatorClient};
pub use layer::X402Paygate;
pub use timestamp::UnixTimestamp;
pub use types::{
    MixedAddress, MixedAddressError, MoneyAmount, PaymentPayload, PaymentRequirements,
    PaymentSignError, TokenAsset, TokenDeployment, TokenDeploymentEip712, PriceTag,
};

pub use client::{
    ClientConfig, InstanceArgs, KeyArgs, x402_client,
    // Re-exported from crate::config
    GlobalConfig,
};
pub use prefs::PaymentArgs;
pub use auth::OwnerExemptFacilitator;
pub use paygate::Paygate;
pub use middleware::{X402PaymentInfo, X402_PAYMENT_INFO_HEADER};
