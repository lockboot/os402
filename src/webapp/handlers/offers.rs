use std::collections::HashMap;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use axum::{
    extract::{Multipart, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use memfd::{MemfdOptions, FileSeal};
use serde::Serialize;
use utoipa::ToSchema;
use sha2::Digest;

use super::super::{
    Offer, SignedOffer, AppState, ErrorResponse,
    error_bad_request, error_forbidden, error_not_found, error_internal
};
use crate::os::ExecutableRef;
use crate::sha256;

/// Fetch an executable from URL and verify its SHA256 hash
async fn fetch_executable(url: &str, expected_sha256: &str) -> Result<Vec<u8>, String> {
    let client = reqwest::Client::new();

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch {}: {}", url, e))?;

    if !response.status().is_success() {
        return Err(format!("HTTP {} fetching {}", response.status(), url));
    }

    let data = response
        .bytes()
        .await
        .map_err(|e| format!("Failed to read response from {}: {}", url, e))?
        .to_vec();

    // Verify SHA256
    let computed = hex::encode(sha256!(&data).finalize());
    if computed != expected_sha256 {
        return Err(format!(
            "SHA256 mismatch for {}: expected {}, got {}",
            url, expected_sha256, computed
        ));
    }

    Ok(data)
}

// Helper macro: Verify SHA256 hash of uploaded data
macro_rules! verify_sha256 {
    ($data:expr, $expected:expr, $field_name:expr) => {
        {
            let computed = hex::encode(sha256!($data).finalize());

            match $expected {
                Some(expected) if computed != *expected => {
                    return error_bad_request(
                        &format!("{} SHA256 mismatch: expected {}, got {}", $field_name, expected, computed));
                }
                None => {
                    return error_bad_request(
                        &format!("{} uploaded but offer does not specify {}_sha256", $field_name, $field_name));
                }
                Some(_) => {} // Valid
            }
        }
    };
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ListOffersResponse {
    pub offers: HashMap<String, Offer>,
    pub count: usize,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UploadOfferResponse {
    pub status: String,
    pub offer_hash: String,
    pub expires_at: u64,
}

/// List all valid offers
#[utoipa::path(
    get,
    tag = "Offers",
    path = "/offers",
    responses(
        (status = 200, description = "List of valid offers", body = ListOffersResponse)
    )
)]
pub async fn list_offers_handler(State(state): State<AppState>) -> impl IntoResponse {
    let offers = state.offers.read().await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let valid_offers: HashMap<String, Offer> = offers
        .iter()
        .filter(|(_, signed_offer)| signed_offer.payload.valid_until > now)
        .map(|(hash, signed_offer)| (hash.clone(), signed_offer.payload.clone()))
        .collect();

    let count = valid_offers.len();

    Json(ListOffersResponse {
        offers: valid_offers,
        count,
    })
}

/// Upload a new signed offer with optional executables (multipart form data)
///
/// Requires multipart/form-data with:
/// - `config` part: JSON containing the signed offer
/// - `exe_{arch}` parts: optional executable binaries (e.g., exe_aarch64, exe_x86_64)
///
/// Executables are only uploaded if they don't already exist on the server.
/// Use HEAD /{sha256}.exe to check existence before uploading.
#[utoipa::path(
    put,
    tag = "Offers",
    path = "/{offer_hash}",
    params(
        ("offer_hash" = String, Path, description = "Hash of the offer")
    ),
    request_body = SignedOffer,
    responses(
        (status = 201, description = "Offer accepted", body = UploadOfferResponse),
        (status = 400, description = "Bad request - offer expired or invalid", body = ErrorResponse),
        (status = 403, description = "Forbidden - owner mismatch", body = ErrorResponse)
    )
)]
pub async fn upload_offer_handler(
    State(state): State<AppState>,
    Path(offer_hash): Path<String>,
    mut multipart: Multipart,
) -> Response {
    // First, process the config field
    let signed_offer = loop {
        match multipart.next_field().await {
            Ok(Some(field)) => {
                let name = field.name().unwrap_or("").to_string();
                if name == "config" {
                    // Parse the signed offer JSON
                    let data = match field.bytes().await {
                        Ok(bytes) => bytes,
                        Err(e) => return error_bad_request(&format!("Failed to read config: {}", e)),
                    };
                    let signed_offer: SignedOffer = match serde_json::from_slice(&data) {
                        Ok(so) => so,
                        Err(e) => return error_bad_request(&format!("Failed to parse config JSON: {}", e)),
                    };
                    // Validate the signature and recover the offer
                    let validated_offer = match signed_offer.validate() {
                        Ok(validated_offer) => validated_offer,
                        Err(e) => return error_bad_request(&format!("Invalid signature: {}", e)),
                    };
                    // Verify the offer owner matches the server owner
                    if validated_offer.owner.to_ascii_lowercase() != state.owner.to_string().to_ascii_lowercase() {
                        return error_forbidden("Offer owner does not match server owner");
                    }
                    break signed_offer;
                } else {
                    return error_bad_request("Config field must be sent first for signature verification");
                }
            },
            Ok(None) => return error_bad_request("No config field provided"),
            Err(e) => return error_bad_request(&format!("Failed to parse multipart: {}", e)),
        }
    };

    let offer = &signed_offer.payload;
    let stage2 = &offer.stage2;
    let mut executables_to_store: HashMap<String, ExecutableRef> = HashMap::new();
    let mut uploaded_env: Option<Vec<u8>> = None;
    let mut uploaded_stdin: Option<Vec<u8>> = None;

    loop {
        match multipart.next_field().await {
            Ok(Some(field)) => {
                let name = field.name().unwrap_or("").to_string();
                if name == "stdin" {
                    let data = match field.bytes().await {
                        Ok(bytes) => bytes,
                        Err(e) => return error_bad_request(&format!("Failed to read stdin: {}", e)),
                    };
                    verify_sha256!(&data, stage2.stdin_sha256.as_ref(), "stdin");
                    uploaded_stdin = Some(data.to_vec());
                }
                else if name == "env" {
                    let data = match field.bytes().await {
                        Ok(bytes) => bytes,
                        Err(e) => return error_bad_request(&format!("Failed to read env: {}", e)),
                    };
                    verify_sha256!(&data, stage2.env_sha256.as_ref(), "env");
                    uploaded_env = Some(data.to_vec());
                }
                else if name.starts_with("exe_") {
                    let arch = name.strip_prefix("exe_").unwrap_or("");

                    // Verify the architecture is declared in the offer
                    if !stage2.variants.contains_key(arch) {
                        return error_bad_request(&format!(
                            "Executable for architecture '{}' is not declared in offer. Valid architectures: {}",
                            arch,
                            stage2.variants.keys().map(|k| k.as_str()).collect::<Vec<_>>().join(", ")
                        ));
                    }

                    let data = match field.bytes().await {
                        Ok(bytes) => bytes.to_vec(),
                        Err(e) => return error_bad_request(&format!("Failed to read executable for {}: {}", arch, e)),
                    };

                    // Compute SHA256 and verify it matches the offer
                    let sha256 = hex::encode(sha256!(&data).finalize());
                    let expected_sha256 = &stage2.variants.get(arch).unwrap().sha256;
                    if &sha256 != expected_sha256 {
                        return error_bad_request(&format!(
                            "Executable SHA256 mismatch for architecture '{}': expected {}, got {}",
                            arch, expected_sha256, sha256
                        ));
                    }

                    // Store executable: direct to disk if cache_dir is set, otherwise use memfd
                    let exe_ref = if let Some(cache_dir) = &state.exec_cache_dir {
                        // Direct-to-disk mode: write to content-addressed file
                        let filename = format!("{}.{}", sha256, arch);
                        let path = cache_dir.join(&filename);

                        // Only write if file doesn't exist (content-addressed)
                        if !path.exists() {
                            // Atomic write: temp file -> rename
                            let temp_path = cache_dir.join(format!(".{}.tmp", filename));
                            if let Err(e) = std::fs::write(&temp_path, &data) {
                                return error_internal(&format!(
                                    "Failed to write executable to cache for {}: {}", arch, e));
                            }
                            if let Err(e) = std::fs::set_permissions(&temp_path,
                                std::fs::Permissions::from_mode(0o755)) {
                                return error_internal(&format!(
                                    "Failed to set executable permissions for {}: {}", arch, e));
                            }
                            if let Err(e) = std::fs::rename(&temp_path, &path) {
                                return error_internal(&format!(
                                    "Failed to rename executable for {}: {}", arch, e));
                            }
                        }
                        ExecutableRef::File(path)
                    } else {
                        // Memfd mode: create sealed in-memory file
                        let opts = MemfdOptions::default().allow_sealing(true);
                        let memfd = match opts.create(&sha256) {
                            Ok(mfd) => mfd,
                            Err(e) => return error_internal(&format!("Failed to create memfd for {}: {}", arch, e)),
                        };
                        if let Err(e) = memfd.as_file().write_all(&data) {
                            return error_internal(&format!("Failed to write executable to memfd for {}: {}", arch, e));
                        }
                        if let Err(e) = memfd.add_seals(&[FileSeal::SealShrink, FileSeal::SealGrow, FileSeal::SealWrite]) {
                            return error_internal(&format!("Failed to seal memfd for {}: {}", arch, e));
                        }
                        ExecutableRef::Memfd(Arc::new(memfd))
                    };

                    executables_to_store.insert(sha256, exe_ref);
                }
                else if name == "config" {
                    return error_bad_request("Config field must be sent first, not after other fields");
                }
                else {
                    return error_bad_request(&format!("Unsupported field: '{}'. Supported fields are: config, stdin, env, exe_<arch>", name));
                }
            },
            Ok(None) => break,
            Err(e) => return error_bad_request(&format!("Failed to parse multipart: {}", e)),
        }
    }

    // Verify that all executables referenced in the offer are either uploaded, already exist,
    // or can be fetched from a URL specified in the offer
    for (arch, exe_info) in &stage2.variants {
        let exe_exists = {
            let executables = state.executables.read().await;
            executables.contains_key(&exe_info.sha256) || executables_to_store.contains_key(&exe_info.sha256)
        };
        if !exe_exists {
            // Try to fetch from URL if specified
            if let Some(url) = &exe_info.url {
                let data = match fetch_executable(url, &exe_info.sha256).await {
                    Ok(data) => data,
                    Err(e) => return error_bad_request(&format!(
                        "Executable for architecture '{}' not available and fetch failed: {}",
                        arch, e)),
                };

                // Store the fetched executable
                let exe_ref = if let Some(cache_dir) = &state.exec_cache_dir {
                    // Direct-to-disk mode
                    let filename = format!("{}.{}", exe_info.sha256, arch);
                    let path = cache_dir.join(&filename);

                    if !path.exists() {
                        let temp_path = cache_dir.join(format!(".{}.tmp", filename));
                        if let Err(e) = std::fs::write(&temp_path, &data) {
                            return error_internal(&format!(
                                "Failed to write fetched executable for {}: {}", arch, e));
                        }
                        if let Err(e) = std::fs::set_permissions(&temp_path,
                            std::fs::Permissions::from_mode(0o755)) {
                            return error_internal(&format!(
                                "Failed to set executable permissions for {}: {}", arch, e));
                        }
                        if let Err(e) = std::fs::rename(&temp_path, &path) {
                            return error_internal(&format!(
                                "Failed to rename fetched executable for {}: {}", arch, e));
                        }
                    }
                    ExecutableRef::File(path)
                } else {
                    // Memfd mode
                    let opts = MemfdOptions::default().allow_sealing(true);
                    let memfd = match opts.create(&exe_info.sha256) {
                        Ok(mfd) => mfd,
                        Err(e) => return error_internal(&format!(
                            "Failed to create memfd for fetched {}: {}", arch, e)),
                    };
                    if let Err(e) = memfd.as_file().write_all(&data) {
                        return error_internal(&format!(
                            "Failed to write fetched executable to memfd for {}: {}", arch, e));
                    }
                    if let Err(e) = memfd.add_seals(&[FileSeal::SealShrink, FileSeal::SealGrow, FileSeal::SealWrite]) {
                        return error_internal(&format!(
                            "Failed to seal memfd for fetched {}: {}", arch, e));
                    }
                    ExecutableRef::Memfd(Arc::new(memfd))
                };

                executables_to_store.insert(exe_info.sha256.clone(), exe_ref);
            } else {
                return error_bad_request(
                    &format!("Executable for architecture '{}' with hash {} is not available (no URL specified)",
                        arch, exe_info.sha256));
            }
        }
    }

    // Prepare secrets if any were uploaded
    let secrets = if uploaded_env.is_some() || uploaded_stdin.is_some() {
        Some(crate::os::TaskSecrets {
            env: uploaded_env,
            stdin: uploaded_stdin,
        })
    } else {
        None
    };

    // Store the offer atomically with all its dependencies
    state.store_offer(
        signed_offer.clone(),
        executables_to_store,
        secrets,
    ).await;

    (StatusCode::CREATED,
        Json(UploadOfferResponse {
            status: "accepted".to_string(),
            offer_hash,
            expires_at: offer.valid_until
        }),
    ).into_response()
}

/// Get a specific offer by hash or name
#[utoipa::path(
    get,
    tag = "Offers",
    path = "/{offer_hash}",
    params(
        ("offer_hash" = String, Path, description = "Hash or name of the offer")
    ),
    responses(
        (status = 200, description = "Offer found", body = SignedOffer),
        (status = 404, description = "Offer not found", body = ErrorResponse)
    )
)]
pub async fn get_offer_handler(
    State(state): State<AppState>,
    Path(offer_hash): Path<String>,
) -> Response {
    match state.get_offer(&offer_hash).await {
        Some(signed_offer) => (StatusCode::OK, Json(signed_offer.as_ref().clone())).into_response(),
        None => error_not_found("Offer not found or expired"),
    }
}
