pub mod cleanup;
pub mod handlers;
pub mod models;
pub mod offers;
pub mod state;
pub mod router;

pub use cleanup::cleanup_loop;
pub use state::AppState;
pub use models::{
    Stage2Config, Offer, SignedOffer, ErrorResponse,
    error_response, error_bad_request, error_forbidden, error_not_found, error_internal
};

use crate::eth::{EvmSigner, EvmAddress};
use crate::x402::{Facilitator, FacilitatorClient, OwnerExemptFacilitator};
use crate::os::TaskManager;

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Result;
use axum::{routing::get, routing::post, Router};
use clap::Args;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use tokio::sync::RwLock;

/// OpenAPI documentation
#[derive(OpenApi)]
#[openapi(
    info(
        title = "x402 Lambda Service",
        version = env!("CARGO_PKG_VERSION"),
        description = "Distributed pay-per-use compute platform built on the x402 payment protocol. \
                       Execute tasks in secure enclaves with TPM attestation and micropayments.",
        license(
            name = "MIT OR Apache-2.0",
        ),
        contact(
            name = "x402 Project",
            url = "https://github.com/lockboot/os402"
        )
    ),
    paths(
        handlers::attest::attest_handler,
        handlers::cgi::cgi_handler,        
        handlers::exe::get_executable_offers_handler,
        handlers::execute::execute_task_handler,
        handlers::health::health_handler,
        handlers::offers::list_offers_handler,
        handlers::offers::upload_offer_handler,
        handlers::offers::get_offer_handler,
        handlers::output::get_task_stdout_handler,
        handlers::output::get_task_stderr_handler,
        handlers::tasks::task_status_handler,
        handlers::tasks::list_tasks_handler,
    ),
    components(
        schemas(
            // Core models
            models::ExecutableInfo,
            models::Stage2Config,
            models::PricingOption,
            models::Offer,
            models::SignedOffer,
            models::ErrorResponse,
            // Handler response types
            handlers::attest::AttestResponse,
            handlers::exe::ExecutableOffersResponse,
            handlers::execute::ExecuteTaskRequest,
            handlers::execute::ExecuteTaskResponse,
            handlers::health::HealthResponse,
            handlers::offers::ListOffersResponse,
            handlers::offers::UploadOfferResponse,
            handlers::output::StreamResponse,
            // Task types
            crate::os::Task,
            crate::os::TaskLimits,
            crate::os::TaskStatus,
        )
    ),
    tags(
        (name = "Health", description = "Service health and status endpoints"),
        (name = "Offers", description = "Manage and query compute offers"),
        (name = "Tasks", description = "Execute and monitor tasks"),
    ),
    external_docs(
        url = "https://docs.x402.example/api",
        description = "Full API documentation and guides"
    )
)]
struct ApiDoc;

/// Creates an instance of the axum app with all routes and state configured
///
/// Returns a tuple of (Router, AppState) where the state can be used to query
/// the facilitator before starting the server.
pub async fn create_app(config: &crate::config::GlobalConfig) -> Result<(Router, AppState)> {
    // Build token registry from config
    let token_registry = config.token_registry()?;

    // Get owner from config (required for server mode)
    let owner = config.owner.as_ref()
        .ok_or_else(|| anyhow::anyhow!(
            "Owner address required. Specify via --owner, X402_OWNER_ADDRESS env var, or config file"
        ))?;

    // Create facilitator client from GlobalConfig (source of truth)
    let base_facilitator = FacilitatorClient::try_from(config)?;

    // Wrap with OwnerExemptFacilitator for owner authentication
    // This allows the owner to authenticate and access free endpoints
    let facilitator = Arc::new(OwnerExemptFacilitator::new(base_facilitator, owner.clone()));

    // Create OpenAPI spec for documentation and payment descriptions
    let openapi = Arc::new(ApiDoc::openapi());

    // Create signer for signing task outputs
    let signer = Arc::new(EvmSigner::random());

    // Create pool states shared between AppState and TaskManager
    let pool_states = Arc::new(RwLock::new(HashMap::new()));

    // Create TaskManager and set pool states reference
    let mut tasks = TaskManager::new(signer.clone(), config.exec_cache_dir.clone())?;
    tasks.set_pool_states(pool_states.clone());

    let state = AppState {
        owner: EvmAddress::from_str(owner)?,
        offers: Arc::new(RwLock::new(HashMap::new())),
        offer_secrets: Arc::new(RwLock::new(HashMap::new())),
        offers_by_name: Arc::new(RwLock::new(HashMap::new())),
        executables: Arc::new(RwLock::new(HashMap::new())),
        executable_refs: Arc::new(RwLock::new(HashMap::new())),
        exec_cache_dir: config.exec_cache_dir.clone(),
        tasks,
        facilitator,
        openapi,
        signer,
        token_registry,
        pool_states,
    };

    // Initialize resource pools from configuration
    state.initialize_pools(config.pools.clone()).await;

    // Dispatcher fallback with large body limit (100MB for offer uploads with binaries)
    let dispatcher_routes = Router::new()
        .fallback(router::dispatch_extension_routes)
        .layer(axum::extract::DefaultBodyLimit::max(100 * 1024 * 1024))
        .with_state(state.clone());

    // Main app with standard body limit (2MB for most requests)
    let main_routes = Router::new()
        .route("/health", get(handlers::health::health_handler))
        .route("/tasks", get(handlers::tasks::list_tasks_handler))
        .route("/attest", get(handlers::attest::attest_handler))
        .route("/offers", get(handlers::offers::list_offers_handler))
        .route("/tasks/{task_id}", post(handlers::tasks::task_status_handler))
        .route("/tasks/{task_id}/stdout", get(handlers::output::get_task_stdout_handler))
        .route("/tasks/{task_id}/stderr", get(handlers::output::get_task_stderr_handler))
        .route(
            "/{offer_hash}/run/{num_seconds}",
            post(handlers::execute::execute_task_handler),
        )
        .layer(axum::extract::DefaultBodyLimit::max(2 * 1024 * 1024)); // 2MB limit for named routes

    let app = Router::new()
        .merge(
            SwaggerUi::new("/swagger-ui")
                .url("/api-docs/openapi.json", ApiDoc::openapi())
        )
        .merge(main_routes)
        .merge(dispatcher_routes)  // Dispatcher has 100MB limit for uploads
        .with_state(state.clone());

    Ok((app, state))
}

const DEFAULT_PORT: u16 = 3000;

#[derive(Args)]
pub struct ServeArgs {
    /// Write process ID to the specified file
    #[arg(long, value_name="./pid.file")]
    pub pid: Option<String>,

    /// Write readiness marker to the specified file once server is listening
    ///
    /// Useful for scripts that need to wait for the server to be fully started.
    #[arg(long)]
    pub ready_file: Option<String>,
}

pub async fn run(args: ServeArgs, config: &crate::config::GlobalConfig) -> Result<()> {
    // Get port from config (default: 3000)
    let port = config.port.unwrap_or(DEFAULT_PORT);

    // Write PID to file if requested
    if let Some(pid_file) = &args.pid {
        let pid = std::process::id();
        std::fs::write(pid_file, pid.to_string())?;
    }

    // Create the app instance and get state
    let (app, state) = create_app(config).await?;

    // Spawn background cleanup task (runs every 5 minutes)
    let cleanup_state = state.clone();
    tokio::spawn(async move {
        cleanup_loop(cleanup_state, std::time::Duration::from_secs(300)).await;
    });

    // Print owner address
    println!("Owner: {}", state.owner);

    // Query supported payment methods from facilitator
    if let Some(url) = &config.facilitator_url {
        println!("Facilitator: {}", url);
    }
    match state.facilitator.supported().await {
        Ok(supported) => {
            for kind in &supported.kinds {
                println!("  - {} ({:?})", kind.network, kind.scheme);
            }
        }
        Err(e) => {
            println!("Warning: Failed to query facilitator: {}", e);
            println!("Server will start anyway, but payments may not work correctly.");
        }
    }

    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("Listening: {}", listener.local_addr()?);
    println!("Swagger UI: http://localhost:{}/swagger-ui", port);

    // Write ready file if requested (server is now ready to accept connections)
    if let Some(ready_file) = &args.ready_file {
        let pid = std::process::id();
        std::fs::write(ready_file, format!("ready {}", pid))?;
    }

    axum::serve(listener, app).await?;

    Ok(())
}
