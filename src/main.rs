//! Moat — MoQ Auth Token Service.
//!
//! Authentication, room management, and scoped token minting for
//! Media over QUIC (MoQ) relays. Supports pluggable identity providers,
//! Privacy Pass (RFC 9578), and C4M (CAT4MoQT) token formats.

mod config;
mod db;
mod error;
mod idp;
mod openapi;
mod routes;
mod token;

use std::sync::Arc;

use axum::http::{header, HeaderValue, Method};
use axum::Router;
use clap::Parser;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use utoipa_swagger_ui::SwaggerUi;

use crate::config::Config;
use crate::db::Database;
use crate::idp::IdpRegistry;
use crate::openapi::ApiDoc;
use crate::token::MinterRegistry;

pub struct AppState {
    pub db: Database,
    pub idp: IdpRegistry,
    pub minter: MinterRegistry,
    pub config: Config,
    pub pp_signing_key: Option<ed25519_dalek::SigningKey>,
    pub http_client: reqwest::Client,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = Config::parse();

    // Validate session secret
    if config.session_secret.len() < 16 {
        anyhow::bail!("MOAT_SESSION_SECRET must be at least 16 characters. Generate one with: openssl rand -hex 32");
    }

    let db = Database::connect(&config.database_url, config.db_max_connections).await?;
    db.migrate().await?;

    let idp = IdpRegistry::from_config(&config).await?;
    let minter = MinterRegistry::from_config(&config)?;

    let pp_signing_key = if let Some(path) = &config.pp_signing_key {
        let pem = tokio::fs::read_to_string(path).await?;
        let sk = load_ed25519_signing_key(&pem)?;
        tracing::info!("PP attester signing key loaded");
        Some(sk)
    } else {
        None
    };

    let http_client = reqwest::Client::new();

    let state = Arc::new(AppState {
        db,
        idp,
        minter,
        config: config.clone(),
        pp_signing_key,
        http_client,
    });

    // Build CORS layer from config
    let cors = build_cors_layer(&config)?;

    let app = Router::new()
        .merge(routes::router())
        .with_state(state)
        .merge(
            SwaggerUi::new("/docs/{tail}")
                .url("/api-doc/openapi.json", ApiDoc::spec()),
        )
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&config.bind).await?;
    tracing::info!("moat listening on {}", config.bind);

    axum::serve(listener, app).await?;
    Ok(())
}

fn build_cors_layer(config: &Config) -> anyhow::Result<CorsLayer> {
    let origins_str = config
        .cors_origins
        .as_deref()
        .unwrap_or(&config.base_url);

    let origins: Vec<HeaderValue> = origins_str
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<HeaderValue>()
                .map_err(|e| anyhow::anyhow!("invalid CORS origin '{s}': {e}"))
        })
        .collect::<Result<_, _>>()?;

    if origins.is_empty() {
        anyhow::bail!("no valid CORS origins configured");
    }

    Ok(CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .max_age(std::time::Duration::from_secs(3600)))
}

fn load_ed25519_signing_key(pem: &str) -> anyhow::Result<ed25519_dalek::SigningKey> {
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    ed25519_dalek::SigningKey::from_pkcs8_pem(pem)
        .map_err(|e| anyhow::anyhow!("failed to load Ed25519 signing key: {e}"))
}
