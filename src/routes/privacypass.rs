//! Privacy Pass challenge and token request proxy (RFC 9578).
//!
//! Supports Blind RSA (0x0002) and Partially Blind RSA (0xda7a) token types.
//! For PBRS, extensions carry MoQ action scope metadata.

use std::sync::Arc;

use anyhow::anyhow;
use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::Signer;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;

use crate::error::AppError;
use crate::AppState;

const TOKEN_TYPE_BLIND_RSA: u16 = 0x0002;
const TOKEN_TYPE_PARTIALLY_BLIND_RSA: u16 = 0xda7a;
const EXTENSION_TYPE_MOQ_ACTIONS: u16 = 0x0001;

#[derive(Deserialize, ToSchema)]
pub struct ChallengeRequest {
    pub room_id: Option<String>,
    /// Token type: 0x0002 (Blind RSA) or 0xda7a (Partially Blind RSA)
    pub token_type: Option<u16>,
}

#[derive(Serialize, ToSchema)]
pub struct ChallengeResponse {
    pub token_type: u16,
    /// Base64url-encoded TokenChallenge (RFC 9578)
    pub token_challenge: String,
    /// Base64url-encoded issuer public key
    pub issuer_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Base64url-encoded extensions (PBRS only)
    pub extensions: Option<String>,
}

#[utoipa::path(
    post,
    path = "/v1/auth/privacypass/challenge",
    request_body = ChallengeRequest,
    responses(
        (status = 200, description = "Privacy Pass challenge issued", body = ChallengeResponse),
    ),
    tag = "privacypass"
)]
pub async fn challenge(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, AppError> {
    let token_type = body.token_type.unwrap_or(TOKEN_TYPE_PARTIALLY_BLIND_RSA);

    let issuer_name = state.config.pp_issuer_name.as_bytes();
    let origin_info = state.config.pp_origin_name.as_bytes();

    let mut redemption_context = [0u8; 32];
    rand::rng().fill_bytes(&mut redemption_context);

    // Build TokenChallenge per RFC 9578 §2.1
    let mut challenge = Vec::with_capacity(2 + 2 + issuer_name.len() + 1 + 32 + 2 + origin_info.len());
    challenge.extend_from_slice(&token_type.to_be_bytes());
    challenge.extend_from_slice(&(issuer_name.len() as u16).to_be_bytes());
    challenge.extend_from_slice(issuer_name);
    challenge.push(32u8);
    challenge.extend_from_slice(&redemption_context);
    challenge.extend_from_slice(&(origin_info.len() as u16).to_be_bytes());
    challenge.extend_from_slice(origin_info);

    // Fetch the appropriate issuer key using shared HTTP client
    let issuer_key = fetch_issuer_key(&state.http_client, &state.config.pp_issuer_url, token_type).await?;

    // For PBRS, build extensions with MoQ action scope
    let extensions = if token_type == TOKEN_TYPE_PARTIALLY_BLIND_RSA {
        let room_id = body.room_id.as_deref().unwrap_or("*");
        if !room_id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '*') {
            return Err(AppError::BadRequest("invalid room_id format".into()));
        }
        let ext_bytes = build_moq_extensions(room_id)?;
        Some(URL_SAFE_NO_PAD.encode(&ext_bytes))
    } else {
        None
    };

    Ok(Json(ChallengeResponse {
        token_type,
        token_challenge: URL_SAFE_NO_PAD.encode(&challenge),
        issuer_key: URL_SAFE_NO_PAD.encode(&issuer_key),
        extensions,
    }))
}

/// Build Privacy Pass Extensions carrying MoQ action scope.
/// Format: extensions_length(2) + [extension_type(2) + extension_data_length(2) + data]*
fn build_moq_extensions(room_id: &str) -> Result<Vec<u8>, AppError> {
    let scope = serde_json::json!({
        "pub": [format!("mocha/*/{}/*", room_id)],
        "sub": [format!("mocha/*/{}/*", room_id)],
    });
    let ext_data = serde_json::to_vec(&scope)
        .map_err(|e| AppError::Internal(anyhow!("failed to encode MoQ scope: {e}")))?;

    // Single extension: type(2) + data_length(2) + data
    let mut ext = Vec::with_capacity(4 + ext_data.len());
    ext.extend_from_slice(&EXTENSION_TYPE_MOQ_ACTIONS.to_be_bytes());
    ext.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
    ext.extend_from_slice(&ext_data);

    // Wrap in extensions envelope: total_length(2) + extensions
    let mut envelope = Vec::with_capacity(2 + ext.len());
    envelope.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    envelope.extend_from_slice(&ext);
    Ok(envelope)
}

async fn fetch_issuer_key(client: &reqwest::Client, issuer_url: &str, token_type: u16) -> Result<Vec<u8>, AppError> {
    let url = format!("{}/.well-known/private-token-issuer-directory", issuer_url);
    let res = client
        .get(&url)
        .send()
        .await
        .map_err(|e| AppError::Internal(anyhow!("failed to fetch issuer directory: {e}")))?;

    if !res.status().is_success() {
        return Err(AppError::Internal(anyhow!(
            "issuer directory returned {}",
            res.status()
        )));
    }

    let body: serde_json::Value = res
        .json()
        .await
        .map_err(|e| AppError::Internal(anyhow!("failed to parse issuer directory: {e}")))?;

    let keys = body["token-keys"]
        .as_array()
        .ok_or_else(|| AppError::Internal(anyhow!("no token-keys in issuer directory")))?;

    for key in keys {
        if key["token-type"].as_u64() == Some(token_type as u64) {
            let key_b64 = key["token-key"]
                .as_str()
                .ok_or_else(|| AppError::Internal(anyhow!("token-key not a string")))?;
            let key_bytes = URL_SAFE_NO_PAD
                .decode(key_b64)
                .or_else(|_| base64::engine::general_purpose::STANDARD.decode(key_b64))
                .map_err(|e| AppError::Internal(anyhow!("failed to decode issuer key: {e}")))?;
            return Ok(key_bytes);
        }
    }

    Err(AppError::Internal(anyhow!(
        "no token key for type 0x{:04x} found in issuer directory",
        token_type
    )))
}

#[utoipa::path(
    post,
    path = "/v1/auth/privacypass/token-request",
    request_body(content = String, content_type = "application/private-token-request"),
    responses(
        (status = 200, description = "Token response from issuer (binary)", content_type = "application/private-token-response"),
    ),
    tag = "privacypass"
)]
pub async fn token_request_proxy(
    State(state): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Result<axum::response::Response, AppError> {
    let url = format!("{}/token-request", state.config.pp_issuer_url);
    let body_bytes = body.to_vec();

    let mut req = state
        .http_client
        .post(&url)
        .header("Content-Type", "application/private-token-request");

    // Sign the request if we have an attester signing key
    if let Some(signing_key) = &state.pp_signing_key {
        let content_digest = format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(&body_bytes)));
        let sig_params = r#"("content-digest");alg="ed25519";keyid="attester""#;
        let sig_base = format!(
            "\"content-digest\": {}\n\"@signature-params\": {}",
            content_digest, sig_params
        );

        let signature = signing_key.sign(sig_base.as_bytes());
        let sig_b64 = STANDARD.encode(signature.to_bytes());

        req = req
            .header("Content-Digest", &content_digest)
            .header("Signature-Input", format!("sig1={}", sig_params))
            .header("Signature", format!("sig1=:{}:", sig_b64));
    }

    let res = req
        .body(body_bytes)
        .send()
        .await
        .map_err(|e| AppError::Internal(anyhow!("issuer request failed: {e}")))?;

    let status = res.status();
    let response_bytes = res
        .bytes()
        .await
        .map_err(|e| AppError::Internal(anyhow!("failed to read issuer response: {e}")))?;

    axum::response::Response::builder()
        .status(status.as_u16())
        .header("Content-Type", "application/private-token-response")
        .body(axum::body::Body::from(response_bytes.to_vec()))
        .map_err(|e| AppError::Internal(anyhow!("failed to build response: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- build_moq_extensions tests ---

    #[test]
    fn moq_extensions_envelope_structure() {
        let ext = build_moq_extensions("room1").unwrap();
        // Envelope starts with 2-byte total length
        assert!(ext.len() > 2);
        let total_len = u16::from_be_bytes([ext[0], ext[1]]) as usize;
        assert_eq!(total_len, ext.len() - 2, "envelope length should match remaining bytes");
    }

    #[test]
    fn moq_extensions_type_is_moq_actions() {
        let ext = build_moq_extensions("test").unwrap();
        // After 2-byte envelope length, next 2 bytes are the extension type
        let ext_type = u16::from_be_bytes([ext[2], ext[3]]);
        assert_eq!(ext_type, EXTENSION_TYPE_MOQ_ACTIONS);
    }

    #[test]
    fn moq_extensions_data_contains_room_scope() {
        let ext = build_moq_extensions("my-room").unwrap();
        // After envelope(2) + type(2) + data_len(2) = 6 bytes of header, the rest is JSON
        let data_len = u16::from_be_bytes([ext[4], ext[5]]) as usize;
        let data = &ext[6..6 + data_len];
        let scope: serde_json::Value = serde_json::from_slice(data).unwrap();
        assert_eq!(scope["pub"][0], "mocha/*/my-room/*");
        assert_eq!(scope["sub"][0], "mocha/*/my-room/*");
    }

    #[test]
    fn moq_extensions_wildcard_room() {
        let ext = build_moq_extensions("*").unwrap();
        let data_len = u16::from_be_bytes([ext[4], ext[5]]) as usize;
        let data = &ext[6..6 + data_len];
        let scope: serde_json::Value = serde_json::from_slice(data).unwrap();
        assert_eq!(scope["pub"][0], "mocha/*/*/*");
        assert_eq!(scope["sub"][0], "mocha/*/*/*");
    }

    // --- TokenChallenge encoding tests ---

    #[test]
    fn token_challenge_starts_with_type() {
        // Build a challenge manually using the same logic as the handler
        let token_type: u16 = TOKEN_TYPE_PARTIALLY_BLIND_RSA;
        let issuer_name = b"issuer.example.com";
        let origin_info = b"relay.example.com";

        let mut challenge = Vec::new();
        challenge.extend_from_slice(&token_type.to_be_bytes());
        challenge.extend_from_slice(&(issuer_name.len() as u16).to_be_bytes());
        challenge.extend_from_slice(issuer_name);
        challenge.push(32u8); // redemption context length
        challenge.extend_from_slice(&[0u8; 32]); // dummy context
        challenge.extend_from_slice(&(origin_info.len() as u16).to_be_bytes());
        challenge.extend_from_slice(origin_info);

        // Verify structure: type(2) + issuer_len(2) + issuer + ctx_len(1) + ctx(32) + origin_len(2) + origin
        let expected_len = 2 + 2 + issuer_name.len() + 1 + 32 + 2 + origin_info.len();
        assert_eq!(challenge.len(), expected_len);

        // First two bytes are the token type
        assert_eq!(u16::from_be_bytes([challenge[0], challenge[1]]), token_type);
    }

    #[test]
    fn blind_rsa_token_type_constant() {
        assert_eq!(TOKEN_TYPE_BLIND_RSA, 0x0002);
    }

    #[test]
    fn pbrs_token_type_constant() {
        assert_eq!(TOKEN_TYPE_PARTIALLY_BLIND_RSA, 0xda7a);
    }
}
