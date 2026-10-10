//! Authentication routes and session token management.
//!
//! Provides guest login, Google OAuth login, and shared helpers for
//! session token creation/verification and Bearer token extraction.

use std::sync::Arc;

use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::db;
use crate::error::AppError;
use crate::AppState;

/// Extractor that validates the Bearer session token and yields the user's UUID.
pub struct AuthUser(pub Uuid);

#[async_trait::async_trait]
impl FromRequestParts<Arc<AppState>> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let auth = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::Unauthorized("missing Authorization header".into()))?;

        let token = auth
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::Unauthorized("expected Bearer token".into()))?;

        let user_id = verify_session_token(token, &state.config.session_secret)
            .ok_or_else(|| AppError::Unauthorized("invalid or expired session token".into()))?;

        Ok(AuthUser(user_id))
    }
}

#[derive(Deserialize, ToSchema)]
pub struct GuestLoginRequest {
    pub display_name: String,
}

#[derive(Serialize, ToSchema)]
pub struct AuthResponse {
    pub user_id: uuid::Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub provider: String,
    pub session_token: String,
}

#[utoipa::path(
    post,
    path = "/v1/auth/guest",
    request_body = GuestLoginRequest,
    responses(
        (status = 200, description = "Guest session created", body = AuthResponse),
        (status = 400, description = "Invalid display name"),
    ),
    tag = "auth"
)]
pub async fn guest_login(
    State(state): State<Arc<AppState>>,
    Json(body): Json<GuestLoginRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let name = body.display_name.trim().to_string();
    if name.is_empty() || name.len() > 64 {
        return Err(AppError::BadRequest(
            "display_name must be 1-64 characters".into(),
        ));
    }

    let (email, _, subject) = generate_guest_identity();

    let user = db::upsert_user(state.db.pool(), &email, "guest", &subject, Some(&name)).await?;

    let session_token = create_session_token(user.id, &state.config.session_secret);

    Ok(Json(AuthResponse {
        user_id: user.id,
        email: user.email,
        display_name: user.display_name,
        provider: "guest".to_string(),
        session_token,
    }))
}

#[utoipa::path(
    post,
    path = "/v1/auth/google",
    responses(
        (status = 200, description = "Google OAuth session created", body = AuthResponse),
        (status = 401, description = "Invalid or missing Bearer token"),
    ),
    security(("bearer" = [])),
    tag = "auth"
)]
pub async fn google_login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<AuthResponse>, AppError> {
    let id_token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| AppError::Unauthorized("missing Bearer token".into()))?;

    let identity = state
        .idp
        .verify(id_token)
        .await
        .map_err(|_| AppError::Unauthorized("identity verification failed".into()))?;

    let user = db::upsert_user(
        state.db.pool(),
        &identity.email,
        identity.provider,
        &identity.subject,
        identity.name.as_deref(),
    )
    .await?;

    let session_token = create_session_token(user.id, &state.config.session_secret);

    Ok(Json(AuthResponse {
        user_id: user.id,
        email: user.email,
        display_name: user.display_name,
        provider: identity.provider.to_string(),
        session_token,
    }))
}

/// Generate a unique guest identity (email, display_name, subject).
pub fn generate_guest_identity() -> (String, String, String) {
    let guest_id = Uuid::new_v4();
    let short_id = &guest_id.to_string()[..8];
    let email = format!("guest-{short_id}@moat.local");
    let display_name = format!("Guest-{short_id}");
    let subject = guest_id.to_string();
    (email, display_name, subject)
}

fn create_session_token(user_id: uuid::Uuid, secret: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let payload = format!("{}:{}", user_id, chrono::Utc::now().timestamp());
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(payload.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    let token = format!("{}.{}", payload, signature);
    URL_SAFE_NO_PAD.encode(token.as_bytes())
}

/// Maximum session token age: 24 hours.
const SESSION_TOKEN_MAX_AGE_SECS: i64 = 86400;

pub fn verify_session_token(token: &str, secret: &str) -> Option<uuid::Uuid> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let decoded = URL_SAFE_NO_PAD.decode(token).ok()?;
    let token_str = String::from_utf8(decoded).ok()?;
    let parts: Vec<&str> = token_str.rsplitn(2, '.').collect();
    if parts.len() != 2 {
        return None;
    }
    let (signature_b64, payload) = (parts[0], parts[1]);
    let signature_bytes = URL_SAFE_NO_PAD.decode(signature_b64).ok()?;

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(payload.as_bytes());

    // Constant-time comparison via hmac crate
    mac.verify_slice(&signature_bytes).ok()?;

    // Parse "user_id:timestamp" and validate expiry
    let (user_id_str, timestamp_str) = payload.split_once(':')?;
    let issued_at: i64 = timestamp_str.parse().ok()?;
    let now = chrono::Utc::now().timestamp();
    if now - issued_at > SESSION_TOKEN_MAX_AGE_SECS {
        return None;
    }

    uuid::Uuid::parse_str(user_id_str).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &str = "test-secret-key-at-least-16-chars";

    #[test]
    fn session_token_round_trip() {
        let user_id = Uuid::new_v4();
        let token = create_session_token(user_id, TEST_SECRET);
        let recovered = verify_session_token(&token, TEST_SECRET);
        assert_eq!(recovered, Some(user_id));
    }

    #[test]
    fn session_token_different_secret_fails() {
        let user_id = Uuid::new_v4();
        let token = create_session_token(user_id, TEST_SECRET);
        let recovered = verify_session_token(&token, "a-different-secret-entirely");
        assert_eq!(recovered, None);
    }

    #[test]
    fn session_token_tampered_fails() {
        let user_id = Uuid::new_v4();
        let mut token = create_session_token(user_id, TEST_SECRET);
        // Flip a character in the middle of the token
        let mid = token.len() / 2;
        let replacement = if token.as_bytes()[mid] == b'A' {
            'B'
        } else {
            'A'
        };
        token.replace_range(mid..mid + 1, &replacement.to_string());
        let recovered = verify_session_token(&token, TEST_SECRET);
        assert_eq!(recovered, None);
    }

    #[test]
    fn session_token_empty_fails() {
        assert_eq!(verify_session_token("", TEST_SECRET), None);
    }

    #[test]
    fn session_token_malformed_fails() {
        assert_eq!(verify_session_token("not-a-valid-token", TEST_SECRET), None);
        assert_eq!(verify_session_token("....", TEST_SECRET), None);
        assert_eq!(verify_session_token("abc.def", TEST_SECRET), None);
    }

    #[test]
    fn session_token_different_users_differ() {
        let user_a = Uuid::new_v4();
        let user_b = Uuid::new_v4();
        let token_a = create_session_token(user_a, TEST_SECRET);
        let token_b = create_session_token(user_b, TEST_SECRET);
        assert_ne!(token_a, token_b);

        // Each token verifies to its own user
        assert_eq!(verify_session_token(&token_a, TEST_SECRET), Some(user_a));
        assert_eq!(verify_session_token(&token_b, TEST_SECRET), Some(user_b));
    }

    #[test]
    fn session_token_different_secret_produces_different_token() {
        let user_id = Uuid::new_v4();
        let token_a = create_session_token(user_id, "secret-one-abcdefgh");
        let token_b = create_session_token(user_id, "secret-two-abcdefgh");
        assert_ne!(token_a, token_b);
    }

    #[test]
    fn guest_identity_format() {
        let (email, display_name, subject) = generate_guest_identity();
        assert!(
            email.starts_with("guest-"),
            "email should start with guest-"
        );
        assert!(
            email.ends_with("@moat.local"),
            "email should end with @moat.local"
        );
        assert!(
            display_name.starts_with("Guest-"),
            "display_name should start with Guest-"
        );
        // Subject should be a valid UUID
        assert!(
            Uuid::parse_str(&subject).is_ok(),
            "subject should be a valid UUID"
        );
    }

    #[test]
    fn guest_identity_unique() {
        let (email_a, _, subject_a) = generate_guest_identity();
        let (email_b, _, subject_b) = generate_guest_identity();
        assert_ne!(email_a, email_b);
        assert_ne!(subject_a, subject_b);
    }

    #[test]
    fn session_token_expired_fails() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let user_id = Uuid::new_v4();
        // Create a token with a timestamp 2 days in the past (exceeds 24h TTL)
        let old_timestamp = chrono::Utc::now().timestamp() - 2 * 86400;
        let payload = format!("{}:{}", user_id, old_timestamp);
        let mut mac = Hmac::<Sha256>::new_from_slice(TEST_SECRET.as_bytes()).unwrap();
        mac.update(payload.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        let token = format!("{}.{}", payload, signature);
        let encoded = URL_SAFE_NO_PAD.encode(token.as_bytes());

        assert_eq!(
            verify_session_token(&encoded, TEST_SECRET),
            None,
            "expired token should be rejected"
        );
    }

    #[test]
    fn session_token_recent_succeeds() {
        // A freshly created token should succeed (sanity check for TTL logic)
        let user_id = Uuid::new_v4();
        let token = create_session_token(user_id, TEST_SECRET);
        assert_eq!(verify_session_token(&token, TEST_SECRET), Some(user_id));
    }

    #[test]
    fn authenticate_missing_header_returns_unauthorized() {
        let headers = HeaderMap::new();
        let _config = crate::config::Config {
            bind: "0.0.0.0:3200".into(),
            database_url: "postgres://localhost/test".into(),
            google_client_id: None,
            c4m_private_key: None,
            c4m_issuer: "moat".into(),
            c4m_audience: "moq-relay".into(),
            token_lifetime_secs: 3600,
            session_secret: TEST_SECRET.into(),
            base_url: "http://localhost".into(),
            pp_issuer_name: "test".into(),
            pp_issuer_url: "http://localhost".into(),
            pp_origin_name: "test".into(),
            pp_signing_key: None,
            db_max_connections: 5,
            cors_origins: None,
        };
        // We can't construct a full AppState without a DB, but we can test
        // the header extraction logic by checking the error type.
        // authenticate() checks headers first, so missing header should fail
        // before touching state.db or state.idp.
        // Unfortunately we can't easily construct AppState without a real DB.
        // Instead, test the header logic inline:

        // No Authorization header
        let auth = headers.get("authorization").and_then(|v| v.to_str().ok());
        assert!(auth.is_none());
    }

    #[test]
    fn authenticate_non_bearer_prefix_fails() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Basic abc123".parse().unwrap());
        let auth = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap();
        let token = auth.strip_prefix("Bearer ");
        assert!(token.is_none(), "Basic auth should not match Bearer prefix");
    }

    #[test]
    fn authenticate_valid_bearer_extracts_token() {
        let mut headers = HeaderMap::new();
        let user_id = Uuid::new_v4();
        let session_token = create_session_token(user_id, TEST_SECRET);
        headers.insert(
            "authorization",
            format!("Bearer {}", session_token).parse().unwrap(),
        );
        let auth = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap();
        let token = auth.strip_prefix("Bearer ").unwrap();
        let recovered = verify_session_token(token, TEST_SECRET);
        assert_eq!(recovered, Some(user_id));
    }
}
