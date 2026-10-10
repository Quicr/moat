//! Token minting routes.
//!
//! Provides authenticated and anonymous token minting for MoQ relay access.
//! Tokens are scoped to specific rooms with publish/subscribe permissions.

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use anyhow::Context;

use crate::db::{self, RoomVisibility};
use crate::error::AppError;
use crate::routes::auth::{self, AuthUser};
use crate::token::{MintRequest, TokenRole};
use crate::AppState;
use chrono::Utc;

#[derive(Deserialize, ToSchema)]
pub struct MintTokenRequest {
    pub room_id: String,
    #[schema(value_type = Option<String>)]
    pub role: Option<TokenRole>,
}

#[derive(Serialize, ToSchema)]
pub struct MintTokenResponse {
    pub token: String,
    pub expires_at: u64,
    pub scopes: Vec<MintTokenScope>,
    pub dpop: bool,
}

#[derive(Serialize, ToSchema)]
pub struct MintTokenScope {
    pub actions: Vec<String>,
    pub namespace: String,
}

#[utoipa::path(
    post,
    path = "/v1/token",
    request_body = MintTokenRequest,
    responses(
        (status = 200, description = "Token minted successfully", body = MintTokenResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Room not found"),
    ),
    security(("bearer" = [])),
    tag = "token"
)]
pub async fn mint_token(
    State(state): State<Arc<AppState>>,
    AuthUser(user_id): AuthUser,
    Json(body): Json<MintTokenRequest>,
) -> Result<Json<MintTokenResponse>, AppError> {
    let room = get_room_by_id_or_name(state.db.pool(), &body.room_id).await?;

    // Look up user once for both visibility check and token subject
    let user = db::get_user_by_id(state.db.pool(), user_id)
        .await
        .context("failed to fetch user")?
        .ok_or_else(|| AppError::NotFound("user not found".into()))?;

    // Enforce visibility rules
    let existing_role = db::get_member_role(state.db.pool(), room.id, user_id)
        .await
        .context("failed to check room membership")?;
    let member_role = match (room.visibility, existing_role) {
        // Already a member — always allowed
        (_, Some(role)) => role,
        // Private rooms require explicit membership
        (RoomVisibility::Private, None) => {
            return Err(AppError::Forbidden(
                "this is a private room — you need an invite link or to be added by a member"
                    .into(),
            ));
        }
        // Authenticated rooms reject guest users
        (RoomVisibility::Authenticated, None) => {
            if user.idp_provider == "guest" {
                return Err(AppError::Forbidden(
                    "this room requires sign-in — please log in with your identity provider to join"
                        .into(),
                ));
            }
            db::add_room_member(state.db.pool(), room.id, user_id, db::MemberRole::Admin)
                .await
                .context("failed to auto-join authenticated room")?;
            db::MemberRole::Admin
        }
        // Public — auto-join as admin
        (RoomVisibility::Public, None) => {
            db::add_room_member(state.db.pool(), room.id, user_id, db::MemberRole::Admin)
                .await
                .context("failed to auto-join public room")?;
            db::MemberRole::Admin
        }
    };

    let token_role = resolve_role(body.role, member_role)?;

    let namespace_parts: Vec<&[u8]> = room
        .namespace_prefix
        .split('/')
        .map(|s| s.as_bytes())
        .collect();

    let minted = state.minter.mint(&MintRequest {
        subject: &user.email,
        namespace_parts: &namespace_parts,
        role: token_role,
        lifetime_secs: state.config.token_lifetime_secs,
    })?;

    let expires_at = Utc::now().timestamp() as u64 + minted.expires_in;

    let actions = token_role_actions(token_role);

    Ok(Json(MintTokenResponse {
        token: minted.token,
        expires_at,
        scopes: vec![MintTokenScope {
            actions,
            namespace: room.namespace_prefix,
        }],
        dpop: false,
    }))
}

#[derive(Deserialize, ToSchema)]
pub struct AnonTokenRequest {
    /// Room ID (UUID) or room name
    pub room_id: String,
    pub role: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct AnonTokenResponse {
    pub token: String,
    pub expires_at: u64,
    pub scopes: Vec<AnonTokenScope>,
    pub dpop: bool,
}

#[derive(Serialize, ToSchema)]
pub struct AnonTokenScope {
    pub actions: Vec<String>,
    pub namespace: String,
}

#[utoipa::path(
    post,
    path = "/v1/token/anonymous",
    request_body = AnonTokenRequest,
    responses(
        (status = 200, description = "Anonymous token minted", body = AnonTokenResponse),
        (status = 403, description = "Room does not allow anonymous access"),
        (status = 404, description = "Room not found"),
    ),
    tag = "token"
)]
pub async fn mint_anonymous(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AnonTokenRequest>,
) -> Result<Json<AnonTokenResponse>, AppError> {
    let (email, display_name, subject) = auth::generate_guest_identity();

    let user = db::upsert_user(
        state.db.pool(),
        &email,
        "guest",
        &subject,
        Some(&display_name),
    )
    .await?;

    let room = get_room_by_id_or_name(state.db.pool(), &body.room_id).await?;

    // Guests can only join public rooms
    match room.visibility {
        RoomVisibility::Authenticated => {
            return Err(AppError::Forbidden(
                "this room requires sign-in — please log in with your identity provider to join"
                    .into(),
            ));
        }
        RoomVisibility::Private => {
            return Err(AppError::Forbidden(
                "this is a private room — you need an invite link or to be added by a member"
                    .into(),
            ));
        }
        RoomVisibility::Public => {}
    }

    let token_role = match body.role.as_deref() {
        Some("publisher") => TokenRole::Publisher,
        Some("subscriber") => TokenRole::Subscriber,
        Some("pubsub") => TokenRole::PubSub,
        Some(r) => {
            return Err(AppError::BadRequest(format!("invalid role: {r}")));
        }
        // Guests default to PubSub for public rooms
        None => TokenRole::PubSub,
    };

    let member_role = match token_role {
        TokenRole::Subscriber => db::MemberRole::Subscriber,
        _ => db::MemberRole::Admin,
    };
    db::add_room_member(state.db.pool(), room.id, user.id, member_role).await?;

    let namespace_parts: Vec<&[u8]> = room
        .namespace_prefix
        .split('/')
        .map(|s| s.as_bytes())
        .collect();

    let minted = state.minter.mint(&MintRequest {
        subject: &user.email,
        namespace_parts: &namespace_parts,
        role: token_role,
        lifetime_secs: state.config.token_lifetime_secs,
    })?;

    let expires_at = Utc::now().timestamp() as u64 + minted.expires_in;

    let actions = token_role_actions(token_role);

    Ok(Json(AnonTokenResponse {
        token: minted.token,
        expires_at,
        scopes: vec![AnonTokenScope {
            actions,
            namespace: room.namespace_prefix,
        }],
        dpop: false,
    }))
}

/// Look up a room by UUID or by name.
async fn get_room_by_id_or_name(
    pool: &sqlx::PgPool,
    id_or_name: &str,
) -> Result<db::Room, AppError> {
    let room = if let Ok(room_id) = Uuid::parse_str(id_or_name) {
        db::get_room_by_id(pool, room_id).await?
    } else {
        db::get_room_by_name(pool, id_or_name).await?
    };
    room.ok_or_else(|| AppError::NotFound("room not found".into()))
}

fn resolve_role(
    requested: Option<TokenRole>,
    membership: db::MemberRole,
) -> Result<TokenRole, AppError> {
    let effective = match membership {
        db::MemberRole::Admin => requested.unwrap_or(TokenRole::PubSub),
        db::MemberRole::Publisher => {
            let role = requested.unwrap_or(TokenRole::Publisher);
            if role == TokenRole::Subscriber {
                return Err(AppError::Forbidden(
                    "publisher members cannot request subscriber-only tokens".into(),
                ));
            }
            role
        }
        db::MemberRole::Subscriber => {
            let role = requested.unwrap_or(TokenRole::Subscriber);
            if role != TokenRole::Subscriber {
                return Err(AppError::Forbidden(
                    "subscriber members can only get subscriber tokens".into(),
                ));
            }
            role
        }
    };
    Ok(effective)
}

fn token_role_actions(role: TokenRole) -> Vec<String> {
    match role {
        TokenRole::PubSub => vec!["publish".into(), "subscribe".into()],
        TokenRole::Publisher => vec!["publish".into()],
        TokenRole::Subscriber => vec!["subscribe".into()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::MemberRole;

    // --- resolve_role tests ---

    #[test]
    fn admin_defaults_to_pubsub() {
        let result = resolve_role(None, MemberRole::Admin).unwrap();
        assert_eq!(result, TokenRole::PubSub);
    }

    #[test]
    fn admin_can_request_any_role() {
        assert_eq!(
            resolve_role(Some(TokenRole::Publisher), MemberRole::Admin).unwrap(),
            TokenRole::Publisher,
        );
        assert_eq!(
            resolve_role(Some(TokenRole::Subscriber), MemberRole::Admin).unwrap(),
            TokenRole::Subscriber,
        );
        assert_eq!(
            resolve_role(Some(TokenRole::PubSub), MemberRole::Admin).unwrap(),
            TokenRole::PubSub,
        );
    }

    #[test]
    fn publisher_defaults_to_publisher() {
        let result = resolve_role(None, MemberRole::Publisher).unwrap();
        assert_eq!(result, TokenRole::Publisher);
    }

    #[test]
    fn publisher_can_request_pubsub() {
        let result = resolve_role(Some(TokenRole::PubSub), MemberRole::Publisher).unwrap();
        assert_eq!(result, TokenRole::PubSub);
    }

    #[test]
    fn publisher_cannot_request_subscriber() {
        let result = resolve_role(Some(TokenRole::Subscriber), MemberRole::Publisher);
        assert!(result.is_err());
    }

    #[test]
    fn subscriber_defaults_to_subscriber() {
        let result = resolve_role(None, MemberRole::Subscriber).unwrap();
        assert_eq!(result, TokenRole::Subscriber);
    }

    #[test]
    fn subscriber_cannot_request_publisher() {
        let result = resolve_role(Some(TokenRole::Publisher), MemberRole::Subscriber);
        assert!(result.is_err());
    }

    #[test]
    fn subscriber_cannot_request_pubsub() {
        let result = resolve_role(Some(TokenRole::PubSub), MemberRole::Subscriber);
        assert!(result.is_err());
    }

    // --- token_role_actions tests ---

    #[test]
    fn pubsub_has_both_actions() {
        let actions = token_role_actions(TokenRole::PubSub);
        assert_eq!(actions, vec!["publish", "subscribe"]);
    }

    #[test]
    fn publisher_has_publish_only() {
        let actions = token_role_actions(TokenRole::Publisher);
        assert_eq!(actions, vec!["publish"]);
    }

    #[test]
    fn subscriber_has_subscribe_only() {
        let actions = token_role_actions(TokenRole::Subscriber);
        assert_eq!(actions, vec!["subscribe"]);
    }

    // --- TokenRole deserialization ---

    #[test]
    fn token_role_deserializes_lowercase() {
        assert_eq!(
            serde_json::from_str::<TokenRole>("\"publisher\"").unwrap(),
            TokenRole::Publisher
        );
        assert_eq!(
            serde_json::from_str::<TokenRole>("\"subscriber\"").unwrap(),
            TokenRole::Subscriber
        );
        assert_eq!(
            serde_json::from_str::<TokenRole>("\"pubsub\"").unwrap(),
            TokenRole::PubSub
        );
    }

    #[test]
    fn token_role_rejects_unknown() {
        assert!(serde_json::from_str::<TokenRole>("\"admin\"").is_err());
        assert!(serde_json::from_str::<TokenRole>("\"Publisher\"").is_err());
    }

    // --- UUID-vs-name parsing (get_room_by_id_or_name logic) ---

    #[test]
    fn uuid_string_parses_as_uuid() {
        let id = "550e8400-e29b-41d4-a716-446655440000";
        assert!(uuid::Uuid::parse_str(id).is_ok());
    }

    #[test]
    fn room_name_does_not_parse_as_uuid() {
        assert!(uuid::Uuid::parse_str("my-room").is_err());
        assert!(uuid::Uuid::parse_str("general").is_err());
        assert!(uuid::Uuid::parse_str("room-123").is_err());
    }
}
