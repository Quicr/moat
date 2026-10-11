// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco
// SPDX-License-Identifier: BSD-2-Clause

//! Invite link creation and redemption routes.
//!
//! Room members can create time-bound, usage-limited invite codes that
//! allow other users to join private or authenticated rooms.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::db;
use crate::error::AppError;
use crate::routes::auth::AuthUser;
use crate::AppState;
use chrono::Utc;
use rand::Rng;

#[derive(Deserialize, ToSchema)]
pub struct CreateInviteRequest {
    pub max_uses: Option<i32>,
    pub expires_in_hours: Option<u64>,
}

#[derive(Serialize, ToSchema)]
pub struct InviteResponse {
    pub code: String,
    pub url: String,
    pub room_name: String,
    pub expires_at: Option<i64>,
    pub max_uses: Option<i32>,
}

#[utoipa::path(
    post,
    path = "/v1/rooms/{room_id}/invites",
    params(("room_id" = uuid::Uuid, Path, description = "Room UUID")),
    request_body = CreateInviteRequest,
    responses(
        (status = 201, description = "Invite created", body = InviteResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not a room member"),
        (status = 404, description = "Room not found"),
    ),
    security(("bearer" = [])),
    tag = "invites"
)]
pub async fn create_invite(
    State(state): State<Arc<AppState>>,
    Path(room_id): Path<uuid::Uuid>,
    AuthUser(user_id): AuthUser,
    Json(body): Json<CreateInviteRequest>,
) -> Result<(StatusCode, Json<InviteResponse>), AppError> {
    let room = db::get_room_by_id(state.db.pool(), room_id)
        .await?
        .ok_or_else(|| AppError::NotFound("room not found".into()))?;

    // Only members can create invites
    db::get_member_role(state.db.pool(), room.id, user_id)
        .await?
        .ok_or_else(|| AppError::Forbidden("only room members can create invite links".into()))?;

    let code = generate_invite_code();
    let expires_at = body
        .expires_in_hours
        .map(|h| Utc::now() + chrono::Duration::hours(h as i64));

    let invite = db::create_invite(
        state.db.pool(),
        room.id,
        &code,
        user_id,
        body.max_uses,
        expires_at,
    )
    .await?;

    let base_url = &state.config.base_url;
    Ok((
        StatusCode::CREATED,
        Json(InviteResponse {
            url: format!("{}/join/{}", base_url, invite.code),
            code: invite.code,
            room_name: room.name,
            expires_at: invite.expires_at.map(|t| t.timestamp()),
            max_uses: invite.max_uses,
        }),
    ))
}

#[derive(Serialize, ToSchema)]
pub struct RedeemResponse {
    pub room_id: String,
    pub room_name: String,
    pub joined: bool,
}

#[utoipa::path(
    post,
    path = "/v1/invites/{code}/redeem",
    params(("code" = String, Path, description = "Invite code")),
    responses(
        (status = 200, description = "Invite redeemed", body = RedeemResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Invite expired or max uses reached"),
        (status = 404, description = "Invite not found"),
    ),
    security(("bearer" = [])),
    tag = "invites"
)]
pub async fn redeem_invite(
    State(state): State<Arc<AppState>>,
    Path(code): Path<String>,
    AuthUser(user_id): AuthUser,
) -> Result<Json<RedeemResponse>, AppError> {
    let invite = db::get_invite_by_code(state.db.pool(), &code)
        .await?
        .ok_or_else(|| AppError::NotFound("invite link not found or expired".into()))?;

    // Check expiry
    if let Some(expires_at) = invite.expires_at {
        if Utc::now() > expires_at {
            return Err(AppError::Forbidden("this invite link has expired".into()));
        }
    }

    // Check max uses
    if let Some(max) = invite.max_uses {
        if invite.use_count >= max {
            return Err(AppError::Forbidden(
                "this invite link has reached its maximum uses".into(),
            ));
        }
    }

    let room = db::get_room_by_id(state.db.pool(), invite.room_id)
        .await?
        .ok_or_else(|| AppError::NotFound("room no longer exists".into()))?;

    // Atomically check membership, add member, and increment invite use count
    let joined = db::redeem_invite_atomic(
        state.db.pool(),
        invite.id,
        invite.max_uses,
        room.id,
        user_id,
        db::MemberRole::Publisher,
    )
    .await?;

    Ok(Json(RedeemResponse {
        room_id: room.id.to_string(),
        room_name: room.name,
        joined,
    }))
}

/// Generate a 12-character alphanumeric invite code (~62 bits of entropy).
fn generate_invite_code() -> String {
    const CHARS: &[u8] = b"abcdefghijkmnpqrstuvwxyz23456789";
    let mut rng = rand::rng();
    (0..12)
        .map(|_| CHARS[rng.random_range(0..CHARS.len())] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALLOWED_CHARS: &str = "abcdefghijkmnpqrstuvwxyz23456789";

    #[test]
    fn invite_code_length() {
        let code = generate_invite_code();
        assert_eq!(code.len(), 12, "invite code should be 12 characters");
    }

    #[test]
    fn invite_code_valid_chars() {
        let code = generate_invite_code();
        for ch in code.chars() {
            assert!(
                ALLOWED_CHARS.contains(ch),
                "character '{}' not in allowed set",
                ch
            );
        }
    }

    #[test]
    fn invite_code_unique() {
        let code_a = generate_invite_code();
        let code_b = generate_invite_code();
        assert_ne!(code_a, code_b, "two invite codes should differ");
    }

    #[test]
    fn invite_code_no_ambiguous_chars() {
        // The charset deliberately excludes 'l', 'o', '0', '1' to avoid ambiguity
        for _ in 0..100 {
            let code = generate_invite_code();
            assert!(!code.contains('l'), "should not contain 'l'");
            assert!(!code.contains('o'), "should not contain 'o'");
            assert!(!code.contains('0'), "should not contain '0'");
            assert!(!code.contains('1'), "should not contain '1'");
        }
    }
}
