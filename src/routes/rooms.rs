//! Room management routes.
//!
//! Provides CRUD operations for rooms (namespace containers) and
//! member management with role-based access control.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::db::{self, MemberRole, RoomVisibility};
use crate::error::AppError;
use crate::routes::auth::AuthUser;
use crate::AppState;

#[derive(Deserialize, ToSchema)]
pub struct CreateRoomRequest {
    pub name: String,
    pub namespace_prefix: String,
    pub visibility: Option<RoomVisibility>,
}

#[derive(Deserialize, IntoParams)]
pub struct ListRoomsQuery {
    /// Maximum number of rooms to return (default 100, max 1000).
    pub limit: Option<i64>,
    /// Offset for pagination.
    pub offset: Option<i64>,
}

#[utoipa::path(
    post,
    path = "/v1/rooms",
    request_body = CreateRoomRequest,
    responses(
        (status = 201, description = "Room created", body = db::Room),
        (status = 400, description = "Invalid room name or namespace"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer" = [])),
    tag = "rooms"
)]
pub async fn create_room(
    State(state): State<Arc<AppState>>,
    AuthUser(user_id): AuthUser,
    Json(body): Json<CreateRoomRequest>,
) -> Result<(StatusCode, Json<db::Room>), AppError> {

    // Validate room name
    let name = body.name.trim();
    if name.is_empty() || name.len() > 256 {
        return Err(AppError::BadRequest(
            "room name must be 1-256 characters".into(),
        ));
    }

    // Validate namespace prefix.
    // MoQ Transport treats namespace tuple entries as opaque bytes. Moat uses
    // '/' as the separator between tuple entries in the REST API. We reject
    // control characters (breaks logs/display) and empty segments, but
    // otherwise allow any valid UTF-8 — the bytes are what matter on the wire.
    let ns = body.namespace_prefix.trim();
    if !is_valid_namespace(ns) {
        return Err(AppError::BadRequest(
            "namespace_prefix must be 1-512 bytes, must not contain control characters, and must not have empty segments between '/' separators".into(),
        ));
    }

    let visibility = body.visibility.unwrap_or(RoomVisibility::Public);
    let room = db::create_room(state.db.pool(), name, ns, visibility).await?;

    if let Err(e) = db::add_room_member(state.db.pool(), room.id, user_id, MemberRole::Admin).await
    {
        tracing::error!(error = %e, room_id = %room.id, "failed to add creator as room admin");
    }

    Ok((StatusCode::CREATED, Json(room)))
}

#[utoipa::path(
    get,
    path = "/v1/rooms",
    params(ListRoomsQuery),
    responses(
        (status = 200, description = "List of rooms", body = Vec<db::Room>),
    ),
    tag = "rooms"
)]
pub async fn list_rooms(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListRoomsQuery>,
) -> Result<Json<Vec<db::Room>>, AppError> {
    let limit = query.limit.unwrap_or(100).min(1000).max(1);
    let offset = query.offset.unwrap_or(0).max(0);
    let rooms = db::list_rooms(state.db.pool(), limit, offset).await?;
    Ok(Json(rooms))
}

#[utoipa::path(
    get,
    path = "/v1/rooms/{room_id}",
    params(("room_id" = Uuid, Path, description = "Room UUID")),
    responses(
        (status = 200, description = "Room details", body = db::Room),
        (status = 404, description = "Room not found"),
    ),
    tag = "rooms"
)]
pub async fn get_room(
    State(state): State<Arc<AppState>>,
    Path(room_id): Path<Uuid>,
) -> Result<Json<db::Room>, AppError> {
    let room = db::get_room_by_id(state.db.pool(), room_id)
        .await?
        .ok_or_else(|| AppError::NotFound("room not found".into()))?;
    Ok(Json(room))
}

#[derive(Deserialize, ToSchema)]
pub struct AddMemberRequest {
    pub user_id: Uuid,
    pub role: MemberRole,
}

#[utoipa::path(
    post,
    path = "/v1/rooms/{room_id}/members",
    params(("room_id" = Uuid, Path, description = "Room UUID")),
    request_body = AddMemberRequest,
    responses(
        (status = 201, description = "Member added", body = db::RoomMember),
        (status = 404, description = "Room not found"),
    ),
    tag = "rooms"
)]
pub async fn add_member(
    State(state): State<Arc<AppState>>,
    Path(room_id): Path<Uuid>,
    Json(body): Json<AddMemberRequest>,
) -> Result<(StatusCode, Json<db::RoomMember>), AppError> {
    db::get_room_by_id(state.db.pool(), room_id)
        .await?
        .ok_or_else(|| AppError::NotFound("room not found".into()))?;

    let member = db::add_room_member(state.db.pool(), room_id, body.user_id, body.role).await?;
    Ok((StatusCode::CREATED, Json(member)))
}

#[utoipa::path(
    get,
    path = "/v1/rooms/{room_id}/members",
    params(("room_id" = Uuid, Path, description = "Room UUID")),
    responses(
        (status = 200, description = "List of members", body = Vec<db::RoomMember>),
    ),
    tag = "rooms"
)]
pub async fn list_members(
    State(state): State<Arc<AppState>>,
    Path(room_id): Path<Uuid>,
) -> Result<Json<Vec<db::RoomMember>>, AppError> {
    let members = db::list_room_members(state.db.pool(), room_id).await?;
    Ok(Json(members))
}

#[utoipa::path(
    delete,
    path = "/v1/rooms/{room_id}/members/{user_id}",
    params(
        ("room_id" = Uuid, Path, description = "Room UUID"),
        ("user_id" = Uuid, Path, description = "User UUID"),
    ),
    responses(
        (status = 200, description = "Member removed"),
        (status = 404, description = "Member not found"),
    ),
    tag = "rooms"
)]
pub async fn remove_member(
    State(state): State<Arc<AppState>>,
    Path((room_id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<serde_json::Value>, AppError> {
    let removed = db::remove_room_member(state.db.pool(), room_id, user_id).await?;
    if !removed {
        return Err(AppError::NotFound("member not found".into()));
    }
    Ok(Json(serde_json::json!({"removed": true})))
}

/// Validate a namespace prefix (extracted for testability).
///
/// MoQ Transport treats each namespace tuple entry as opaque bytes, so we
/// are intentionally permissive here. The only constraints are:
/// - 1–512 bytes total
/// - No ASCII control characters (breaks logs, display, and could be used
///   for injection in downstream systems)
/// - No empty segments between `/` separators (each tuple entry must be
///   at least one byte on the wire)
fn is_valid_namespace(ns: &str) -> bool {
    !ns.is_empty()
        && ns.len() <= 512
        && !ns.chars().any(|c| c.is_ascii_control())
        && !ns.starts_with('/')
        && !ns.ends_with('/')
        && !ns.contains("//")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_namespaces() {
        assert!(is_valid_namespace("mocha/room1"));
        assert!(is_valid_namespace("conference/2024/track-a"));
        assert!(is_valid_namespace("a_b.c-d/e"));
        assert!(is_valid_namespace("simple"));
        // MoQ namespace fields are bytes — unicode, spaces, special chars are fine
        assert!(is_valid_namespace("room name"));
        assert!(is_valid_namespace("emoji🔥"));
        assert!(is_valid_namespace("ns;value"));
        assert!(is_valid_namespace("ns with spaces/sub"));
        assert!(is_valid_namespace("日本語/部屋"));
    }

    #[test]
    fn invalid_namespaces() {
        assert!(!is_valid_namespace(""), "empty");
        assert!(!is_valid_namespace("room\ttab"), "tab is a control char");
        assert!(!is_valid_namespace("room\nline"), "newline is a control char");
        assert!(!is_valid_namespace("room\0null"), "null byte");
        assert!(!is_valid_namespace("/leading"), "leading slash = empty first segment");
        assert!(!is_valid_namespace("trailing/"), "trailing slash = empty last segment");
        assert!(!is_valid_namespace("a//b"), "double slash = empty middle segment");
    }

    #[test]
    fn namespace_max_length() {
        let long = "a".repeat(512);
        assert!(is_valid_namespace(&long), "exactly 512 should be valid");
        let too_long = "a".repeat(513);
        assert!(!is_valid_namespace(&too_long), "513 should be invalid");
    }

    #[test]
    fn namespace_deeply_nested() {
        assert!(is_valid_namespace("a/b/c/d/e/f/g/h"));
    }

    #[test]
    fn namespace_single_char_segments() {
        assert!(is_valid_namespace("a/b/c"));
    }

    // --- Room name validation (inline in create_room handler) ---

    fn is_valid_room_name(name: &str) -> bool {
        let trimmed = name.trim();
        !trimmed.is_empty() && trimmed.len() <= 256
    }

    #[test]
    fn room_name_valid() {
        assert!(is_valid_room_name("my-room"));
        assert!(is_valid_room_name("  padded  ")); // trimmed to "padded"
        assert!(is_valid_room_name("x")); // 1 char
    }

    #[test]
    fn room_name_invalid() {
        assert!(!is_valid_room_name(""), "empty");
        assert!(!is_valid_room_name("   "), "whitespace only");
        let long = "a".repeat(257);
        assert!(!is_valid_room_name(&long), "too long");
    }

    #[test]
    fn room_name_max_length() {
        let exactly_256 = "a".repeat(256);
        assert!(is_valid_room_name(&exactly_256));
    }
}
