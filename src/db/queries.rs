//! Database query functions for users, rooms, members, and invites.
//!
//! All queries use parameterized statements via sqlx to prevent SQL injection.

use sqlx::PgPool;
use uuid::Uuid;

use super::{MemberRole, Room, RoomInvite, RoomMember, User};
use chrono::{DateTime, Utc};

pub async fn upsert_user(
    pool: &PgPool,
    email: &str,
    idp_provider: &str,
    idp_subject: &str,
    display_name: Option<&str>,
) -> Result<User, sqlx::Error> {
    sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users (id, email, idp_provider, idp_subject, display_name, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
        ON CONFLICT (idp_provider, idp_subject)
        DO UPDATE SET
            email = EXCLUDED.email,
            display_name = COALESCE(EXCLUDED.display_name, users.display_name),
            updated_at = NOW()
        RETURNING *
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(email)
    .bind(idp_provider)
    .bind(idp_subject)
    .bind(display_name)
    .fetch_one(pool)
    .await
}

pub async fn get_user_by_id(pool: &PgPool, user_id: Uuid) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await
}

pub async fn create_room(
    pool: &PgPool,
    name: &str,
    namespace_prefix: &str,
    visibility: super::RoomVisibility,
) -> Result<Room, sqlx::Error> {
    sqlx::query_as::<_, Room>(
        r#"
        INSERT INTO rooms (id, name, namespace_prefix, visibility, created_at, updated_at)
        VALUES ($1, $2, $3, $4, NOW(), NOW())
        RETURNING *
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(name)
    .bind(namespace_prefix)
    .bind(visibility)
    .fetch_one(pool)
    .await
}

pub async fn get_room_by_id(pool: &PgPool, room_id: Uuid) -> Result<Option<Room>, sqlx::Error> {
    sqlx::query_as::<_, Room>("SELECT * FROM rooms WHERE id = $1")
        .bind(room_id)
        .fetch_optional(pool)
        .await
}

pub async fn get_room_by_name(pool: &PgPool, name: &str) -> Result<Option<Room>, sqlx::Error> {
    sqlx::query_as::<_, Room>("SELECT * FROM rooms WHERE name = $1")
        .bind(name)
        .fetch_optional(pool)
        .await
}

pub async fn list_rooms(pool: &PgPool, limit: i64, offset: i64) -> Result<Vec<Room>, sqlx::Error> {
    sqlx::query_as::<_, Room>("SELECT * FROM rooms ORDER BY name LIMIT $1 OFFSET $2")
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
}

pub async fn add_room_member(
    pool: &PgPool,
    room_id: Uuid,
    user_id: Uuid,
    role: MemberRole,
) -> Result<RoomMember, sqlx::Error> {
    sqlx::query_as::<_, RoomMember>(
        r#"
        INSERT INTO room_members (id, room_id, user_id, role, added_at)
        VALUES ($1, $2, $3, $4, NOW())
        ON CONFLICT (room_id, user_id)
        DO UPDATE SET role = EXCLUDED.role
        RETURNING *
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(room_id)
    .bind(user_id)
    .bind(role)
    .fetch_one(pool)
    .await
}

pub async fn get_member_role(
    pool: &PgPool,
    room_id: Uuid,
    user_id: Uuid,
) -> Result<Option<MemberRole>, sqlx::Error> {
    let row: Option<(MemberRole,)> =
        sqlx::query_as("SELECT role FROM room_members WHERE room_id = $1 AND user_id = $2")
            .bind(room_id)
            .bind(user_id)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|r| r.0))
}

pub async fn list_room_members(
    pool: &PgPool,
    room_id: Uuid,
) -> Result<Vec<RoomMember>, sqlx::Error> {
    sqlx::query_as::<_, RoomMember>(
        "SELECT * FROM room_members WHERE room_id = $1 ORDER BY added_at",
    )
    .bind(room_id)
    .fetch_all(pool)
    .await
}

pub async fn remove_room_member(
    pool: &PgPool,
    room_id: Uuid,
    user_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM room_members WHERE room_id = $1 AND user_id = $2")
        .bind(room_id)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn create_invite(
    pool: &PgPool,
    room_id: Uuid,
    code: &str,
    created_by: Uuid,
    max_uses: Option<i32>,
    expires_at: Option<DateTime<Utc>>,
) -> Result<RoomInvite, sqlx::Error> {
    sqlx::query_as::<_, RoomInvite>(
        r#"
        INSERT INTO room_invites (id, room_id, code, created_by, max_uses, expires_at, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, NOW())
        RETURNING *
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(room_id)
    .bind(code)
    .bind(created_by)
    .bind(max_uses)
    .bind(expires_at)
    .fetch_one(pool)
    .await
}

pub async fn get_invite_by_code(
    pool: &PgPool,
    code: &str,
) -> Result<Option<RoomInvite>, sqlx::Error> {
    sqlx::query_as::<_, RoomInvite>("SELECT * FROM room_invites WHERE code = $1")
        .bind(code)
        .fetch_optional(pool)
        .await
}

/// Atomically redeem an invite: check membership, add member, and increment
/// the invite use count in a single transaction. Returns `true` if the user
/// was newly added, `false` if they were already a member.
pub async fn redeem_invite_atomic(
    pool: &PgPool,
    invite_id: Uuid,
    max_uses: Option<i32>,
    room_id: Uuid,
    user_id: Uuid,
    role: MemberRole,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;

    // Lock the invite row to prevent concurrent redemptions
    let current_use_count: (i32,) =
        sqlx::query_as("SELECT use_count FROM room_invites WHERE id = $1 FOR UPDATE")
            .bind(invite_id)
            .fetch_one(&mut *tx)
            .await?;

    // Re-check max uses under the lock
    if let Some(max) = max_uses {
        if current_use_count.0 >= max {
            tx.rollback().await?;
            return Ok(false);
        }
    }

    // Check if already a member
    let existing: Option<(MemberRole,)> =
        sqlx::query_as("SELECT role FROM room_members WHERE room_id = $1 AND user_id = $2")
            .bind(room_id)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;

    if existing.is_some() {
        tx.commit().await?;
        return Ok(false);
    }

    // Add member
    sqlx::query(
        r#"
        INSERT INTO room_members (id, room_id, user_id, role, added_at)
        VALUES ($1, $2, $3, $4, NOW())
        ON CONFLICT (room_id, user_id) DO NOTHING
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(room_id)
    .bind(user_id)
    .bind(role)
    .execute(&mut *tx)
    .await?;

    // Increment use count
    sqlx::query("UPDATE room_invites SET use_count = use_count + 1 WHERE id = $1")
        .bind(invite_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(true)
}
