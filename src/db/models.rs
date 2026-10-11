// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco
// SPDX-License-Identifier: BSD-2-Clause

//! Database model types for users, rooms, members, and invites.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize, ToSchema)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub idp_provider: String,
    pub idp_subject: String,
    pub display_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, ToSchema)]
#[sqlx(type_name = "room_visibility", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum RoomVisibility {
    Public,
    Authenticated,
    Private,
}

#[derive(Debug, Clone, FromRow, Serialize, ToSchema)]
pub struct Room {
    pub id: Uuid,
    pub name: String,
    pub namespace_prefix: String,
    pub visibility: RoomVisibility,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, ToSchema)]
#[sqlx(type_name = "member_role", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum MemberRole {
    Admin,
    Publisher,
    Subscriber,
}

#[derive(Debug, Clone, FromRow, Serialize, ToSchema)]
pub struct RoomMember {
    pub id: Uuid,
    pub room_id: Uuid,
    pub user_id: Uuid,
    pub role: MemberRole,
    pub added_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, ToSchema)]
pub struct RoomInvite {
    pub id: Uuid,
    pub room_id: Uuid,
    pub code: String,
    pub created_by: Uuid,
    pub max_uses: Option<i32>,
    pub use_count: i32,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- RoomVisibility serde ---

    #[test]
    fn room_visibility_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&RoomVisibility::Public).unwrap(),
            "\"public\""
        );
        assert_eq!(
            serde_json::to_string(&RoomVisibility::Authenticated).unwrap(),
            "\"authenticated\""
        );
        assert_eq!(
            serde_json::to_string(&RoomVisibility::Private).unwrap(),
            "\"private\""
        );
    }

    #[test]
    fn room_visibility_deserializes_lowercase() {
        assert_eq!(
            serde_json::from_str::<RoomVisibility>("\"public\"").unwrap(),
            RoomVisibility::Public
        );
        assert_eq!(
            serde_json::from_str::<RoomVisibility>("\"authenticated\"").unwrap(),
            RoomVisibility::Authenticated
        );
        assert_eq!(
            serde_json::from_str::<RoomVisibility>("\"private\"").unwrap(),
            RoomVisibility::Private
        );
    }

    #[test]
    fn room_visibility_rejects_unknown() {
        assert!(serde_json::from_str::<RoomVisibility>("\"secret\"").is_err());
    }

    #[test]
    fn room_visibility_round_trip() {
        for vis in [
            RoomVisibility::Public,
            RoomVisibility::Authenticated,
            RoomVisibility::Private,
        ] {
            let json = serde_json::to_string(&vis).unwrap();
            let back: RoomVisibility = serde_json::from_str(&json).unwrap();
            assert_eq!(vis, back);
        }
    }

    // --- MemberRole serde ---

    #[test]
    fn member_role_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&MemberRole::Admin).unwrap(),
            "\"admin\""
        );
        assert_eq!(
            serde_json::to_string(&MemberRole::Publisher).unwrap(),
            "\"publisher\""
        );
        assert_eq!(
            serde_json::to_string(&MemberRole::Subscriber).unwrap(),
            "\"subscriber\""
        );
    }

    #[test]
    fn member_role_deserializes_lowercase() {
        assert_eq!(
            serde_json::from_str::<MemberRole>("\"admin\"").unwrap(),
            MemberRole::Admin
        );
        assert_eq!(
            serde_json::from_str::<MemberRole>("\"publisher\"").unwrap(),
            MemberRole::Publisher
        );
        assert_eq!(
            serde_json::from_str::<MemberRole>("\"subscriber\"").unwrap(),
            MemberRole::Subscriber
        );
    }

    #[test]
    fn member_role_rejects_unknown() {
        assert!(serde_json::from_str::<MemberRole>("\"moderator\"").is_err());
    }

    #[test]
    fn member_role_round_trip() {
        for role in [
            MemberRole::Admin,
            MemberRole::Publisher,
            MemberRole::Subscriber,
        ] {
            let json = serde_json::to_string(&role).unwrap();
            let back: MemberRole = serde_json::from_str(&json).unwrap();
            assert_eq!(role, back);
        }
    }

    #[test]
    fn member_role_case_sensitive() {
        assert!(serde_json::from_str::<MemberRole>("\"Admin\"").is_err());
        assert!(serde_json::from_str::<MemberRole>("\"PUBLISHER\"").is_err());
    }
}