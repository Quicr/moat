// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco
// SPDX-License-Identifier: BSD-2-Clause

//! Integration tests for the Moat API.
//!
//! These tests require a running Moat server with a PostgreSQL database.
//! They are marked `#[ignore]` by default and can be run with:
//!
//!   cargo test --test api_tests -- --ignored
//!
//! Set MOAT_TEST_BASE_URL to point to the running server (default: http://localhost:3200).

use std::env;

fn base_url() -> String {
    env::var("MOAT_TEST_BASE_URL").unwrap_or_else(|_| "http://localhost:3200".to_string())
}

#[tokio::test]
#[ignore]
async fn health_check_returns_200() {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/health", base_url()))
        .send()
        .await
        .expect("failed to reach server");
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "ok");
}

#[tokio::test]
#[ignore]
async fn guest_login_with_valid_name() {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/auth/guest", base_url()))
        .json(&serde_json::json!({ "display_name": "TestUser" }))
        .send()
        .await
        .expect("failed to reach server");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["user_id"].is_string(),
        "response should contain user_id"
    );
    assert!(
        body["session_token"].is_string(),
        "response should contain session_token"
    );
    assert_eq!(body["provider"], "guest");
}

#[tokio::test]
#[ignore]
async fn guest_login_with_empty_name_returns_400() {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/auth/guest", base_url()))
        .json(&serde_json::json!({ "display_name": "" }))
        .send()
        .await
        .expect("failed to reach server");

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
#[ignore]
async fn guest_login_with_long_name_returns_400() {
    let client = reqwest::Client::new();
    let long_name = "x".repeat(65);
    let resp = client
        .post(format!("{}/v1/auth/guest", base_url()))
        .json(&serde_json::json!({ "display_name": long_name }))
        .send()
        .await
        .expect("failed to reach server");

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
#[ignore]
async fn create_room_requires_auth() {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/rooms", base_url()))
        .json(&serde_json::json!({
            "name": "test-room",
            "namespace_prefix": "test"
        }))
        .send()
        .await
        .expect("failed to reach server");

    assert_eq!(
        resp.status(),
        401,
        "creating a room without auth should return 401"
    );
}

#[tokio::test]
#[ignore]
async fn mint_token_requires_auth() {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/token", base_url()))
        .json(&serde_json::json!({
            "room_id": "00000000-0000-0000-0000-000000000000"
        }))
        .send()
        .await
        .expect("failed to reach server");

    assert_eq!(
        resp.status(),
        401,
        "minting a token without auth should return 401"
    );
}

#[tokio::test]
#[ignore]
async fn list_rooms_returns_paginated() {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/v1/rooms?limit=10", base_url()))
        .send()
        .await
        .expect("failed to reach server");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body.is_array(), "rooms response should be an array");
}

#[tokio::test]
#[ignore]
async fn guest_login_then_create_room() {
    let client = reqwest::Client::new();

    // Login as guest
    let login_resp = client
        .post(format!("{}/v1/auth/guest", base_url()))
        .json(&serde_json::json!({ "display_name": "IntegrationTest" }))
        .send()
        .await
        .expect("failed to reach server");
    assert_eq!(login_resp.status(), 200);
    let login_body: serde_json::Value = login_resp.json().await.unwrap();
    let session_token = login_body["session_token"].as_str().unwrap();

    // Create a room with the session token
    let create_resp = client
        .post(format!("{}/v1/rooms", base_url()))
        .header("Authorization", format!("Bearer {}", session_token))
        .json(&serde_json::json!({
            "name": "integration-test-room",
            "namespace_prefix": "integration/test"
        }))
        .send()
        .await
        .expect("failed to reach server");

    assert_eq!(create_resp.status(), 201);
    let room: serde_json::Value = create_resp.json().await.unwrap();
    assert!(room["id"].is_string(), "room should have an id");
    assert_eq!(room["name"], "integration-test-room");
}

#[tokio::test]
#[ignore]
async fn invalid_session_token_returns_401() {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/rooms", base_url()))
        .header("Authorization", "Bearer invalid-token-here")
        .json(&serde_json::json!({
            "name": "test",
            "namespace_prefix": "test"
        }))
        .send()
        .await
        .expect("failed to reach server");

    assert_eq!(resp.status(), 401);
}