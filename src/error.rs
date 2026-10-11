// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco
// SPDX-License-Identifier: BSD-2-Clause

//! Application error types with HTTP status code mapping.
//!
//! Internal errors and database errors are logged server-side but
//! return generic messages to clients to avoid leaking implementation details.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("internal: {0}")]
    Internal(#[from] anyhow::Error),

    #[error("database: {0}")]
    Database(#[from] sqlx::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.as_str()),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.as_str()),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.as_str()),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.as_str()),
            AppError::Internal(e) => {
                tracing::error!(error = %e, "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            AppError::Database(e) => {
                tracing::error!(error = %e, "database error");
                (StatusCode::INTERNAL_SERVER_ERROR, "database error")
            }
        };

        let body = json!({ "error": message });
        (status, axum::Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    #[test]
    fn unauthorized_returns_401() {
        let err = AppError::Unauthorized("test".into());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn forbidden_returns_403() {
        let err = AppError::Forbidden("test".into());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn not_found_returns_404() {
        let err = AppError::NotFound("test".into());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn bad_request_returns_400() {
        let err = AppError::BadRequest("test".into());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn internal_returns_500() {
        let err = AppError::Internal(anyhow::anyhow!("boom"));
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn database_returns_500() {
        let err = AppError::Database(sqlx::Error::RowNotFound);
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn error_response_has_json_body() {
        let err = AppError::BadRequest("invalid input".into());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "invalid input");
    }
}