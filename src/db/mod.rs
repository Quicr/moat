// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco
// SPDX-License-Identifier: BSD-2-Clause

//! Database layer for Moat.
//!
//! Provides PostgreSQL connection pooling, migrations, and query functions
//! for users, rooms, room members, and invite links.

mod models;
mod queries;

pub(crate) use models::*;
pub(crate) use queries::*;

use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

pub struct Database {
    pool: PgPool,
}

impl Database {
    pub async fn connect(url: &str, max_connections: u32) -> anyhow::Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(Duration::from_secs(10))
            .idle_timeout(Duration::from_secs(600))
            .connect(url)
            .await?;

        tracing::info!(max_connections, "connected to database");
        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> anyhow::Result<()> {
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        tracing::info!("database migrations applied");
        Ok(())
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}