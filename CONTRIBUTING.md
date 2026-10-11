# Contributing to Moat

Thank you for your interest in contributing to Moat! This guide will help you get started.

## Development Setup

### Prerequisites

- **Rust** 1.75+ (install via [rustup](https://rustup.rs/))
- **PostgreSQL** 14+
- **OpenSSL** (for key generation)

### Getting Started

```bash
# Clone the repo
git clone https://github.com/Quicr/moat.git
cd moat

# Build (debug)
cargo build

# Build all workspace members (moat + pp-issuer)
cargo build --workspace
```

### Database Setup

```bash
createdb moat
export MOAT_DATABASE_URL=postgres://localhost/moat
```

### Generate Keys

```bash
# ES256 key for C4M token signing
openssl ecparam -name prime256v1 -genkey -noout -out c4m-private.pem

# Session secret
export MOAT_SESSION_SECRET=$(openssl rand -hex 32)
```

### Running Locally

```bash
cargo run -- \
  --database-url "$MOAT_DATABASE_URL" \
  --session-secret "$MOAT_SESSION_SECRET" \
  --c4m-private-key ./c4m-private.pem
```

Moat starts on `http://localhost:3200`. Visit `/docs/` for the Swagger UI.

## Repository Structure

```
moat/
├── src/
│   ├── main.rs              # Entry point, server setup
│   ├── config.rs             # CLI/env configuration (clap)
│   ├── error.rs              # Error types with HTTP status mapping
│   ├── openapi.rs            # OpenAPI/Swagger spec generation
│   ├── db/
│   │   ├── mod.rs            # Connection pool, migrations
│   │   ├── models.rs         # Database model types
│   │   └── queries.rs        # SQL query functions
│   ├── idp/
│   │   ├── mod.rs            # IdpVerifier trait, registry
│   │   └── google.rs         # Google OAuth2 provider
│   ├── routes/
│   │   ├── mod.rs            # Route module exports
│   │   ├── auth.rs           # Login (guest + Google OAuth)
│   │   ├── token.rs          # Token minting endpoints
│   │   ├── rooms.rs          # Room CRUD + member management
│   │   ├── invites.rs        # Invite link creation/redemption
│   │   ├── privacypass.rs    # RFC 9578 Privacy Pass proxy
│   │   └── web.rs            # Landing page
│   └── token/
│       ├── mod.rs            # TokenMinter trait, registry
│       └── c4m.rs            # CAT4MoQT (COSE_Sign1 + ES256)
├── pp-issuer/                # Privacy Pass issuer (workspace member)
├── tests/
│   └── api_tests.rs          # Integration tests
├── benches/
│   └── token_bench.rs        # Crypto benchmarks
└── scripts/                  # End-to-end demo scripts
```

## Commands

```bash
# Build
cargo build
cargo build --release

# Run tests (unit)
cargo test

# Run integration tests (requires running Moat + PostgreSQL)
MOAT_TEST_BASE_URL=http://localhost:3200 cargo test --test api_tests -- --ignored

# Run benchmarks
cargo bench

# Format code
cargo fmt --all

# Lint
cargo clippy --workspace -- -D warnings

# Regenerate OpenAPI spec
cargo test export_openapi -- --ignored
```

## Code Style

- Run `cargo fmt --all` before committing — CI enforces formatting.
- Run `cargo clippy --workspace -- -D warnings` — CI treats warnings as errors.
- Add `//!` module-level doc comments to new modules.
- Add SPDX license headers to all new source files:
  ```rust
  // SPDX-FileCopyrightText: Copyright (c) 2025 Cisco
  // SPDX-License-Identifier: BSD-2-Clause
  ```
- Use `thiserror` for error types and map them to HTTP status codes in `error.rs`.
- Use parameterized queries via `sqlx` — never interpolate user input into SQL.

## Testing

- **Unit tests**: Run with `cargo test`. No external dependencies needed.
- **Integration tests**: Located in `tests/api_tests.rs`. Require a running Moat instance with PostgreSQL. Marked `#[ignore]` so they don't run by default.
- **Benchmarks**: Located in `benches/token_bench.rs`. Run with `cargo bench`. Results in `target/criterion/`.

## Pull Request Guidelines

1. **Fork and branch** — create a feature branch from `main` (e.g. `feat/my-feature` or `fix/my-bug`).
2. **Keep PRs focused** — one logical change per PR. Split large changes into smaller, reviewable pieces.
3. **Ensure CI passes** — all of these must pass before merge:
   - `cargo check --workspace`
   - `cargo test --workspace`
   - `cargo fmt --all -- --check`
   - `cargo clippy --workspace -- -D warnings`
4. **Write descriptive commit messages** — explain *why*, not just *what*.
5. **Add tests** for new functionality where practical.
6. **Update documentation** if your change affects the API, configuration, or setup.

## Reporting Issues

Use [GitHub Issues](https://github.com/Quicr/moat/issues) to report bugs or request features. Please include:

- Steps to reproduce (for bugs)
- Expected vs actual behavior
- Rust version (`rustc --version`) and OS

## License

By contributing, you agree that your contributions will be licensed under the [BSD 2-Clause License](LICENSE).
