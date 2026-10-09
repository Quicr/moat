<p align="center">
  <img src="docs/moat-logo.svg" alt="Moat" width="480" />
</p>

# Moat

**Moat** is an authentication and scoped token minting service for [Media over QUIC (MoQ)](https://datatracker.ietf.org/group/moq/about/) relays. It sits between your identity provider and the relay, issuing cryptographic access tokens that control who can publish or subscribe to which namespaces.

## Features

- **Pluggable Identity Providers** — Google OAuth2 out of the box, extensible `IdpVerifier` trait for others
- **Guest Access** — anonymous login for public rooms, no IdP required
- **Room Management** — create rooms with namespace prefixes, manage members with admin/publisher/subscriber roles
- **Scoped Token Minting** — [CAT4MoQT](https://datatracker.ietf.org/doc/draft-ietf-moq-catalogtoken/) tokens (COSE_Sign1 + ES256) with per-namespace publish/subscribe permissions
- **Privacy Pass** — [RFC 9578](https://www.rfc-editor.org/rfc/rfc9578) Blind RSA and Partially Blind RSA token issuance
- **Invite Links** — time-bound, usage-limited invite codes for private rooms
- **API Documentation** — auto-generated OpenAPI/Swagger UI at `/docs/`

## Architecture

```
                         Clients (browsers, apps, CLI)
                          │            │           │
                    login │    mint    │    PP     │
                          ▼            ▼           ▼
               ┌──────────────────────────────────────────┐
               │                 Moat                      │
               │                                           │
               │  Auth ── Token ── Rooms ── Privacy Pass   │
               │    │       │        │           │         │
               │    ▼       ▼        ▼           ▼         │
               │  IdP    C4M      PostgreSQL   HTTP ──────────▶ PP-Issuer
               │  Registry (ES256)  (users,      Client    │   (Blind RSA,
               │  [Google]  COSE    rooms,                 │    PBRS)
               │            Sign1   members,               │
               │                    invites)               │
               └───────────────────┬───────────────────────┘
                                   │ C4M token
                                   ▼
                              MoQ Relay
                       (validates pub/sub access)
```

## Quick Start

### Prerequisites

- Rust 1.75+
- PostgreSQL 14+

### 1. Generate keys

```bash
# ES256 key for C4M token signing
openssl ecparam -name prime256v1 -genkey -noout -out c4m-private.pem

# Session secret
export MOAT_SESSION_SECRET=$(openssl rand -hex 32)
```

### 2. Set up the database

```bash
createdb moat
export MOAT_DATABASE_URL=postgres://localhost/moat
```

### 3. Run Moat

```bash
cargo run -- \
  --database-url "$MOAT_DATABASE_URL" \
  --session-secret "$MOAT_SESSION_SECRET" \
  --c4m-private-key ./c4m-private.pem
```

Moat starts on `http://localhost:3200`. Visit `/docs/` for the Swagger UI, or `/app` for the web dashboard.

### 4. (Optional) Run the Privacy Pass Issuer

```bash
cargo run -p pp-issuer -- --bind 127.0.0.1:3300
```

Then point Moat at it with `--pp-issuer-url http://127.0.0.1:3300` (or set `MOAT_PP_ISSUER_URL`).

## Configuration

All options can be set via CLI flags or environment variables:

| Variable | Required | Default | Description |
|---|---|---|---|
| `MOAT_DATABASE_URL` | Yes | — | PostgreSQL connection URL |
| `MOAT_SESSION_SECRET` | Yes | — | HMAC-SHA256 secret (min 16 chars). Generate with `openssl rand -hex 32` |
| `MOAT_BIND` | No | `0.0.0.0:3200` | HTTP listen address |
| `MOAT_C4M_PRIVATE_KEY` | No | — | Path to ES256 PEM. Token minting disabled if unset |
| `MOAT_C4M_ISSUER` | No | `moat` | Issuer claim in minted tokens |
| `MOAT_C4M_AUDIENCE` | No | `moq-relay` | Audience claim in minted tokens |
| `MOAT_TOKEN_LIFETIME` | No | `3600` | Token lifetime in seconds |
| `MOAT_GOOGLE_CLIENT_ID` | No | — | Google OAuth2 client ID. Google login disabled if unset |
| `MOAT_CORS_ORIGINS` | No | `$MOAT_BASE_URL` | Comma-separated allowed CORS origins |
| `MOAT_DB_MAX_CONNECTIONS` | No | `20` | Maximum database connection pool size |
| `MOAT_BASE_URL` | No | `https://chat.mocha-net.dev` | Base URL for invite links |
| `MOAT_PP_ISSUER_URL` | No | `https://pat.issuer.mocha-net.dev` | Privacy Pass issuer URL |
| `MOAT_PP_SIGNING_KEY` | No | — | Ed25519 key for RFC 9421 attester signatures |

## API

Full API documentation is available via:
- **Swagger UI** at `/docs/` when the server is running
- **OpenAPI spec** at [`openapi.json`](openapi.json) (also served at `/api-doc/openapi.json`)

Endpoints cover authentication, token minting, room management, invite links, and Privacy Pass (RFC 9578).

### Room Visibility

| Level | Who can join | Use case |
|---|---|---|
| **public** | Anyone (guests + authenticated) | Open rooms, demos |
| **authenticated** | Logged-in users only | Team rooms |
| **private** | Invite or explicit add only | Restricted access |

## Development

### Building

```bash
# Debug build
cargo build

# Release build (both moat and pp-issuer)
cargo build --release

# See all CLI options
cargo run -- --help
cargo run -p pp-issuer -- --help
```

### Tests

Unit tests run without any external dependencies:

```bash
cargo test
```

Integration tests require a running Moat server with a PostgreSQL database:

```bash
# 1. Start Moat (see Quick Start above)
# 2. Run the integration tests against it
MOAT_TEST_BASE_URL=http://localhost:3200 cargo test --test api_tests -- --ignored
```

`MOAT_TEST_BASE_URL` defaults to `http://localhost:3200` if not set.

### Benchmarks

Benchmarks measure the crypto hot paths (session token create/verify, namespace canonicalization, invite code generation):

```bash
cargo bench
```

Results are written to `target/criterion/` with HTML reports.

### Regenerate OpenAPI spec

The `openapi.json` file is generated from `utoipa` annotations in the source code:

```bash
cargo test export_openapi -- --ignored
```

### Scripts

The `scripts/` directory contains end-to-end demos:

| Script | Description |
|---|---|
| `scripts/demo-2-guests.sh [moat_url] [relay_url]` | Two-guest demo: creates a room, logs in Alice (publisher) and Bob (subscriber), mints scoped tokens, and prints relay commands |
| `scripts/run-moq-chat-e2e.sh` | Starts Moat + MoQ relay + moq-chat dev server for full end-to-end testing. Requires `moq-rs` and `moq-web` repos alongside this one |

## Production Deployment

For production, deploy behind a reverse proxy (nginx, Caddy) that handles:
- TLS termination
- Per-IP rate limiting
- Security headers (HSTS, X-Content-Type-Options, CSP)

## License

Licensed under the [BSD 2-Clause License](LICENSE).
