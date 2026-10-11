// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco
// SPDX-License-Identifier: BSD-2-Clause

use criterion::{black_box, criterion_group, criterion_main, Criterion};

// Re-implement the public helpers inline since we can't access private fns from benchmarks.
// These benchmarks measure the crypto hot paths that run on every request.

mod session_token {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use uuid::Uuid;

    pub fn create(user_id: Uuid, secret: &str) -> String {
        let payload = format!("{}:{}", user_id, chrono::Utc::now().timestamp());
        let mut mac =
            Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
        mac.update(payload.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        let token = format!("{}.{}", payload, signature);
        URL_SAFE_NO_PAD.encode(token.as_bytes())
    }

    const SESSION_TOKEN_MAX_AGE_SECS: i64 = 86400;

    pub fn verify(token: &str, secret: &str) -> Option<Uuid> {
        let decoded = URL_SAFE_NO_PAD.decode(token).ok()?;
        let token_str = String::from_utf8(decoded).ok()?;
        let parts: Vec<&str> = token_str.rsplitn(2, '.').collect();
        if parts.len() != 2 {
            return None;
        }
        let (signature_b64, payload) = (parts[0], parts[1]);
        let signature_bytes = URL_SAFE_NO_PAD.decode(signature_b64).ok()?;

        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
        mac.update(payload.as_bytes());
        mac.verify_slice(&signature_bytes).ok()?;

        let mut parts_iter = payload.splitn(2, ':');
        let user_id_str = parts_iter.next()?;
        let timestamp_str = parts_iter.next()?;
        let issued_at: i64 = timestamp_str.parse().ok()?;
        let now = chrono::Utc::now().timestamp();
        if now - issued_at > SESSION_TOKEN_MAX_AGE_SECS {
            return None;
        }

        Uuid::parse_str(user_id_str).ok()
    }
}

fn canonical_namespace(parts: &[&[u8]]) -> Vec<u8> {
    let total_len: usize = parts.iter().map(|p| 4 + p.len()).sum();
    let mut out = Vec::with_capacity(total_len);
    for part in parts {
        let len = part.len() as u32;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

fn bench_session_token_create(c: &mut Criterion) {
    let user_id = uuid::Uuid::new_v4();
    let secret = "bench-secret-at-least-32-bytes-long-for-realism";

    c.bench_function("session_token_create", |b| {
        b.iter(|| session_token::create(black_box(user_id), black_box(secret)))
    });
}

fn bench_session_token_verify(c: &mut Criterion) {
    let user_id = uuid::Uuid::new_v4();
    let secret = "bench-secret-at-least-32-bytes-long-for-realism";
    let token = session_token::create(user_id, secret);

    c.bench_function("session_token_verify", |b| {
        b.iter(|| session_token::verify(black_box(&token), black_box(secret)))
    });
}

fn bench_session_token_verify_invalid(c: &mut Criterion) {
    let user_id = uuid::Uuid::new_v4();
    let secret = "bench-secret-at-least-32-bytes-long-for-realism";
    let token = session_token::create(user_id, secret);

    c.bench_function("session_token_verify_invalid_secret", |b| {
        b.iter(|| {
            session_token::verify(
                black_box(&token),
                black_box("wrong-secret-entirely-different"),
            )
        })
    });
}

fn bench_canonical_namespace_short(c: &mut Criterion) {
    let parts: Vec<&[u8]> = vec![b"mocha", b"room1"];

    c.bench_function("canonical_namespace_short", |b| {
        b.iter(|| canonical_namespace(black_box(&parts)))
    });
}

fn bench_canonical_namespace_deep(c: &mut Criterion) {
    let parts: Vec<&[u8]> = vec![b"mocha", b"conference", b"2024", b"track-a", b"session-42"];

    c.bench_function("canonical_namespace_deep", |b| {
        b.iter(|| canonical_namespace(black_box(&parts)))
    });
}

fn bench_invite_code_generation(c: &mut Criterion) {
    use rand::Rng;

    c.bench_function("invite_code_generate", |b| {
        b.iter(|| {
            const CHARS: &[u8] = b"abcdefghijkmnpqrstuvwxyz23456789";
            let mut rng = rand::rng();
            let code: String = (0..12)
                .map(|_| CHARS[rng.random_range(0..CHARS.len())] as char)
                .collect();
            black_box(code);
        })
    });
}

criterion_group!(
    benches,
    bench_session_token_create,
    bench_session_token_verify,
    bench_session_token_verify_invalid,
    bench_canonical_namespace_short,
    bench_canonical_namespace_deep,
    bench_invite_code_generation,
);
criterion_main!(benches);