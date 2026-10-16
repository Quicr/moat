// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco
// SPDX-License-Identifier: BSD-2-Clause

//! C4M (CAT4MoQT) token minter.
//!
//! Produces COSE_Sign1 tokens with ES256 signatures carrying MoQT scopes.
//! Uses the `cat-token` crate's `CatToken` + `MoqtScopeBuilder` + `encode_token_base64`
//! for correct encoding: CBOR tag 18, raw r||s signatures, claim key 327,
//! inline scope arrays, and per-field namespace matching.
//!
//! Token type for SETUP AUTHORIZATION_TOKEN is 1 (c4m-01 §7.1.1).

use cat_token::{
    CatToken, Es256Algorithm, MoqtAction, MoqtScopeBuilder, encode_token_base64,
};
use p256::ecdsa::SigningKey;
use p256::pkcs8::DecodePrivateKey;

use super::{MintRequest, MintedToken, TokenMinter, TokenRole};

/// Token type 1 per c4m-01 §7.1.1, used in SETUP AUTHORIZATION_TOKEN.
const C4M_TOKEN_TYPE: u64 = 1;

pub struct C4mMinter {
    signing_key: Es256Algorithm,
    issuer: String,
    audience: String,
    default_lifetime: u64,
}

impl C4mMinter {
    pub fn new(
        private_key_pem: &str,
        issuer: String,
        audience: String,
        default_lifetime: u64,
    ) -> anyhow::Result<Self> {
        let sk = SigningKey::from_pkcs8_pem(private_key_pem)
            .map_err(|e| anyhow::anyhow!("invalid ES256 private key PEM: {e}"))?;
        let vk = *sk.verifying_key();
        let signing_key = Es256Algorithm::from_key_pair(sk, vk);

        Ok(Self {
            signing_key,
            issuer,
            audience,
            default_lifetime,
        })
    }
}

impl TokenMinter for C4mMinter {
    fn mint(&self, request: &MintRequest) -> anyhow::Result<MintedToken> {
        let lifetime = if request.lifetime_secs > 0 {
            request.lifetime_secs
        } else {
            self.default_lifetime
        };

        // Build the base token with standard CWT claims
        let mut token = CatToken::new()
            .with_issuer(&self.issuer)
            .with_single_audience(&self.audience)
            .with_subject(request.subject)
            .with_expires_in(lifetime as i64);

        // Scope 0: ClientSetup (action 0) — required for session admission
        token = token.with_moqt_scope(
            MoqtScopeBuilder::new()
                .action(MoqtAction::ClientSetup)
                .build(),
        );

        // Build namespace scope with one exact match per tuple field.
        // No track match = any track (omitted from wire, not empty bstr).
        let build_ns_scope = |builder: MoqtScopeBuilder| -> MoqtScopeBuilder {
            let mut b = builder;
            for part in request.namespace_parts {
                b = b.namespace_exact(part);
            }
            b
        };

        // Publisher scope: PublishNamespace + Publish
        if matches!(request.role, TokenRole::Publisher | TokenRole::PubSub) {
            let scope = build_ns_scope(MoqtScopeBuilder::new().publisher()).build();
            token = token.with_moqt_scope(scope);
        }

        // Subscriber scope: SubscribeNamespace + Subscribe + Fetch
        if matches!(request.role, TokenRole::Subscriber | TokenRole::PubSub) {
            let scope = build_ns_scope(MoqtScopeBuilder::new().subscriber()).build();
            token = token.with_moqt_scope(scope);
        }

        // Encode: CBOR tag 18, raw r||s signature, claim key 327, inline scopes
        let token_string = encode_token_base64(&token, &self.signing_key)
            .map_err(|e| anyhow::anyhow!("token encoding failed: {e}"))?;

        Ok(MintedToken {
            token: token_string,
            token_type: C4M_TOKEN_TYPE,
            expires_in: lifetime,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use ciborium::Value;

    fn generate_test_key_pem() -> String {
        use p256::pkcs8::EncodePrivateKey;
        let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        sk.to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .unwrap()
            .to_string()
    }

    #[test]
    fn c4m_minter_token_type_is_1() {
        let pem = generate_test_key_pem();
        let minter =
            C4mMinter::new(&pem, "test-issuer".into(), "test-audience".into(), 3600).unwrap();

        let ns_parts: Vec<&[u8]> = vec![b"mocha", b"room1"];
        let result = minter
            .mint(&MintRequest {
                subject: "user@test",
                namespace_parts: &ns_parts,
                role: TokenRole::Publisher,
                lifetime_secs: 300,
            })
            .unwrap();

        assert_eq!(result.token_type, 1, "token type must be 1 per c4m-01");
        assert_eq!(result.expires_in, 300);
    }

    #[test]
    fn c4m_minter_produces_tagged_cose_sign1() {
        let pem = generate_test_key_pem();
        let minter =
            C4mMinter::new(&pem, "issuer".into(), "audience".into(), 3600).unwrap();

        let ns_parts: Vec<&[u8]> = vec![b"room"];
        let result = minter
            .mint(&MintRequest {
                subject: "u",
                namespace_parts: &ns_parts,
                role: TokenRole::Publisher,
                lifetime_secs: 60,
            })
            .unwrap();

        let cose_bytes = URL_SAFE_NO_PAD.decode(&result.token).unwrap();
        let cbor: Value = ciborium::de::from_reader(&cose_bytes[..]).unwrap();

        // Must be CBOR tag 18 (COSE_Sign1)
        match cbor {
            Value::Tag(18, inner) => match *inner {
                Value::Array(items) => {
                    assert_eq!(items.len(), 4, "COSE_Sign1 should have 4 elements");
                    // Signature should be raw r||s = 64 bytes
                    match &items[3] {
                        Value::Bytes(sig) => {
                            assert_eq!(sig.len(), 64, "ES256 raw signature must be 64 bytes (r||s)");
                        }
                        other => panic!("expected signature bytes, got {:?}", other),
                    }
                }
                other => panic!("expected array inside tag 18, got {:?}", other),
            },
            other => panic!("expected CBOR tag 18 (COSE_Sign1), got {:?}", other),
        }
    }

    #[test]
    fn c4m_minter_uses_claim_key_327() {
        let pem = generate_test_key_pem();
        let minter =
            C4mMinter::new(&pem, "issuer".into(), "audience".into(), 3600).unwrap();

        let ns_parts: Vec<&[u8]> = vec![b"ns"];
        let result = minter
            .mint(&MintRequest {
                subject: "u",
                namespace_parts: &ns_parts,
                role: TokenRole::PubSub,
                lifetime_secs: 60,
            })
            .unwrap();

        let cose_bytes = URL_SAFE_NO_PAD.decode(&result.token).unwrap();
        let cbor: Value = ciborium::de::from_reader(&cose_bytes[..]).unwrap();

        let payload_bytes = match cbor {
            Value::Tag(18, inner) => match *inner {
                Value::Array(items) => match &items[2] {
                    Value::Bytes(b) => b.clone(),
                    _ => panic!("expected payload bytes"),
                },
                _ => panic!("expected array"),
            },
            _ => panic!("expected tag 18"),
        };

        let payload: Value = ciborium::de::from_reader(&payload_bytes[..]).unwrap();
        let map = match payload {
            Value::Map(m) => m,
            _ => panic!("not a map"),
        };

        // MoQT scopes should be at claim key 327 (not 65000)
        let has_327 = map
            .iter()
            .any(|(k, _)| *k == Value::Integer(327.into()));
        let has_65000 = map
            .iter()
            .any(|(k, _)| *k == Value::Integer(65000.into()));

        assert!(has_327, "payload should contain MoQT scopes at claim key 327");
        assert!(!has_65000, "payload should NOT contain legacy claim key 65000");
    }

    #[test]
    fn c4m_minter_moqt_scopes_are_inline_array() {
        let pem = generate_test_key_pem();
        let minter =
            C4mMinter::new(&pem, "issuer".into(), "audience".into(), 60).unwrap();

        let ns_parts: Vec<&[u8]> = vec![b"test"];
        let result = minter
            .mint(&MintRequest {
                subject: "u",
                namespace_parts: &ns_parts,
                role: TokenRole::Publisher,
                lifetime_secs: 60,
            })
            .unwrap();

        let cose_bytes = URL_SAFE_NO_PAD.decode(&result.token).unwrap();
        let cbor: Value = ciborium::de::from_reader(&cose_bytes[..]).unwrap();
        let payload_bytes = match cbor {
            Value::Tag(18, inner) => match *inner {
                Value::Array(items) => match &items[2] {
                    Value::Bytes(b) => b.clone(),
                    _ => panic!("expected bytes"),
                },
                _ => panic!("expected array"),
            },
            _ => panic!("expected tag"),
        };

        let payload: Value = ciborium::de::from_reader(&payload_bytes[..]).unwrap();
        let map = match payload {
            Value::Map(m) => m,
            _ => panic!("not a map"),
        };

        let (_, scope_val) = map
            .iter()
            .find(|(k, _)| *k == Value::Integer(327.into()))
            .expect("missing MoQT claim 327");

        // Must be an inline Array, NOT a Bytes (bstr-wrapped)
        match scope_val {
            Value::Array(scopes) => {
                // Publisher: ClientSetup + publisher scope = 2 scopes
                assert_eq!(scopes.len(), 2, "publisher should have 2 scopes");
            }
            Value::Bytes(_) => panic!("scopes must be inline array, not bstr-wrapped"),
            other => panic!("expected array, got {:?}", other),
        }
    }

    #[test]
    fn c4m_minter_default_lifetime() {
        let pem = generate_test_key_pem();
        let minter = C4mMinter::new(&pem, "i".into(), "a".into(), 3600).unwrap();

        let ns_parts: Vec<&[u8]> = vec![b"ns"];
        let result = minter
            .mint(&MintRequest {
                subject: "u",
                namespace_parts: &ns_parts,
                role: TokenRole::Subscriber,
                lifetime_secs: 0,
            })
            .unwrap();

        assert_eq!(result.expires_in, 3600, "zero lifetime should use default");
    }

    #[test]
    fn c4m_minter_pubsub_has_three_scopes() {
        let pem = generate_test_key_pem();
        let minter = C4mMinter::new(&pem, "i".into(), "a".into(), 60).unwrap();

        let ns_parts: Vec<&[u8]> = vec![b"ns"];
        let result = minter
            .mint(&MintRequest {
                subject: "u",
                namespace_parts: &ns_parts,
                role: TokenRole::PubSub,
                lifetime_secs: 60,
            })
            .unwrap();

        let cose_bytes = URL_SAFE_NO_PAD.decode(&result.token).unwrap();
        let cbor: Value = ciborium::de::from_reader(&cose_bytes[..]).unwrap();
        let payload_bytes = match cbor {
            Value::Tag(18, inner) => match *inner {
                Value::Array(items) => match &items[2] {
                    Value::Bytes(b) => b.clone(),
                    _ => panic!("expected bytes"),
                },
                _ => panic!("expected array"),
            },
            _ => panic!("expected tag"),
        };

        let payload: Value = ciborium::de::from_reader(&payload_bytes[..]).unwrap();
        let map = match payload {
            Value::Map(m) => m,
            _ => panic!("not a map"),
        };
        let (_, scope_val) = map
            .iter()
            .find(|(k, _)| *k == Value::Integer(327.into()))
            .expect("missing MoQT claim");

        match scope_val {
            Value::Array(arr) => assert_eq!(arr.len(), 3, "PubSub = ClientSetup + pub + sub"),
            _ => panic!("expected array"),
        }
    }

    #[test]
    fn c4m_minter_invalid_pem_fails() {
        let result = C4mMinter::new("not a real pem", "i".into(), "a".into(), 60);
        assert!(result.is_err());
    }
}
