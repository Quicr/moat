//! C4M (CAT4MoQT) token minter.
//!
//! Produces COSE_Sign1 tokens with ES256 signatures carrying MoQT scopes.
//! Scopes use claim key 65000 (bstr-wrapped CBOR) to match relay expectations.
//! Namespace fields are encoded in the relay's canonical form: [4-byte-BE-len][field]...

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use cat_token::{CatTokenBuilder, CryptographicAlgorithm, Es256Algorithm};
use ciborium::Value;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;

use super::{MintRequest, MintedToken, TokenMinter, TokenRole};

const C4M_TOKEN_TYPE: u64 = 6501485;
/// MoQT scope claim key — matches relay/catapult expectation (not the cat-token default of 327).
const CLAIM_MOQT: i64 = 65000;

pub struct C4mMinter {
    signing_key: Es256Algorithm,
    raw_signing_key: SigningKey,
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
        let signing_key = Es256Algorithm::from_key_pair(sk.clone(), vk);

        Ok(Self {
            signing_key,
            raw_signing_key: sk,
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

        // The relay canonicalizes namespaces as [4-byte-BE-len][field]... for each element,
        // then applies match rules against that single byte string.
        let canonical_ns = canonical_namespace(request.namespace_parts);

        let mut moqt_scopes: Vec<Value> = Vec::with_capacity(3);

        // Scope 0: ClientSetup (action 0 — no namespace constraint)
        moqt_scopes.push(Value::Array(vec![Value::Array(vec![Value::Integer(
            0.into(),
        )])]));

        // Publisher scope: actions [2 (PublishNamespace), 6 (Publish)]
        if matches!(request.role, TokenRole::Publisher | TokenRole::PubSub) {
            moqt_scopes.push(build_scope(&[2, 6], &canonical_ns));
        }

        // Subscriber scope: actions [3 (SubscribeNamespace), 4 (Subscribe), 7 (Fetch)]
        if matches!(request.role, TokenRole::Subscriber | TokenRole::PubSub) {
            moqt_scopes.push(build_scope(&[3, 4, 7], &canonical_ns));
        }

        // Build base token (without MoQT scopes — we inject those manually)
        let token = CatTokenBuilder::new()
            .issuer(&self.issuer)
            .single_audience(&self.audience)
            .subject(request.subject)
            .expires_in(lifetime as i64)
            .build();

        let token_string = encode_cose_sign1(
            &token,
            &self.signing_key,
            &self.raw_signing_key,
            &moqt_scopes,
        )?;

        Ok(MintedToken {
            token: token_string,
            token_type: C4M_TOKEN_TYPE,
            expires_in: lifetime,
        })
    }
}

/// Build a scope entry: [[actions...], [ns_prefix_match], track_match]
fn build_scope(actions: &[i64], canonical_ns: &[u8]) -> Value {
    let actions_arr = Value::Array(actions.iter().map(|&a| Value::Integer(a.into())).collect());
    // Single prefix match on the canonical namespace bytes
    let ns_match = Value::Array(vec![Value::Array(vec![
        Value::Integer(1.into()), // PREFIX match type
        Value::Bytes(canonical_ns.to_vec()),
    ])]);
    // Empty track match = matches any track
    let track_match = Value::Bytes(vec![]);
    Value::Array(vec![actions_arr, ns_match, track_match])
}

/// Encode namespace parts as the relay's canonical form: [4-byte-BE-len][bytes]...
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

/// Encode a CatToken + MoQT scopes as base64url(COSE_Sign1 CBOR).
fn encode_cose_sign1(
    token: &cat_token::CatToken,
    algorithm: &Es256Algorithm,
    raw_key: &SigningKey,
    moqt_scopes: &[Value],
) -> anyhow::Result<String> {
    use cat_token::Cwt;

    let alg_id = algorithm.algorithm_id();

    // Build protected header CBOR
    let cwt = Cwt::new(alg_id, token.clone());
    let mut header_map = std::collections::BTreeMap::new();
    header_map.insert(1i64, Value::Integer(alg_id.into()));
    if let Some(ref typ) = cwt.header.typ {
        header_map.insert(16i64, Value::Text(typ.clone()));
    }

    let header_cbor_map: Vec<(Value, Value)> = header_map
        .into_iter()
        .map(|(k, v)| (Value::Integer(k.into()), v))
        .collect();

    let mut protected_header = Vec::with_capacity(32);
    ciborium::ser::into_writer(&Value::Map(header_cbor_map), &mut protected_header)
        .map_err(|e| anyhow::anyhow!("header CBOR encode failed: {e}"))?;

    // Build payload: use cat-token for standard CWT claims, then inject MoQT scopes
    let payload = build_payload(&cwt, moqt_scopes)?;

    // Build COSE Sig_structure for signing:
    // ["Signature1", bstr(protected_header), bstr(external_aad), bstr(payload)]
    let sig_structure = Value::Array(vec![
        Value::Text("Signature1".to_string()),
        Value::Bytes(protected_header.clone()),
        Value::Bytes(vec![]),
        Value::Bytes(payload.clone()),
    ]);

    let mut signing_input = Vec::with_capacity(128);
    ciborium::ser::into_writer(&sig_structure, &mut signing_input)
        .map_err(|e| anyhow::anyhow!("sig_structure CBOR encode failed: {e}"))?;

    // Sign with ES256 — DER-encoded for OpenSSL compatibility
    let signature: Signature = raw_key.sign(&signing_input);
    let sig_der = signature.to_der();

    // COSE_Sign1 = [bstr(protected), map(unprotected), bstr(payload), bstr(signature)]
    let cose_sign1 = Value::Array(vec![
        Value::Bytes(protected_header),
        Value::Map(vec![]),
        Value::Bytes(payload),
        Value::Bytes(sig_der.as_bytes().to_vec()),
    ]);

    let mut cose_bytes = Vec::with_capacity(256);
    ciborium::ser::into_writer(&cose_sign1, &mut cose_bytes)
        .map_err(|e| anyhow::anyhow!("COSE_Sign1 CBOR encode failed: {e}"))?;

    Ok(URL_SAFE_NO_PAD.encode(&cose_bytes))
}

/// Build the CWT payload CBOR map with standard claims + MoQT scopes (key 65000, bstr-wrapped).
fn build_payload(cwt: &cat_token::Cwt, moqt_scopes: &[Value]) -> anyhow::Result<Vec<u8>> {
    // Get base claims from cat-token (excludes MoQT since we didn't add any scopes to token)
    let base_raw = cwt
        .encode_payload()
        .map_err(|e| anyhow::anyhow!("payload encode failed: {e}"))?;

    let base: Value = ciborium::de::from_reader(&base_raw[..])
        .map_err(|e| anyhow::anyhow!("CBOR decode payload failed: {e}"))?;

    let mut map = match base {
        Value::Map(entries) => entries,
        _ => anyhow::bail!("expected CBOR map in payload"),
    };

    // Encode MoQT scopes array to bytes, then add as bstr under key 65000
    let scopes_value = Value::Array(moqt_scopes.to_vec());
    let mut scopes_bytes = Vec::with_capacity(128);
    ciborium::ser::into_writer(&scopes_value, &mut scopes_bytes)
        .map_err(|e| anyhow::anyhow!("MoQT scopes CBOR encode failed: {e}"))?;

    map.push((
        Value::Integer(CLAIM_MOQT.into()),
        Value::Bytes(scopes_bytes),
    ));

    let mut out = Vec::with_capacity(256);
    ciborium::ser::into_writer(&Value::Map(map), &mut out)
        .map_err(|e| anyhow::anyhow!("payload CBOR encode failed: {e}"))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_namespace_empty() {
        let result = canonical_namespace(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn canonical_namespace_single_part() {
        let result = canonical_namespace(&[b"hello"]);
        // Should be: 4-byte BE length (5) + b"hello"
        let mut expected = Vec::new();
        expected.extend_from_slice(&5u32.to_be_bytes());
        expected.extend_from_slice(b"hello");
        assert_eq!(result, expected);
    }

    #[test]
    fn canonical_namespace_multiple_parts() {
        let result = canonical_namespace(&[b"abc", b"de"]);
        let mut expected = Vec::new();
        expected.extend_from_slice(&3u32.to_be_bytes());
        expected.extend_from_slice(b"abc");
        expected.extend_from_slice(&2u32.to_be_bytes());
        expected.extend_from_slice(b"de");
        assert_eq!(result, expected);
    }

    #[test]
    fn canonical_namespace_known_output() {
        // "moq" => len=3 (0x00000003) + "moq"
        let result = canonical_namespace(&[b"moq"]);
        assert_eq!(result, vec![0x00, 0x00, 0x00, 0x03, b'm', b'o', b'q']);
    }

    #[test]
    fn canonical_namespace_empty_part() {
        let result = canonical_namespace(&[b""]);
        // 4-byte BE length (0) + empty bytes
        assert_eq!(result, vec![0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn build_scope_structure() {
        let ns = canonical_namespace(&[b"test"]);
        let scope = build_scope(&[2, 6], &ns);

        // Should be an Array of 3 elements: [actions, ns_match, track_match]
        match scope {
            Value::Array(ref items) => {
                assert_eq!(items.len(), 3, "scope should have 3 elements");

                // First element: array of action integers
                match &items[0] {
                    Value::Array(actions) => {
                        assert_eq!(actions.len(), 2);
                        assert_eq!(actions[0], Value::Integer(2.into()));
                        assert_eq!(actions[1], Value::Integer(6.into()));
                    }
                    other => panic!("expected actions array, got {:?}", other),
                }

                // Second element: namespace match array
                match &items[1] {
                    Value::Array(ns_matches) => {
                        assert_eq!(ns_matches.len(), 1);
                        match &ns_matches[0] {
                            Value::Array(inner) => {
                                assert_eq!(inner.len(), 2);
                                assert_eq!(inner[0], Value::Integer(1.into())); // PREFIX
                                match &inner[1] {
                                    Value::Bytes(b) => assert_eq!(b, &ns),
                                    other => panic!("expected bytes, got {:?}", other),
                                }
                            }
                            other => panic!("expected inner array, got {:?}", other),
                        }
                    }
                    other => panic!("expected ns_match array, got {:?}", other),
                }

                // Third element: empty bytes (track match)
                assert_eq!(items[2], Value::Bytes(vec![]));
            }
            other => panic!("expected array, got {:?}", other),
        }
    }

    #[test]
    fn build_scope_single_action() {
        let ns = canonical_namespace(&[b"x"]);
        let scope = build_scope(&[0], &ns);
        match scope {
            Value::Array(items) => match &items[0] {
                Value::Array(actions) => {
                    assert_eq!(actions.len(), 1);
                    assert_eq!(actions[0], Value::Integer(0.into()));
                }
                other => panic!("expected actions array, got {:?}", other),
            },
            other => panic!("expected array, got {:?}", other),
        }
    }

    #[test]
    fn build_scope_subscriber_actions() {
        let ns = canonical_namespace(&[b"room", b"123"]);
        let scope = build_scope(&[3, 4, 7], &ns);
        match scope {
            Value::Array(items) => match &items[0] {
                Value::Array(actions) => {
                    assert_eq!(actions.len(), 3);
                    assert_eq!(actions[0], Value::Integer(3.into()));
                    assert_eq!(actions[1], Value::Integer(4.into()));
                    assert_eq!(actions[2], Value::Integer(7.into()));
                }
                other => panic!("expected actions array, got {:?}", other),
            },
            other => panic!("expected array, got {:?}", other),
        }
    }

    // --- build_payload tests ---

    #[test]
    fn build_payload_contains_moqt_scopes_key() {
        use cat_token::Cwt;

        let token = CatTokenBuilder::new()
            .issuer("test-issuer")
            .single_audience("test-audience")
            .subject("user@test")
            .expires_in(3600)
            .build();

        let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let vk = *sk.verifying_key();
        let alg = Es256Algorithm::from_key_pair(sk, vk);
        let cwt = Cwt::new(alg.algorithm_id(), token);

        let ns = canonical_namespace(&[b"room"]);
        let scopes = vec![build_scope(&[2, 6], &ns)];
        let payload_bytes = build_payload(&cwt, &scopes).unwrap();

        // Decode the CBOR payload and check key 65000 exists
        let payload: Value = ciborium::de::from_reader(&payload_bytes[..]).unwrap();
        match payload {
            Value::Map(entries) => {
                let has_moqt = entries.iter().any(|(k, v)| {
                    *k == Value::Integer(CLAIM_MOQT.into()) && matches!(v, Value::Bytes(_))
                });
                assert!(
                    has_moqt,
                    "payload should contain MoQT scopes at key {CLAIM_MOQT}"
                );
            }
            other => panic!("expected CBOR map, got {:?}", other),
        }
    }

    #[test]
    fn build_payload_moqt_scopes_are_valid_cbor() {
        use cat_token::Cwt;

        let token = CatTokenBuilder::new()
            .issuer("issuer")
            .single_audience("audience")
            .subject("sub")
            .expires_in(60)
            .build();

        let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let vk = *sk.verifying_key();
        let alg = Es256Algorithm::from_key_pair(sk, vk);
        let cwt = Cwt::new(alg.algorithm_id(), token);

        let ns = canonical_namespace(&[b"test", b"ns"]);
        let scopes = vec![build_scope(&[2, 6], &ns), build_scope(&[3, 4, 7], &ns)];
        let payload_bytes = build_payload(&cwt, &scopes).unwrap();

        let payload: Value = ciborium::de::from_reader(&payload_bytes[..]).unwrap();
        let map = match payload {
            Value::Map(m) => m,
            _ => panic!("not a map"),
        };

        // Extract the bstr-wrapped scopes and decode them
        let (_, scope_val) = map
            .iter()
            .find(|(k, _)| *k == Value::Integer(CLAIM_MOQT.into()))
            .expect("missing MOQT claim");

        let scope_bytes = match scope_val {
            Value::Bytes(b) => b,
            other => panic!("expected bytes, got {:?}", other),
        };

        // The bstr should be valid CBOR containing an array of scopes
        let decoded: Value = ciborium::de::from_reader(&scope_bytes[..]).unwrap();
        match decoded {
            Value::Array(arr) => assert_eq!(arr.len(), 2, "should have 2 scopes (pub + sub)"),
            other => panic!("expected array, got {:?}", other),
        }
    }

    // --- C4mMinter integration test ---

    fn generate_test_key_pem() -> String {
        use p256::pkcs8::EncodePrivateKey;
        let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        sk.to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .unwrap()
            .to_string()
    }

    #[test]
    fn c4m_minter_mint_publisher() {
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

        assert_eq!(result.token_type, C4M_TOKEN_TYPE);
        assert_eq!(result.expires_in, 300);
        assert!(!result.token.is_empty());

        // Token should be valid base64url
        let decoded = URL_SAFE_NO_PAD.decode(&result.token);
        assert!(decoded.is_ok(), "token should be valid base64url");

        // Decoded bytes should be valid CBOR (COSE_Sign1 array)
        let cbor: Value = ciborium::de::from_reader(&decoded.unwrap()[..]).unwrap();
        match cbor {
            Value::Array(items) => {
                assert_eq!(items.len(), 4, "COSE_Sign1 should have 4 elements");
            }
            other => panic!("expected COSE_Sign1 array, got {:?}", other),
        }
    }

    #[test]
    fn c4m_minter_mint_subscriber() {
        let pem = generate_test_key_pem();
        let minter = C4mMinter::new(&pem, "issuer".into(), "audience".into(), 3600).unwrap();

        let ns_parts: Vec<&[u8]> = vec![b"chat", b"general"];
        let result = minter
            .mint(&MintRequest {
                subject: "sub@test",
                namespace_parts: &ns_parts,
                role: TokenRole::Subscriber,
                lifetime_secs: 0, // should use default
            })
            .unwrap();

        assert_eq!(result.expires_in, 3600, "zero lifetime should use default");
    }

    #[test]
    fn c4m_minter_mint_pubsub_has_both_scopes() {
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

        // Decode and check scopes in the payload
        let cose_bytes = URL_SAFE_NO_PAD.decode(&result.token).unwrap();
        let cose: Value = ciborium::de::from_reader(&cose_bytes[..]).unwrap();
        let payload_bytes = match &cose {
            Value::Array(items) => match &items[2] {
                Value::Bytes(b) => b.clone(),
                _ => panic!("expected payload bytes"),
            },
            _ => panic!("expected array"),
        };

        let payload: Value = ciborium::de::from_reader(&payload_bytes[..]).unwrap();
        let map = match payload {
            Value::Map(m) => m,
            _ => panic!("not a map"),
        };
        let (_, scope_val) = map
            .iter()
            .find(|(k, _)| *k == Value::Integer(CLAIM_MOQT.into()))
            .expect("missing MOQT claim");

        let scope_bytes = match scope_val {
            Value::Bytes(b) => b,
            _ => panic!("not bytes"),
        };
        let scopes: Value = ciborium::de::from_reader(&scope_bytes[..]).unwrap();
        match scopes {
            // ClientSetup + Publisher + Subscriber = 3 scopes
            Value::Array(arr) => assert_eq!(arr.len(), 3, "PubSub should have 3 scopes"),
            _ => panic!("not an array"),
        }
    }

    #[test]
    fn c4m_minter_invalid_pem_fails() {
        let result = C4mMinter::new("not a real pem", "i".into(), "a".into(), 60);
        assert!(result.is_err());
    }

    // --- Namespace with non-ASCII bytes ---

    #[test]
    fn canonical_namespace_unicode_bytes() {
        let result = canonical_namespace(&["日本語".as_bytes()]);
        let expected_bytes = "日本語".as_bytes();
        let mut expected = Vec::new();
        expected.extend_from_slice(&(expected_bytes.len() as u32).to_be_bytes());
        expected.extend_from_slice(expected_bytes);
        assert_eq!(result, expected);
    }
}
