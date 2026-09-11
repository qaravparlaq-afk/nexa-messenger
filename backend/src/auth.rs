use axum::http::{HeaderMap, Method};
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use sha2::{Digest, Sha256};
use std::{collections::{HashMap, VecDeque}, sync::Arc, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
use tokio::sync::Mutex;

const DOMAIN: &[u8] = b"M/relay-auth/v1";
const DEVICE_ID_DOMAIN: &[u8] = b"M/device-id/v1";
const MAX_CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;
const NONCE_TTL: Duration = Duration::from_secs(5 * 60);
// Must cover the maximum number of accepted requests during the nonce TTL.
// RATE_LIMIT_PER_DEVICE allows up to 600 requests in five minutes.
const MAX_NONCES_PER_DEVICE: usize = 1024;
const RATE_WINDOW: Duration = Duration::from_secs(60);
const RATE_LIMIT_PER_DEVICE: u32 = 120;

const H_DEVICE_ID: &str = "x-m-device-id";
const H_PUBLIC_KEY: &str = "x-m-public-key";
const H_TIMESTAMP: &str = "x-m-timestamp";
const H_NONCE: &str = "x-m-nonce";
const H_SIGNATURE: &str = "x-m-signature";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    MissingHeader,
    InvalidHeader,
    InvalidTimestamp,
    InvalidDevice,
    InvalidSignature,
    Replay,
    RateLimited,
}

#[derive(Clone, Default)]
pub struct AuthState {
    inner: Arc<Mutex<AuthInner>>,
}

#[derive(Default)]
struct AuthInner {
    nonces: HashMap<[u8; 16], VecDeque<([u8; 16], Instant)>>,
    rates: HashMap<[u8; 16], (Instant, u32)>,
}

impl AuthState {
    pub async fn authenticate(
        &self,
        headers: &HeaderMap,
        method: &Method,
        path: &str,
        body: &[u8],
    ) -> Result<[u8; 16], AuthError> {
        let device_id = parse_hex::<16>(headers, H_DEVICE_ID)?;
        let public_key_bytes = parse_hex::<32>(headers, H_PUBLIC_KEY)?;
        let timestamp_ms = header(headers, H_TIMESTAMP)?.parse::<u64>().map_err(|_| AuthError::InvalidHeader)?;
        let nonce = parse_hex::<16>(headers, H_NONCE)?;
        let signature = parse_hex::<64>(headers, H_SIGNATURE)?;

        let expected_device = device_id_from_public_key(&public_key_bytes);
        if device_id != expected_device {
            return Err(AuthError::InvalidDevice);
        }

        let now = now_ms();
        if timestamp_ms > now.saturating_add(MAX_CLOCK_SKEW_MS)
            || now.saturating_sub(timestamp_ms) > MAX_CLOCK_SKEW_MS
        {
            return Err(AuthError::InvalidTimestamp);
        }

        let body_hash = Sha256::digest(body);
        let signed = signing_bytes(method, path, &device_id, &public_key_bytes, timestamp_ms, &nonce, &body_hash);
        let key = VerifyingKey::from_bytes(&public_key_bytes).map_err(|_| AuthError::InvalidHeader)?;
        let sig = Signature::from_bytes(&signature);
        key.verify(&signed, &sig).map_err(|_| AuthError::InvalidSignature)?;

        let mut guard = self.inner.lock().await;
        let now_instant = Instant::now();

        let replayed = {
            let queue = guard.nonces.entry(device_id).or_default();
            queue.retain(|(_, expires)| *expires > now_instant);
            queue.iter().any(|(seen, _)| *seen == nonce)
        };
        if replayed {
            return Err(AuthError::Replay);
        }

        {
            let rate = guard.rates.entry(device_id).or_insert((now_instant, 0));
            if now_instant.duration_since(rate.0) >= RATE_WINDOW {
                *rate = (now_instant, 0);
            }
            if rate.1 >= RATE_LIMIT_PER_DEVICE {
                return Err(AuthError::RateLimited);
            }
            rate.1 += 1;
        }

        let queue = guard.nonces.entry(device_id).or_default();
        if queue.len() >= MAX_NONCES_PER_DEVICE {
            queue.pop_front();
        }
        queue.push_back((nonce, now_instant + NONCE_TTL));
        Ok(device_id)
    }
}

pub fn device_id_from_public_key(public_key: &[u8; 32]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(DEVICE_ID_DOMAIN);
    hasher.update(public_key);
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

pub fn signing_bytes(
    method: &Method,
    path: &str,
    device_id: &[u8; 16],
    public_key: &[u8; 32],
    timestamp_ms: u64,
    nonce: &[u8; 16],
    body_hash: &[u8],
) -> Vec<u8> {
    let method = method.as_str().as_bytes();
    let path = path.as_bytes();
    let mut out = Vec::with_capacity(DOMAIN.len() + 2 + method.len() + 4 + path.len() + 16 + 32 + 8 + 16 + 32);
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(&(method.len() as u16).to_be_bytes());
    out.extend_from_slice(method);
    out.extend_from_slice(&(path.len() as u32).to_be_bytes());
    out.extend_from_slice(path);
    out.extend_from_slice(device_id);
    out.extend_from_slice(public_key);
    out.extend_from_slice(&timestamp_ms.to_be_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(body_hash);
    out
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, AuthError> {
    headers.get(name).ok_or(AuthError::MissingHeader)?.to_str().map_err(|_| AuthError::InvalidHeader)
}

fn parse_hex<const N: usize>(headers: &HeaderMap, name: &str) -> Result<[u8; N], AuthError> {
    let value = header(headers, name)?;
    if value.len() != N * 2 {
        return Err(AuthError::InvalidHeader);
    }
    let bytes = value.as_bytes();
    let mut out = [0u8; N];
    for i in 0..N {
        let hi = hex_nibble(bytes[i * 2]).ok_or(AuthError::InvalidHeader)?;
        let lo = hex_nibble(bytes[i * 2 + 1]).ok_or(AuthError::InvalidHeader)?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use ed25519_dalek::{Signer, SigningKey};

    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    fn signed_headers(key: &SigningKey, method: Method, path: &str, body: &[u8], timestamp: u64, nonce: [u8; 16]) -> HeaderMap {
        let public = key.verifying_key().to_bytes();
        let device = device_id_from_public_key(&public);
        let hash = Sha256::digest(body);
        let signature = key.sign(&signing_bytes(&method, path, &device, &public, timestamp, &nonce, &hash));
        let mut h = HeaderMap::new();
        h.insert(H_DEVICE_ID, HeaderValue::from_str(&hex(&device)).unwrap());
        h.insert(H_PUBLIC_KEY, HeaderValue::from_str(&hex(&public)).unwrap());
        h.insert(H_TIMESTAMP, HeaderValue::from_str(&timestamp.to_string()).unwrap());
        h.insert(H_NONCE, HeaderValue::from_str(&hex(&nonce)).unwrap());
        h.insert(H_SIGNATURE, HeaderValue::from_str(&hex(&signature.to_bytes())).unwrap());
        h
    }

    fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

    #[tokio::test]
    async fn valid_signature_authenticates() {
        let key = test_key();
        let auth = AuthState::default();
        let headers = signed_headers(&key, Method::POST, "/v1/relay", b"ciphertext", now_ms(), [7; 16]);
        assert!(auth.authenticate(&headers, &Method::POST, "/v1/relay", b"ciphertext").await.is_ok());
    }

    #[tokio::test]
    async fn tampering_is_rejected() {
        let key = test_key();
        let auth = AuthState::default();
        let headers = signed_headers(&key, Method::POST, "/v1/relay", b"a", now_ms(), [8; 16]);
        assert_eq!(auth.authenticate(&headers, &Method::POST, "/v1/relay", b"b").await, Err(AuthError::InvalidSignature));
    }

    #[tokio::test]
    async fn nonce_replay_is_rejected() {
        let key = test_key();
        let auth = AuthState::default();
        let headers = signed_headers(&key, Method::GET, "/v1/relay/abc", b"", now_ms(), [9; 16]);
        assert!(auth.authenticate(&headers, &Method::GET, "/v1/relay/abc", b"").await.is_ok());
        assert_eq!(auth.authenticate(&headers, &Method::GET, "/v1/relay/abc", b"").await, Err(AuthError::Replay));
    }

    #[test]
    fn nonce_capacity_covers_rate_window_and_ttl() {
        let max_requests_during_ttl = RATE_LIMIT_PER_DEVICE as usize * (NONCE_TTL.as_secs() / RATE_WINDOW.as_secs());
        assert!(MAX_NONCES_PER_DEVICE >= max_requests_during_ttl);
    }

    #[test]
    fn device_id_is_deterministic() {
        let key = test_key();
        let public = key.verifying_key().to_bytes();
        assert_eq!(device_id_from_public_key(&public), device_id_from_public_key(&public));
    }
}
