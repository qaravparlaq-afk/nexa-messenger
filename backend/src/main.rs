mod auth;
mod relay;

use axum::{
    body::Bytes,
    extract::{ws::{Message, WebSocket, WebSocketUpgrade}, Path, State},
    http::{HeaderMap, Method, StatusCode},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use futures_util::{SinkExt, StreamExt};
use nexa_protocol::EncryptedMessage;
use nexa_transport::{Frame, FrameKind, MAX_FRAME};
use relay::{PushResult, RelayStore};
use std::{net::SocketAddr, str::FromStr, time::Duration};
use tokio::time::{timeout, Instant};

const WS_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const WS_MAX_MESSAGE: usize = MAX_FRAME + 8;

#[derive(Clone)]
struct AppState {
    relay: RelayStore,
    auth: auth::AuthState,
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "service": "nexa-gateway",
        "status": "ok",
        "plaintext_storage": false,
        "environment": "development",
        "authentication": "ed25519",
        "websocket": true
    }))
}

async fn enqueue(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, StatusCode> {
    let device = state.auth.authenticate(&headers, &Method::POST, "/v1/relay", &body)
        .await.map_err(auth_status)?;
    let message: EncryptedMessage = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    if message.sender_device_id != device {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(match state.relay.push(message).await {
        PushResult::Accepted => StatusCode::ACCEPTED,
        PushResult::Duplicate => StatusCode::CONFLICT,
        PushResult::Invalid => StatusCode::BAD_REQUEST,
        PushResult::Full => StatusCode::TOO_MANY_REQUESTS,
    })
}

async fn poll(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device): Path<String>,
) -> Result<Json<Vec<EncryptedMessage>>, StatusCode> {
    let bytes = hex_to_16(&device).ok_or(StatusCode::BAD_REQUEST)?;
    let path = format!("/v1/relay/{device}");
    let authenticated = state.auth.authenticate(&headers, &Method::GET, &path, &[])
        .await.map_err(auth_status)?;
    if authenticated != bytes {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(Json(state.relay.pull(bytes).await))
}

async fn ack(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((device, message_id)): Path<(String, String)>,
) -> Result<StatusCode, StatusCode> {
    let device_id = hex_to_16(&device).ok_or(StatusCode::BAD_REQUEST)?;
    let message_id = hex_to_16(&message_id).ok_or(StatusCode::BAD_REQUEST)?;
    let path = format!("/v1/relay/{device}/{message_id}/ack");
    let authenticated = state.auth.authenticate(&headers, &Method::POST, &path, &[])
        .await.map_err(auth_status)?;
    if authenticated != device_id {
        return Err(StatusCode::FORBIDDEN);
    }
    if state.relay.ack(device_id, message_id).await {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Ok(StatusCode::NOT_FOUND)
    }
}

/// Authenticates the WebSocket upgrade with the same Ed25519 request signature as HTTP.
/// After upgrade, the gateway only validates the binary transport envelope and never decrypts payloads.
async fn websocket(
    State(state): State<AppState>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Result<Response, StatusCode> {
    let device = state.auth.authenticate(&headers, &Method::GET, "/v1/ws", &[])
        .await.map_err(auth_status)?;
    Ok(upgrade
        .max_frame_size(WS_MAX_MESSAGE)
        .max_message_size(WS_MAX_MESSAGE)
        .on_upgrade(move |socket| websocket_session(socket, device)))
}

async fn websocket_session(mut socket: WebSocket, device: [u8; 16]) {
    let mut last_activity = Instant::now();
    let _device = device;

    loop {
        let remaining = WS_IDLE_TIMEOUT.saturating_sub(last_activity.elapsed());
        if remaining.is_zero() {
            let _ = socket.send(Message::Close(None)).await;
            return;
        }

        let next = match timeout(remaining, socket.next()).await {
            Ok(value) => value,
            Err(_) => {
                let _ = socket.send(Message::Close(None)).await;
                return;
            }
        };

        let Some(result) = next else { return };
        let Ok(message) = result else { return };
        last_activity = Instant::now();

        match message {
            Message::Binary(bytes) => {
                if bytes.len() > WS_MAX_MESSAGE {
                    let _ = socket.send(Message::Close(None)).await;
                    return;
                }
                let Ok(frame) = Frame::from_bytes(&bytes) else {
                    let _ = socket.send(Message::Close(None)).await;
                    return;
                };
                match frame.kind() {
                    Ok(FrameKind::Ping) => {
                        if let Ok(pong) = Frame::new(FrameKind::Pong, 0, frame.payload.clone()) {
                            if let Ok(bytes) = pong.to_bytes() {
                                if socket.send(Message::Binary(bytes.into())).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                    Ok(FrameKind::Pong) => {}
                    Ok(FrameKind::ClientHello)
                    | Ok(FrameKind::EncryptedMessage)
                    | Ok(FrameKind::MessageAck)
                    | Ok(FrameKind::MessageBatch)
                    | Ok(FrameKind::PreKeyBundle)
                    | Ok(FrameKind::PreKeyRequest) => {
                        // Payload is intentionally opaque at this layer.
                        // Routing/persistence is handled by later protocol stages.
                    }
                    Err(_) => return,
                }
            }
            Message::Ping(bytes) => {
                if socket.send(Message::Pong(bytes)).await.is_err() {
                    return;
                }
            }
            Message::Pong(_) => {}
            Message::Text(_) => {
                let _ = socket.send(Message::Close(None)).await;
                return;
            }
            Message::Close(_) => return,
        }
    }
}

fn auth_status(error: auth::AuthError) -> StatusCode {
    match error {
        auth::AuthError::MissingHeader
        | auth::AuthError::InvalidHeader
        | auth::AuthError::InvalidTimestamp
        | auth::AuthError::InvalidDevice
        | auth::AuthError::InvalidSignature
        | auth::AuthError::Replay => StatusCode::UNAUTHORIZED,
        auth::AuthError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
    }
}

fn hex_to_16(input: &str) -> Option<[u8; 16]> {
    if input.len() != 32 { return None; }
    let mut out = [0u8; 16];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&input[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[tokio::main]
async fn main() {
    let state = AppState { relay: RelayStore::default(), auth: auth::AuthState::default() };
    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/relay", post(enqueue))
        .route("/v1/relay/{device_id}", get(poll))
        .route("/v1/relay/{device_id}/{message_id}/ack", post(ack))
        .route("/v1/ws", get(websocket))
        .with_state(state);

    let bind = std::env::var("NEXA_BIND").unwrap_or_else(|_| "127.0.0.1:8787".into());
    let addr = SocketAddr::from_str(&bind).expect("valid NEXA_BIND");
    let production = std::env::var("NEXA_ENV").map(|v| v.eq_ignore_ascii_case("production")).unwrap_or(false);
    let insecure_allowed = std::env::var("NEXA_ALLOW_INSECURE_HTTP").map(|v| v == "true").unwrap_or(false);
    if production && !insecure_allowed {
        panic!("production requires TLS termination; set NEXA_ALLOW_INSECURE_HTTP=true only for an explicitly trusted local/private deployment");
    }
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind gateway");
    println!("NEXA gateway listening on {addr}");
    axum::serve(listener, app).await.expect("serve gateway");
}
