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
use nexa_protocol::{decode_message_ack, EncryptedMessage};
use nexa_transport::{Frame, FrameKind, MAX_FRAME};
use relay::{PushResult, RelayStore};
use std::{collections::HashMap, net::SocketAddr, str::FromStr, sync::{atomic::{AtomicU64, Ordering}, Arc}, time::Duration};
use tokio::{sync::{mpsc, Mutex}, time::{timeout, Instant}};

const WS_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const WS_HELLO_TIMEOUT: Duration = Duration::from_secs(15);
const WS_MAX_MESSAGE: usize = MAX_FRAME + 8;
const LIVE_CHANNEL_CAPACITY: usize = 256;

#[derive(Clone)]
struct ConnectionRegistry {
    inner: Arc<Mutex<HashMap<[u8; 16], (u64, mpsc::Sender<EncryptedMessage>)>>>,
    next_id: Arc<AtomicU64>,
}

impl Default for ConnectionRegistry {
    fn default() -> Self {
        Self { inner: Arc::new(Mutex::new(HashMap::new())), next_id: Arc::new(AtomicU64::new(1)) }
    }
}

impl ConnectionRegistry {
    async fn register(&self, device: [u8; 16]) -> (u64, mpsc::Receiver<EncryptedMessage>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = mpsc::channel(LIVE_CHANNEL_CAPACITY);
        let mut guard = self.inner.lock().await;
        guard.insert(device, (id, sender));
        (id, receiver)
    }

    async fn unregister(&self, device: [u8; 16], id: u64) {
        let mut guard = self.inner.lock().await;
        if guard.get(&device).map(|(current_id, _)| *current_id == id).unwrap_or(false) { guard.remove(&device); }
    }

    async fn try_send(&self, device: [u8; 16], message: EncryptedMessage) {
        let sender = {
            let guard = self.inner.lock().await;
            guard.get(&device).map(|(_, sender)| sender.clone())
        };
        if let Some(sender) = sender { let _ = sender.try_send(message); }
    }
}

#[derive(Clone)]
struct AppState { relay: RelayStore, auth: auth::AuthState, connections: ConnectionRegistry }

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"service":"nexa-gateway","status":"ok","plaintext_storage":false,"environment":"development","authentication":"ed25519","websocket":true,"live_routing":true}))
}

async fn enqueue(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Result<StatusCode, StatusCode> {
    let device = state.auth.authenticate(&headers, &Method::POST, "/v1/relay", &body).await.map_err(auth_status)?;
    let message: EncryptedMessage = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    if message.sender_device_id != device { return Err(StatusCode::FORBIDDEN); }
    let recipient = message.recipient_device_id;
    let response = match state.relay.push(message.clone()).await {
        PushResult::Accepted => { state.connections.try_send(recipient, message).await; StatusCode::ACCEPTED }
        PushResult::Duplicate => StatusCode::CONFLICT,
        PushResult::Invalid => StatusCode::BAD_REQUEST,
        PushResult::Full => StatusCode::TOO_MANY_REQUESTS,
    };
    Ok(response)
}

async fn poll(State(state): State<AppState>, headers: HeaderMap, Path(device): Path<String>) -> Result<Json<Vec<EncryptedMessage>>, StatusCode> {
    let bytes = hex_to_16(&device).ok_or(StatusCode::BAD_REQUEST)?;
    let path = format!("/v1/relay/{device}");
    let authenticated = state.auth.authenticate(&headers, &Method::GET, &path, &[]).await.map_err(auth_status)?;
    if authenticated != bytes { return Err(StatusCode::FORBIDDEN); }
    Ok(Json(state.relay.pull(bytes).await))
}

async fn ack(State(state): State<AppState>, headers: HeaderMap, Path((device, message_id)): Path<(String, String)>) -> Result<StatusCode, StatusCode> {
    let device_id = hex_to_16(&device).ok_or(StatusCode::BAD_REQUEST)?;
    let message_id_bytes = hex_to_16(&message_id).ok_or(StatusCode::BAD_REQUEST)?;
    let path = format!("/v1/relay/{device}/{message_id}/ack");
    let authenticated = state.auth.authenticate(&headers, &Method::POST, &path, &[]).await.map_err(auth_status)?;
    if authenticated != device_id { return Err(StatusCode::FORBIDDEN); }
    if state.relay.ack(device_id, message_id_bytes).await { Ok(StatusCode::NO_CONTENT) } else { Ok(StatusCode::NOT_FOUND) }
}

async fn websocket(State(state): State<AppState>, headers: HeaderMap, upgrade: WebSocketUpgrade) -> Result<Response, StatusCode> {
    let device = state.auth.authenticate(&headers, &Method::GET, "/v1/ws", &[]).await.map_err(auth_status)?;
    Ok(upgrade.max_frame_size(WS_MAX_MESSAGE).max_message_size(WS_MAX_MESSAGE).on_upgrade(move |socket| websocket_session(socket, device, state.relay, state.connections)))
}

async fn websocket_session(mut socket: WebSocket, device: [u8; 16], relay: RelayStore, connections: ConnectionRegistry) {
    let first = match timeout(WS_HELLO_TIMEOUT, socket.next()).await {
        Ok(Some(Ok(message))) => message,
        _ => { close(&mut socket).await; return; }
    };

    let Message::Binary(bytes) = first else { close(&mut socket).await; return; };
    if bytes.len() > WS_MAX_MESSAGE { close(&mut socket).await; return; }
    let Ok(frame) = Frame::from_bytes(&bytes) else { close(&mut socket).await; return; };
    let Ok(kind) = frame.kind() else { close(&mut socket).await; return; };
    if kind != FrameKind::ClientHello || frame.payload != device { close(&mut socket).await; return; }

    let (connection_id, mut outbound) = connections.register(device).await;
    if let Err(()) = send_hello(&mut socket, device).await {
        connections.unregister(device, connection_id).await;
        return;
    }

    for message in relay.pull(device).await {
        if send_encrypted(&mut socket, message).await.is_err() {
            connections.unregister(device, connection_id).await;
            return;
        }
    }

    let mut last_activity = Instant::now();
    loop {
        let idle_deadline = last_activity + WS_IDLE_TIMEOUT;
        tokio::select! {
            _ = tokio::time::sleep_until(idle_deadline) => {
                close(&mut socket).await;
                connections.unregister(device, connection_id).await;
                return;
            }
            inbound = socket.next() => {
                let Some(result) = inbound else { connections.unregister(device, connection_id).await; return; };
                let Ok(message) = result else { connections.unregister(device, connection_id).await; return; };
                last_activity = Instant::now();
                match handle_authenticated_message(&mut socket, message, device, &relay, &connections).await {
                    Ok(true) => {}
                    Ok(false) | Err(()) => { connections.unregister(device, connection_id).await; return; }
                }
            }
            outbound_result = outbound.recv() => {
                match outbound_result {
                    Some(message) => {
                        if send_encrypted(&mut socket, message).await.is_err() {
                            connections.unregister(device, connection_id).await;
                            return;
                        }
                    }
                    None => {
                        connections.unregister(device, connection_id).await;
                        return;
                    }
                }
            }
        }
    }
}

async fn handle_authenticated_message(socket: &mut WebSocket, message: Message, device: [u8; 16], relay: &RelayStore, connections: &ConnectionRegistry) -> Result<bool, ()> {
    match message {
        Message::Binary(bytes) => {
            if bytes.len() > WS_MAX_MESSAGE { close(socket).await; return Err(()); }
            let frame = Frame::from_bytes(&bytes).map_err(|_| ())?;
            let kind = frame.kind().map_err(|_| ())?;
            match kind {
                FrameKind::Ping => {
                    let pong = Frame::new(FrameKind::Pong, 0, frame.payload).map_err(|_| ())?;
                    let bytes = pong.to_bytes().map_err(|_| ())?;
                    socket.send(Message::Binary(bytes.into())).await.map_err(|_| ())?;
                }
                FrameKind::Pong => {}
                FrameKind::EncryptedMessage => {
                    let message = EncryptedMessage::decode(&frame.payload).map_err(|_| ())?;
                    if message.sender_device_id != device { close(socket).await; return Err(()); }
                    let recipient = message.recipient_device_id;
                    match relay.push(message.clone()).await {
                        PushResult::Accepted => { connections.try_send(recipient, message).await; }
                        PushResult::Duplicate => {}
                        PushResult::Invalid | PushResult::Full => { close(socket).await; return Err(()); }
                    }
                }
                FrameKind::MessageAck => {
                    let message_id = decode_message_ack(&frame.payload).map_err(|_| ())?;
                    let _ = relay.ack(device, message_id).await;
                }
                FrameKind::ClientHello | FrameKind::MessageBatch | FrameKind::PreKeyBundle | FrameKind::PreKeyRequest => {
                    close(socket).await;
                    return Err(());
                }
            }
            Ok(true)
        }
        Message::Ping(bytes) => {
            socket.send(Message::Pong(bytes)).await.map_err(|_| ())?;
            Ok(true)
        }
        Message::Pong(_) => Ok(true),
        Message::Text(_) | Message::Close(_) => Ok(false),
    }
}

async fn send_hello(socket: &mut WebSocket, device: [u8; 16]) -> Result<(), ()> {
    let reply = Frame::new(FrameKind::ClientHello, 1, device.to_vec()).map_err(|_| ())?;
    let bytes = reply.to_bytes().map_err(|_| ())?;
    socket.send(Message::Binary(bytes.into())).await.map_err(|_| ())
}

async fn send_encrypted(socket: &mut WebSocket, message: EncryptedMessage) -> Result<(), ()> {
    let payload = message.encode().map_err(|_| ())?;
    let frame = Frame::new(FrameKind::EncryptedMessage, 0, payload).map_err(|_| ())?;
    let bytes = frame.to_bytes().map_err(|_| ())?;
    socket.send(Message::Binary(bytes.into())).await.map_err(|_| ())
}

async fn close(socket: &mut WebSocket) { let _ = socket.send(Message::Close(None)).await; }

fn auth_status(error: auth::AuthError) -> StatusCode {
    match error {
        auth::AuthError::MissingHeader | auth::AuthError::InvalidHeader | auth::AuthError::InvalidTimestamp | auth::AuthError::InvalidDevice | auth::AuthError::InvalidSignature | auth::AuthError::Replay => StatusCode::UNAUTHORIZED,
        auth::AuthError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
    }
}

fn hex_to_16(input: &str) -> Option<[u8; 16]> {
    if input.len() != 32 { return None; }
    let mut out = [0u8; 16];
    for (i, slot) in out.iter_mut().enumerate() { *slot = u8::from_str_radix(&input[i * 2..i * 2 + 2], 16).ok()?; }
    Some(out)
}

#[tokio::main]
async fn main() {
    let state = AppState { relay: RelayStore::default(), auth: auth::AuthState::default(), connections: ConnectionRegistry::default() };
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
    if production && !insecure_allowed { panic!("production requires TLS termination; set NEXA_ALLOW_INSECURE_HTTP=true only for an explicitly trusted local/private deployment"); }
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind gateway");
    println!("NEXA gateway listening on {addr}");
    axum::serve(listener, app).await.expect("serve gateway");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn registry_replaces_stale_connection_without_stale_unregister() {
        let registry = ConnectionRegistry::default();
        let device = [7u8; 16];
        let (old_id, _old_rx) = registry.register(device).await;
        let (new_id, mut new_rx) = registry.register(device).await;
        assert_ne!(old_id, new_id);
        registry.unregister(device, old_id).await;
        registry.try_send(device, EncryptedMessage::new([1; 16], [2; 16], [3; 16], device, vec![4], vec![5], 1)).await;
        assert!(new_rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn registry_backpressure_never_blocks_sender() {
        let registry = ConnectionRegistry::default();
        let device = [8u8; 16];
        let (_id, _rx) = registry.register(device).await;
        for i in 0..LIVE_CHANNEL_CAPACITY { registry.try_send(device, EncryptedMessage::new([i as u8 + 1; 16], [2; 16], [3; 16], device, vec![4], vec![5], 1)).await; }
        registry.try_send(device, EncryptedMessage::new([255; 16], [2; 16], [3; 16], device, vec![4], vec![5], 1)).await;
    }
}
