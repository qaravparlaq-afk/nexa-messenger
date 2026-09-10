mod relay;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use nexa_protocol::EncryptedMessage;
use relay::{PushResult, RelayStore};
use std::{net::SocketAddr, str::FromStr};

#[derive(Clone)]
struct AppState {
    relay: RelayStore,
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "service": "nexa-gateway",
        "status": "ok",
        "plaintext_storage": false,
        "environment": "development"
    }))
}

async fn enqueue(
    State(state): State<AppState>,
    Json(message): Json<EncryptedMessage>,
) -> StatusCode {
    match state.relay.push(message).await {
        PushResult::Accepted => StatusCode::ACCEPTED,
        PushResult::Duplicate => StatusCode::CONFLICT,
        PushResult::Invalid => StatusCode::BAD_REQUEST,
        PushResult::Full => StatusCode::TOO_MANY_REQUESTS,
    }
}

async fn poll(
    State(state): State<AppState>,
    Path(device): Path<String>,
) -> Result<Json<Vec<EncryptedMessage>>, StatusCode> {
    let bytes = hex_to_16(&device).ok_or(StatusCode::BAD_REQUEST)?;
    Ok(Json(state.relay.pull(bytes).await))
}

async fn ack(
    State(state): State<AppState>,
    Path((device, message_id)): Path<(String, String)>,
) -> Result<StatusCode, StatusCode> {
    let device_id = hex_to_16(&device).ok_or(StatusCode::BAD_REQUEST)?;
    let message_id = hex_to_16(&message_id).ok_or(StatusCode::BAD_REQUEST)?;
    if state.relay.ack(device_id, message_id).await {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Ok(StatusCode::NOT_FOUND)
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
    let state = AppState { relay: RelayStore::default() };
    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/relay", post(enqueue))
        .route("/v1/relay/{device_id}", get(poll))
        .route("/v1/relay/{device_id}/{message_id}/ack", post(ack))
        .with_state(state);

    let bind = std::env::var("NEXA_BIND").unwrap_or_else(|_| "127.0.0.1:8787".into());
    let addr = SocketAddr::from_str(&bind).expect("valid NEXA_BIND");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind gateway");
    println!("NEXA gateway listening on http://{addr}");
    axum::serve(listener, app).await.expect("serve gateway");
}
