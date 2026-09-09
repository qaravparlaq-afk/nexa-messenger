use axum::{routing::get, Json, Router};
use serde::Serialize;
use std::net::SocketAddr;

#[derive(Serialize)]
struct Health {
    service: &'static str,
    status: &'static str,
    plaintext_storage: bool,
}

async fn health() -> Json<Health> {
    Json(Health {
        service: "nexa-gateway",
        status: "ok",
        plaintext_storage: false,
    })
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/health", get(health));
    let addr = SocketAddr::from(([127, 0, 0, 1], 8787));
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind gateway");
    println!("NEXA gateway listening on http://{addr}");
    axum::serve(listener, app).await.expect("serve gateway");
}
