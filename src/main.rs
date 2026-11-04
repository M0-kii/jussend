mod config;
mod delivery;
mod message;
mod queue;

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use config::Config;
use queue::{Enqueued, Queue};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use subtle::ConstantTimeEq;

#[derive(Clone)]
struct App {
    config: Arc<Config>,
    queue: Queue,
}

struct ApiError(StatusCode, &'static str);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error":self.1}))).into_response()
    }
}
type ApiResult<T> = std::result::Result<T, ApiError>;

fn authorize(headers: &HeaderMap, config: &Config) -> ApiResult<()> {
    let token = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default();
    let hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    if bool::from(hash.ct_eq(&config.api_key_hash)) {
        Ok(())
    } else {
        Err(ApiError(StatusCode::UNAUTHORIZED, "unauthorized"))
    }
}

async fn enqueue(
    State(app): State<App>,
    headers: HeaderMap,
    Json(body): Json<message::Submission>,
) -> ApiResult<Response> {
    authorize(&headers, &app.config)?;
    let key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
        })
        .ok_or(ApiError(StatusCode::BAD_REQUEST, "invalid_idempotency_key"))?
        .to_owned();
    let config = app.config.clone();
    let prepared =
        tokio::task::spawn_blocking(move || message::prepare(&config, body, key, queue::now()))
            .await
            .map_err(|_| {
                ApiError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "message_preparation_failed",
                )
            })?
            .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_message"))?;
    match app
        .queue
        .enqueue(prepared)
        .await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "queue_unavailable"))?
    {
        Enqueued::New(receipt) => Ok((StatusCode::ACCEPTED, Json(receipt)).into_response()),
        Enqueued::Existing(receipt) => Ok((StatusCode::OK, Json(receipt)).into_response()),
        Enqueued::Conflict => Err(ApiError(StatusCode::CONFLICT, "idempotency_conflict")),
        Enqueued::Limited => Ok((
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", "60")],
            Json(json!({"error":"rate_limited"})),
        )
            .into_response()),
        Enqueued::Full => Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "queue_full")),
    }
}

async fn status(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<queue::Receipt>> {
    authorize(&headers, &app.config)?;
    if uuid::Uuid::parse_str(&id).is_err() {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid_id"));
    }
    app.queue
        .status(id)
        .await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "queue_unavailable"))?
        .map(Json)
        .ok_or(ApiError(StatusCode::NOT_FOUND, "not_found"))
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Install SIGTERM handler");
        tokio::select! { _=tokio::signal::ctrl_c()=>{}, _=term.recv()=>{} }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "jussend=info".into()),
        )
        .init();
    let config = Arc::new(Config::load()?);
    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .context("Could not bind jussend")?;
    let path = config.db.clone();
    let queue = tokio::task::spawn_blocking(move || Queue::open(&path)).await??;
    let app = App {
        config: config.clone(),
        queue: queue.clone(),
    };
    let router = Router::new()
        .route("/health", get(|| async { Json(json!({"status":"ok"})) }))
        .route("/v1/emails", post(enqueue))
        .route("/v1/emails/{id}", get(status))
        .layer(DefaultBodyLimit::max(12 * 1024))
        .with_state(app);
    let (stop, receiver) = tokio::sync::watch::channel(false);
    let mut worker = tokio::spawn(delivery::worker(config.clone(), queue, receiver));
    let signal_stop = stop.clone();
    let server = async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                shutdown_signal().await;
                let _ = signal_stop.send(true);
            })
            .await
    };
    tokio::pin!(server);
    tracing::info!(bind=%config.bind,"jussend is ready");
    tokio::select! {
        result=&mut worker => { result??; anyhow::bail!("Mail worker stopped unexpectedly"); }
        result=&mut server => { result?; }
    }
    let _ = stop.send(true);
    tokio::time::timeout(std::time::Duration::from_secs(130), worker)
        .await
        .context("Mail worker did not stop in time")???;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_submission_and_unknown_fields_are_rejected() {
        assert!(serde_json::from_value::<message::Submission>(json!({"to":"user@example.com","kind":"marketing","url":"https://example.com","expires_at":1})).is_err());
        assert!(serde_json::from_value::<message::Submission>(json!({"to":"user@example.com","kind":"verify_email","url":"https://example.com","expires_at":1,"from":"spoof@example.com"})).is_err());
    }
}
