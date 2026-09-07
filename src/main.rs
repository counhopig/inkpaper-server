mod auth;
mod db;
mod models;
mod routes;

use std::net::SocketAddr;

use anyhow::Context;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load project-local configuration for direct binary/cargo launches.
    // Variables already exported by the shell or service manager take precedence.
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "inkwash_server=info,tower_http=info".into()),
        )
        .init();

    // Database: a single `DATABASE_URL` selects the backend - `sqlite://…`
    // (default, SQLite file) or `postgres://…`. Do not log the URL - a
    // postgres URL may embed credentials.
    let db_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://inkwash.sqlite3".to_string());
    let db_kind = if db_url.starts_with("postgres://") {
        "postgres"
    } else {
        "sqlite"
    };
    let admin_token = std::env::var("ADMIN_TOKEN").context(
        "ADMIN_TOKEN env var is required - this is the bearer token inkwash-desktop uses \
         for device registration and alarm/todo management; generate one long random string \
         and keep it secret, e.g. `openssl rand -hex 32`",
    )?;
    let bind_addr: SocketAddr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
        .parse()
        .context("BIND_ADDR must be a valid host:port")?;

    let db = db::open(&db_url, 2).await?;
    let cleanup_db = db.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60 * 60));
        loop {
            interval.tick().await;
            match db::delete_expired_sessions(&cleanup_db).await {
                Ok(deleted) if deleted > 0 => {
                    tracing::info!(deleted, "expired console sessions cleaned up")
                }
                Ok(_) => {}
                Err(err) => tracing::warn!("failed to clean expired console sessions: {err:#}"),
            }
        }
    });
    let state = routes::AppState::new(db, admin_token);

    // Deliberately no CORS layer. Every legitimate client is either
    // same-origin (the embedded admin console, including its Vite dev
    // proxy - see admin-ui/vite.config.ts) or non-browser (firmware,
    // inkwash-desktop's reqwest client, webhook/agent POSTs), and neither
    // kind is affected by CORS. The old blanket `CorsLayer::permissive()`
    // only widened browser attack surface for no working cross-origin
    // client, so it was removed rather than narrowed.
    let app = routes::router(state)
        .layer(ConcurrencyLimitLayer::new(64))
        .layer(TraceLayer::new_for_http());

    tracing::info!("inkwash-server listening on {bind_addr}, db={db_kind}");
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
