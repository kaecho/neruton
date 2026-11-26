use std::net::SocketAddr;

use clap::Parser;
use neruton_server::{build_app, AppState, ServerConfig};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("neruton_server=info,tower_http=info")),
        )
        .with_target(false)
        .init();

    let config = ServerConfig::parse();
    let bind_addr = config.bind.clone();
    let state = AppState::new(config.clone())?;
    let app = build_app(state.clone());

    let listener = TcpListener::bind(&bind_addr).await?;
    let local_addr = listener.local_addr()?;

    info!(
        listen = %local_addr,
        base_domain = %config.base_domain(),
        panel_host = %config.panel_host(),
        public_scheme = %config.public_scheme(),
        data_dir = %config.data_dir.display(),
        web_upstream = ?config.web_upstream(),
        require_tunnel_auth = state.store.require_tunnel_auth(),
        needs_setup = state.store.needs_setup(),
        env_token_configured = config.auth_token().is_some(),
        "neruton-server listening"
    );

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }

    info!("shutdown signal received, draining neruton-server...");
}
