use clap::{Parser, Subcommand};

mod client;
mod proto;
mod server;

#[derive(Parser)]
#[command(name = "tunneld", version, about = "HTTP reverse tunnel with subdomain routing")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Server(server::Args),
    Client(client::Args),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "tunneld=info,tower_http=info".into()),
        )
        .init();

    match Cli::parse().cmd {
        Cmd::Server(a) => server::run(a).await,
        Cmd::Client(a) => client::run(a).await,
    }
}
