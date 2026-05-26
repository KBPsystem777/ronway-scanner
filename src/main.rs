use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "ronway", about = "TLS/SSL security scanner")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Scan {
        #[arg(long)]
        target: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan { target } => {
            println!("Scanning {}...", target);
        }
    }
    Ok(())
}
