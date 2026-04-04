use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "open-attest", version, about = "Endpoint attestation agent")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Enroll this device with the attestation server
    Enroll {
        /// Enrollment token
        #[arg(long)]
        token: String,
        /// Server URL
        #[arg(long)]
        server: String,
    },
    /// Show agent status
    Status,
    /// Run all checks and print results
    Check {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Run checks, sign, and submit attestation
    Attest,
    /// Uninstall the agent
    Uninstall,
    /// Run in daemon mode (heartbeat + periodic attestation)
    Daemon,
    /// Open the admin UI in the default browser
    Web,
}
