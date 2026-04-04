use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "open-attest", version, about = "macOS endpoint attestation agent")]
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
    Check,
    /// Run checks, sign, and submit attestation
    Attest,
    /// Uninstall the agent
    Uninstall,
    /// Run in daemon mode (heartbeat + periodic attestation)
    Daemon,
}
