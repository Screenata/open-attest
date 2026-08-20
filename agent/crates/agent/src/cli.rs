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
    /// Reinstall the managed binary and daemon supervisor for an enrolled
    /// device whose background agent is not running
    Repair,
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
    /// Check for and apply a pending update (one-shot). The daemon does this
    /// automatically; this subcommand is for manual / MDM-driven triggers.
    Update {
        /// Bypass rate-limit and "already at this version" checks. Signature
        /// verification is never bypassed.
        #[arg(long)]
        force: bool,
    },
}
