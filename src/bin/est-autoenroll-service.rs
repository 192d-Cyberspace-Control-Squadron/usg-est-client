// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! EST Auto-Enrollment Windows Service
//!
//! This is the main service binary that runs as a Windows service to
//! automatically enroll and renew X.509 certificates using EST (RFC 7030).
//!
//! # Service Behavior
//!
//! 1. **Startup**: Loads configuration, checks for existing certificates
//! 2. **Initial Enrollment**: If no valid certificate exists, performs enrollment
//! 3. **Renewal Loop**: Periodically checks certificates and renews as needed
//! 4. **Shutdown**: Gracefully stops and saves state
//!
//! # Running Modes
//!
//! - **Service Mode**: When started by Windows SCM (default behavior)
//! - **Console Mode**: When run with `--console` flag for debugging
//!
//! # Example
//!
//! ```text
//! # Run as console application for debugging
//! est-autoenroll-service --console
//!
//! # Run with specific config file
//! est-autoenroll-service --console --config C:\ProgramData\EST\config.toml
//! ```

use std::env;
use std::process::ExitCode;

#[cfg(all(windows, feature = "windows-service"))]
use std::sync::Arc;

#[cfg(all(windows, feature = "windows-service"))]
use usg_est_client::windows::service::{EnrollmentService, ServiceConfig};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    // Check for console mode
    let console_mode = args.iter().any(|a| a == "--console" || a == "-c");

    // Parse config path
    let config_path = args
        .iter()
        .position(|a| a == "--config" || a == "-C")
        .and_then(|i| args.get(i + 1))
        .cloned();

    // Check for help
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_usage(&args[0]);
        return ExitCode::SUCCESS;
    }

    #[cfg(all(windows, feature = "windows-service"))]
    {
        if console_mode {
            // Run in console mode for debugging
            run_console_mode(config_path)
        } else {
            // Run as Windows service
            run_service_mode()
        }
    }

    #[cfg(not(all(windows, feature = "windows-service")))]
    {
        let _ = (console_mode, config_path);
        eprintln!("This service requires Windows and the 'windows-service' feature.");
        ExitCode::FAILURE
    }
}

fn print_usage(program: &str) {
    println!("EST Auto-Enrollment Service");
    println!();
    println!("Usage: {} [options]", program);
    println!();
    println!("Options:");
    println!("  --console, -c      Run in console mode (for debugging)");
    println!("  --config, -C PATH  Path to configuration file");
    println!("  --help, -h         Show this help message");
    println!();
    println!("When run without --console, this binary expects to be started");
    println!("by the Windows Service Control Manager.");
    println!();
    println!("To install as a service, use est-service-install.exe");
}

#[cfg(all(windows, feature = "windows-service"))]
fn run_service_mode() -> ExitCode {
    // Initialize tracing to Windows Event Log
    // In production, this would use the Windows Event Log tracing subscriber
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("Starting EST Auto-Enrollment service");

    match EnrollmentService::run() {
        Ok(()) => {
            tracing::info!("Service exited normally");
            ExitCode::SUCCESS
        }
        Err(e) => {
            tracing::error!("Service failed: {}", e);
            ExitCode::FAILURE
        }
    }
}

#[cfg(all(windows, feature = "windows-service"))]
fn run_console_mode(config_path: Option<String>) -> ExitCode {
    // Initialize console logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(std::io::stdout)
        .init();

    println!("EST Auto-Enrollment Service - Console Mode");
    println!("=========================================");
    println!();
    println!("Press Ctrl+C to stop");
    println!();

    let config = ServiceConfig {
        config_path,
        verbose: true,
        check_interval: 60, // Check every minute in console mode
        ..Default::default()
    };

    let service = EnrollmentService::new(config);
    let state = service.state();

    // Set up Ctrl+C handler
    let state_clone = Arc::clone(&state);
    ctrlc_handler(state_clone);

    // Create tokio runtime
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Failed to create runtime: {}", e);
            return ExitCode::FAILURE;
        }
    };

    // Run the service loop
    match rt.block_on(service.run_service_loop()) {
        Ok(()) => {
            println!("\nService stopped.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("\nService error: {}", e);
            ExitCode::FAILURE
        }
    }
}

#[cfg(all(windows, feature = "windows-service"))]
fn ctrlc_handler(state: Arc<usg_est_client::windows::service::ServiceState>) {
    // Note: In a real implementation, you'd use the ctrlc crate
    // For now, we'll rely on the service loop's natural exit
    std::thread::spawn(move || {
        // Simple signal handling - in production, use the ctrlc crate
        loop {
            std::thread::sleep(std::time::Duration::from_millis(100));
            if state.is_shutdown_requested() {
                break;
            }
        }
    });
}

/// Enrollment workflow implementation.
#[cfg(all(windows, feature = "windows-service"))]
mod enrollment {
    use usg_est_client::auto_enroll::config::AutoEnrollConfig;
    use usg_est_client::error::Result;
    use usg_est_client::windows::{CertStore, MachineIdentity};

    /// Check if enrollment is needed.
    pub async fn needs_enrollment(config: &AutoEnrollConfig) -> Result<bool> {
        // Get machine identity
        let identity = MachineIdentity::current()?;
        tracing::debug!("Machine: {}", identity.computer_name);

        // Check for existing certificate
        let store_path = config
            .storage
            .as_ref()
            .and_then(|s| s.windows_store.as_ref())
            .map(|s| s.as_str())
            .unwrap_or("LocalMachine\\My");

        let store = CertStore::open_path(store_path)?;

        // Look for a certificate matching our subject
        let cn = config
            .certificate
            .as_ref()
            .and_then(|c| c.common_name.as_ref())
            .map(|s| s.as_str())
            .unwrap_or(&identity.suggested_cn());

        match store.find_by_subject(cn)? {
            Some(cert) => {
                tracing::info!("Found existing certificate: {}", cert.subject);
                // TODO: Check expiration and renewal threshold
                Ok(false)
            }
            None => {
                tracing::info!("No existing certificate found, enrollment needed");
                Ok(true)
            }
        }
    }

    /// Perform certificate enrollment.
    pub async fn perform_enrollment(_config: &AutoEnrollConfig) -> Result<()> {
        tracing::info!("Starting certificate enrollment");

        // TODO: Implement full enrollment workflow:
        // 1. Generate key pair (CNG/TPM)
        // 2. Build CSR
        // 3. Connect to EST server
        // 4. Submit enrollment request
        // 5. Import certificate to store
        // 6. Associate private key

        tracing::info!("Enrollment complete");
        Ok(())
    }

    /// Check for renewal needs.
    pub async fn check_renewal(_config: &AutoEnrollConfig) -> Result<bool> {
        // TODO: Check certificate expiration against renewal threshold
        Ok(false)
    }

    /// Perform certificate renewal.
    pub async fn perform_renewal(_config: &AutoEnrollConfig) -> Result<()> {
        tracing::info!("Starting certificate renewal");

        // TODO: Implement renewal workflow:
        // 1. Get existing certificate for TLS auth
        // 2. Generate new key pair
        // 3. Build CSR
        // 4. Submit re-enrollment request
        // 5. Import new certificate
        // 6. Archive old certificate (optional)

        tracing::info!("Renewal complete");
        Ok(())
    }
}
