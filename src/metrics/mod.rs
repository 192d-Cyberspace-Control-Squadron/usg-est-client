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

//! Metrics collection and monitoring for EST operations.
//!
//! This module provides metrics collection for monitoring EST client
//! operations, including operation counts, durations, and error rates.
//!
//! ## Exporters
//!
//! When the `metrics-prometheus` feature is enabled, this module also provides
//! exporters for Prometheus and OpenTelemetry:
//!
//! - [`prometheus`] - Prometheus metrics exporter
//! - [`opentelemetry`] - OpenTelemetry metrics exporter with Prometheus backend
//!
//! # Example
//!
//! ```no_run
//! use usg_est_client::metrics::{MetricsCollector, OperationType};
//! use std::time::Instant;
//!
//! # async fn example() {
//! // Create metrics collector
//! let metrics = MetricsCollector::new();
//!
//! // Record an operation
//! let start = Instant::now();
//! // ... perform EST operation ...
//! metrics.record_operation(OperationType::SimpleEnroll, start.elapsed(), true).await;
//!
//! // Get metrics summary
//! let summary = metrics.get_summary().await;
//! println!("Total enrollments: {}", summary.enrollments.total);
//! println!("Success rate: {:.2}%", summary.enrollments.success_rate());
//! # }
//! ```

// Export Prometheus and OpenTelemetry modules when feature is enabled
#[cfg(feature = "metrics-prometheus")]
pub mod prometheus;

#[cfg(feature = "metrics-prometheus")]
pub mod opentelemetry;

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Types of EST operations that can be measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationType {
    /// GET /cacerts operation.
    GetCaCerts,
    /// POST /simpleenroll operation.
    SimpleEnroll,
    /// POST /simplereenroll operation.
    SimpleReenroll,
    /// GET /csrattrs operation.
    GetCsrAttributes,
    /// POST /serverkeygen operation.
    ServerKeygen,
    /// POST /fullcmc operation.
    FullCmc,
}

impl OperationType {
    /// Get a string representation of the operation type.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GetCaCerts => "get_ca_certs",
            Self::SimpleEnroll => "simple_enroll",
            Self::SimpleReenroll => "simple_reenroll",
            Self::GetCsrAttributes => "get_csr_attributes",
            Self::ServerKeygen => "server_keygen",
            Self::FullCmc => "full_cmc",
        }
    }
}

/// Metrics for a specific operation type.
#[derive(Debug, Default, Clone)]
pub struct OperationMetrics {
    /// Total number of operations attempted.
    pub total: u64,
    /// Number of successful operations.
    pub success: u64,
    /// Number of failed operations.
    pub failed: u64,
    /// Total duration of all operations (nanoseconds).
    pub total_duration_nanos: u64,
    /// Minimum operation duration (nanoseconds).
    pub min_duration_nanos: u64,
    /// Maximum operation duration (nanoseconds).
    pub max_duration_nanos: u64,
}

impl OperationMetrics {
    /// Calculate the success rate as a percentage.
    pub fn success_rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.success as f64 / self.total as f64) * 100.0
        }
    }

    /// Calculate the average operation duration.
    pub fn average_duration(&self) -> Duration {
        if self.total == 0 {
            Duration::from_nanos(0)
        } else {
            Duration::from_nanos(self.total_duration_nanos / self.total)
        }
    }

    /// Get the minimum operation duration.
    pub fn min_duration(&self) -> Duration {
        Duration::from_nanos(self.min_duration_nanos)
    }

    /// Get the maximum operation duration.
    pub fn max_duration(&self) -> Duration {
        Duration::from_nanos(self.max_duration_nanos)
    }
}

/// TLS handshake metrics.
#[derive(Debug, Default, Clone)]
pub struct TlsMetrics {
    /// Total number of TLS handshakes.
    pub total_handshakes: u64,
    /// Number of successful TLS handshakes.
    pub successful_handshakes: u64,
    /// Number of failed TLS handshakes.
    pub failed_handshakes: u64,
    /// Total duration of all TLS handshakes (nanoseconds).
    pub total_handshake_duration_nanos: u64,
}

impl TlsMetrics {
    /// Calculate the TLS handshake success rate.
    pub fn success_rate(&self) -> f64 {
        if self.total_handshakes == 0 {
            0.0
        } else {
            (self.successful_handshakes as f64 / self.total_handshakes as f64) * 100.0
        }
    }

    /// Calculate the average TLS handshake duration.
    pub fn average_handshake_duration(&self) -> Duration {
        if self.total_handshakes == 0 {
            Duration::from_nanos(0)
        } else {
            Duration::from_nanos(self.total_handshake_duration_nanos / self.total_handshakes)
        }
    }
}

/// Complete metrics summary for all operations.
#[derive(Debug, Default, Clone)]
pub struct MetricsSummary {
    /// Metrics for CA certificate retrieval.
    pub ca_certs: OperationMetrics,
    /// Metrics for simple enrollment.
    pub enrollments: OperationMetrics,
    /// Metrics for re-enrollment.
    pub reenrollments: OperationMetrics,
    /// Metrics for CSR attributes retrieval.
    pub csr_attrs: OperationMetrics,
    /// Metrics for server key generation.
    pub server_keygen: OperationMetrics,
    /// Metrics for full CMC operations.
    pub full_cmc: OperationMetrics,
    /// TLS handshake metrics.
    pub tls: TlsMetrics,
}

impl MetricsSummary {
    /// Get total number of operations across all types.
    pub fn total_operations(&self) -> u64 {
        self.ca_certs.total
            + self.enrollments.total
            + self.reenrollments.total
            + self.csr_attrs.total
            + self.server_keygen.total
            + self.full_cmc.total
    }

    /// Get total number of successful operations.
    pub fn total_successful(&self) -> u64 {
        self.ca_certs.success
            + self.enrollments.success
            + self.reenrollments.success
            + self.csr_attrs.success
            + self.server_keygen.success
            + self.full_cmc.success
    }

    /// Get overall success rate.
    pub fn overall_success_rate(&self) -> f64 {
        let total = self.total_operations();
        if total == 0 {
            0.0
        } else {
            (self.total_successful() as f64 / total as f64) * 100.0
        }
    }
}

/// Thread-safe metrics collector.
#[derive(Clone)]
pub struct MetricsCollector {
    inner: Arc<MetricsCollectorInner>,
}

struct MetricsCollectorInner {
    ca_certs: RwLock<OperationMetrics>,
    enrollments: RwLock<OperationMetrics>,
    reenrollments: RwLock<OperationMetrics>,
    csr_attrs: RwLock<OperationMetrics>,
    server_keygen: RwLock<OperationMetrics>,
    full_cmc: RwLock<OperationMetrics>,
    tls: RwLock<TlsMetrics>,
}

impl MetricsCollector {
    /// Create a new metrics collector.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(MetricsCollectorInner {
                ca_certs: RwLock::new(OperationMetrics::default()),
                enrollments: RwLock::new(OperationMetrics::default()),
                reenrollments: RwLock::new(OperationMetrics::default()),
                csr_attrs: RwLock::new(OperationMetrics::default()),
                server_keygen: RwLock::new(OperationMetrics::default()),
                full_cmc: RwLock::new(OperationMetrics::default()),
                tls: RwLock::new(TlsMetrics::default()),
            }),
        }
    }

    /// Record an EST operation.
    ///
    /// # Arguments
    ///
    /// * `op_type` - The type of operation
    /// * `duration` - How long the operation took
    /// * `success` - Whether the operation succeeded
    pub async fn record_operation(
        &self,
        op_type: OperationType,
        duration: Duration,
        success: bool,
    ) {
        let metrics_lock = match op_type {
            OperationType::GetCaCerts => &self.inner.ca_certs,
            OperationType::SimpleEnroll => &self.inner.enrollments,
            OperationType::SimpleReenroll => &self.inner.reenrollments,
            OperationType::GetCsrAttributes => &self.inner.csr_attrs,
            OperationType::ServerKeygen => &self.inner.server_keygen,
            OperationType::FullCmc => &self.inner.full_cmc,
        };

        let mut metrics = metrics_lock.write().await;
        metrics.total += 1;

        if success {
            metrics.success += 1;
        } else {
            metrics.failed += 1;
        }

        let duration_nanos = duration.as_nanos() as u64;
        metrics.total_duration_nanos += duration_nanos;

        if metrics.min_duration_nanos == 0 || duration_nanos < metrics.min_duration_nanos {
            metrics.min_duration_nanos = duration_nanos;
        }

        if duration_nanos > metrics.max_duration_nanos {
            metrics.max_duration_nanos = duration_nanos;
        }
    }

    /// Record a TLS handshake.
    ///
    /// # Arguments
    ///
    /// * `duration` - How long the handshake took
    /// * `success` - Whether the handshake succeeded
    pub async fn record_tls_handshake(&self, duration: Duration, success: bool) {
        let mut tls = self.inner.tls.write().await;
        tls.total_handshakes += 1;

        if success {
            tls.successful_handshakes += 1;
        } else {
            tls.failed_handshakes += 1;
        }

        tls.total_handshake_duration_nanos += duration.as_nanos() as u64;
    }

    /// Get a summary of all collected metrics.
    pub async fn get_summary(&self) -> MetricsSummary {
        MetricsSummary {
            ca_certs: self.inner.ca_certs.read().await.clone(),
            enrollments: self.inner.enrollments.read().await.clone(),
            reenrollments: self.inner.reenrollments.read().await.clone(),
            csr_attrs: self.inner.csr_attrs.read().await.clone(),
            server_keygen: self.inner.server_keygen.read().await.clone(),
            full_cmc: self.inner.full_cmc.read().await.clone(),
            tls: self.inner.tls.read().await.clone(),
        }
    }

    /// Reset all metrics to zero.
    pub async fn reset(&self) {
        *self.inner.ca_certs.write().await = OperationMetrics::default();
        *self.inner.enrollments.write().await = OperationMetrics::default();
        *self.inner.reenrollments.write().await = OperationMetrics::default();
        *self.inner.csr_attrs.write().await = OperationMetrics::default();
        *self.inner.server_keygen.write().await = OperationMetrics::default();
        *self.inner.full_cmc.write().await = OperationMetrics::default();
        *self.inner.tls.write().await = TlsMetrics::default();
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Format metrics summary as a human-readable string.
pub fn format_metrics_summary(summary: &MetricsSummary) -> String {
    let mut output = String::new();

    output.push_str("=== EST Client Metrics Summary ===\n\n");

    output.push_str(&format!(
        "Total Operations: {}\n",
        summary.total_operations()
    ));
    output.push_str(&format!(
        "Overall Success Rate: {:.2}%\n\n",
        summary.overall_success_rate()
    ));

    // CA Certs
    output.push_str(&format_operation_metrics(
        "CA Certificate Retrieval",
        &summary.ca_certs,
    ));

    // Enrollments
    output.push_str(&format_operation_metrics(
        "Simple Enrollment",
        &summary.enrollments,
    ));

    // Re-enrollments
    output.push_str(&format_operation_metrics(
        "Re-enrollment",
        &summary.reenrollments,
    ));

    // CSR Attrs
    output.push_str(&format_operation_metrics(
        "CSR Attributes",
        &summary.csr_attrs,
    ));

    // Server Keygen
    output.push_str(&format_operation_metrics(
        "Server Key Generation",
        &summary.server_keygen,
    ));

    // Full CMC
    output.push_str(&format_operation_metrics("Full CMC", &summary.full_cmc));

    // TLS
    output.push_str("--- TLS Handshakes ---\n");
    output.push_str(&format!("Total: {}\n", summary.tls.total_handshakes));
    output.push_str(&format!(
        "Success Rate: {:.2}%\n",
        summary.tls.success_rate()
    ));
    output.push_str(&format!(
        "Avg Duration: {:?}\n\n",
        summary.tls.average_handshake_duration()
    ));

    output
}

fn format_operation_metrics(name: &str, metrics: &OperationMetrics) -> String {
    if metrics.total == 0 {
        return String::new(); // Skip operations with no data
    }

    let mut output = String::new();
    output.push_str(&format!("--- {} ---\n", name));
    output.push_str(&format!("Total: {}\n", metrics.total));
    output.push_str(&format!("Success: {}\n", metrics.success));
    output.push_str(&format!("Failed: {}\n", metrics.failed));
    output.push_str(&format!("Success Rate: {:.2}%\n", metrics.success_rate()));
    output.push_str(&format!("Avg Duration: {:?}\n", metrics.average_duration()));
    output.push_str(&format!("Min Duration: {:?}\n", metrics.min_duration()));
    output.push_str(&format!("Max Duration: {:?}\n\n", metrics.max_duration()));
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_collector() {
        let collector = MetricsCollector::new();

        // Record some operations
        collector
            .record_operation(
                OperationType::SimpleEnroll,
                Duration::from_millis(100),
                true,
            )
            .await;
        collector
            .record_operation(
                OperationType::SimpleEnroll,
                Duration::from_millis(150),
                true,
            )
            .await;
        collector
            .record_operation(
                OperationType::SimpleEnroll,
                Duration::from_millis(200),
                false,
            )
            .await;

        let summary = collector.get_summary().await;

        assert_eq!(summary.enrollments.total, 3);
        assert_eq!(summary.enrollments.success, 2);
        assert_eq!(summary.enrollments.failed, 1);
        // Use approximate comparison for floating point
        assert!((summary.enrollments.success_rate() - 66.666666).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_operation_metrics_average_duration() {
        let collector = MetricsCollector::new();

        collector
            .record_operation(OperationType::GetCaCerts, Duration::from_millis(100), true)
            .await;
        collector
            .record_operation(OperationType::GetCaCerts, Duration::from_millis(200), true)
            .await;

        let summary = collector.get_summary().await;
        assert_eq!(
            summary.ca_certs.average_duration(),
            Duration::from_millis(150)
        );
    }

    #[tokio::test]
    async fn test_metrics_reset() {
        let collector = MetricsCollector::new();

        collector
            .record_operation(
                OperationType::SimpleEnroll,
                Duration::from_millis(100),
                true,
            )
            .await;

        let summary_before = collector.get_summary().await;
        assert_eq!(summary_before.enrollments.total, 1);

        collector.reset().await;

        let summary_after = collector.get_summary().await;
        assert_eq!(summary_after.enrollments.total, 0);
    }

    #[test]
    fn test_operation_type_as_str() {
        assert_eq!(OperationType::GetCaCerts.as_str(), "get_ca_certs");
        assert_eq!(OperationType::SimpleEnroll.as_str(), "simple_enroll");
        assert_eq!(OperationType::SimpleReenroll.as_str(), "simple_reenroll");
    }
}
