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

//! OpenTelemetry metrics exporter for EST operations.
//!
//! This module provides OpenTelemetry-compatible metrics export using the
//! OpenTelemetry SDK with Prometheus exporter backend. This allows EST client
//! metrics to be integrated into OpenTelemetry observability pipelines.
//!
//! # Example
//!
//! ```no_run
//! use usg_est_client::metrics::{MetricsCollector, OperationType};
//! use usg_est_client::metrics::opentelemetry::OpenTelemetryExporter;
//! use std::time::Instant;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create OpenTelemetry exporter
//! let exporter = OpenTelemetryExporter::new("est-client", "0.1.0")?;
//!
//! // Create metrics collector
//! let metrics = MetricsCollector::new();
//!
//! // Record operations
//! let start = Instant::now();
//! // ... perform EST operation ...
//! metrics.record_operation(OperationType::SimpleEnroll, start.elapsed(), true).await;
//!
//! // Export metrics
//! let prometheus_text = exporter.export(&metrics).await?;
//! println!("{}", prometheus_text);
//!
//! // Shutdown
//! exporter.shutdown()?;
//! # Ok(())
//! # }
//! ```

use crate::metrics::{MetricsCollector, MetricsSummary};
use opentelemetry::global;
use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::{MeterProvider, PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::Resource;
use std::error::Error as StdError;
use std::sync::Arc;

/// OpenTelemetry metrics exporter for EST client operations.
pub struct OpenTelemetryExporter {
    meter_provider: SdkMeterProvider,
    prometheus_exporter: Arc<opentelemetry_prometheus::PrometheusExporter>,
}

impl OpenTelemetryExporter {
    /// Create a new OpenTelemetry exporter with Prometheus backend.
    ///
    /// # Arguments
    ///
    /// * `service_name` - Name of the service (e.g., "est-client")
    /// * `service_version` - Version of the service (e.g., "0.1.0")
    ///
    /// # Errors
    ///
    /// Returns an error if the OpenTelemetry pipeline cannot be initialized.
    pub fn new(service_name: &str, service_version: &str) -> Result<Self, Box<dyn StdError>> {
        // Create Prometheus exporter
        let prometheus_exporter = opentelemetry_prometheus::exporter()
            .with_resource(Resource::new(vec![
                KeyValue::new("service.name", service_name.to_string()),
                KeyValue::new("service.version", service_version.to_string()),
            ]))
            .build()?;

        let meter_provider = SdkMeterProvider::builder()
            .with_reader(prometheus_exporter.clone())
            .with_resource(Resource::new(vec![
                KeyValue::new("service.name", service_name.to_string()),
                KeyValue::new("service.version", service_version.to_string()),
            ]))
            .build();

        // Set global meter provider
        global::set_meter_provider(meter_provider.clone());

        Ok(Self {
            meter_provider,
            prometheus_exporter: Arc::new(prometheus_exporter),
        })
    }

    /// Export metrics in Prometheus format.
    ///
    /// # Arguments
    ///
    /// * `collector` - The metrics collector to export from
    ///
    /// # Returns
    ///
    /// A string containing the metrics in Prometheus text format.
    pub async fn export(&self, collector: &MetricsCollector) -> Result<String, Box<dyn StdError>> {
        let summary = collector.get_summary().await;
        self.update_metrics(&summary)?;

        // Get Prometheus formatted output
        let encoded = self.prometheus_exporter.encode()?;
        Ok(String::from_utf8(encoded)?)
    }

    /// Update OpenTelemetry metrics from a metrics summary.
    fn update_metrics(&self, summary: &MetricsSummary) -> Result<(), Box<dyn StdError>> {
        let meter = self.meter_provider.meter("est-client");

        // Create gauges for operation metrics
        let operation_total = meter
            .u64_observable_gauge("est.operations.total")
            .with_description("Total number of EST operations")
            .with_callback(move |observer| {
                observer.observe(summary.ca_certs.total, &[KeyValue::new("operation", "get_ca_certs")]);
                observer.observe(summary.enrollments.total, &[KeyValue::new("operation", "simple_enroll")]);
                observer.observe(summary.reenrollments.total, &[KeyValue::new("operation", "simple_reenroll")]);
                observer.observe(summary.csr_attrs.total, &[KeyValue::new("operation", "get_csr_attributes")]);
                observer.observe(summary.server_keygen.total, &[KeyValue::new("operation", "server_keygen")]);
                observer.observe(summary.full_cmc.total, &[KeyValue::new("operation", "full_cmc")]);
            })
            .init();

        let operation_success = meter
            .u64_observable_gauge("est.operations.success")
            .with_description("Number of successful EST operations")
            .with_callback(move |observer| {
                observer.observe(summary.ca_certs.success, &[KeyValue::new("operation", "get_ca_certs")]);
                observer.observe(summary.enrollments.success, &[KeyValue::new("operation", "simple_enroll")]);
                observer.observe(summary.reenrollments.success, &[KeyValue::new("operation", "simple_reenroll")]);
                observer.observe(summary.csr_attrs.success, &[KeyValue::new("operation", "get_csr_attributes")]);
                observer.observe(summary.server_keygen.success, &[KeyValue::new("operation", "server_keygen")]);
                observer.observe(summary.full_cmc.success, &[KeyValue::new("operation", "full_cmc")]);
            })
            .init();

        let operation_failed = meter
            .u64_observable_gauge("est.operations.failed")
            .with_description("Number of failed EST operations")
            .with_callback(move |observer| {
                observer.observe(summary.ca_certs.failed, &[KeyValue::new("operation", "get_ca_certs")]);
                observer.observe(summary.enrollments.failed, &[KeyValue::new("operation", "simple_enroll")]);
                observer.observe(summary.reenrollments.failed, &[KeyValue::new("operation", "simple_reenroll")]);
                observer.observe(summary.csr_attrs.failed, &[KeyValue::new("operation", "get_csr_attributes")]);
                observer.observe(summary.server_keygen.failed, &[KeyValue::new("operation", "server_keygen")]);
                observer.observe(summary.full_cmc.failed, &[KeyValue::new("operation", "full_cmc")]);
            })
            .init();

        let operation_success_rate = meter
            .f64_observable_gauge("est.operations.success_rate")
            .with_description("Success rate of EST operations (0-100)")
            .with_callback(move |observer| {
                observer.observe(summary.ca_certs.success_rate(), &[KeyValue::new("operation", "get_ca_certs")]);
                observer.observe(summary.enrollments.success_rate(), &[KeyValue::new("operation", "simple_enroll")]);
                observer.observe(summary.reenrollments.success_rate(), &[KeyValue::new("operation", "simple_reenroll")]);
                observer.observe(summary.csr_attrs.success_rate(), &[KeyValue::new("operation", "get_csr_attributes")]);
                observer.observe(summary.server_keygen.success_rate(), &[KeyValue::new("operation", "server_keygen")]);
                observer.observe(summary.full_cmc.success_rate(), &[KeyValue::new("operation", "full_cmc")]);
            })
            .init();

        let operation_duration_avg = meter
            .f64_observable_gauge("est.operations.duration.avg_seconds")
            .with_description("Average EST operation duration in seconds")
            .with_callback(move |observer| {
                observer.observe(summary.ca_certs.average_duration().as_secs_f64(), &[KeyValue::new("operation", "get_ca_certs")]);
                observer.observe(summary.enrollments.average_duration().as_secs_f64(), &[KeyValue::new("operation", "simple_enroll")]);
                observer.observe(summary.reenrollments.average_duration().as_secs_f64(), &[KeyValue::new("operation", "simple_reenroll")]);
                observer.observe(summary.csr_attrs.average_duration().as_secs_f64(), &[KeyValue::new("operation", "get_csr_attributes")]);
                observer.observe(summary.server_keygen.average_duration().as_secs_f64(), &[KeyValue::new("operation", "server_keygen")]);
                observer.observe(summary.full_cmc.average_duration().as_secs_f64(), &[KeyValue::new("operation", "full_cmc")]);
            })
            .init();

        // TLS metrics
        let tls_handshakes_total = meter
            .u64_observable_gauge("est.tls.handshakes.total")
            .with_description("Total number of TLS handshakes")
            .with_callback(move |observer| {
                observer.observe(summary.tls.total_handshakes, &[]);
            })
            .init();

        let tls_handshake_success_rate = meter
            .f64_observable_gauge("est.tls.handshakes.success_rate")
            .with_description("TLS handshake success rate (0-100)")
            .with_callback(move |observer| {
                observer.observe(summary.tls.success_rate(), &[]);
            })
            .init();

        Ok(())
    }

    /// Shutdown the OpenTelemetry pipeline.
    ///
    /// This should be called before the application exits to ensure all
    /// metrics are flushed.
    pub fn shutdown(self) -> Result<(), Box<dyn StdError>> {
        self.meter_provider.shutdown()?;
        Ok(())
    }

    /// Get a reference to the Prometheus exporter.
    ///
    /// This can be used to access the underlying Prometheus registry
    /// or integrate with HTTP servers.
    pub fn prometheus_exporter(&self) -> &opentelemetry_prometheus::PrometheusExporter {
        &self.prometheus_exporter
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::OperationType;
    use std::time::Duration;

    #[tokio::test]
    async fn test_opentelemetry_exporter_creation() {
        let exporter = OpenTelemetryExporter::new("test-est", "0.1.0").unwrap();
        assert!(exporter.prometheus_exporter().registry().is_some());
    }

    #[tokio::test]
    async fn test_opentelemetry_export() {
        let collector = MetricsCollector::new();
        let exporter = OpenTelemetryExporter::new("test-est", "0.1.0").unwrap();

        // Record some metrics
        collector
            .record_operation(
                OperationType::SimpleEnroll,
                Duration::from_millis(100),
                true,
            )
            .await;

        collector
            .record_tls_handshake(Duration::from_millis(50), true)
            .await;

        // Export to Prometheus format via OpenTelemetry
        let output = exporter.export(&collector).await.unwrap();

        // Verify output contains OpenTelemetry metric names
        assert!(output.contains("est_operations") || output.contains("est.operations"));
    }

    #[tokio::test]
    async fn test_opentelemetry_shutdown() {
        let exporter = OpenTelemetryExporter::new("test-est", "0.1.0").unwrap();
        // Should not panic
        exporter.shutdown().unwrap();
    }
}
