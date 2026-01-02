// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! Integration tests for metrics collection and export.

use std::time::Duration;
use usg_est_client::metrics::{MetricsCollector, MetricsSummary, OperationType};

#[cfg(feature = "metrics-prometheus")]
use usg_est_client::metrics::prometheus::PrometheusExporter;

#[cfg(feature = "metrics-prometheus")]
use usg_est_client::metrics::opentelemetry::OpenTelemetryExporter;

#[tokio::test]
async fn test_metrics_collection_basic() {
    let collector = MetricsCollector::new();

    // Record various operations
    collector
        .record_operation(OperationType::GetCaCerts, Duration::from_millis(100), true)
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

    // Get summary and verify
    let summary = collector.get_summary().await;

    assert_eq!(summary.ca_certs.total, 1);
    assert_eq!(summary.ca_certs.success, 1);
    assert_eq!(summary.enrollments.total, 2);
    assert_eq!(summary.enrollments.success, 1);
    assert_eq!(summary.enrollments.failed, 1);
}

#[tokio::test]
async fn test_metrics_duration_tracking() {
    let collector = MetricsCollector::new();

    // Record operations with known durations
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
            Duration::from_millis(200),
            true,
        )
        .await;

    collector
        .record_operation(
            OperationType::SimpleEnroll,
            Duration::from_millis(300),
            true,
        )
        .await;

    let summary = collector.get_summary().await;

    // Verify min, max, and average
    assert_eq!(
        summary.enrollments.min_duration(),
        Duration::from_millis(100)
    );
    assert_eq!(
        summary.enrollments.max_duration(),
        Duration::from_millis(300)
    );
    assert_eq!(
        summary.enrollments.average_duration(),
        Duration::from_millis(200)
    );
}

#[tokio::test]
async fn test_metrics_success_rate() {
    let collector = MetricsCollector::new();

    // Record 7 successful and 3 failed operations
    for _ in 0..7 {
        collector
            .record_operation(OperationType::FullCmc, Duration::from_millis(100), true)
            .await;
    }

    for _ in 0..3 {
        collector
            .record_operation(OperationType::FullCmc, Duration::from_millis(100), false)
            .await;
    }

    let summary = collector.get_summary().await;

    assert_eq!(summary.full_cmc.total, 10);
    assert_eq!(summary.full_cmc.success, 7);
    assert_eq!(summary.full_cmc.failed, 3);
    assert!((summary.full_cmc.success_rate() - 70.0).abs() < 0.01);
}

#[tokio::test]
async fn test_metrics_tls_handshakes() {
    let collector = MetricsCollector::new();

    // Record TLS handshakes
    collector
        .record_tls_handshake(Duration::from_millis(50), true)
        .await;
    collector
        .record_tls_handshake(Duration::from_millis(60), true)
        .await;
    collector
        .record_tls_handshake(Duration::from_millis(70), false)
        .await;

    let summary = collector.get_summary().await;

    assert_eq!(summary.tls.total_handshakes, 3);
    assert_eq!(summary.tls.successful_handshakes, 2);
    assert_eq!(summary.tls.failed_handshakes, 1);
    assert!((summary.tls.success_rate() - 66.666666).abs() < 0.01);
}

#[tokio::test]
async fn test_metrics_reset() {
    let collector = MetricsCollector::new();

    // Record some operations
    collector
        .record_operation(
            OperationType::SimpleEnroll,
            Duration::from_millis(100),
            true,
        )
        .await;

    let summary_before = collector.get_summary().await;
    assert_eq!(summary_before.enrollments.total, 1);

    // Reset
    collector.reset().await;

    let summary_after = collector.get_summary().await;
    assert_eq!(summary_after.enrollments.total, 0);
    assert_eq!(summary_after.total_operations(), 0);
}

#[tokio::test]
async fn test_metrics_all_operation_types() {
    let collector = MetricsCollector::new();

    // Record one of each operation type
    collector
        .record_operation(OperationType::GetCaCerts, Duration::from_millis(50), true)
        .await;
    collector
        .record_operation(
            OperationType::SimpleEnroll,
            Duration::from_millis(100),
            true,
        )
        .await;
    collector
        .record_operation(
            OperationType::SimpleReenroll,
            Duration::from_millis(120),
            true,
        )
        .await;
    collector
        .record_operation(
            OperationType::GetCsrAttributes,
            Duration::from_millis(30),
            true,
        )
        .await;
    collector
        .record_operation(
            OperationType::ServerKeygen,
            Duration::from_millis(200),
            true,
        )
        .await;
    collector
        .record_operation(OperationType::FullCmc, Duration::from_millis(150), true)
        .await;

    let summary: MetricsSummary = collector.get_summary().await;

    assert_eq!(summary.total_operations(), 6);
    assert_eq!(summary.total_successful(), 6);
    assert_eq!(summary.overall_success_rate(), 100.0);
}

#[cfg(feature = "metrics-prometheus")]
#[tokio::test]
async fn test_prometheus_exporter_creation() {
    let exporter = PrometheusExporter::new("test_est_client");
    assert!(exporter.is_ok());
}

#[cfg(feature = "metrics-prometheus")]
#[tokio::test]
async fn test_prometheus_export_format() {
    let collector = MetricsCollector::new();
    let exporter = PrometheusExporter::new("test_est").unwrap();

    // Record some operations
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

    // Export
    let output = exporter.export(&collector).await.unwrap();

    // Verify Prometheus format
    assert!(output.contains("# HELP"));
    assert!(output.contains("# TYPE"));
    assert!(output.contains("test_est_"));
}

#[cfg(feature = "metrics-prometheus")]
#[tokio::test]
async fn test_prometheus_metric_names() {
    let collector = MetricsCollector::new();
    let exporter = PrometheusExporter::new("est_client").unwrap();

    collector
        .record_operation(
            OperationType::SimpleEnroll,
            Duration::from_millis(100),
            true,
        )
        .await;

    let output = exporter.export(&collector).await.unwrap();

    // Verify expected metric names
    assert!(output.contains("est_client_operation_success_rate"));
    assert!(output.contains("est_client_operation_duration_avg_seconds"));
    assert!(output.contains("simple_enroll"));
}

#[cfg(feature = "metrics-prometheus")]
#[tokio::test]
async fn test_prometheus_multiple_operations() {
    let collector = MetricsCollector::new();
    let exporter = PrometheusExporter::new("est").unwrap();

    // Record multiple operation types
    collector
        .record_operation(OperationType::GetCaCerts, Duration::from_millis(50), true)
        .await;
    collector
        .record_operation(
            OperationType::SimpleEnroll,
            Duration::from_millis(100),
            true,
        )
        .await;
    collector
        .record_operation(OperationType::FullCmc, Duration::from_millis(150), false)
        .await;

    let output = exporter.export(&collector).await.unwrap();

    // Verify all operation types are present
    assert!(output.contains("get_ca_certs"));
    assert!(output.contains("simple_enroll"));
    assert!(output.contains("full_cmc"));
}

#[cfg(feature = "metrics-prometheus")]
#[tokio::test]
async fn test_opentelemetry_exporter_creation() {
    let exporter = OpenTelemetryExporter::new("test-est-client", "0.1.0");
    assert!(exporter.is_ok());
    if let Ok(exp) = exporter {
        exp.shutdown().unwrap();
    }
}

#[cfg(feature = "metrics-prometheus")]
#[tokio::test]
async fn test_opentelemetry_export() {
    let collector = MetricsCollector::new();
    let exporter = OpenTelemetryExporter::new("test-est", "0.1.0").unwrap();

    // Record operations
    collector
        .record_operation(
            OperationType::SimpleEnroll,
            Duration::from_millis(100),
            true,
        )
        .await;
    collector
        .record_tls_handshake(Duration::from_millis(25), true)
        .await;

    // Export
    let output = exporter.export(&collector).await.unwrap();

    // Should contain metric data
    assert!(!output.is_empty());

    exporter.shutdown().unwrap();
}

#[cfg(feature = "metrics-prometheus")]
#[tokio::test]
async fn test_opentelemetry_metric_labels() {
    let collector = MetricsCollector::new();
    let exporter = OpenTelemetryExporter::new("est", "1.0").unwrap();

    collector
        .record_operation(
            OperationType::SimpleEnroll,
            Duration::from_millis(100),
            true,
        )
        .await;

    let output = exporter.export(&collector).await.unwrap();

    // Verify operation labels are present
    assert!(output.contains("simple_enroll") || output.contains("operation"));

    exporter.shutdown().unwrap();
}

#[cfg(feature = "metrics-prometheus")]
#[tokio::test]
async fn test_both_exporters_same_data() {
    let collector = MetricsCollector::new();

    // Record some operations
    for _ in 0..5 {
        collector
            .record_operation(
                OperationType::SimpleEnroll,
                Duration::from_millis(100),
                true,
            )
            .await;
    }

    // Export via both exporters
    let prometheus_exporter = PrometheusExporter::new("est").unwrap();
    let otel_exporter = OpenTelemetryExporter::new("est", "1.0").unwrap();

    let prometheus_output = prometheus_exporter.export(&collector).await.unwrap();
    let otel_output = otel_exporter.export(&collector).await.unwrap();

    // Both should contain data
    assert!(!prometheus_output.is_empty());
    assert!(!otel_output.is_empty());

    otel_exporter.shutdown().unwrap();
}
