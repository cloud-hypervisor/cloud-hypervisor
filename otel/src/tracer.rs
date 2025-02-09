// Copyright © 2025 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{trace as sdktrace, Resource};
use opentelemetry_semantic_conventions::resource::SERVICE_NAME;

use crate::OTEL_SERVICE_NAME;

pub fn init() {
    let exporter = opentelemetry_otlp::new_exporter()
        .http()
        .with_endpoint("http://localhost:4318/v1/traces");
    let tracer_provider = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(exporter)
        .with_trace_config(
            sdktrace::Config::default().with_resource(Resource::new(vec![KeyValue::new(
                SERVICE_NAME,
                OTEL_SERVICE_NAME,
            )])),
        )
        .install_simple();
    global::set_tracer_provider(tracer_provider.unwrap());
}

pub fn get(name: &'static str) -> global::BoxedTracer {
    global::tracer(name)
}
