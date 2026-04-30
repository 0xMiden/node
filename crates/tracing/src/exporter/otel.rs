use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::SdkTracerProvider;

use super::InstallError;

pub(super) fn grpc_trace_provider(
    endpoint: String,
    service_name: String,
) -> Result<SdkTracerProvider, InstallError> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
        .map_err(InstallError::OtlpExporter)?;
    let resource = Resource::builder_empty().with_service_name(service_name).build();

    Ok(SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build())
}
