use miden_node_tracing::spawn::spawn_blocking_in_current_span;

/// Selects where a gRPC method decodes its request before entering the handler.
#[derive(Clone, Copy, Debug)]
pub enum DecodeExecution {
    /// Decode on the task serving the request.
    Inline,
    /// Decode on Tokio's blocking pool in the current tracing span.
    Blocking,
}

impl DecodeExecution {
    pub(crate) async fn run<T: Send + 'static>(
        self,
        decode: impl FnOnce() -> tonic::Result<T> + Send + 'static,
    ) -> tonic::Result<T> {
        match self {
            Self::Inline => decode(),
            Self::Blocking => spawn_blocking_in_current_span(decode).await.map_err(|err| {
                let mut status =
                    tonic::Status::internal(format!("request decoding task failed: {err}"));
                status.set_source(std::sync::Arc::new(err));
                status
            })?,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::thread;

    use super::DecodeExecution;
    use crate::generated::miden::validator::v1::{StatusRequest, StatusResponse};
    use crate::server::miden_validator_v1_validator_service::Status;

    struct BlockingDecoder;

    #[tonic::async_trait]
    impl Status for BlockingDecoder {
        const DECODE_EXECUTION: DecodeExecution = DecodeExecution::Blocking;
        type Input = thread::ThreadId;
        type Output = StatusResponse;

        fn decode(_: StatusRequest) -> tonic::Result<Self::Input> {
            Ok(thread::current().id())
        }

        async fn handle(
            &self,
            decode_thread: Self::Input,
            _: &tonic::metadata::MetadataMap,
            _: &tonic::codegen::http::Extensions,
        ) -> tonic::Result<Self::Output> {
            assert_ne!(decode_thread, thread::current().id());
            Ok(StatusResponse::default())
        }

        fn encode(response: Self::Output) -> tonic::Result<StatusResponse> {
            Ok(response)
        }
    }

    #[tokio::test]
    async fn dispatcher_offloads_a_blocking_decoder() {
        BlockingDecoder
            .full(tonic::Request::new(StatusRequest::default()))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn decode_runs_on_the_selected_thread() {
        let caller = thread::current().id();
        let decode = || Ok(thread::current().id());
        assert_eq!(DecodeExecution::Inline.run(decode).await.unwrap(), caller);
        assert_ne!(DecodeExecution::Blocking.run(decode).await.unwrap(), caller);
    }

    #[tokio::test]
    async fn blocking_decode_reports_task_failure() {
        let status = DecodeExecution::Blocking
            .run(|| -> tonic::Result<()> { panic!("decoder panic") })
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::Internal);
        assert!(status.message().contains("decoder panic"));
        let cause = status.source().unwrap().downcast_ref::<tokio::task::JoinError>().unwrap();
        assert!(cause.is_panic());
    }

    #[tokio::test]
    async fn blocking_decode_preserves_request_errors() {
        let status = DecodeExecution::Blocking
            .run(|| Err::<(), _>(tonic::Status::invalid_argument("missing header")))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert_eq!(status.message(), "missing header");
    }
}
