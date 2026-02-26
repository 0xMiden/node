use std::task::{Context, Poll};

use tonic::{Request, Response, Status};

use crate::generated::remote_prover::{self as proto, api_server};
use crate::server::{GrpcInterface, GrpcUnary, handle_unary};

pub struct ProveMethod;

impl GrpcInterface for ProveMethod {
    type Request = proto::ProofRequest;
    type Response = proto::Proof;
}

/// Public server trait for the remote prover API.
pub trait RemoteProverService: GrpcUnary<ProveMethod> {}

impl<T> RemoteProverService for T where T: GrpcUnary<ProveMethod> {}

#[tonic::async_trait]
impl<T> api_server::Api for T
where
    T: RemoteProverService,
{
    async fn prove(
        &self,
        request: Request<proto::ProofRequest>,
    ) -> Result<Response<proto::Proof>, Status> {
        handle_unary::<_, ProveMethod>(self, request).await
    }
}

pub struct RemoteProverServer<T> {
    inner: api_server::ApiServer<T>,
}

impl<T> RemoteProverServer<T>
where
    T: RemoteProverService,
{
    pub fn new(service: T) -> Self {
        Self {
            inner: api_server::ApiServer::new(service),
        }
    }
}

impl<T> Clone for RemoteProverServer<T> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

impl<T, B> tonic::codegen::Service<http::Request<B>> for RemoteProverServer<T>
where
    api_server::ApiServer<T>: tonic::codegen::Service<http::Request<B>>,
{
    type Response =
        <api_server::ApiServer<T> as tonic::codegen::Service<http::Request<B>>>::Response;
    type Error = <api_server::ApiServer<T> as tonic::codegen::Service<http::Request<B>>>::Error;
    type Future = <api_server::ApiServer<T> as tonic::codegen::Service<http::Request<B>>>::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        self.inner.call(req)
    }
}

impl<T> tonic::server::NamedService for RemoteProverServer<T> {
    const NAME: &'static str = api_server::SERVICE_NAME;
}
