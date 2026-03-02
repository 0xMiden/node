use core::fmt::Display;

use futures::stream::Stream;
use tonic::{Request, Response, Status};

/// Decode a gRPC request body into a domain input type.
pub trait GrpcDecode<T>: Sized + Send + Sync + 'static {
    type Error: Display + Send + Sync + 'static;

    fn decode(input: T) -> Result<Self, Self::Error>;
}

/// Encode a domain output into a gRPC response body.
///
/// The encode consumes `self` so implementors can move out of the output.
pub trait GrpcEncode<T>: Send + Sync + 'static {
    fn encode(self) -> Result<T, Status>;
}

pub trait GrpcInterface {
    type Request;
    type Response;
}

/// Unary method handler.
///
/// The method marker `M` is used to disambiguate multiple methods that share request/response
/// types.
#[tonic::async_trait]
pub trait GrpcUnary<Method: GrpcInterface>: Send + Sync + 'static {
    type Input: GrpcDecode<Method::Request>;
    type Output: GrpcEncode<Method::Response>;

    async fn handle(&self, input: Self::Input) -> Result<Self::Output, Status>;
}

/// Server-streaming method handler.
///
/// The method marker `M` is used to disambiguate multiple methods that share request/response
/// types.
#[tonic::async_trait]
pub trait GrpcServerStream<Method: GrpcInterface>: Send + Sync + 'static {
    type Input: GrpcDecode<Method::Request>;
    type Stream: Stream<Item = Result<Method::Response, Status>> + Send + 'static;

    async fn handle(&self, input: Self::Input) -> Result<Self::Stream, Status>;
}

/// Execute the standard unary flow: decode → handle → encode.
///
/// Decode errors are mapped to `Status::invalid_argument`.
pub async fn handle_unary<Method>(
    request: Request<Method::Request>,
) -> Result<Response<Method::Response>, Status>
where
    Method: GrpcInterface,
{
    let input = Method::Input::decode(request.into_inner())
        .map_err(|err| Status::invalid_argument(err.to_string()))?;
    let output = Method::handle(input).await?;
    let response = output.encode()?;
    Ok(Response::new(response))
}
