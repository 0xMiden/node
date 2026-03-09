use tonic::service::Interceptor;
use tonic::{Request, Status};

// Extracts the IP for connection management and rate-limiting requests, called `Governor`.
#[derive(Debug, Clone)]
pub struct ConnectInfoInterceptor;

impl Interceptor for ConnectInfoInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let addr = request
            .remote_addr()
            .ok_or_else(|| Status::failed_precondition("Expected TCP connection"))?;
        request
            .metadata_mut()
            .insert("forwarded", format!("for={addr}").try_into().unwrap());
        Ok(request)
    }
}
