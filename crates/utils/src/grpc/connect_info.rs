use tonic::service::Interceptor;
use tonic::{Request, Status};

// Extracts the IP for `Governor`
#[derive(Debug, Clone)]
pub struct ConnectInfoInterceptor;

impl Interceptor for ConnectInfoInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let addr = request
            .remote_addr()
            .ok_or_else(|| Status::failed_precondition("Expected TCP connection"))?;
        // TODO double check how to address proxy rate limiting based on i.e. `X-Real-IP`.
        request
            .metadata_mut()
            .insert("forwarded", format!("for={addr}").try_into().unwrap());
        Ok(request)
    }
}
