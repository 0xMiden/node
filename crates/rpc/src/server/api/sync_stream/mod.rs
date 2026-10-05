use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::sync::mpsc::error::SendTimeoutError;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;
use tracing::Instrument;

mod admission;
#[cfg(test)]
mod tests;

pub(super) use admission::{SyncStreamLimiter, SyncStreamPermit};

#[tonic::async_trait]
pub(super) trait Paginator: Send + 'static {
    type Item: Send + 'static;

    async fn load_next_page(&mut self) -> tonic::Result<Option<Vec<Self::Item>>>;
}

/// Retains admission while the response holds unread data, including after the producer finishes.
pub struct SyncResponseStream<T> {
    receiver: ReceiverStream<tonic::Result<T>>,
    permit: Option<Arc<SyncStreamPermit>>,
}

impl<T> std::fmt::Debug for SyncResponseStream<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SyncResponseStream").finish_non_exhaustive()
    }
}

impl<T> tokio_stream::Stream for SyncResponseStream<T> {
    type Item = tonic::Result<T>;
    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let result = Pin::new(&mut self.receiver).poll_next(context);
        if matches!(result, Poll::Ready(None)) {
            self.permit.take();
        }
        result
    }
}

pub(super) struct SyncStream<P: Paginator> {
    paginator: P,
    tx: mpsc::Sender<tonic::Result<P::Item>>,
    terminal: Option<mpsc::OwnedPermit<tonic::Result<P::Item>>>,
    send_timeout: Duration,
    _permit: Arc<SyncStreamPermit>,
}

impl<P: Paginator> SyncStream<P> {
    pub(super) async fn start(
        mut paginator: P,
        permit: SyncStreamPermit,
        buffer_capacity: usize,
        send_timeout: Duration,
    ) -> tonic::Result<SyncResponseStream<P::Item>> {
        let capacity = buffer_capacity
            .checked_add(1)
            .filter(|_| buffer_capacity > 0)
            .ok_or_else(|| Status::internal("invalid synchronization stream buffer capacity"))?;
        // Initial validation errors are RPC statuses, before any stream data is sent.
        let first_page = checked_page(paginator.load_next_page().await?)?;
        let (tx, rx) = mpsc::channel(capacity);
        let response_permit = if let Some(page) = first_page {
            let permit = Arc::new(permit);
            // Keep one slot available for an error even when the data buffer is full.
            let terminal = tx.clone().try_reserve_owned().expect("new stream has capacity");
            let producer = Self {
                paginator,
                tx,
                terminal: Some(terminal),
                send_timeout,
                _permit: Arc::clone(&permit),
            };
            tokio::spawn(producer.run(page).instrument(tracing::Span::current()));
            Some(permit)
        } else {
            None
        };
        Ok(SyncResponseStream {
            receiver: ReceiverStream::new(rx),
            permit: response_permit,
        })
    }

    async fn run(mut self, mut page: Vec<P::Item>) {
        loop {
            for item in page {
                match self.tx.send_timeout(Ok(item), self.send_timeout).await {
                    Ok(()) => {},
                    Err(SendTimeoutError::Closed(_)) => return,
                    Err(SendTimeoutError::Timeout(_)) => {
                        self.fail(Status::deadline_exceeded(
                            "synchronization client stopped consuming updates",
                        ));
                        return;
                    },
                }
            }

            let next = tokio::select! {
                biased;
                () = self.tx.closed() => return,
                result = self.paginator.load_next_page() => result.and_then(checked_page),
            };
            match next {
                Ok(Some(next)) => page = next,
                Ok(None) => return,
                Err(status) => {
                    self.fail(status);
                    return;
                },
            }
        }
    }

    fn fail(&mut self, status: Status) {
        self.terminal.take().expect("terminal status is sent once").send(Err(status));
    }
}

fn checked_page<T>(page: Option<Vec<T>>) -> tonic::Result<Option<Vec<T>>> {
    if page.as_ref().is_some_and(Vec::is_empty) {
        return Err(Status::internal("synchronization paginator returned an empty page"));
    }
    Ok(page)
}
