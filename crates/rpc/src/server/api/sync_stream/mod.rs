use std::time::Duration;

use tokio::sync::mpsc;
use tokio::sync::mpsc::error::SendTimeoutError;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;
use tracing::Instrument;

#[cfg(test)]
mod tests;

#[tonic::async_trait]
pub(super) trait Paginator: Send + 'static {
    type Item: Send + 'static;

    /// Returns a bounded, nonempty page, or `None` after successful completion.
    ///
    /// Page errors must fail the complete synchronization attempt. Do not retain database
    /// transactions or state views after the page is loaded.
    async fn load_next_page(&mut self) -> tonic::Result<Option<Vec<Self::Item>>>;
}

pub type SyncResponseStream<T> = ReceiverStream<tonic::Result<T>>;

pub(super) struct SyncStream<P: Paginator> {
    paginator: P,
    tx: mpsc::Sender<tonic::Result<P::Item>>,
    terminal: Option<mpsc::OwnedPermit<tonic::Result<P::Item>>>,
    send_timeout: Duration,
}

impl<P: Paginator> SyncStream<P> {
    /// Validates the first page before exposing a response stream.
    ///
    /// Reserves a channel slot for a terminal error so a full data buffer cannot hide failure.
    pub(super) async fn start(
        mut paginator: P,
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
        if let Some(page) = first_page {
            // Keep one slot available for an error even when the data buffer is full.
            let terminal = tx.clone().try_reserve_owned().expect("new stream has capacity");
            let producer = Self {
                paginator,
                tx,
                terminal: Some(terminal),
                send_timeout,
            };
            tokio::spawn(producer.run(page).instrument(tracing::Span::current()));
        }
        Ok(ReceiverStream::new(rx))
    }

    /// Sends bounded pages with backpressure and a deadline for each blocked send.
    ///
    /// Cancels pending page loads on disconnect. Sends later failures through the reserved terminal slot.
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

    /// Uses the reserved slot to report failure even when the data buffer is full.
    fn fail(&mut self, status: Status) {
        self.terminal.take().expect("terminal status is sent once").send(Err(status));
    }
}

/// Rejects empty pages so a faulty paginator cannot report incomplete data as successful
/// completion.
fn checked_page<T>(page: Option<Vec<T>>) -> tonic::Result<Option<Vec<T>>> {
    if page.as_ref().is_some_and(Vec::is_empty) {
        return Err(Status::internal("synchronization paginator returned an empty page"));
    }
    Ok(page)
}
