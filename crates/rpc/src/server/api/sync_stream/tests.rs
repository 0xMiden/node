use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio_stream::StreamExt;
use tonic::{Code, Status};

use super::{Paginator, SyncStream};

struct Pages {
    pages: VecDeque<tonic::Result<Vec<u32>>>,
    loads: Arc<AtomicUsize>,
}

impl Pages {
    fn new(pages: impl IntoIterator<Item = tonic::Result<Vec<u32>>>) -> Self {
        Self {
            pages: pages.into_iter().collect(),
            loads: Arc::default(),
        }
    }
}

#[tonic::async_trait]
impl Paginator for Pages {
    type Item = u32;

    /// Returns scripted pages and counts loads so tests can detect unwanted reads after
    /// cancellation.
    async fn load_next_page(&mut self) -> tonic::Result<Option<Vec<Self::Item>>> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        self.pages.pop_front().transpose()
    }
}

/// An empty result must complete successfully with no records.
#[tokio::test]
async fn empty_stream_completes() {
    let mut stream = SyncStream::start(Pages::new([]), 1, Duration::from_secs(1)).await.unwrap();
    assert!(stream.next().await.is_none());
}

/// Page boundaries must not change result order or omit items under backpressure.
#[tokio::test]
async fn pages_preserve_every_item_in_order() {
    let mut stream =
        SyncStream::start(Pages::new([Ok(vec![1, 2]), Ok(vec![3, 4])]), 1, Duration::from_secs(1))
            .await
            .unwrap();
    let mut items = Vec::new();
    while let Some(item) = stream.next().await {
        items.push(item.unwrap());
    }
    assert_eq!(items, [1, 2, 3, 4]);
}

/// Initial validation must fail before any stream data is exposed.
#[tokio::test]
async fn first_page_error_is_initial_status() {
    let result = SyncStream::start(
        Pages::new([Err(Status::invalid_argument("unavailable target"))]),
        1,
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(result.unwrap_err().code(), Code::InvalidArgument);
}

/// A page failure after valid data must terminate the stream with a failure.
#[tokio::test]
async fn later_page_error_follows_delivered_items() {
    let mut stream = SyncStream::start(
        Pages::new([Ok(vec![1]), Err(Status::internal("database unavailable"))]),
        1,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(stream.next().await.unwrap().unwrap(), 1);
    assert_eq!(stream.next().await.unwrap().unwrap_err().code(), Code::Internal);
    assert!(stream.next().await.is_none());
}

/// A full data buffer must not hide a stalled-reader failure behind successful completion.
#[tokio::test(start_paused = true)]
async fn stalled_reader_receives_terminal_error_even_when_buffer_is_full() {
    let mut stream = SyncStream::start(Pages::new([Ok(vec![1, 2, 3])]), 1, Duration::from_secs(1))
        .await
        .unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(2)).await;
    tokio::task::yield_now().await;
    assert_eq!(stream.next().await.unwrap().unwrap(), 1);
    assert_eq!(stream.next().await.unwrap().unwrap_err().code(), Code::DeadlineExceeded);
    assert!(stream.next().await.is_none());
}

/// Disconnected readers must not trigger more database work.
#[tokio::test]
async fn disconnect_prevents_next_page() {
    let pages = Pages::new([Ok(vec![1, 2, 3]), Ok(vec![4])]);
    let loads = Arc::clone(&pages.loads);
    let stream = SyncStream::start(pages, 1, Duration::from_secs(1)).await.unwrap();
    tokio::task::yield_now().await;
    drop(stream);
    tokio::task::yield_now().await;
    assert_eq!(loads.load(Ordering::SeqCst), 1);
}

/// An invalid empty continuation page must not make an incomplete update appear successful.
#[tokio::test]
async fn empty_page_is_an_error_instead_of_silent_incomplete_success() {
    let result =
        SyncStream::start(Pages::new([Ok(vec![]), Ok(vec![1])]), 1, Duration::from_secs(1)).await;
    assert_eq!(result.unwrap_err().code(), Code::Internal);
}

struct PendingPage {
    started: Arc<tokio::sync::Notify>,
    first: bool,
    drops: Arc<AtomicUsize>,
}

impl Drop for PendingPage {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[tonic::async_trait]
impl Paginator for PendingPage {
    type Item = u32;

    /// Waits indefinitely after notifying the test that page loading has started.
    ///
    /// Lets the test verify that a disconnect cancels a pending page load.
    async fn load_next_page(&mut self) -> tonic::Result<Option<Vec<Self::Item>>> {
        if self.first {
            self.first = false;
            return Ok(Some(vec![1]));
        }
        self.started.notify_one();
        std::future::pending().await
    }
}

/// Dropping a response must cancel an in-progress page load.
#[tokio::test]
async fn disconnect_cancels_pending_page() {
    let started = Arc::new(tokio::sync::Notify::new());
    let drops = Arc::new(AtomicUsize::new(0));
    let mut stream = SyncStream::start(
        PendingPage {
            started: Arc::clone(&started),
            first: true,
            drops: Arc::clone(&drops),
        },
        1,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(stream.next().await.unwrap().unwrap(), 1);
    started.notified().await;
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(stream);
    tokio::task::yield_now().await;
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}
