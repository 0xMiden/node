use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio_stream::StreamExt;
use tonic::{Code, Status};

use super::{Paginator, SyncStream, SyncStreamLimiter};

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

    async fn load_next_page(&mut self) -> tonic::Result<Option<Vec<Self::Item>>> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        self.pages.pop_front().transpose()
    }
}

fn client(n: u8) -> IpAddr {
    Ipv4Addr::new(127, 0, 0, n).into()
}

#[tokio::test]
async fn empty_stream_completes_and_releases_admission() {
    let limiter = SyncStreamLimiter::new(1, 1);
    let mut stream = SyncStream::start(
        Pages::new([]),
        limiter.acquire(Some(client(1))).unwrap(),
        1,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert!(stream.next().await.is_none());
    assert!(limiter.acquire(Some(client(1))).is_ok());
}

#[tokio::test]
async fn pages_preserve_every_item_in_order() {
    let limiter = SyncStreamLimiter::new(1, 1);
    let mut stream = SyncStream::start(
        Pages::new([Ok(vec![1, 2]), Ok(vec![3, 4])]),
        limiter.acquire(Some(client(1))).unwrap(),
        1,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    let mut items = Vec::new();
    while let Some(item) = stream.next().await {
        items.push(item.unwrap());
    }
    assert_eq!(items, [1, 2, 3, 4]);
    assert!(limiter.acquire(Some(client(1))).is_ok());
}

#[tokio::test]
async fn first_page_error_is_initial_status_and_releases_admission() {
    let limiter = SyncStreamLimiter::new(1, 1);
    let result = SyncStream::start(
        Pages::new([Err(Status::invalid_argument("unavailable target"))]),
        limiter.acquire(Some(client(1))).unwrap(),
        1,
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(result.unwrap_err().code(), Code::InvalidArgument);
    assert!(limiter.acquire(Some(client(1))).is_ok());
}

#[tokio::test]
async fn later_page_error_follows_delivered_items() {
    let limiter = SyncStreamLimiter::new(1, 1);
    let mut stream = SyncStream::start(
        Pages::new([Ok(vec![1]), Err(Status::internal("database unavailable"))]),
        limiter.acquire(Some(client(1))).unwrap(),
        1,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(stream.next().await.unwrap().unwrap(), 1);
    assert_eq!(stream.next().await.unwrap().unwrap_err().code(), Code::Internal);
    assert!(stream.next().await.is_none());
    assert!(limiter.acquire(Some(client(1))).is_ok());
}

#[tokio::test(start_paused = true)]
async fn stalled_reader_receives_terminal_error_even_when_buffer_is_full() {
    let limiter = SyncStreamLimiter::new(1, 1);
    let mut stream = SyncStream::start(
        Pages::new([Ok(vec![1, 2, 3])]),
        limiter.acquire(Some(client(1))).unwrap(),
        1,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(2)).await;
    tokio::task::yield_now().await;
    assert_eq!(stream.next().await.unwrap().unwrap(), 1);
    assert_eq!(stream.next().await.unwrap().unwrap_err().code(), Code::DeadlineExceeded);
    assert!(stream.next().await.is_none());
    assert!(limiter.acquire(Some(client(1))).is_ok());
}

#[tokio::test]
async fn disconnect_prevents_next_page_and_releases_admission() {
    let limiter = SyncStreamLimiter::new(1, 1);
    let pages = Pages::new([Ok(vec![1, 2, 3]), Ok(vec![4])]);
    let loads = Arc::clone(&pages.loads);
    let stream = SyncStream::start(
        pages,
        limiter.acquire(Some(client(1))).unwrap(),
        1,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    tokio::task::yield_now().await;
    drop(stream);
    tokio::task::yield_now().await;
    assert_eq!(loads.load(Ordering::SeqCst), 1);
    assert!(limiter.acquire(Some(client(1))).is_ok());
}

#[tokio::test]
async fn empty_page_is_an_error_instead_of_silent_incomplete_success() {
    let limiter = SyncStreamLimiter::new(1, 1);
    let result = SyncStream::start(
        Pages::new([Ok(vec![]), Ok(vec![1])]),
        limiter.acquire(Some(client(1))).unwrap(),
        1,
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(result.unwrap_err().code(), Code::Internal);
    assert!(limiter.acquire(Some(client(1))).is_ok());
}

#[test]
fn global_and_client_limits_are_independent_and_reusable() {
    let limiter = SyncStreamLimiter::new(2, 1);
    let first = limiter.acquire(Some(client(1))).unwrap();
    assert_eq!(limiter.acquire(Some(client(1))).err().unwrap().code(), Code::ResourceExhausted);
    let second = limiter.acquire(Some(client(2))).unwrap();
    assert_eq!(limiter.acquire(Some(client(3))).err().unwrap().code(), Code::ResourceExhausted);
    drop(first);
    let replacement = limiter.acquire(Some(client(1))).unwrap();
    drop(second);
    drop(replacement);
    assert!(limiter.acquire(Some(client(3))).is_ok());
}

#[test]
fn unresolved_addresses_share_a_limit() {
    let limiter = SyncStreamLimiter::new(3, 1);
    let first = limiter.acquire(None).unwrap();
    assert_eq!(limiter.acquire(None).err().unwrap().code(), Code::ResourceExhausted);
    assert!(limiter.acquire(Some(client(1))).is_ok());
    drop(first);
    assert!(limiter.acquire(None).is_ok());
}

struct PendingPage {
    started: Arc<tokio::sync::Notify>,
    first: bool,
}

#[tonic::async_trait]
impl Paginator for PendingPage {
    type Item = u32;

    async fn load_next_page(&mut self) -> tonic::Result<Option<Vec<Self::Item>>> {
        if self.first {
            self.first = false;
            return Ok(Some(vec![1]));
        }
        self.started.notify_one();
        std::future::pending().await
    }
}

#[tokio::test]
async fn disconnect_cancels_pending_page_and_releases_admission() {
    let limiter = SyncStreamLimiter::new(1, 1);
    let started = Arc::new(tokio::sync::Notify::new());
    let mut stream = SyncStream::start(
        PendingPage {
            started: Arc::clone(&started),
            first: true,
        },
        limiter.acquire(Some(client(1))).unwrap(),
        1,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(stream.next().await.unwrap().unwrap(), 1);
    started.notified().await;
    assert_eq!(limiter.acquire(Some(client(1))).err().unwrap().code(), Code::ResourceExhausted);
    drop(stream);
    tokio::task::yield_now().await;
    assert!(limiter.acquire(Some(client(1))).is_ok());
}

#[tokio::test]
async fn completed_producer_keeps_unread_response_admitted_until_eof_or_drop() {
    let limiter = SyncStreamLimiter::new(1, 1);
    let mut stream = SyncStream::start(
        Pages::new([Ok(vec![1])]),
        limiter.acquire(Some(client(1))).unwrap(),
        1,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    assert_eq!(limiter.acquire(Some(client(1))).err().unwrap().code(), Code::ResourceExhausted);
    assert_eq!(stream.next().await.unwrap().unwrap(), 1);
    assert!(stream.next().await.is_none());
    let mut stream = SyncStream::start(
        Pages::new([Ok(vec![2])]),
        limiter.acquire(Some(client(1))).unwrap(),
        1,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    assert_eq!(limiter.acquire(Some(client(2))).err().unwrap().code(), Code::ResourceExhausted);
    assert_eq!(stream.next().await.unwrap().unwrap(), 2);
    // Consuming data alone does not signal successful termination.
    assert!(limiter.acquire(Some(client(1))).is_err());
    drop(stream);
    assert!(limiter.acquire(Some(client(1))).is_ok());
}
