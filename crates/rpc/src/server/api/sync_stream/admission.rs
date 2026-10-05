use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tonic::Status;

pub(in crate::server::api) struct SyncStreamLimits {
    pub global: usize,
    pub per_client: usize,
}

impl Default for SyncStreamLimits {
    fn default() -> Self {
        Self { global: 32, per_client: 2 }
    }
}

struct Admission {
    global: Arc<Semaphore>,
    per_client: usize,
    clients: Mutex<HashMap<Option<IpAddr>, usize>>,
}

pub(in crate::server::api) struct SyncStreamLimiter(Arc<Admission>);

pub(in crate::server::api) struct SyncStreamPermit {
    admission: Arc<Admission>,
    client: Option<IpAddr>,
    _global: OwnedSemaphorePermit,
}

impl Default for SyncStreamLimiter {
    fn default() -> Self {
        let limits = SyncStreamLimits::default();
        Self::new(limits.global, limits.per_client)
    }
}

impl SyncStreamLimiter {
    pub(in crate::server::api) fn new(global: usize, per_client: usize) -> Self {
        Self(Arc::new(Admission {
            global: Arc::new(Semaphore::new(global)),
            per_client,
            clients: Mutex::default(),
        }))
    }

    pub(in crate::server::api) fn acquire(
        &self,
        client: Option<IpAddr>,
    ) -> tonic::Result<SyncStreamPermit> {
        let global = Arc::clone(&self.0.global)
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("too many active synchronization streams"))?;
        let mut clients = self.0.clients.lock().expect("sync admission lock is not poisoned");
        if clients.get(&client).copied().unwrap_or(0) >= self.0.per_client {
            return Err(Status::resource_exhausted("too many synchronization streams for client"));
        }
        *clients.entry(client).or_default() += 1;
        Ok(SyncStreamPermit {
            admission: Arc::clone(&self.0),
            client,
            _global: global,
        })
    }
}

impl Drop for SyncStreamPermit {
    fn drop(&mut self) {
        let mut clients =
            self.admission.clients.lock().expect("sync admission lock is not poisoned");
        let count = clients.get_mut(&self.client).expect("admitted client has an active count");
        *count -= 1;
        if *count == 0 {
            clients.remove(&self.client);
        }
    }
}
