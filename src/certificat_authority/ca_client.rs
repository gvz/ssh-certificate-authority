//! # CA Client
//!
//! This module provides a client for interacting with the Certificate Authority (CA) server
//! over a Unix socket. Each request is wrapped in an [`AuthenticatedRequest`] envelope
//! that carries a shared bearer token and a monotonic counter for replay protection.
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use log::{debug, error};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use super::{AuthenticatedRequest, CaRequest, CaResponse, MAX_MESSAGE_SIZE};

/// A client for the Certificate Authority.
#[derive(Clone)]
pub struct CaClient {
    socket_path: String,
    /// Shared secret token for authenticating requests to the CA server.
    auth_token: String,
    /// Monotonic counter shared across all clones of this client, used for replay protection.
    counter: Arc<AtomicU64>,
}

impl CaClient {
    /// Creates a new `CaClient`.
    ///
    /// # Arguments
    ///
    /// * `socket_path` - The path to the Unix socket for communication with the CA server.
    /// * `auth_token` - The shared secret token for authenticating IPC requests.
    pub fn new(socket_path: String, auth_token: String) -> Self {
        CaClient {
            socket_path,
            auth_token,
            counter: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Sends a request to the CA server and returns the response.
    ///
    /// The request is wrapped in an [`AuthenticatedRequest`] envelope containing
    /// the bearer token and a monotonically increasing counter value.
    ///
    /// # Arguments
    ///
    /// * `request` - The request to send to the CA server.
    ///
    /// # Returns
    ///
    /// A `Result` containing the `CaResponse` from the server or an error.
    pub async fn send_request(&self, request: CaRequest) -> Result<CaResponse> {
        debug!("connection to: {}", self.socket_path);
        let mut stream = UnixStream::connect(&self.socket_path).await?;

        let prev = self.counter.fetch_add(1, Ordering::SeqCst);
        let counter = prev.checked_add(1).ok_or_else(|| {
            error!("IPC counter exhausted after 2^64 requests; CA must be restarted");
            anyhow::anyhow!("IPC counter exhausted: restart the CA process to restore service")
        })?;
        let auth_request = AuthenticatedRequest {
            token: self.auth_token.clone(),
            counter,
            request,
        };

        let request_json = serde_json::to_string(&auth_request)?;
        let request_bytes = request_json.as_bytes();
        let request_len = request_bytes.len() as u32;
        if request_len > MAX_MESSAGE_SIZE {
            anyhow::bail!(
                "Request size {} exceeds maximum allowed {}",
                request_len,
                MAX_MESSAGE_SIZE
            );
        }
        // Write the 4-byte big-endian length prefix followed by the payload.
        stream.write_all(&request_len.to_be_bytes()).await?;
        stream.write_all(request_bytes).await?;
        debug!("wrote to: {}", self.socket_path);

        // Read the 4-byte big-endian length prefix of the response.
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let response_len = u32::from_be_bytes(len_buf);
        if response_len > MAX_MESSAGE_SIZE {
            anyhow::bail!(
                "Response size {} exceeds maximum allowed {}",
                response_len,
                MAX_MESSAGE_SIZE
            );
        }
        // Read exactly the declared number of bytes.
        let mut response_buf = vec![0u8; response_len as usize];
        stream.read_exact(&mut response_buf).await?;
        let response_json = String::from_utf8(response_buf)?;
        debug!("read from: {}, {}", self.socket_path, response_json);
        let response: CaResponse = serde_json::from_str(&response_json)?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Tests that the counter starts at 0 and increments correctly.
    #[test]
    fn test_counter_starts_at_zero() {
        let client = CaClient::new("/tmp/test.sock".to_string(), "test-token".to_string());

        // Counter should start at 0
        assert_eq!(client.counter.load(Ordering::SeqCst), 0);
    }

    /// Tests that the counter increments with each call (simulated).
    #[test]
    fn test_counter_increment_behavior() {
        let client = CaClient::new("/tmp/test.sock".to_string(), "test-token".to_string());

        // Simulate what send_request does: fetch_add(1) + 1
        let counter1 = client.counter.fetch_add(1, Ordering::SeqCst) + 1;
        assert_eq!(counter1, 1, "First request should use counter 1");

        let counter2 = client.counter.fetch_add(1, Ordering::SeqCst) + 1;
        assert_eq!(counter2, 2, "Second request should use counter 2");

        let counter3 = client.counter.fetch_add(1, Ordering::SeqCst) + 1;
        assert_eq!(counter3, 3, "Third request should use counter 3");
    }

    /// Tests that cloned clients share the same counter.
    #[test]
    fn test_cloned_clients_share_counter() {
        let client1 = CaClient::new("/tmp/test.sock".to_string(), "test-token".to_string());

        let client2 = client1.clone();

        // Increment via client1
        let counter1 = client1.counter.fetch_add(1, Ordering::SeqCst) + 1;
        assert_eq!(counter1, 1);

        // Increment via client2 - should see the update from client1
        let counter2 = client2.counter.fetch_add(1, Ordering::SeqCst) + 1;
        assert_eq!(counter2, 2, "Cloned client should share the same counter");

        // Both should now see the same value
        assert_eq!(client1.counter.load(Ordering::SeqCst), 2);
        assert_eq!(client2.counter.load(Ordering::SeqCst), 2);
    }

    /// Tests that the counter is thread-safe across concurrent increments.
    #[test]
    fn test_counter_thread_safety() {
        use std::thread;

        let client = Arc::new(CaClient::new(
            "/tmp/test.sock".to_string(),
            "test-token".to_string(),
        ));

        let mut handles = vec![];

        // Spawn 10 threads, each incrementing 100 times
        for _ in 0..10 {
            let client_clone = Arc::clone(&client);
            let handle = thread::spawn(move || {
                for _ in 0..100 {
                    client_clone.counter.fetch_add(1, Ordering::SeqCst);
                }
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Total increments should be 10 * 100 = 1000
        assert_eq!(
            client.counter.load(Ordering::SeqCst),
            1000,
            "Counter should be thread-safe"
        );
    }

    /// Tests that the counter saturates at u64::MAX and does not wrap.
    #[test]
    fn test_counter_near_max() {
        let client = CaClient::new("/tmp/test.sock".to_string(), "test-token".to_string());

        // Set counter to near max value
        client.counter.store(u64::MAX - 2, Ordering::SeqCst);

        // Second-to-last valid counter
        let prev1 = client.counter.fetch_add(1, Ordering::SeqCst);
        assert_eq!(prev1.checked_add(1), Some(u64::MAX - 1));

        // Last valid counter
        let prev2 = client.counter.fetch_add(1, Ordering::SeqCst);
        assert_eq!(prev2.checked_add(1), Some(u64::MAX));

        // At u64::MAX: checked_add returns None — overflow detected, no wrap
        let prev3 = client.counter.fetch_add(1, Ordering::SeqCst);
        assert_eq!(prev3, u64::MAX, "fetch_add returns u64::MAX before wrapping");
        assert!(prev3.checked_add(1).is_none(), "overflow detected, request must be rejected");
    }
}
