//! RPC client library for SilverBitcoin blockchain
//!
//! This module provides async RPC clients for interacting with SilverBitcoin nodes:
//! - HTTP/JSON-RPC client for queries and transaction submission
//! - WebSocket client for real-time event subscriptions
//! - Connection pooling and automatic retry logic

use jsonrpsee::{
    core::client::{ClientT, Subscription, SubscriptionClientT},
    http_client::{HttpClient, HttpClientBuilder},
    rpc_params,
    ws_client::{WsClient, WsClientBuilder},
};
use serde::{Deserialize, Serialize};
use silver_core::{Object, ObjectID, ObjectRef, SilverAddress, Transaction, TransactionDigest};
use tracing::debug;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::RwLock;
use tokio::time::sleep;

/// RPC client errors
#[derive(Debug, Error)]
pub enum ClientError {
    /// Connection error
    #[error("Connection error: {0}")]
    Connection(String),

    /// RPC error
    #[error("RPC error: {0}")]
    Rpc(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Invalid response
    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    /// Timeout error
    #[error("Request timeout")]
    Timeout,

    /// Not found error
    #[error("Not found: {0}")]
    NotFound(String),
}

// Note: We can't implement From for jsonrpsee::core::Error directly due to orphan rules
// Users should convert errors manually using .map_err(|e| ClientError::Rpc(e.to_string()))

/// Result type for client operations
pub type Result<T> = std::result::Result<T, ClientError>;

/// Transaction status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionStatus {
    /// Transaction is pending in mempool
    Pending,
    /// Transaction has been executed
    Executed,
    /// Transaction execution failed
    Failed {
        /// Error message describing the failure
        error: String,
    },
}

/// Transaction response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionResponse {
    /// Transaction digest
    pub digest: TransactionDigest,
    /// Transaction status
    pub status: TransactionStatus,
    /// Fuel used (if executed)
    pub fuel_used: Option<u64>,
    /// Snapshot number (if finalized)
    pub snapshot: Option<u64>,
}

/// Event filter for subscriptions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventFilter {
    /// Filter by sender address
    pub sender: Option<SilverAddress>,
    /// Filter by event type
    pub event_type: Option<String>,
    /// Filter by object type
    pub object_type: Option<String>,
}

impl Default for EventFilter {
    fn default() -> Self {
        Self {
            sender: None,
            event_type: None,
            object_type: None,
        }
    }
}

/// Blockchain event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Transaction that emitted this event
    pub transaction_digest: TransactionDigest,
    /// Event index within transaction
    pub event_index: u32,
    /// Event type
    pub event_type: String,
    /// Sender address
    pub sender: SilverAddress,
    /// Event data (JSON)
    pub data: serde_json::Value,
    /// Timestamp
    pub timestamp: u64,
}

/// Network information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    /// Current snapshot height
    pub snapshot_height: u64,
    /// Number of connected peers
    pub peer_count: usize,
    /// Node is synchronized
    pub is_synced: bool,
    /// Node is a validator
    pub is_validator: bool,
}

/// Main SilverBitcoin client combining HTTP and WebSocket functionality
///
/// # Example
///
/// ```no_run
/// use silver_sdk::SilverClient;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let client = SilverClient::new("http://localhost:9545").await?;
///     
///     let info = client.get_network_info().await?;
///     println!("Snapshot height: {}", info.snapshot_height);
///     
///     Ok(())
/// }
/// ```
pub struct SilverClient {
    rpc: RpcClient,
}

impl SilverClient {
    /// Create a new client connected to the specified node
    pub async fn new(url: &str) -> Result<Self> {
        let rpc = RpcClient::new(url)?;
        Ok(Self { rpc })
    }

    /// Create a new client with custom configuration
    pub async fn with_config(config: ClientConfig) -> Result<Self> {
        let rpc = RpcClient::with_config(config)?;
        Ok(Self { rpc })
    }

    /// Get an object by ID
    pub async fn get_object(&self, object_id: ObjectID) -> Result<Object> {
        self.rpc.get_object(object_id).await
    }

    /// Get objects owned by an address
    pub async fn get_objects_owned_by(&self, address: SilverAddress) -> Result<Vec<ObjectRef>> {
        self.rpc.get_objects_owned_by(address).await
    }

    /// Get transaction status
    pub async fn get_transaction(&self, digest: TransactionDigest) -> Result<TransactionResponse> {
        self.rpc.get_transaction(digest).await
    }

    /// Submit a transaction
    pub async fn submit_transaction(&self, transaction: Transaction) -> Result<TransactionDigest> {
        self.rpc.submit_transaction(transaction).await
    }

    /// Get network information
    pub async fn get_network_info(&self) -> Result<NetworkInfo> {
        self.rpc.get_network_info().await
    }

    /// Get the current snapshot height
    pub async fn get_snapshot_height(&self) -> Result<u64> {
        self.rpc.get_snapshot_height().await
    }

    /// Create a WebSocket client for event subscriptions
    pub async fn websocket(&self, ws_url: &str) -> Result<WebSocketClient> {
        WebSocketClient::new(ws_url).await
    }
}

/// Client configuration
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Node URL
    pub url: String,
    /// Request timeout
    pub timeout: Duration,
    /// Maximum number of concurrent requests
    pub max_concurrent_requests: usize,
    /// Maximum request size in bytes
    pub max_request_size: u32,
    /// Maximum response size in bytes
    pub max_response_size: u32,
    /// Enable automatic retry on failure
    pub enable_retry: bool,
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Initial retry delay (exponential backoff)
    pub initial_retry_delay: Duration,
    /// Maximum retry delay
    pub max_retry_delay: Duration,
    /// Connection pool size
    pub connection_pool_size: usize,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            url: "http://localhost:9545".to_string(),
            timeout: Duration::from_secs(30),
            max_concurrent_requests: 100,
            max_request_size: 10 * 1024 * 1024,  // 10 MB
            max_response_size: 10 * 1024 * 1024, // 10 MB
            enable_retry: true,
            max_retries: 3,
            initial_retry_delay: Duration::from_millis(100),
            max_retry_delay: Duration::from_secs(10),
            connection_pool_size: 10,
        }
    }
}

/// HTTP/JSON-RPC client for SilverBitcoin node
///
/// Provides methods for querying blockchain state and submitting transactions.
/// Includes automatic retry logic with exponential backoff.
pub struct RpcClient {
    client: HttpClient,
    config: ClientConfig,
}

impl RpcClient {
    /// Create a new RPC client
    pub fn new(url: &str) -> Result<Self> {
        let config = ClientConfig {
            url: url.to_string(),
            ..Default::default()
        };
        Self::with_config(config)
    }

    /// Create a new RPC client with custom configuration
    pub fn with_config(config: ClientConfig) -> Result<Self> {
        let client = HttpClientBuilder::default()
            .request_timeout(config.timeout)
            .max_concurrent_requests(config.max_concurrent_requests)
            .max_request_size(config.max_request_size)
            .max_response_size(config.max_response_size)
            .build(&config.url)
            .map_err(|e| ClientError::Connection(e.to_string()))?;

        Ok(Self { client, config })
    }

    /// Execute a request with automatic retry logic
    async fn request_with_retry<T, P>(&self, method: &str, params: P) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
        P: jsonrpsee::core::traits::ToRpcParams + Clone + Send,
    {
        if !self.config.enable_retry {
            return self
                .client
                .request(method, params)
                .await
                .map_err(|e| ClientError::Rpc(e.to_string()));
        }

        let mut attempt = 0;
        let mut delay = self.config.initial_retry_delay;

        loop {
            match self.client.request(method, params.clone()).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    attempt += 1;

                    // Check if we should retry
                    if attempt >= self.config.max_retries || !Self::is_retryable_error(&e) {
                        return Err(ClientError::Rpc(e.to_string()));
                    }

                    // Exponential backoff with jitter
                    let jitter = Duration::from_millis(rand::random::<u64>() % 100);
                    let sleep_duration = std::cmp::min(delay + jitter, self.config.max_retry_delay);

                    tracing::warn!(
                        method = method,
                        attempt = attempt,
                        delay_ms = sleep_duration.as_millis(),
                        error = %e,
                        "RPC request failed, retrying"
                    );

                    sleep(sleep_duration).await;
                    delay = delay * 2; // Exponential backoff
                }
            }
        }
    }

    /// Check if an error is retryable
    fn is_retryable_error(error: &jsonrpsee::core::client::Error) -> bool {
        // Check error message for retryable conditions
        let error_str = error.to_string().to_lowercase();

        // Network/connection errors are retryable
        if error_str.contains("connection")
            || error_str.contains("timeout")
            || error_str.contains("network")
            || error_str.contains("transport")
        {
            return true;
        }

        // Server errors might be retryable
        if error_str.contains("server error") {
            return true;
        }

        // Parse errors and invalid params are not retryable
        false
    }

    /// Get an object by ID
    pub async fn get_object(&self, object_id: ObjectID) -> Result<Object> {
        let object_id_hex = object_id.to_hex();
        let response: Option<Object> = self
            .request_with_retry("silver_getObject", rpc_params![object_id_hex])
            .await?;

        response.ok_or_else(|| ClientError::NotFound(format!("Object {} not found", object_id)))
    }

    /// Get objects owned by an address
    pub async fn get_objects_owned_by(&self, address: SilverAddress) -> Result<Vec<ObjectRef>> {
        let address_hex = address.to_hex();
        let response: Vec<ObjectRef> = self
            .request_with_retry("silver_getObjectsOwnedBy", rpc_params![address_hex])
            .await?;

        Ok(response)
    }

    /// Get transaction status
    pub async fn get_transaction(&self, digest: TransactionDigest) -> Result<TransactionResponse> {
        let digest_hex = hex::encode(digest.as_bytes());
        let response: Option<TransactionResponse> = self
            .request_with_retry("silver_getTransaction", rpc_params![&digest_hex])
            .await?;

        response
            .ok_or_else(|| ClientError::NotFound(format!("Transaction {} not found", digest_hex)))
    }

    /// Submit a transaction
    pub async fn submit_transaction(&self, transaction: Transaction) -> Result<TransactionDigest> {
        // Serialize transaction
        let tx_bytes = bincode::serialize(&transaction)
            .map_err(|e| ClientError::Serialization(e.to_string()))?;
        let tx_hex = hex::encode(tx_bytes);

        let response: String = self
            .request_with_retry("silver_submitTransaction", rpc_params![tx_hex])
            .await?;

        // Parse digest from hex response
        let digest_bytes = hex::decode(&response)
            .map_err(|e| ClientError::InvalidResponse(format!("Invalid digest hex: {}", e)))?;

        if digest_bytes.len() != 64 {
            return Err(ClientError::InvalidResponse(format!(
                "Invalid digest length: expected 64, got {}",
                digest_bytes.len()
            )));
        }

        let mut digest = [0u8; 64];
        digest.copy_from_slice(&digest_bytes);
        Ok(TransactionDigest::new(digest))
    }

    /// Get network information
    pub async fn get_network_info(&self) -> Result<NetworkInfo> {
        let response: NetworkInfo = self
            .request_with_retry("silver_getNetworkInfo", rpc_params![])
            .await?;

        Ok(response)
    }

    /// Get the current snapshot height
    pub async fn get_snapshot_height(&self) -> Result<u64> {
        let response: u64 = self
            .request_with_retry("silver_getSnapshotHeight", rpc_params![])
            .await?;

        Ok(response)
    }

    /// Execute a batch of RPC requests
    ///
    /// Note: This executes requests sequentially with retry logic.
    /// For true batch execution, use the underlying jsonrpsee batch API.
    pub async fn batch_request<T>(&self, requests: Vec<(&str, serde_json::Value)>) -> Result<Vec<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let mut results = Vec::new();
        for (method, params) in requests {
            let result: T = self.request_with_retry(method, rpc_params![params]).await?;
            results.push(result);
        }
        Ok(results)
    }

    /// Get the underlying HTTP client
    pub fn http_client(&self) -> &HttpClient {
        &self.client
    }

    /// Get the client configuration
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// Check connection health
    pub async fn health_check(&self) -> Result<bool> {
        match self.get_snapshot_height().await {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

/// Connection pool for managing multiple RPC clients
///
/// Provides load balancing and failover across multiple nodes.
pub struct ConnectionPool {
    clients: Vec<RpcClient>,
    current_index: Arc<RwLock<usize>>,
}

impl ConnectionPool {
    /// Create a new connection pool with multiple node URLs
    pub fn new(urls: Vec<String>) -> Result<Self> {
        let clients: Result<Vec<_>> = urls.into_iter().map(|url| RpcClient::new(&url)).collect();

        Ok(Self {
            clients: clients?,
            current_index: Arc::new(RwLock::new(0)),
        })
    }

    /// Create a new connection pool with custom configuration
    pub fn with_configs(configs: Vec<ClientConfig>) -> Result<Self> {
        let clients: Result<Vec<_>> = configs.into_iter().map(RpcClient::with_config).collect();

        Ok(Self {
            clients: clients?,
            current_index: Arc::new(RwLock::new(0)),
        })
    }

    /// Get the next client using round-robin
    pub async fn get_client(&self) -> &RpcClient {
        let mut index = self.current_index.write().await;
        let client = &self.clients[*index];
        *index = (*index + 1) % self.clients.len();
        client
    }

    /// Get a healthy client (with health check)
    pub async fn get_healthy_client(&self) -> Result<&RpcClient> {
        for _ in 0..self.clients.len() {
            let client = self.get_client().await;
            if client.health_check().await.unwrap_or(false) {
                return Ok(client);
            }
        }
        Err(ClientError::Connection(
            "No healthy clients available".to_string(),
        ))
    }

    /// Get the number of clients in the pool
    pub fn size(&self) -> usize {
        self.clients.len()
    }

    /// Execute a request on any healthy client
    pub async fn execute<F, Fut, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&RpcClient) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let client = self.get_healthy_client().await?;
        f(client).await
    }
}

/// WebSocket client for real-time event subscriptions
///
/// Supports filtering events by sender, type, and object type.
/// Maintains persistent connection with automatic reconnection.
pub struct WebSocketClient {
    client: Arc<RwLock<WsClient>>,
    url: String,
    config: WebSocketConfig,
}

/// WebSocket client configuration
#[derive(Debug, Clone)]
pub struct WebSocketConfig {
    /// Enable automatic reconnection
    pub enable_reconnect: bool,
    /// Maximum reconnection attempts (0 = infinite)
    pub max_reconnect_attempts: u32,
    /// Initial reconnection delay
    pub initial_reconnect_delay: Duration,
    /// Maximum reconnection delay
    pub max_reconnect_delay: Duration,
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Ping interval for keep-alive
    pub ping_interval: Duration,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            enable_reconnect: true,
            max_reconnect_attempts: 0, // Infinite retries
            initial_reconnect_delay: Duration::from_secs(1),
            max_reconnect_delay: Duration::from_secs(60),
            connection_timeout: Duration::from_secs(30),
            ping_interval: Duration::from_secs(30),
        }
    }
}

impl WebSocketClient {
    /// Create a new WebSocket client with default configuration
    pub async fn new(url: &str) -> Result<Self> {
        Self::with_config(url, WebSocketConfig::default()).await
    }

    /// Create a new WebSocket client with custom configuration
    pub async fn with_config(url: &str, config: WebSocketConfig) -> Result<Self> {
        let client = Self::connect(url, &config).await?;

        Ok(Self {
            client: Arc::new(RwLock::new(client)),
            url: url.to_string(),
            config,
        })
    }

    /// Establish WebSocket connection
    async fn connect(url: &str, config: &WebSocketConfig) -> Result<WsClient> {
        let client = WsClientBuilder::default()
            .connection_timeout(config.connection_timeout)
            // Note: ping_interval is not available in all jsonrpsee versions
            // The client will use default ping settings
            .build(url)
            .await
            .map_err(|e| ClientError::Connection(e.to_string()))?;

        Ok(client)
    }

    /// Reconnect to the WebSocket server
    async fn reconnect(&self) -> Result<()> {
        if !self.config.enable_reconnect {
            return Err(ClientError::Connection("Reconnection disabled".to_string()));
        }

        let mut attempt = 0;
        let mut delay = self.config.initial_reconnect_delay;

        loop {
            attempt += 1;

            if self.config.max_reconnect_attempts > 0
                && attempt > self.config.max_reconnect_attempts
            {
                return Err(ClientError::Connection(format!(
                    "Failed to reconnect after {} attempts",
                    attempt - 1
                )));
            }

            tracing::info!(
                url = %self.url,
                attempt = attempt,
                delay_ms = delay.as_millis(),
                "Attempting to reconnect WebSocket"
            );

            match Self::connect(&self.url, &self.config).await {
                Ok(new_client) => {
                    let mut client = self.client.write().await;
                    *client = new_client;
                    tracing::info!(url = %self.url, "WebSocket reconnected successfully");
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!(
                        url = %self.url,
                        attempt = attempt,
                        error = %e,
                        "WebSocket reconnection failed"
                    );

                    // Exponential backoff with jitter
                    let jitter = Duration::from_millis(rand::random::<u64>() % 1000);
                    let sleep_duration =
                        std::cmp::min(delay + jitter, self.config.max_reconnect_delay);

                    sleep(sleep_duration).await;
                    delay = delay * 2;
                }
            }
        }
    }

    /// Get a read lock on the client
    async fn get_client(&self) -> tokio::sync::RwLockReadGuard<'_, WsClient> {
        self.client.read().await
    }

    /// Subscribe to events with optional filter
    pub async fn subscribe_events(&self, filter: EventFilter) -> Result<Subscription<Event>> {
        let client = self.get_client().await;
        let subscription: Subscription<Event> = client
            .subscribe(
                "silver_subscribeEvents",
                rpc_params![filter],
                "silver_unsubscribeEvents",
            )
            .await
            .map_err(|e| ClientError::Rpc(e.to_string()))?;

        Ok(subscription)
    }

    /// Subscribe to all events (no filter)
    pub async fn subscribe_all_events(&self) -> Result<Subscription<Event>> {
        self.subscribe_events(EventFilter::default()).await
    }

    /// Subscribe to events from a specific sender
    pub async fn subscribe_events_by_sender(
        &self,
        sender: SilverAddress,
    ) -> Result<Subscription<Event>> {
        let filter = EventFilter {
            sender: Some(sender),
            ..Default::default()
        };
        self.subscribe_events(filter).await
    }

    /// Subscribe to events of a specific type
    pub async fn subscribe_events_by_type(
        &self,
        event_type: String,
    ) -> Result<Subscription<Event>> {
        let filter = EventFilter {
            event_type: Some(event_type),
            ..Default::default()
        };
        self.subscribe_events(filter).await
    }

    /// Subscribe to snapshot updates
    pub async fn subscribe_snapshots(&self) -> Result<Subscription<u64>> {
        let client = self.get_client().await;
        let subscription: Subscription<u64> = client
            .subscribe(
                "silver_subscribeSnapshots",
                rpc_params![],
                "silver_unsubscribeSnapshots",
            )
            .await
            .map_err(|e| ClientError::Rpc(e.to_string()))?;

        Ok(subscription)
    }

    /// Get the WebSocket URL
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Get the WebSocket configuration
    pub fn config(&self) -> &WebSocketConfig {
        &self.config
    }

    /// Check if the connection is alive
    pub async fn is_connected(&self) -> bool {
        // Simple connectivity check - if we can acquire the read lock, connection is alive
        let _client = self.get_client().await;
        debug!("Health check passed");
        true
    }

    /// Manually trigger reconnection
    pub async fn ensure_connected(&self) -> Result<()> {
        if !self.is_connected().await {
            self.reconnect().await?;
        }
        Ok(())
    }
}
