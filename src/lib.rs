//! # SilverBitcoin SDK
//!
//! Rust SDK for building applications on SilverBitcoin blockchain.
//!
//! This crate provides:
//! - Transaction builder API
//! - RPC client for node communication
//! - WebSocket client for event subscriptions
//! - Type-safe function call builders

#![warn(missing_docs, rust_2018_idioms)]
#![forbid(unsafe_code)]

pub mod client;
pub mod codegen;
pub mod transaction_builder;
pub mod types;
pub mod wallet;
pub mod wallet_connect;
pub mod config;
pub mod signing;

pub use client::{
    ClientConfig, ClientError, ConnectionPool, Event, EventFilter, NetworkInfo,
    Result as ClientResult, RpcClient, SilverClient, TransactionResponse, TransactionStatus,
    WebSocketClient, WebSocketConfig,
};
pub use codegen::{
    CodeGenerator, CodegenError, QuantumFunction, QuantumModule, QuantumParameter, QuantumStruct,
    QuantumType, Result as CodegenResult,
};
pub use transaction_builder::{CallArgBuilder, TransactionBuilder, TypeTagBuilder};
pub use wallet::{
    Account, AddressFormat, DerivationPath, Wallet, WalletCredentials, WalletConnectionInfo,
    WalletError, WalletManager, WalletType, Result as WalletResult,
};
pub use wallet_connect::{
    EthereumWalletConnection, PeerMetadata, SolanaWalletConnection, WalletConnectClient,
    WalletConnectError, WalletConnectRequest, WalletConnectResponse, WalletConnectSession,
    Result as WalletConnectResult,
};
pub use config::{
    NetworkEnvironment, SilverBitcoinConfig, SilverBitcoinDevnet, SilverBitcoinTestnet,
};
pub use signing::{
    EcdsaSigner, MessageSigner, Sha256Hasher, SignatureWithRecovery, SigningError,
    TransactionSigner, Result as SigningResult,
};

// Re-export commonly used types from transaction_builder
pub use transaction_builder::{BuilderError, Result as BuilderResult};
