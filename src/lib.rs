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
pub mod transaction_builder;
pub mod types;

pub use client::{SilverClient, RpcClient, WebSocketClient};
pub use transaction_builder::{
    CallArgBuilder, TransactionBuilder, TypeTagBuilder,
};

// Re-export commonly used types from transaction_builder
pub use transaction_builder::{BuilderError, Result as BuilderResult};
