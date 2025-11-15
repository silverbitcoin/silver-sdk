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

pub use client::{
    ClientConfig, ClientError, ConnectionPool, Event, EventFilter, NetworkInfo,
    RpcClient, SilverClient, TransactionResponse, TransactionStatus, WebSocketClient,
    WebSocketConfig, Result as ClientResult,
};
pub use codegen::{
    CodeGenerator, CodegenError, QuantumFunction, QuantumModule, QuantumParameter,
    QuantumStruct, QuantumType, Result as CodegenResult,
};
pub use transaction_builder::{
    CallArgBuilder, TransactionBuilder, TypeTagBuilder,
};

// Re-export commonly used types from transaction_builder
pub use transaction_builder::{BuilderError, Result as BuilderResult};
