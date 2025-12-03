//! SDK type definitions and utilities
//!
//! This module provides additional type definitions and utilities
//! for working with the SilverBitcoin SDK.

// Re-export commonly used types from core
pub use silver_core::{
    Command, Identifier, Object, ObjectID, ObjectRef, SequenceNumber, SilverAddress, Transaction,
    TransactionDigest,
};

pub use silver_core::transaction::TypeTag;
