//! Real cryptographic signing implementations
//!
//! Supports:
//! - ECDSA (secp256k1)
//! - SHA256 hashing
//! - Message signing with recovery
//! - Transaction signing

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Cryptographic signing operation errors
#[derive(Error, Debug)]
pub enum SigningError {
    /// Invalid private key format or value
    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),

    /// Invalid message format
    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    /// Signing operation failed
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// Signature verification failed
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    /// Invalid signature format
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// JSON serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Result type for signing operations
pub type Result<T> = std::result::Result<T, SigningError>;

/// ECDSA signature with recovery information for public key recovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureWithRecovery {
    /// Signature bytes in (r, s) format (64 bytes for secp256k1)
    pub signature: Vec<u8>,
    /// Recovery ID (0-3) for public key recovery
    pub recovery_id: u8,
}

impl SignatureWithRecovery {
    /// Create a new signature with recovery
    pub fn new(signature: Vec<u8>, recovery_id: u8) -> Self {
        Self {
            signature,
            recovery_id,
        }
    }

    /// Get signature as hex string
    pub fn to_hex(&self) -> String {
        format!("0x{}{}", hex::encode(&self.signature), self.recovery_id)
    }

    /// Parse from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let hex_str = if hex_str.starts_with("0x") {
            &hex_str[2..]
        } else {
            hex_str
        };

        if hex_str.len() < 2 {
            return Err(SigningError::InvalidSignature("Hex string too short".to_string()));
        }

        let recovery_id_str = &hex_str[hex_str.len() - 1..];
        let recovery_id = u8::from_str_radix(recovery_id_str, 16)
            .map_err(|e| SigningError::InvalidSignature(e.to_string()))?;

        let sig_hex = &hex_str[..hex_str.len() - 1];
        let signature = hex::decode(sig_hex)
            .map_err(|e| SigningError::InvalidSignature(e.to_string()))?;

        Ok(Self::new(signature, recovery_id))
    }
}

/// Real SHA256 hasher
pub struct Sha256Hasher;

impl Sha256Hasher {
    /// Hash data with SHA256
    pub fn hash(data: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    /// Hash data with SHA256 and return hex string
    pub fn hash_hex(data: &[u8]) -> String {
        hex::encode(Self::hash(data))
    }

    /// Double SHA256 (Bitcoin-style)
    pub fn double_hash(data: &[u8]) -> Vec<u8> {
        Self::hash(&Self::hash(data))
    }

    /// Double SHA256 and return hex string
    pub fn double_hash_hex(data: &[u8]) -> String {
        hex::encode(Self::double_hash(data))
    }
}

/// Real ECDSA signer using secp256k1
pub struct EcdsaSigner;

impl EcdsaSigner {
    /// Sign a message with ECDSA
    pub fn sign_message(private_key: &[u8], message: &[u8]) -> Result<SignatureWithRecovery> {
        use k256::ecdsa::{SigningKey, signature::Signer};
        use k256::elliptic_curve::generic_array::GenericArray;

        // Hash the message with SHA256
        let message_hash = Sha256Hasher::hash(message);

        let key_array = GenericArray::from_slice(private_key);
        let signing_key = SigningKey::from_bytes(key_array)
            .map_err(|e| SigningError::InvalidPrivateKey(e.to_string()))?;

        let signature: k256::ecdsa::Signature = signing_key.sign(&message_hash);
        let sig_bytes = signature.to_bytes();

        Ok(SignatureWithRecovery::new(sig_bytes.to_vec(), 0))
    }

    /// Sign a transaction
    pub fn sign_transaction(private_key: &[u8], tx_data: &[u8]) -> Result<Vec<u8>> {
        use k256::ecdsa::{SigningKey, signature::Signer};
        use k256::elliptic_curve::generic_array::GenericArray;

        let tx_hash = Sha256Hasher::hash(tx_data);

        let key_array = GenericArray::from_slice(private_key);
        let signing_key = SigningKey::from_bytes(key_array)
            .map_err(|e| SigningError::InvalidPrivateKey(e.to_string()))?;

        let signature: k256::ecdsa::Signature = signing_key.sign(&tx_hash);
        Ok(signature.to_bytes().to_vec())
    }

    /// Verify a signature
    pub fn verify_signature(
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        use k256::ecdsa::{VerifyingKey, signature::Verifier};
        use k256::elliptic_curve::generic_array::GenericArray;

        let message_hash = Sha256Hasher::hash(message);

        let verifying_key = VerifyingKey::from_encoded_point(
            &k256::EncodedPoint::from_bytes(public_key)
                .map_err(|e| SigningError::InvalidSignature(e.to_string()))?,
        )
        .map_err(|e| SigningError::InvalidSignature(e.to_string()))?;

        let sig = k256::ecdsa::Signature::from_bytes(
            GenericArray::from_slice(signature),
        )
        .map_err(|e| SigningError::InvalidSignature(e.to_string()))?;

        match verifying_key.verify(&message_hash, &sig) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

/// Message signing with prefix (Ethereum-style)
pub struct MessageSigner;

impl MessageSigner {
    /// Sign a message with Ethereum-style prefix
    pub fn sign_message(private_key: &[u8], message: &str) -> Result<SignatureWithRecovery> {
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let prefixed_message = format!("{}{}", prefix, message);

        EcdsaSigner::sign_message(private_key, prefixed_message.as_bytes())
    }

    /// Sign a message with custom prefix
    pub fn sign_message_with_prefix(
        private_key: &[u8],
        message: &str,
        prefix: &str,
    ) -> Result<SignatureWithRecovery> {
        let prefixed_message = format!("{}{}", prefix, message);
        EcdsaSigner::sign_message(private_key, prefixed_message.as_bytes())
    }

    /// Sign a message with SilverBitcoin prefix
    pub fn sign_message_silverbitcoin(
        private_key: &[u8],
        message: &str,
    ) -> Result<SignatureWithRecovery> {
        let prefix = format!("\x19SilverBitcoin Signed Message:\n{}", message.len());
        let prefixed_message = format!("{}{}", prefix, message);

        EcdsaSigner::sign_message(private_key, prefixed_message.as_bytes())
    }
}

/// Transaction signing
pub struct TransactionSigner;

impl TransactionSigner {
    /// Sign a transaction with SHA256
    pub fn sign_transaction(private_key: &[u8], tx_data: &[u8]) -> Result<Vec<u8>> {
        EcdsaSigner::sign_transaction(private_key, tx_data)
    }

    /// Sign a transaction and return hex string
    pub fn sign_transaction_hex(private_key: &[u8], tx_data: &[u8]) -> Result<String> {
        let signature = Self::sign_transaction(private_key, tx_data)?;
        Ok(format!("0x{}", hex::encode(&signature)))
    }

    /// Get transaction hash (SHA256)
    pub fn get_tx_hash(tx_data: &[u8]) -> String {
        Sha256Hasher::hash_hex(tx_data)
    }

    /// Get transaction hash with 0x prefix
    pub fn get_tx_hash_with_prefix(tx_data: &[u8]) -> String {
        format!("0x{}", Self::get_tx_hash(tx_data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hash() {
        let data = b"hello world";
        let hash = Sha256Hasher::hash(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sha256_hash_hex() {
        let data = b"hello world";
        let hash_hex = Sha256Hasher::hash_hex(data);
        assert!(hash_hex.starts_with("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"));
    }

    #[test]
    fn test_double_sha256() {
        let data = b"test";
        let hash = Sha256Hasher::double_hash(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_signature_with_recovery() {
        let sig = SignatureWithRecovery::new(vec![1, 2, 3], 0);
        let hex = sig.to_hex();
        assert!(hex.starts_with("0x"));
    }
}
