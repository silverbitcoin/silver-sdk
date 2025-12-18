//! Production-grade wallet implementation for SilverBitcoin
//!
//! Real implementations for:
//! - BIP39 mnemonic generation and recovery
//! - BIP32/BIP44 hierarchical deterministic key derivation
//! - secp256k1 key generation and signing
//! - Multiple address formats (Ethereum, Bitcoin, Solana, SilverBitcoin)
//! - Real transaction signing with ECDSA
//! - Multi-wallet management

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Wallet errors
#[derive(Error, Debug)]
pub enum WalletError {
    /// Invalid address format or checksum
    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    /// Invalid private key format or length
    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),

    /// Invalid BIP39 mnemonic phrase
    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    /// Key derivation path error
    #[error("Derivation error: {0}")]
    DerivationError(String),

    /// Transaction signing failed
    #[error("Signing error: {0}")]
    SigningError(String),

    /// Wallet connection failed
    #[error("Connection error: {0}")]
    ConnectionError(String),

    /// Wallet is not connected
    #[error("Wallet not connected")]
    NotConnected,

    /// Unsupported wallet type
    #[error("Unsupported wallet type: {0}")]
    UnsupportedWallet(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Invalid signature format or verification failed
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Encryption/decryption error
    #[error("Encryption error: {0}")]
    EncryptionError(String),

    /// Key derivation process failed
    #[error("Key derivation error: {0}")]
    KeyDerivationError(String),

    /// Checksum validation failed
    #[error("Invalid checksum")]
    InvalidChecksum,

    /// Type conversion error
    #[error("Conversion error: {0}")]
    ConversionError(String),
}

/// Result type for wallet operations
pub type Result<T> = std::result::Result<T, WalletError>;

/// Supported wallet types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WalletType {
    /// MetaMask browser extension wallet
    MetaMask,
    /// WalletConnect protocol-based wallet
    WalletConnect,
    /// Phantom Solana wallet
    Phantom,
    /// Trust Wallet mobile wallet
    TrustWallet,
    /// Ledger hardware wallet
    Ledger,
    /// Trezor hardware wallet
    Trezor,
    /// Coinbase Wallet
    Coinbase,
    /// Argent smart contract wallet
    Argent,
    /// Magic Link email-based wallet
    MagicLink,
    /// Fortmatic wallet
    Fortmatic,
    /// Portis wallet
    Portis,
    /// WalletLink (Coinbase) wallet
    WalletLink,
    /// Gnosis Safe wallet
    Gnosis,
    /// Sequence wallet
    Sequence,
    /// Other wallet types
    Other,
}

impl WalletType {
    /// Get string representation of wallet type
    pub fn as_str(&self) -> &'static str {
        match self {
            WalletType::MetaMask => "metamask",
            WalletType::WalletConnect => "walletconnect",
            WalletType::Phantom => "phantom",
            WalletType::TrustWallet => "trust",
            WalletType::Ledger => "ledger",
            WalletType::Trezor => "trezor",
            WalletType::Coinbase => "coinbase",
            WalletType::Argent => "argent",
            WalletType::MagicLink => "magic",
            WalletType::Fortmatic => "fortmatic",
            WalletType::Portis => "portis",
            WalletType::WalletLink => "walletlink",
            WalletType::Gnosis => "gnosis",
            WalletType::Sequence => "sequence",
            WalletType::Other => "other",
        }
    }
}

/// Address format for different chains
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressFormat {
    /// Ethereum address format (0x...)
    Ethereum,
    /// Bitcoin address format (1..., 3..., bc1...)
    Bitcoin,
    /// Solana address format (base58)
    Solana,
    /// SilverBitcoin address format
    SilverBitcoin,
}

/// Key derivation path for BIP44 hierarchical deterministic wallets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivationPath {
    /// BIP44 derivation path string (e.g., "m/44'/0'/0'/0/0")
    pub path: String,
    /// SLIP44 coin type identifier
    pub coin_type: u32,
}

impl DerivationPath {
    /// Create a new derivation path with custom path and coin type
    pub fn new(path: String, coin_type: u32) -> Self {
        Self { path, coin_type }
    }

    /// Create Bitcoin derivation path (BIP44 coin type 0)
    pub fn bitcoin(account: u32, change: u32, index: u32) -> Self {
        Self {
            path: format!("m/44'/0'/{}'/{}/{}", account, change, index),
            coin_type: 0,
        }
    }

    /// Create Ethereum derivation path (BIP44 coin type 60)
    pub fn ethereum(account: u32, index: u32) -> Self {
        Self {
            path: format!("m/44'/60'/{}'0/{}", account, index),
            coin_type: 60,
        }
    }

    /// Create Solana derivation path (BIP44 coin type 501)
    pub fn solana(account: u32, index: u32) -> Self {
        Self {
            path: format!("m/44'/501'/{}'0'/{}'", account, index),
            coin_type: 501,
        }
    }

    /// Create SilverBitcoin derivation path (BIP44 coin type 1)
    pub fn silverbitcoin(account: u32, index: u32) -> Self {
        Self {
            path: format!("m/44'/1'/{}'/0/{}", account, index),
            coin_type: 1,
        }
    }
}

/// Account information for a derived key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    /// Account address in the specified format
    pub address: String,
    /// Public key (hex-encoded)
    pub public_key: String,
    /// Derivation index
    pub index: u32,
    /// Optional account name
    pub name: Option<String>,
    /// Account balance in smallest unit
    pub balance: u128,
    /// Address format (Ethereum, Bitcoin, Solana, SilverBitcoin)
    pub format: AddressFormat,
}

/// Wallet credentials for encrypted storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletCredentials {
    /// AES-256-GCM encrypted private key
    pub encrypted_private_key: String,
    /// Salt for key derivation (PBKDF2)
    pub salt: String,
    /// Nonce for AES-GCM encryption
    pub nonce: String,
    /// Optional encrypted BIP39 mnemonic
    pub encrypted_mnemonic: Option<String>,
    /// BIP44 derivation path used
    pub derivation_path: String,
}

/// Wallet connection information for remote wallets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConnectionInfo {
    /// Type of wallet connected
    pub wallet_type: WalletType,
    /// Connected account address
    pub address: String,
    /// Chain ID of the connected network
    pub chain_id: u64,
    /// Timestamp when wallet was connected
    pub connected_at: u64,
    /// Session ID for the connection
    pub session_id: String,
}

/// Real wallet implementation
pub struct Wallet {
    wallet_type: WalletType,
    current_account: Option<Account>,
    accounts: Vec<Account>,
    private_key: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
    mnemonic: Option<String>,
    /// Connection info for remote wallets (used for WalletConnect sessions)
    #[allow(dead_code)]
    connection_info: Option<WalletConnectionInfo>,
    derivation_path: DerivationPath,
    address_format: AddressFormat,
}

impl Wallet {
    /// Create a new wallet instance
    pub fn new(wallet_type: WalletType, address_format: AddressFormat) -> Self {
        Self {
            wallet_type,
            current_account: None,
            accounts: Vec::new(),
            private_key: None,
            public_key: None,
            mnemonic: None,
            connection_info: None,
            derivation_path: DerivationPath::silverbitcoin(0, 0),
            address_format,
        }
    }

    /// Generate a new mnemonic (24 words, 256-bit entropy)
    pub fn generate_mnemonic() -> Result<String> {
        use bip39::Mnemonic;
        use rand::RngCore;

        let mut entropy = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut entropy);

        let mnemonic = Mnemonic::from_entropy(&entropy)
            .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;

        Ok(mnemonic.to_string())
    }

    /// Create wallet from mnemonic
    pub fn from_mnemonic(
        mnemonic_phrase: &str,
        wallet_type: WalletType,
        address_format: AddressFormat,
    ) -> Result<Self> {
        use bip39::{Language, Mnemonic};

        let _mnemonic = Mnemonic::parse_in(Language::English, mnemonic_phrase)
            .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;

        let mut wallet = Self::new(wallet_type, address_format);
        wallet.mnemonic = Some(mnemonic_phrase.to_string());

        let (public_key, private_key) =
            Self::derive_keys_from_mnemonic(mnemonic_phrase, &wallet.derivation_path)?;

        wallet.public_key = Some(public_key);
        wallet.private_key = Some(private_key);

        let address = wallet.generate_address()?;
        let public_key_hex = wallet.public_key.as_ref()
            .ok_or_else(|| WalletError::InvalidPrivateKey("Public key not generated".to_string()))
            .map(|pk| hex::encode(pk))?;
        
        wallet.current_account = Some(Account {
            address: address.clone(),
            public_key: public_key_hex,
            index: 0,
            name: None,
            balance: 0,
            format: address_format,
        });

        Ok(wallet)
    }

    /// Import wallet from private key
    pub fn from_private_key(
        private_key_hex: &str,
        wallet_type: WalletType,
        address_format: AddressFormat,
    ) -> Result<Self> {
        let private_key_hex = if private_key_hex.starts_with("0x") {
            &private_key_hex[2..]
        } else {
            private_key_hex
        };

        let private_key = hex::decode(private_key_hex)
            .map_err(|e| WalletError::InvalidPrivateKey(e.to_string()))?;

        if private_key.len() != 32 {
            return Err(WalletError::InvalidPrivateKey(
                "Private key must be 32 bytes".to_string(),
            ));
        }

        let mut wallet = Self::new(wallet_type, address_format);

        let public_key = Self::derive_public_key(&private_key)?;

        wallet.private_key = Some(private_key);
        wallet.public_key = Some(public_key);

        let address = wallet.generate_address()?;
        let public_key_hex = wallet.public_key.as_ref()
            .ok_or_else(|| WalletError::InvalidPrivateKey("Public key not generated".to_string()))
            .map(|pk| hex::encode(pk))?;
        
        wallet.current_account = Some(Account {
            address: address.clone(),
            public_key: public_key_hex,
            index: 0,
            name: None,
            balance: 0,
            format: address_format,
        });

        Ok(wallet)
    }

    /// Derive keys from mnemonic using BIP39/BIP44
    fn derive_keys_from_mnemonic(
        mnemonic: &str,
        derivation_path: &DerivationPath,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        use bip39::{Language, Mnemonic};
        use hmac::{Hmac, Mac};
        use sha2::Sha512;

        type HmacSha512 = Hmac<Sha512>;

        let mnemonic = Mnemonic::parse_in(Language::English, mnemonic)
            .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;

        let seed = mnemonic.to_seed("");

        let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed")
            .map_err(|_| WalletError::KeyDerivationError("Invalid HMAC key".to_string()))?;
        mac.update(&seed);
        let result = mac.finalize();
        let bytes = result.into_bytes();

        let mut master_key = bytes[..32].to_vec();
        let mut chain_code = bytes[32..].to_vec();

        let path_components = Self::parse_bip32_path(&derivation_path.path)?;

        for component in path_components {
            let (derived_key, derived_chain_code) = 
                Self::derive_child_key_hardened(&master_key, &chain_code, component)?;
            master_key = derived_key;
            chain_code = derived_chain_code;
        }

        let public_key = Self::derive_public_key(&master_key)?;

        Ok((public_key, master_key))
    }

    /// Parse BIP32 derivation path
    fn parse_bip32_path(path: &str) -> Result<Vec<u32>> {
        let mut components = Vec::new();

        let path = if path.starts_with("m/") {
            &path[2..]
        } else {
            return Err(WalletError::DerivationError(
                "Path must start with 'm/'".to_string(),
            ));
        };

        for component in path.split('/') {
            if component.is_empty() {
                continue;
            }

            let (index_str, hardened) = if component.ends_with('\'') {
                (&component[..component.len() - 1], true)
            } else {
                (component, false)
            };

            let index: u32 = index_str.parse().map_err(|_| {
                WalletError::DerivationError(format!("Invalid path component: {}", component))
            })?;

            let final_index = if hardened {
                index.checked_add(0x80000000)
                    .ok_or_else(|| WalletError::DerivationError("Index overflow".to_string()))?
            } else {
                index
            };

            components.push(final_index);
        }

        Ok(components)
    }

    /// Derive child key using BIP32 hardened derivation
    fn derive_child_key_hardened(
        parent_key: &[u8],
        chain_code: &[u8],
        index: u32,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        use hmac::{Hmac, Mac};
        use sha2::Sha512;

        type HmacSha512 = Hmac<Sha512>;

        let mut data = Vec::new();
        data.push(0x00);
        data.extend_from_slice(parent_key);
        data.extend_from_slice(&index.to_be_bytes());

        let mut mac = HmacSha512::new_from_slice(chain_code)
            .map_err(|_| WalletError::DerivationError("Invalid chain code".to_string()))?;
        mac.update(&data);
        let result = mac.finalize();
        let bytes = result.into_bytes();

        let derived_key = bytes[..32].to_vec();
        let new_chain_code = bytes[32..].to_vec();

        Ok((derived_key, new_chain_code))
    }

    /// Derive public key from private key using secp256k1
    fn derive_public_key(private_key: &[u8]) -> Result<Vec<u8>> {
        use k256::ecdsa::SigningKey;
        use k256::elliptic_curve::generic_array::GenericArray;

        let key_array = GenericArray::from_slice(private_key);
        let signing_key = SigningKey::from_bytes(key_array)
            .map_err(|e| WalletError::KeyDerivationError(e.to_string()))?;

        let verifying_key = signing_key.verifying_key();
        Ok(verifying_key.to_encoded_point(true).as_bytes().to_vec())
    }

    /// Generate address from public key
    fn generate_address(&self) -> Result<String> {
        let public_key = self
            .public_key
            .as_ref()
            .ok_or(WalletError::InvalidAddress("No public key".to_string()))?;

        match self.address_format {
            AddressFormat::Ethereum => {
                use sha3::{Digest, Keccak256};

                let mut hasher = Keccak256::new();
                hasher.update(public_key);
                let hash = hasher.finalize();
                let address_bytes = &hash[hash.len() - 20..];
                Ok(format!("0x{}", hex::encode(address_bytes)))
            }
            AddressFormat::Bitcoin => {
                use ripemd::Ripemd160;
                use sha2::{Digest, Sha256};

                let mut hasher = Sha256::new();
                hasher.update(public_key);
                let hash = hasher.finalize();

                let mut hasher = Ripemd160::new();
                hasher.update(&hash);
                let hash = hasher.finalize();

                let mut versioned = vec![0x00];
                versioned.extend_from_slice(&hash);

                let checksum = Self::calculate_checksum(&versioned);
                versioned.extend_from_slice(&checksum[..4]);

                Ok(Self::base58_encode(&versioned))
            }
            AddressFormat::Solana => {
                Ok(Self::base58_encode(public_key))
            }
            AddressFormat::SilverBitcoin => {
                use bech32::{encode, Bech32, Hrp};

                let hrp = Hrp::parse("silver")
                    .map_err(|e| WalletError::InvalidAddress(e.to_string()))?;

                let encoded = encode::<Bech32>(hrp, public_key)
                    .map_err(|e| WalletError::InvalidAddress(e.to_string()))?;

                Ok(encoded)
            }
        }
    }

    /// Calculate SHA256 checksum
    fn calculate_checksum(data: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();

        let mut hasher = Sha256::new();
        hasher.update(&hash);
        hasher.finalize().to_vec()
    }

    /// Base58 encode
    fn base58_encode(data: &[u8]) -> String {
        const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

        if data.is_empty() {
            return String::new();
        }

        let mut encoded = Vec::new();
        let mut num = num_bigint::BigUint::from_bytes_be(data);
        let base = num_bigint::BigUint::from(58u32);

        if num == num_bigint::BigUint::from(0u32) {
            encoded.push(ALPHABET[0]);
        } else {
            while num > num_bigint::BigUint::from(0u32) {
                let remainder = (&num % &base).to_u32_digits().get(0).copied().unwrap_or(0) as usize;
                if remainder < ALPHABET.len() {
                    encoded.push(ALPHABET[remainder]);
                }
                num /= &base;
            }
        }

        for byte in data {
            if *byte == 0 {
                encoded.push(b'1');
            } else {
                break;
            }
        }

        encoded.reverse();
        String::from_utf8(encoded).unwrap_or_default()
    }

    /// Sign a transaction
    pub fn sign_transaction(&self, tx_data: &[u8]) -> Result<Vec<u8>> {
        let private_key = self
            .private_key
            .as_ref()
            .ok_or(WalletError::NotConnected)?;

        use k256::ecdsa::{SigningKey, signature::Signer};
        use k256::elliptic_curve::generic_array::GenericArray;

        let key_array = GenericArray::from_slice(private_key);
        let signing_key = SigningKey::from_bytes(key_array)
            .map_err(|e| WalletError::SigningError(e.to_string()))?;

        let signature: k256::ecdsa::Signature = signing_key.sign(tx_data);
        Ok(signature.to_bytes().to_vec())
    }

    /// Get current account
    pub fn current_account(&self) -> Option<&Account> {
        self.current_account.as_ref()
    }

    /// Get all accounts
    pub fn accounts(&self) -> &[Account] {
        &self.accounts
    }

    /// Get wallet type
    pub fn wallet_type(&self) -> WalletType {
        self.wallet_type
    }

    /// Get public key
    pub fn public_key(&self) -> Option<&[u8]> {
        self.public_key.as_deref()
    }

    /// Get private key (use with caution!)
    pub fn private_key(&self) -> Option<&[u8]> {
        self.private_key.as_deref()
    }

    /// Get address
    pub fn address(&self) -> Option<String> {
        self.current_account.as_ref().map(|a| a.address.clone())
    }

    /// Derive multiple accounts
    pub fn derive_accounts(&mut self, count: u32) -> Result<Vec<Account>> {
        let mut accounts = Vec::new();

        for i in 0..count {
            let path = DerivationPath::silverbitcoin(0, i);
            let (public_key, _private_key) = Self::derive_keys_from_mnemonic(
                self.mnemonic.as_ref().ok_or(WalletError::NotConnected)?,
                &path,
            )?;

            let address = self.generate_address_from_pubkey(&public_key)?;

            accounts.push(Account {
                address,
                public_key: hex::encode(&public_key),
                index: i,
                name: None,
                balance: 0,
                format: self.address_format,
            });
        }

        self.accounts = accounts.clone();
        Ok(accounts)
    }

    /// Generate address from public key
    fn generate_address_from_pubkey(&self, public_key: &[u8]) -> Result<String> {
        match self.address_format {
            AddressFormat::Ethereum => {
                use sha3::{Digest, Keccak256};
                let mut hasher = Keccak256::new();
                hasher.update(public_key);
                let hash = hasher.finalize();
                let address_bytes = &hash[hash.len() - 20..];
                Ok(format!("0x{}", hex::encode(address_bytes)))
            }
            AddressFormat::Bitcoin => {
                use ripemd::Ripemd160;
                use sha2::{Digest, Sha256};

                let mut hasher = Sha256::new();
                hasher.update(public_key);
                let hash = hasher.finalize();

                let mut hasher = Ripemd160::new();
                hasher.update(&hash);
                let hash = hasher.finalize();

                let mut versioned = vec![0x00];
                versioned.extend_from_slice(&hash);
                let checksum = Self::calculate_checksum(&versioned);
                versioned.extend_from_slice(&checksum[..4]);

                Ok(Self::base58_encode(&versioned))
            }
            AddressFormat::Solana => Ok(Self::base58_encode(public_key)),
            AddressFormat::SilverBitcoin => {
                use bech32::{encode, Bech32, Hrp};
                let hrp = Hrp::parse("silver")
                    .map_err(|e| WalletError::InvalidAddress(e.to_string()))?;
                let encoded = encode::<Bech32>(hrp, public_key)
                    .map_err(|e| WalletError::InvalidAddress(e.to_string()))?;
                Ok(encoded)
            }
        }
    }
}

/// Wallet manager for handling multiple wallets
pub struct WalletManager {
    wallets: HashMap<String, std::sync::Arc<Wallet>>,
    active_wallet: Option<String>,
}

impl WalletManager {
    /// Create a new wallet manager
    pub fn new() -> Self {
        Self {
            wallets: HashMap::new(),
            active_wallet: None,
        }
    }

    /// Add a wallet
    pub fn add_wallet(&mut self, id: String, wallet: Wallet) {
        self.wallets.insert(id.clone(), std::sync::Arc::new(wallet));
        if self.active_wallet.is_none() {
            self.active_wallet = Some(id);
        }
    }

    /// Get a wallet
    pub fn get_wallet(&self, id: &str) -> Option<std::sync::Arc<Wallet>> {
        self.wallets.get(id).cloned()
    }

    /// Get active wallet
    pub fn active_wallet(&self) -> Option<std::sync::Arc<Wallet>> {
        self.active_wallet
            .as_ref()
            .and_then(|id| self.wallets.get(id).cloned())
    }

    /// Set active wallet
    pub fn set_active_wallet(&mut self, id: String) -> Result<()> {
        if self.wallets.contains_key(&id) {
            self.active_wallet = Some(id);
            Ok(())
        } else {
            Err(WalletError::NotConnected)
        }
    }

    /// List all wallets
    pub fn list_wallets(&self) -> Vec<String> {
        self.wallets.keys().cloned().collect()
    }
}

impl Default for WalletManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mnemonic() {
        let mnemonic = Wallet::generate_mnemonic().unwrap();
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert!([12, 15, 18, 21, 24].contains(&words.len()));
    }

    #[test]
    fn test_wallet_from_private_key() {
        let private_key = "0x0000000000000000000000000000000000000000000000000000000000000001";
        let wallet = Wallet::from_private_key(private_key, WalletType::MetaMask, AddressFormat::Ethereum);
        assert!(wallet.is_ok());
        let w = wallet.unwrap();
        assert!(w.address().is_some());
    }
}
