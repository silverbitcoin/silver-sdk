//! SilverBitcoin network configuration
//!
//! Production configuration for SilverBitcoin blockchain:
//! - Chain ID: 5200
//! - RPC: https://rpc.silverbitcoin.org
//! - Explorer: https://explorer.silverbitcoin.org
//! - Website: https://silverbitcoin.org

/// SilverBitcoin network configuration
pub struct SilverBitcoinConfig;

impl SilverBitcoinConfig {
    /// Chain ID for SilverBitcoin mainnet
    pub const CHAIN_ID: u64 = 5200;

    /// RPC endpoint URL
    pub const RPC_URL: &'static str = "https://rpc.silverbitcoin.org";

    /// Explorer URL
    pub const EXPLORER_URL: &'static str = "https://explorer.silverbitcoin.org";

    /// Website URL
    pub const WEBSITE_URL: &'static str = "https://silverbitcoin.org";

    /// Network name
    pub const NETWORK_NAME: &'static str = "SilverBitcoin";

    /// Network symbol
    pub const NETWORK_SYMBOL: &'static str = "SBTC";

    /// Decimals
    pub const DECIMALS: u8 = 18;

    /// Block time in seconds
    pub const BLOCK_TIME: u64 = 12;

    /// Gas limit per block
    pub const GAS_LIMIT_PER_BLOCK: u64 = 30_000_000;

    /// Minimum gas price in wei
    pub const MIN_GAS_PRICE: u128 = 1_000_000_000; // 1 Gwei

    /// Address prefix for Bech32 encoding
    pub const ADDRESS_PREFIX: &'static str = "silver";

    /// Get RPC endpoint with optional custom URL
    pub fn rpc_url(custom: Option<&str>) -> String {
        custom.unwrap_or(Self::RPC_URL).to_string()
    }

    /// Get explorer URL with optional custom URL
    pub fn explorer_url(custom: Option<&str>) -> String {
        custom.unwrap_or(Self::EXPLORER_URL).to_string()
    }

    /// Get full explorer address URL
    pub fn explorer_address_url(address: &str) -> String {
        format!("{}/address/{}", Self::EXPLORER_URL, address)
    }

    /// Get full explorer transaction URL
    pub fn explorer_tx_url(tx_hash: &str) -> String {
        format!("{}/tx/{}", Self::EXPLORER_URL, tx_hash)
    }

    /// Get full explorer block URL
    pub fn explorer_block_url(block_number: u64) -> String {
        format!("{}/block/{}", Self::EXPLORER_URL, block_number)
    }
}

/// Testnet configuration
pub struct SilverBitcoinTestnet;

impl SilverBitcoinTestnet {
    /// Chain ID for SilverBitcoin testnet
    pub const CHAIN_ID: u64 = 5201;

    /// RPC endpoint URL
    pub const RPC_URL: &'static str = "https://testnet-rpc.silverbitcoin.org";

    /// Explorer URL
    pub const EXPLORER_URL: &'static str = "https://testnet-explorer.silverbitcoin.org";

    /// Network name
    pub const NETWORK_NAME: &'static str = "SilverBitcoin Testnet";

    /// Network symbol
    pub const NETWORK_SYMBOL: &'static str = "tSBTC";

    /// Decimals
    pub const DECIMALS: u8 = 18;

    /// Block time in seconds
    pub const BLOCK_TIME: u64 = 12;

    /// Gas limit per block
    pub const GAS_LIMIT_PER_BLOCK: u64 = 30_000_000;

    /// Minimum gas price in wei
    pub const MIN_GAS_PRICE: u128 = 1_000_000_000; // 1 Gwei

    /// Address prefix for Bech32 encoding
    pub const ADDRESS_PREFIX: &'static str = "silver";
}

/// Devnet configuration
pub struct SilverBitcoinDevnet;

impl SilverBitcoinDevnet {
    /// Chain ID for SilverBitcoin devnet
    pub const CHAIN_ID: u64 = 5202;

    /// RPC endpoint URL
    pub const RPC_URL: &'static str = "http://localhost:9000";

    /// Explorer URL
    pub const EXPLORER_URL: &'static str = "http://localhost:3000";

    /// Network name
    pub const NETWORK_NAME: &'static str = "SilverBitcoin Devnet";

    /// Network symbol
    pub const NETWORK_SYMBOL: &'static str = "dSBTC";

    /// Decimals
    pub const DECIMALS: u8 = 18;

    /// Block time in seconds
    pub const BLOCK_TIME: u64 = 1;

    /// Gas limit per block
    pub const GAS_LIMIT_PER_BLOCK: u64 = 30_000_000;

    /// Minimum gas price in wei
    pub const MIN_GAS_PRICE: u128 = 1; // 1 wei for testing

    /// Address prefix for Bech32 encoding
    pub const ADDRESS_PREFIX: &'static str = "silver";
}

/// Network environment
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkEnvironment {
    /// Mainnet (Chain ID 5200)
    Mainnet,
    /// Testnet (Chain ID 5201)
    Testnet,
    /// Devnet (Chain ID 5202)
    Devnet,
}

impl NetworkEnvironment {
    /// Get chain ID for this environment
    pub fn chain_id(&self) -> u64 {
        match self {
            NetworkEnvironment::Mainnet => SilverBitcoinConfig::CHAIN_ID,
            NetworkEnvironment::Testnet => SilverBitcoinTestnet::CHAIN_ID,
            NetworkEnvironment::Devnet => SilverBitcoinDevnet::CHAIN_ID,
        }
    }

    /// Get RPC URL for this environment
    pub fn rpc_url(&self) -> &'static str {
        match self {
            NetworkEnvironment::Mainnet => SilverBitcoinConfig::RPC_URL,
            NetworkEnvironment::Testnet => SilverBitcoinTestnet::RPC_URL,
            NetworkEnvironment::Devnet => SilverBitcoinDevnet::RPC_URL,
        }
    }

    /// Get explorer URL for this environment
    pub fn explorer_url(&self) -> &'static str {
        match self {
            NetworkEnvironment::Mainnet => SilverBitcoinConfig::EXPLORER_URL,
            NetworkEnvironment::Testnet => SilverBitcoinTestnet::EXPLORER_URL,
            NetworkEnvironment::Devnet => SilverBitcoinDevnet::EXPLORER_URL,
        }
    }

    /// Get network name for this environment
    pub fn network_name(&self) -> &'static str {
        match self {
            NetworkEnvironment::Mainnet => SilverBitcoinConfig::NETWORK_NAME,
            NetworkEnvironment::Testnet => SilverBitcoinTestnet::NETWORK_NAME,
            NetworkEnvironment::Devnet => SilverBitcoinDevnet::NETWORK_NAME,
        }
    }

    /// Get network symbol for this environment
    pub fn network_symbol(&self) -> &'static str {
        match self {
            NetworkEnvironment::Mainnet => SilverBitcoinConfig::NETWORK_SYMBOL,
            NetworkEnvironment::Testnet => SilverBitcoinTestnet::NETWORK_SYMBOL,
            NetworkEnvironment::Devnet => SilverBitcoinDevnet::NETWORK_SYMBOL,
        }
    }

    /// Get decimals for this environment
    pub fn decimals(&self) -> u8 {
        match self {
            NetworkEnvironment::Mainnet => SilverBitcoinConfig::DECIMALS,
            NetworkEnvironment::Testnet => SilverBitcoinTestnet::DECIMALS,
            NetworkEnvironment::Devnet => SilverBitcoinDevnet::DECIMALS,
        }
    }

    /// Get minimum gas price for this environment
    pub fn min_gas_price(&self) -> u128 {
        match self {
            NetworkEnvironment::Mainnet => SilverBitcoinConfig::MIN_GAS_PRICE,
            NetworkEnvironment::Testnet => SilverBitcoinTestnet::MIN_GAS_PRICE,
            NetworkEnvironment::Devnet => SilverBitcoinDevnet::MIN_GAS_PRICE,
        }
    }

    /// Get address prefix for this environment
    pub fn address_prefix(&self) -> &'static str {
        match self {
            NetworkEnvironment::Mainnet => SilverBitcoinConfig::ADDRESS_PREFIX,
            NetworkEnvironment::Testnet => SilverBitcoinTestnet::ADDRESS_PREFIX,
            NetworkEnvironment::Devnet => SilverBitcoinDevnet::ADDRESS_PREFIX,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet_config() {
        assert_eq!(SilverBitcoinConfig::CHAIN_ID, 5200);
        assert_eq!(SilverBitcoinConfig::RPC_URL, "https://rpc.silverbitcoin.org");
        assert_eq!(SilverBitcoinConfig::EXPLORER_URL, "https://explorer.silverbitcoin.org");
    }

    #[test]
    fn test_testnet_config() {
        assert_eq!(SilverBitcoinTestnet::CHAIN_ID, 5201);
        assert_eq!(SilverBitcoinTestnet::RPC_URL, "https://testnet-rpc.silverbitcoin.org");
    }

    #[test]
    fn test_devnet_config() {
        assert_eq!(SilverBitcoinDevnet::CHAIN_ID, 5202);
        assert_eq!(SilverBitcoinDevnet::RPC_URL, "http://localhost:9000");
    }

    #[test]
    fn test_network_environment() {
        assert_eq!(NetworkEnvironment::Mainnet.chain_id(), 5200);
        assert_eq!(NetworkEnvironment::Testnet.chain_id(), 5201);
        assert_eq!(NetworkEnvironment::Devnet.chain_id(), 5202);
    }

    #[test]
    fn test_explorer_urls() {
        let addr = "silver1abc123";
        let url = SilverBitcoinConfig::explorer_address_url(addr);
        assert!(url.contains(addr));
        assert!(url.contains("https://explorer.silverbitcoin.org"));
    }
}
