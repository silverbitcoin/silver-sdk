//! Transaction builder API for constructing SilverBitcoin transactions
//!
//! This module provides a fluent API for building transactions with
//! Composite Transaction Chains (CTC) and proper signing.

use silver_core::transaction::{CallArg, TypeTag};
use silver_core::{
    Command, Identifier, ObjectID, ObjectRef, SilverAddress, Transaction, TransactionData,
    TransactionExpiration, TransactionKind,
};
use silver_crypto::KeyPair;
use thiserror::Error;

/// Transaction builder errors
#[derive(Debug, Error)]
pub enum BuilderError {
    /// Missing required field
    #[error("Missing required field: {0}")]
    MissingField(String),

    /// Invalid data provided
    #[error("Invalid data: {0}")]
    InvalidData(String),

    /// Core library error
    #[error("Core error: {0}")]
    CoreError(#[from] silver_core::Error),

    /// Cryptographic operation error
    #[error("Crypto error: {0}")]
    CryptoError(String),
}

/// Result type for transaction builder operations
pub type Result<T> = std::result::Result<T, BuilderError>;

/// Fluent transaction builder for constructing SilverBitcoin transactions
///
/// # Example
///
/// ```no_run
/// use silver_sdk::TransactionBuilder;
/// use silver_core::{SilverAddress, ObjectRef, ObjectID, SequenceNumber, TransactionDigest};
///
/// let sender = SilverAddress::new([1u8; 64]);
/// let recipient = SilverAddress::new([2u8; 64]);
/// let fuel_payment = ObjectRef::new(
///     ObjectID::new([3u8; 64]),
///     SequenceNumber::initial(),
///     TransactionDigest::new([4u8; 64]),
/// );
///
/// let tx = TransactionBuilder::new()
///     .sender(sender)
///     .fuel_payment(fuel_payment)
///     .fuel_budget(10000)
///     .fuel_price(1000)
///     .transfer_objects(vec![fuel_payment], recipient)
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct TransactionBuilder {
    sender: Option<SilverAddress>,
    fuel_payment: Option<ObjectRef>,
    fuel_budget: Option<u64>,
    fuel_price: Option<u64>,
    sponsor: Option<SilverAddress>,
    expiration: TransactionExpiration,
    commands: Vec<Command>,
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionBuilder {
    /// Create a new transaction builder
    pub fn new() -> Self {
        Self {
            sender: None,
            fuel_payment: None,
            fuel_budget: None,
            fuel_price: Some(1000), // Default minimum fuel price
            sponsor: None,
            expiration: TransactionExpiration::None,
            commands: Vec::new(),
        }
    }

    /// Set the sender address
    pub fn sender(mut self, sender: SilverAddress) -> Self {
        self.sender = Some(sender);
        self
    }

    /// Set the fuel payment object
    pub fn fuel_payment(mut self, fuel_payment: ObjectRef) -> Self {
        self.fuel_payment = Some(fuel_payment);
        self
    }

    /// Set the fuel budget (maximum fuel units to consume)
    pub fn fuel_budget(mut self, budget: u64) -> Self {
        self.fuel_budget = Some(budget);
        self
    }

    /// Set the fuel price per unit (in MIST, minimum 1000)
    pub fn fuel_price(mut self, price: u64) -> Self {
        self.fuel_price = Some(price);
        self
    }

    /// Set the sponsor address for fuel payment
    pub fn sponsor(mut self, sponsor: SilverAddress) -> Self {
        self.sponsor = Some(sponsor);
        self
    }

    /// Set transaction expiration by timestamp
    pub fn expires_at_timestamp(mut self, timestamp: u64) -> Self {
        self.expiration = TransactionExpiration::Timestamp(timestamp);
        self
    }

    /// Set transaction expiration by snapshot number
    pub fn expires_at_snapshot(mut self, snapshot: u64) -> Self {
        self.expiration = TransactionExpiration::Snapshot(snapshot);
        self
    }

    /// Set no expiration
    pub fn no_expiration(mut self) -> Self {
        self.expiration = TransactionExpiration::None;
        self
    }

    /// Add a command to the transaction
    pub fn add_command(mut self, command: Command) -> Self {
        self.commands.push(command);
        self
    }

    /// Transfer objects to a recipient
    pub fn transfer_objects(mut self, objects: Vec<ObjectRef>, recipient: SilverAddress) -> Self {
        self.commands
            .push(Command::TransferObjects { objects, recipient });
        self
    }

    /// Split a coin into multiple coins
    pub fn split_coins(mut self, coin: ObjectRef, amounts: Vec<u64>) -> Self {
        self.commands.push(Command::SplitCoins { coin, amounts });
        self
    }

    /// Merge multiple coins into one
    pub fn merge_coins(mut self, primary: ObjectRef, coins: Vec<ObjectRef>) -> Self {
        self.commands.push(Command::MergeCoins { primary, coins });
        self
    }

    /// Publish Quantum Move modules
    pub fn publish(mut self, modules: Vec<Vec<u8>>) -> Self {
        self.commands.push(Command::Publish { modules });
        self
    }

    /// Call a Quantum Move function
    pub fn call(
        mut self,
        package: ObjectID,
        module: impl Into<String>,
        function: impl Into<String>,
        type_arguments: Vec<TypeTag>,
        arguments: Vec<CallArg>,
    ) -> Result<Self> {
        let module = Identifier::new(module)?;
        let function = Identifier::new(function)?;

        self.commands.push(Command::Call {
            package,
            module,
            function,
            type_arguments,
            arguments,
        });
        Ok(self)
    }

    /// Make a Move vector
    pub fn make_move_vec(mut self, element_type: Option<TypeTag>, elements: Vec<CallArg>) -> Self {
        self.commands.push(Command::MakeMoveVec {
            element_type,
            elements,
        });
        self
    }

    /// Delete an object
    pub fn delete_object(mut self, object: ObjectRef) -> Self {
        self.commands.push(Command::DeleteObject { object });
        self
    }

    /// Make an object shared
    pub fn share_object(mut self, object: ObjectRef) -> Self {
        self.commands.push(Command::ShareObject { object });
        self
    }

    /// Freeze an object (make immutable)
    pub fn freeze_object(mut self, object: ObjectRef) -> Self {
        self.commands.push(Command::FreezeObject { object });
        self
    }

    /// Build the transaction data (unsigned)
    pub fn build(self) -> Result<TransactionData> {
        let sender = self
            .sender
            .ok_or_else(|| BuilderError::MissingField("sender".to_string()))?;

        let fuel_payment = self
            .fuel_payment
            .ok_or_else(|| BuilderError::MissingField("fuel_payment".to_string()))?;

        let fuel_budget = self
            .fuel_budget
            .ok_or_else(|| BuilderError::MissingField("fuel_budget".to_string()))?;

        let fuel_price = self
            .fuel_price
            .ok_or_else(|| BuilderError::MissingField("fuel_price".to_string()))?;

        if self.commands.is_empty() {
            return Err(BuilderError::InvalidData(
                "Transaction must have at least one command".to_string(),
            ));
        }

        let kind = TransactionKind::CompositeChain(self.commands);

        let data = if let Some(sponsor) = self.sponsor {
            TransactionData::new_sponsored(
                sender,
                sponsor,
                fuel_payment,
                fuel_budget,
                fuel_price,
                kind,
                self.expiration,
            )
        } else {
            TransactionData::new(
                sender,
                fuel_payment,
                fuel_budget,
                fuel_price,
                kind,
                self.expiration,
            )
        };

        // Validate the transaction data
        data.validate()?;

        Ok(data)
    }

    /// Build and sign the transaction with a single keypair
    pub fn build_and_sign(self, keypair: &KeyPair) -> Result<Transaction> {
        let data = self.build()?;
        let signature = keypair
            .sign_transaction(&data)
            .map_err(|e| BuilderError::CryptoError(e.to_string()))?;

        Ok(Transaction::new(data, vec![signature]))
    }

    /// Build and sign the transaction with sender and sponsor keypairs
    pub fn build_and_sign_sponsored(
        self,
        sender_keypair: &KeyPair,
        sponsor_keypair: &KeyPair,
    ) -> Result<Transaction> {
        let data = self.build()?;

        if data.sponsor.is_none() {
            return Err(BuilderError::InvalidData(
                "Transaction is not sponsored".to_string(),
            ));
        }

        let sender_signature = sender_keypair
            .sign_transaction(&data)
            .map_err(|e| BuilderError::CryptoError(e.to_string()))?;

        let sponsor_signature = sponsor_keypair
            .sign_transaction(&data)
            .map_err(|e| BuilderError::CryptoError(e.to_string()))?;

        Ok(Transaction::new(
            data,
            vec![sender_signature, sponsor_signature],
        ))
    }
}

/// Helper for building call arguments for Quantum Move function calls
pub struct CallArgBuilder;

impl CallArgBuilder {
    /// Create a pure value argument
    pub fn pure(value: Vec<u8>) -> CallArg {
        CallArg::Pure(value)
    }

    /// Create an object reference argument
    pub fn object(object_ref: ObjectRef) -> CallArg {
        CallArg::Object(object_ref)
    }

    /// Create a result reference from previous command
    pub fn result(command_index: u16) -> CallArg {
        CallArg::Result(command_index)
    }

    /// Create a nested result reference
    pub fn nested_result(command_index: u16, result_index: u16) -> CallArg {
        CallArg::NestedResult(command_index, result_index)
    }

    /// Serialize a value to pure bytes
    pub fn serialize_pure<T: serde::Serialize>(value: &T) -> Result<CallArg> {
        let bytes = bincode::serialize(value)
            .map_err(|e| BuilderError::InvalidData(format!("Serialization failed: {}", e)))?;
        Ok(CallArg::Pure(bytes))
    }
}

/// Helper for building type tags for Quantum Move types
pub struct TypeTagBuilder;

impl TypeTagBuilder {
    /// Create a bool type tag
    pub fn bool() -> TypeTag {
        TypeTag::Bool
    }

    /// Create a u8 type tag
    pub fn u8() -> TypeTag {
        TypeTag::U8
    }

    /// Create a u64 type tag
    pub fn u64() -> TypeTag {
        TypeTag::U64
    }

    /// Create a u128 type tag
    pub fn u128() -> TypeTag {
        TypeTag::U128
    }

    /// Create an address type tag
    pub fn address() -> TypeTag {
        TypeTag::Address
    }

    /// Create a vector type tag
    pub fn vector(element_type: TypeTag) -> TypeTag {
        TypeTag::Vector(Box::new(element_type))
    }

    /// Create a struct type tag
    pub fn struct_type(
        package: ObjectID,
        module: impl Into<String>,
        name: impl Into<String>,
        type_params: Vec<TypeTag>,
    ) -> Result<TypeTag> {
        Ok(TypeTag::Struct {
            package,
            module: Identifier::new(module)?,
            name: Identifier::new(name)?,
            type_params,
        })
    }
}
