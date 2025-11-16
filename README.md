# Code Generation from Quantum Modules

This document describes how to generate type-safe Rust bindings from Quantum smart contract modules.

## Overview

The SilverBitcoin SDK provides a code generation tool that creates Rust bindings from Quantum modules. This enables:

- **Type Safety**: Generated code provides compile-time type checking for function calls
- **IDE Support**: Full autocomplete and documentation in your IDE
- **Reduced Errors**: Catch mistakes at compile time instead of runtime
- **Better Developer Experience**: Work with native Rust types instead of raw bytes

## Quick Start

### Using the CLI

Generate bindings from a Quantum source file:

```bash
silver codegen --source my_module.move --output bindings.rs
```

Generate bindings from compiled bytecode:

```bash
silver codegen --bytecode my_module.mv --output bindings.rs
```

### Using the SDK Programmatically

```rust
use silver_sdk::CodeGenerator;

let quantum_source = r#"
    module my_package::coin {
        struct Coin has key, store {
            value: u64
        }
        
        public fun mint(value: u64): Coin {
            Coin { value }
        }
    }
"#;

let mut generator = CodeGenerator::new();
let rust_code = generator.generate_from_source(quantum_source)?;

// Write to file
std::fs::write("coin_bindings.rs", rust_code)?;
```

## Generated Code Structure

For a Quantum module like this:

```move
module my_package::coin {
    struct Coin has key, store {
        value: u64
    }
    
    public fun mint(value: u64): Coin {
        Coin { value }
    }
    
    public fun transfer(coin: Coin, recipient: address) {
        // ...
    }
}
```

The generator creates:

### 1. Struct Definitions

```rust
/// Quantum struct: Coin
/// Abilities: key, store
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Coin {
    pub value: u64,
}
```

### 2. Function Call Builders

```rust
/// Call builder for function: my_package::coin::mint
pub fn call_mint(
    builder: TransactionBuilder,
    package: ObjectID,
    value: u64,
) -> Result<TransactionBuilder, silver_sdk::BuilderError> {
    // Generated implementation
}

/// Call builder for function: my_package::coin::transfer
pub fn call_transfer(
    builder: TransactionBuilder,
    package: ObjectID,
    coin: ObjectRef,
    recipient: SilverAddress,
) -> Result<TransactionBuilder, silver_sdk::BuilderError> {
    // Generated implementation
}
```

### 3. Module Helper Struct

```rust
/// Helper struct for my_package::coin module
pub struct CoinModule {
    pub package_id: ObjectID,
}

impl CoinModule {
    pub fn new(package_id: ObjectID) -> Self {
        Self { package_id }
    }
    
    /// Call mint
    pub fn mint(
        &self,
        builder: TransactionBuilder,
        value: u64,
    ) -> Result<TransactionBuilder, silver_sdk::BuilderError> {
        call_mint(builder, self.package_id, value)
    }
    
    /// Call transfer
    pub fn transfer(
        &self,
        builder: TransactionBuilder,
        coin: ObjectRef,
        recipient: SilverAddress,
    ) -> Result<TransactionBuilder, silver_sdk::BuilderError> {
        call_transfer(builder, self.package_id, coin, recipient)
    }
}
```

## Usage Examples

### Basic Function Call

```rust
use silver_sdk::TransactionBuilder;
use silver_core::{ObjectID, SilverAddress};

// Import generated bindings
mod coin_bindings;
use coin_bindings::*;

// Create module helper
let package_id = ObjectID::from_hex("0x123...")?;
let coin_module = CoinModule::new(package_id);

// Build transaction
let sender = SilverAddress::from_hex("0xabc...")?;
let fuel_payment = /* ... */;

let tx = TransactionBuilder::new()
    .sender(sender)
    .fuel_payment(fuel_payment)
    .fuel_budget(1_000_000);

// Call mint function
let tx = coin_module.mint(tx, 1000)?;

// Sign and submit
let signed_tx = tx.sign(&keypair)?;
client.submit_transaction(signed_tx).await?;
```

### Complex Transaction with Multiple Calls

```rust
// Build a transaction that mints and transfers in one atomic operation
let tx = TransactionBuilder::new()
    .sender(sender)
    .fuel_payment(fuel_payment)
    .fuel_budget(2_000_000);

// Mint a coin
let tx = coin_module.mint(tx, 1000)?;

// Transfer it to recipient
let tx = coin_module.transfer(tx, coin_ref, recipient)?;

// Sign and submit
let signed_tx = tx.sign(&keypair)?;
client.submit_transaction(signed_tx).await?;
```

### Working with Structs

```rust
// Deserialize a Coin object from blockchain data
let coin_data: Vec<u8> = client.get_object(object_id).await?.data;
let coin: Coin = bincode::deserialize(&coin_data)?;

println!("Coin value: {}", coin.value);

// Serialize for storage or transmission
let serialized = bincode::serialize(&coin)?;
```

## Type Mapping

The code generator maps Quantum types to Rust types:

| Quantum Type | Rust Type | Notes |
|--------------|-----------|-------|
| `bool` | `bool` | Direct mapping |
| `u8` | `u8` | Direct mapping |
| `u16` | `u16` | Direct mapping |
| `u32` | `u32` | Direct mapping |
| `u64` | `u64` | Direct mapping |
| `u128` | `u128` | Direct mapping |
| `u256` | `[u8; 32]` | Represented as byte array |
| `address` | `SilverAddress` | 512-bit quantum-resistant address |
| `vector<T>` | `Vec<T>` | Generic vector |
| `&T` | `&T` | Immutable reference |
| `&mut T` | `&mut T` | Mutable reference |
| Custom struct | `ObjectRef` | For function arguments |
| Custom struct | Generated struct | For return values |

## Advanced Features

### Generic Functions

For Quantum functions with type parameters:

```move
public fun swap<T1, T2>(coin1: Coin<T1>, coin2: Coin<T2>): (Coin<T2>, Coin<T1>) {
    // ...
}
```

The generator creates:

```rust
pub fn call_swap<T1, T2>(
    builder: TransactionBuilder,
    package: ObjectID,
    type_arg_t1: TypeTag,
    type_arg_t2: TypeTag,
    coin1: ObjectRef,
    coin2: ObjectRef,
) -> Result<TransactionBuilder, silver_sdk::BuilderError> {
    // Generated implementation with type arguments
}
```

### Entry Functions

Entry functions (marked with `entry` keyword) are special:

```move
public entry fun mint_and_transfer(value: u64, recipient: address) {
    // ...
}
```

These can be called directly from transactions without returning values.

### Module Dependencies

When a module uses types from other modules:

```move
module my_package::nft {
    use my_package::coin::Coin;
    
    public fun buy_nft(payment: Coin): NFT {
        // ...
    }
}
```

The generator creates proper imports:

```rust
use my_package_coin::Coin;

pub fn call_buy_nft(
    builder: TransactionBuilder,
    package: ObjectID,
    payment: ObjectRef,
) -> Result<TransactionBuilder, silver_sdk::BuilderError> {
    // ...
}
```

## Best Practices

### 1. Regenerate After Module Updates

Always regenerate bindings when you update your Quantum modules:

```bash
silver codegen --source updated_module.move --output bindings.rs
```

### 2. Version Control

Commit generated bindings to version control so all developers have consistent types.

### 3. Separate Bindings Per Module

Generate separate binding files for each module:

```bash
silver codegen --source coin.move --output coin_bindings.rs
silver codegen --source nft.move --output nft_bindings.rs
```

### 4. Use Module Helpers

Prefer the module helper struct over direct function calls:

```rust
// Good: Using module helper
let coin_module = CoinModule::new(package_id);
let tx = coin_module.mint(tx, 1000)?;

// Less convenient: Direct function call
let tx = call_mint(tx, package_id, 1000)?;
```

### 5. Type Safety

Let the compiler catch errors:

```rust
// Compile error: wrong type
let tx = coin_module.mint(tx, "1000")?; // ❌ Expected u64, got &str

// Correct
let tx = coin_module.mint(tx, 1000)?; // ✅
```

## Integration with Build Systems

### Cargo Build Script

Add code generation to your `build.rs`:

```rust
use silver_sdk::CodeGenerator;
use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    
    // Generate bindings
    let mut generator = CodeGenerator::new();
    let source = std::fs::read_to_string("quantum/coin.move").unwrap();
    let bindings = generator.generate_from_source(&source).unwrap();
    
    // Write to output directory
    std::fs::write(out_dir.join("coin_bindings.rs"), bindings).unwrap();
    
    // Tell Cargo to rerun if source changes
    println!("cargo:rerun-if-changed=quantum/coin.move");
}
```

Then include in your code:

```rust
include!(concat!(env!("OUT_DIR"), "/coin_bindings.rs"));
```

### Makefile Integration

```makefile
.PHONY: codegen
codegen:
	silver codegen --source quantum/coin.move --output src/bindings/coin.rs
	silver codegen --source quantum/nft.move --output src/bindings/nft.rs
	rustfmt src/bindings/*.rs

.PHONY: build
build: codegen
	cargo build --release
```

## Troubleshooting

### Parse Errors

If you get parse errors, ensure your Quantum source is valid:

```bash
# Compile the module first to check for errors
quantum build
```

### Missing Types

If generated code references unknown types, ensure all dependencies are included:

```rust
// Add missing imports
use silver_core::{ObjectID, ObjectRef, SilverAddress};
```

### Compilation Errors

If generated code doesn't compile, file an issue with:
- Your Quantum source code
- The generated Rust code
- The error message

## API Reference

### `CodeGenerator`

Main struct for code generation.

#### Methods

- `new() -> Self`: Create a new code generator
- `generate_from_source(&mut self, source: &str) -> Result<String>`: Generate from Quantum source
- `generate_from_bytecode(&mut self, bytecode: &[u8]) -> Result<String>`: Generate from compiled bytecode

### `CodegenError`

Error type for code generation operations.

#### Variants

- `ParseError(String)`: Failed to parse Quantum source
- `InvalidModule(String)`: Invalid module structure
- `UnsupportedFeature(String)`: Feature not yet supported
- `IoError(std::io::Error)`: IO operation failed

## Examples

See the `examples/` directory for complete examples:

- `codegen_example.rs`: Basic code generation
- `nft_example.rs`: NFT module with complex types
- `defi_example.rs`: DeFi module with generic functions

## Contributing

To improve code generation:

1. Add test cases in `src/codegen.rs`
2. Update type mappings in `quantum_type_to_rust()`
3. Add support for new Quantum features
4. Update this documentation

## License

Apache-2.0
