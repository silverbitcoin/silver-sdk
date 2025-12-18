//! Example demonstrating code generation from Quantum modules
//!
//! This example shows how to:
//! 1. Parse a Quantum module
//! 2. Generate type-safe Rust bindings
//! 3. Use the generated code to build transactions

use silver_sdk::CodeGenerator;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example Quantum module source
    let quantum_source = r#"
        module my_package::nft {
            use silver::object;
            use silver::transfer;
            
            struct NFT has key, store {
                id: object::UID,
                name: vector<u8>,
                description: vector<u8>,
                url: vector<u8>,
                creator: address
            }
            
            struct MintCap has key {
                id: object::UID,
                supply: u64
            }
            
            public fun mint(
                cap: &mut MintCap,
                name: vector<u8>,
                description: vector<u8>,
                url: vector<u8>,
                ctx: &mut TxContext
            ): NFT {
                cap.supply = cap.supply + 1;
                NFT {
                    id: object::new(ctx),
                    name,
                    description,
                    url,
                    creator: tx_context::sender(ctx)
                }
            }
            
            public entry fun transfer_nft(
                nft: NFT,
                recipient: address
            ) {
                transfer::transfer(nft, recipient)
            }
            
            public fun burn(nft: NFT) {
                let NFT { id, name: _, description: _, url: _, creator: _ } = nft;
                object::delete(id)
            }
        }
    "#;

    println!("=== Quantum Module Source ===\n");
    println!("{}\n", quantum_source);

    // Create code generator
    let mut generator = CodeGenerator::new();

    // Generate Rust bindings
    println!("=== Generating Rust Bindings ===\n");
    let rust_code = generator.generate_from_source(quantum_source)?;

    println!("=== Generated Rust Code ===\n");
    println!("{}", rust_code);

    println!("\n=== Usage Example ===\n");
    println!(
        r#"
// Using the generated code:

use silver_sdk::TransactionBuilder;
use silver_core::{{ObjectID, ObjectRef, SilverAddress}};

// Create module helper
let nft_module = NftModule::new(package_id);

// Build a transaction to mint an NFT
let tx = TransactionBuilder::new()
    .sender(sender_address)
    .fuel_payment(fuel_object)
    .fuel_budget(1_000_000);

// Call the mint function using generated helper
let tx = nft_module.mint(
    tx,
    mint_cap_ref,
    b"My NFT".to_vec(),
    b"A beautiful NFT".to_vec(),
    b"https://example.com/nft.png".to_vec(),
)?;

// Sign and submit
let signed_tx = tx.sign(&keypair)?;
client.submit_transaction(signed_tx).await?;
    "#
    );

    Ok(())
}
