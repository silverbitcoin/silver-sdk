//! Code generation from Quantum modules
//!
//! This module provides tools to generate type-safe Rust bindings from
//! compiled Quantum modules. It creates:
//! - Struct definitions matching Quantum structs
//! - Type-safe function call builders
//! - Serialization/deserialization helpers
//!
//! # Example
//!
//! ```no_run
//! use silver_sdk::codegen::CodeGenerator;
//!
//! let quantum_source = r#"
//!     module my_package::coin {
//!         struct Coin has key, store {
//!             value: u64
//!         }
//!         
//!         public fun mint(value: u64): Coin {
//!             Coin { value }
//!         }
//!     }
//! "#;
//!
//! let generator = CodeGenerator::new();
//! let rust_code = generator.generate_from_source(quantum_source).unwrap();
//! println!("{}", rust_code);
//! ```

// Note: CallArg and TypeTag will be used when full codegen is implemented
#[allow(unused_imports)]
use silver_core::transaction::{CallArg, TypeTag};
use std::collections::HashMap;
use thiserror::Error;

/// Code generation errors
#[derive(Debug, Error)]
pub enum CodegenError {
    /// Failed to parse Quantum source
    #[error("Parse error: {0}")]
    ParseError(String),

    /// Invalid module structure
    #[error("Invalid module: {0}")]
    InvalidModule(String),

    /// Unsupported feature
    #[error("Unsupported feature: {0}")]
    UnsupportedFeature(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Result type for code generation operations
pub type Result<T> = std::result::Result<T, CodegenError>;

/// Quantum type information
#[derive(Debug, Clone)]
pub struct QuantumType {
    /// Type name
    pub name: String,
    /// Module path (if external)
    pub module: Option<String>,
    /// Generic parameters
    pub generics: Vec<QuantumType>,
    /// Is reference
    pub is_reference: bool,
    /// Is mutable reference
    pub is_mut_reference: bool,
}

/// Quantum struct information
#[derive(Debug, Clone)]
pub struct QuantumStruct {
    /// Struct name
    pub name: String,
    /// Fields
    pub fields: Vec<QuantumField>,
    /// Abilities
    pub abilities: Vec<String>,
    /// Is public
    pub is_public: bool,
}

/// Quantum field information
#[derive(Debug, Clone)]
pub struct QuantumField {
    /// Field name
    pub name: String,
    /// Field type
    pub field_type: QuantumType,
}

/// Quantum function information
#[derive(Debug, Clone)]
pub struct QuantumFunction {
    /// Function name
    pub name: String,
    /// Parameters
    pub parameters: Vec<QuantumParameter>,
    /// Return type
    pub return_type: Option<QuantumType>,
    /// Is public
    pub is_public: bool,
    /// Is entry function
    pub is_entry: bool,
}

/// Quantum parameter information
#[derive(Debug, Clone)]
pub struct QuantumParameter {
    /// Parameter name
    pub name: String,
    /// Parameter type
    pub param_type: QuantumType,
    /// Is mutable
    pub is_mut: bool,
}

/// Quantum module information
#[derive(Debug, Clone)]
pub struct QuantumModule {
    /// Module name (e.g., "my_package::coin")
    pub name: String,
    /// Structs defined in module
    pub structs: Vec<QuantumStruct>,
    /// Functions defined in module
    pub functions: Vec<QuantumFunction>,
    /// Use declarations
    pub uses: Vec<String>,
}

/// Code generator for creating Rust bindings from Quantum modules
pub struct CodeGenerator {
    /// Module cache (will be used for caching parsed modules in future)
    #[allow(dead_code)]
    modules: HashMap<String, QuantumModule>,
}

impl Default for CodeGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl CodeGenerator {
    /// Create a new code generator
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
        }
    }

    /// Generate Rust code from Quantum source
    pub fn generate_from_source(&mut self, source: &str) -> Result<String> {
        // Parse the Quantum source using the quantum-compiler
        let module = self.parse_quantum_source(source)?;
        
        // Generate Rust code
        self.generate_module_code(&module)
    }

    /// Generate Rust code from compiled bytecode
    pub fn generate_from_bytecode(&mut self, bytecode: &[u8]) -> Result<String> {
        // Extract module metadata from bytecode
        let module = self.extract_module_from_bytecode(bytecode)?;
        
        // Generate Rust code
        self.generate_module_code(&module)
    }

    /// Parse Quantum source into module information
    fn parse_quantum_source(&self, source: &str) -> Result<QuantumModule> {
        // This is a simplified parser for demonstration
        // In production, this would use the full quantum-compiler
        
        // For now, we'll do basic parsing
        let lines: Vec<&str> = source.lines().collect();
        let mut module_name = String::new();
        let mut structs = Vec::new();
        let mut functions = Vec::new();
        let mut uses = Vec::new();

        let mut i = 0;
        while i < lines.len() {
            let line = lines[i].trim();
            
            if line.starts_with("module ") {
                // Extract module name
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    module_name = parts[1].trim_end_matches('{').trim().to_string();
                }
            } else if line.starts_with("use ") {
                // Extract use declaration
                let use_path = line.trim_start_matches("use ")
                    .trim_end_matches(';')
                    .trim()
                    .to_string();
                uses.push(use_path);
            } else if line.contains("struct ") {
                // Parse struct
                if let Some(s) = self.parse_struct(&lines, &mut i)? {
                    structs.push(s);
                }
            } else if line.contains("fun ") {
                // Parse function
                if let Some(f) = self.parse_function(&lines, &mut i)? {
                    functions.push(f);
                }
            }
            
            i += 1;
        }

        Ok(QuantumModule {
            name: module_name,
            structs,
            functions,
            uses,
        })
    }

    /// Parse a struct definition
    fn parse_struct(&self, lines: &[&str], index: &mut usize) -> Result<Option<QuantumStruct>> {
        let line = lines[*index].trim();
        
        let is_public = line.starts_with("public ");
        let struct_line = if is_public {
            line.trim_start_matches("public ").trim()
        } else {
            line
        };

        if !struct_line.contains("struct ") {
            return Ok(None);
        }

        // Extract struct name
        let parts: Vec<&str> = struct_line.split_whitespace().collect();
        let name_part = parts.iter()
            .skip_while(|&&p| p != "struct")
            .nth(1)
            .ok_or_else(|| CodegenError::ParseError("Missing struct name".to_string()))?;
        
        let name = name_part.trim_end_matches('{').trim().to_string();

        // Extract abilities
        let mut abilities = Vec::new();
        if struct_line.contains(" has ") {
            let has_part = struct_line.split(" has ").nth(1)
                .ok_or_else(|| CodegenError::ParseError("Invalid has clause".to_string()))?;
            let ability_str = has_part.split('{').next().unwrap_or("").trim();
            abilities = ability_str.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        // Parse fields
        let mut fields = Vec::new();
        *index += 1;
        while *index < lines.len() {
            let field_line = lines[*index].trim();
            if field_line.starts_with('}') {
                break;
            }
            if field_line.is_empty() {
                *index += 1;
                continue;
            }

            // Parse field: name: type
            if let Some(colon_pos) = field_line.find(':') {
                let field_name = field_line[..colon_pos].trim().to_string();
                let type_str = field_line[colon_pos + 1..]
                    .trim()
                    .trim_end_matches(',')
                    .trim()
                    .to_string();
                
                let field_type = self.parse_type(&type_str)?;
                fields.push(QuantumField {
                    name: field_name,
                    field_type,
                });
            }

            *index += 1;
        }

        Ok(Some(QuantumStruct {
            name,
            fields,
            abilities,
            is_public,
        }))
    }

    /// Parse a function definition
    fn parse_function(&self, lines: &[&str], index: &mut usize) -> Result<Option<QuantumFunction>> {
        let line = lines[*index].trim();
        
        let mut is_public = false;
        let mut is_entry = false;
        let mut fun_line = line;

        if line.starts_with("public ") {
            is_public = true;
            fun_line = line.trim_start_matches("public ").trim();
        }
        if fun_line.starts_with("entry ") {
            is_entry = true;
            fun_line = fun_line.trim_start_matches("entry ").trim();
        }

        if !fun_line.contains("fun ") {
            return Ok(None);
        }

        // Extract function name
        let parts: Vec<&str> = fun_line.split_whitespace().collect();
        let name_part = parts.iter()
            .skip_while(|&&p| p != "fun")
            .nth(1)
            .ok_or_else(|| CodegenError::ParseError("Missing function name".to_string()))?;
        
        let name = name_part.split('(').next().unwrap_or("").trim().to_string();

        // Parse parameters (simplified)
        let mut parameters = Vec::new();
        if let Some(params_start) = fun_line.find('(') {
            if let Some(params_end) = fun_line.find(')') {
                let params_str = &fun_line[params_start + 1..params_end];
                if !params_str.trim().is_empty() {
                    for param in params_str.split(',') {
                        let param = param.trim();
                        if let Some(colon_pos) = param.find(':') {
                            let param_name = param[..colon_pos].trim();
                            let is_mut = param_name.starts_with("mut ");
                            let param_name = if is_mut {
                                param_name.trim_start_matches("mut ").trim().to_string()
                            } else {
                                param_name.to_string()
                            };
                            
                            let type_str = param[colon_pos + 1..].trim().to_string();
                            let param_type = self.parse_type(&type_str)?;
                            
                            parameters.push(QuantumParameter {
                                name: param_name,
                                param_type,
                                is_mut,
                            });
                        }
                    }
                }
            }
        }

        // Parse return type
        let return_type = if fun_line.contains("->") {
            let return_str = fun_line.split("->").nth(1)
                .ok_or_else(|| CodegenError::ParseError("Invalid return type".to_string()))?
                .split('{').next().unwrap_or("").trim();
            Some(self.parse_type(return_str)?)
        } else {
            None
        };

        Ok(Some(QuantumFunction {
            name,
            parameters,
            return_type,
            is_public,
            is_entry,
        }))
    }

    /// Parse a type string
    fn parse_type(&self, type_str: &str) -> Result<QuantumType> {
        let type_str = type_str.trim();

        // Handle references
        if type_str.starts_with("&mut ") {
            let inner = self.parse_type(&type_str[5..])?;
            return Ok(QuantumType {
                name: inner.name,
                module: inner.module,
                generics: inner.generics,
                is_reference: true,
                is_mut_reference: true,
            });
        }
        if type_str.starts_with('&') {
            let inner = self.parse_type(&type_str[1..])?;
            return Ok(QuantumType {
                name: inner.name,
                module: inner.module,
                generics: inner.generics,
                is_reference: true,
                is_mut_reference: false,
            });
        }

        // Handle vectors
        if type_str.starts_with("vector<") {
            let inner_type = type_str.trim_start_matches("vector<")
                .trim_end_matches('>')
                .trim();
            let inner = self.parse_type(inner_type)?;
            return Ok(QuantumType {
                name: "vector".to_string(),
                module: None,
                generics: vec![inner],
                is_reference: false,
                is_mut_reference: false,
            });
        }

        // Handle module-qualified types
        if type_str.contains("::") {
            let parts: Vec<&str> = type_str.split("::").collect();
            let module = parts[..parts.len() - 1].join("::");
            let name = parts[parts.len() - 1].to_string();
            return Ok(QuantumType {
                name,
                module: Some(module),
                generics: Vec::new(),
                is_reference: false,
                is_mut_reference: false,
            });
        }

        // Simple type
        Ok(QuantumType {
            name: type_str.to_string(),
            module: None,
            generics: Vec::new(),
            is_reference: false,
            is_mut_reference: false,
        })
    }

    /// Extract module information from bytecode
    fn extract_module_from_bytecode(&self, _bytecode: &[u8]) -> Result<QuantumModule> {
        // In a real implementation, this would deserialize the bytecode
        // and extract module metadata
        Err(CodegenError::UnsupportedFeature(
            "Bytecode extraction not yet implemented".to_string()
        ))
    }

    /// Generate Rust code for a module
    fn generate_module_code(&self, module: &QuantumModule) -> Result<String> {
        let mut code = String::new();

        // Generate module header
        code.push_str(&format!("// Generated code for Quantum module: {}\n", module.name));
        code.push_str("// DO NOT EDIT - This file is auto-generated\n\n");
        code.push_str("#![allow(dead_code, unused_imports)]\n\n");

        // Generate imports
        code.push_str("use silver_sdk::{{TransactionBuilder, CallArgBuilder, TypeTagBuilder}};\n");
        code.push_str("use silver_core::{{CallArg, ObjectID, ObjectRef, SilverAddress, TypeTag}};\n");
        code.push_str("use serde::{{Serialize, Deserialize}};\n\n");

        // Generate struct definitions
        for s in &module.structs {
            code.push_str(&self.generate_struct_code(s)?);
            code.push('\n');
        }

        // Generate function call builders
        for f in &module.functions {
            if f.is_public {
                code.push_str(&self.generate_function_builder(module, f)?);
                code.push('\n');
            }
        }

        // Generate module helper struct
        code.push_str(&self.generate_module_helper(module)?);

        Ok(code)
    }

    /// Generate Rust struct code
    fn generate_struct_code(&self, s: &QuantumStruct) -> Result<String> {
        let mut code = String::new();

        // Generate documentation
        code.push_str(&format!("/// Quantum struct: {}\n", s.name));
        if !s.abilities.is_empty() {
            code.push_str(&format!("/// Abilities: {}\n", s.abilities.join(", ")));
        }

        // Generate derive attributes
        code.push_str("#[derive(Debug, Clone, Serialize, Deserialize");
        if s.abilities.contains(&"copy".to_string()) {
            code.push_str(", Copy");
        }
        if s.abilities.contains(&"drop".to_string()) || s.abilities.is_empty() {
            // Default is droppable
        }
        code.push_str(")]\n");

        // Generate struct definition
        let visibility = if s.is_public { "pub " } else { "" };
        code.push_str(&format!("{}struct {} {{\n", visibility, s.name));

        // Generate fields
        for field in &s.fields {
            let rust_type = self.quantum_type_to_rust(&field.field_type)?;
            code.push_str(&format!("    pub {}: {},\n", field.name, rust_type));
        }

        code.push_str("}\n");

        Ok(code)
    }

    /// Generate function call builder
    fn generate_function_builder(&self, module: &QuantumModule, f: &QuantumFunction) -> Result<String> {
        let mut code = String::new();

        // Generate documentation
        code.push_str(&format!("/// Call builder for function: {}::{}\n", module.name, f.name));
        if f.is_entry {
            code.push_str("/// This is an entry function\n");
        }

        // Generate function signature
        code.push_str(&format!("pub fn call_{}(\n", f.name));
        code.push_str("    builder: TransactionBuilder,\n");
        code.push_str("    package: ObjectID,\n");

        // Generate parameters
        for param in &f.parameters {
            let rust_type = self.quantum_type_to_rust_arg(&param.param_type)?;
            code.push_str(&format!("    {}: {},\n", param.name, rust_type));
        }

        code.push_str(") -> Result<TransactionBuilder, silver_sdk::BuilderError> {\n");

        // Generate function body
        code.push_str("    let mut arguments = Vec::new();\n");

        // Convert parameters to CallArgs
        for param in &f.parameters {
            code.push_str(&self.generate_arg_conversion(&param.name, &param.param_type)?);
        }

        // Generate the call
        let module_parts: Vec<&str> = module.name.split("::").collect();
        let module_name = module_parts.last().unwrap_or(&"unknown");
        
        code.push_str(&format!("    builder.call(\n"));
        code.push_str(&format!("        package,\n"));
        code.push_str(&format!("        \"{}\",\n", module_name));
        code.push_str(&format!("        \"{}\",\n", f.name));
        code.push_str(&format!("        vec![], // type arguments\n"));
        code.push_str(&format!("        arguments,\n"));
        code.push_str(&format!("    )\n"));
        code.push_str("}\n");

        Ok(code)
    }

    /// Generate argument conversion code
    fn generate_arg_conversion(&self, param_name: &str, param_type: &QuantumType) -> Result<String> {
        let mut code = String::new();

        match param_type.name.as_str() {
            "u8" | "u16" | "u32" | "u64" | "u128" | "u256" => {
                code.push_str(&format!("    arguments.push(CallArg::Pure(bincode::serialize(&{}).unwrap()));\n", param_name));
            }
            "bool" => {
                code.push_str(&format!("    arguments.push(CallArg::Pure(bincode::serialize(&{}).unwrap()));\n", param_name));
            }
            "address" => {
                code.push_str(&format!("    arguments.push(CallArg::Pure(bincode::serialize(&{}).unwrap()));\n", param_name));
            }
            "vector" => {
                code.push_str(&format!("    arguments.push(CallArg::Pure(bincode::serialize(&{}).unwrap()));\n", param_name));
            }
            _ => {
                // Assume it's an object reference
                if param_type.is_reference {
                    code.push_str(&format!("    arguments.push(CallArg::Object({}));\n", param_name));
                } else {
                    code.push_str(&format!("    arguments.push(CallArg::Object({}));\n", param_name));
                }
            }
        }

        Ok(code)
    }

    /// Generate module helper struct
    fn generate_module_helper(&self, module: &QuantumModule) -> Result<String> {
        let mut code = String::new();

        let module_parts: Vec<&str> = module.name.split("::").collect();
        let module_name = module_parts.last().unwrap_or(&"unknown");
        let struct_name = format!("{}Module", to_pascal_case(module_name));

        code.push_str(&format!("/// Helper struct for {} module\n", module.name));
        code.push_str(&format!("pub struct {} {{\n", struct_name));
        code.push_str("    /// Package ID containing this module\n");
        code.push_str("    pub package_id: ObjectID,\n");
        code.push_str("}\n\n");

        code.push_str(&format!("impl {} {{\n", struct_name));
        code.push_str("    /// Create a new module helper\n");
        code.push_str("    pub fn new(package_id: ObjectID) -> Self {\n");
        code.push_str("        Self { package_id }\n");
        code.push_str("    }\n");

        // Generate convenience methods
        for f in &module.functions {
            if f.is_public {
                code.push_str(&self.generate_module_method(module, f)?);
            }
        }

        code.push_str("}\n");

        Ok(code)
    }

    /// Generate module method
    fn generate_module_method(&self, _module: &QuantumModule, f: &QuantumFunction) -> Result<String> {
        let mut code = String::new();

        code.push_str(&format!("\n    /// Call {}\n", f.name));
        code.push_str(&format!("    pub fn {}(\n", f.name));
        code.push_str("        &self,\n");
        code.push_str("        builder: TransactionBuilder,\n");

        for param in &f.parameters {
            let rust_type = self.quantum_type_to_rust_arg(&param.param_type)?;
            code.push_str(&format!("        {}: {},\n", param.name, rust_type));
        }

        code.push_str("    ) -> Result<TransactionBuilder, silver_sdk::BuilderError> {\n");
        code.push_str(&format!("        call_{}(\n", f.name));
        code.push_str("            builder,\n");
        code.push_str("            self.package_id,\n");

        for param in &f.parameters {
            code.push_str(&format!("            {},\n", param.name));
        }

        code.push_str("        )\n");
        code.push_str("    }\n");

        Ok(code)
    }

    /// Convert Quantum type to Rust type
    fn quantum_type_to_rust(&self, qtype: &QuantumType) -> Result<String> {
        let base_type = match qtype.name.as_str() {
            "bool" => "bool".to_string(),
            "u8" => "u8".to_string(),
            "u16" => "u16".to_string(),
            "u32" => "u32".to_string(),
            "u64" => "u64".to_string(),
            "u128" => "u128".to_string(),
            "u256" => "[u8; 32]".to_string(), // U256 as byte array
            "address" => "SilverAddress".to_string(),
            "vector" => {
                if qtype.generics.is_empty() {
                    return Err(CodegenError::InvalidModule("Vector without element type".to_string()));
                }
                let elem_type = self.quantum_type_to_rust(&qtype.generics[0])?;
                format!("Vec<{}>", elem_type)
            }
            _ => {
                // Custom struct type
                if let Some(module) = &qtype.module {
                    format!("{}::{}", module.replace("::", "_"), qtype.name)
                } else {
                    qtype.name.clone()
                }
            }
        };

        if qtype.is_mut_reference {
            Ok(format!("&mut {}", base_type))
        } else if qtype.is_reference {
            Ok(format!("&{}", base_type))
        } else {
            Ok(base_type)
        }
    }

    /// Convert Quantum type to Rust argument type
    fn quantum_type_to_rust_arg(&self, qtype: &QuantumType) -> Result<String> {
        // For function arguments, we use owned types or ObjectRef for objects
        match qtype.name.as_str() {
            "bool" | "u8" | "u16" | "u32" | "u64" | "u128" | "u256" | "address" => {
                self.quantum_type_to_rust(qtype)
            }
            "vector" => self.quantum_type_to_rust(qtype),
            _ => {
                // Object types become ObjectRef
                Ok("ObjectRef".to_string())
            }
        }
    }
}

/// Convert snake_case to PascalCase
fn to_pascal_case(s: &str) -> String {
    s.split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().chain(chars).collect(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_module() {
        let source = r#"
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
        let result = generator.generate_from_source(source);
        assert!(result.is_ok());
        
        let code = result.unwrap();
        assert!(code.contains("struct Coin"));
        assert!(code.contains("pub value: u64"));
        assert!(code.contains("pub fn call_mint"));
    }

    #[test]
    fn test_parse_type() {
        let generator = CodeGenerator::new();
        
        let t = generator.parse_type("u64").unwrap();
        assert_eq!(t.name, "u64");
        assert!(!t.is_reference);

        let t = generator.parse_type("&u64").unwrap();
        assert_eq!(t.name, "u64");
        assert!(t.is_reference);
        assert!(!t.is_mut_reference);

        let t = generator.parse_type("&mut u64").unwrap();
        assert_eq!(t.name, "u64");
        assert!(t.is_reference);
        assert!(t.is_mut_reference);

        let t = generator.parse_type("vector<u8>").unwrap();
        assert_eq!(t.name, "vector");
        assert_eq!(t.generics.len(), 1);
        assert_eq!(t.generics[0].name, "u8");
    }

    #[test]
    fn test_to_pascal_case() {
        assert_eq!(to_pascal_case("coin"), "Coin");
        assert_eq!(to_pascal_case("my_module"), "MyModule");
        assert_eq!(to_pascal_case("nft_marketplace"), "NftMarketplace");
    }
}
