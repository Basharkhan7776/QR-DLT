//! QR-DLT Sovereign EVM Engine and Native Precompiles.

pub mod engine;
pub mod error;
pub mod precompile;
pub mod provider;

pub use engine::{BlockExecutionResult, EvmExecutionReceipt, FalconEvm, FalconEvmEngine};
pub use error::EvmEngineError;
pub use precompile::{
    falcon512_precompile, falcon512_verify_eth, Falcon512CallData, FALCON512_PRECOMPILE_ADDRESS,
    FALCON512_PRECOMPILE_GAS, FALCON512_PUBLIC_KEY_SIZE,
};
pub use provider::FalconPrecompileProvider;

pub use revm;
