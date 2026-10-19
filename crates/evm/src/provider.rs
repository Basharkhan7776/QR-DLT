//! Custom PrecompileProvider integrating Falcon-512 into revm.

use crate::precompile::{falcon512_precompile_fn, FALCON512_PRECOMPILE_ADDRESS};
use revm::context::Cfg;
use revm::context_interface::ContextTr;
use revm::handler::{precompile_output_to_interpreter_result, EthPrecompiles, PrecompileProvider};
use revm::interpreter::{CallInputs, InterpreterResult};
use revm::primitives::{hardfork::SpecId, Address, AddressSet};

/// Precompile provider wrapping standard Ethereum precompiles and adding Falcon-512 (0x15).
#[derive(Clone, Debug)]
pub struct FalconPrecompileProvider {
    pub eth_precompiles: EthPrecompiles,
    pub falcon_address: Address,
    pub warm_addresses: AddressSet,
}

impl FalconPrecompileProvider {
    /// Creates a new `FalconPrecompileProvider` for the given Ethereum specification.
    pub fn new(spec: SpecId) -> Self {
        let eth = EthPrecompiles::new(spec);
        let mut warm = eth.warm_addresses().clone();
        warm.insert(FALCON512_PRECOMPILE_ADDRESS);
        Self {
            eth_precompiles: eth,
            falcon_address: FALCON512_PRECOMPILE_ADDRESS,
            warm_addresses: warm,
        }
    }
}

impl<CTX: ContextTr> PrecompileProvider<CTX> for FalconPrecompileProvider {
    type Output = InterpreterResult;

    fn set_spec(&mut self, spec: <CTX::Cfg as Cfg>::Spec) -> bool {
        let changed =
            <EthPrecompiles as PrecompileProvider<CTX>>::set_spec(&mut self.eth_precompiles, spec);
        if changed {
            let mut warm = self.eth_precompiles.warm_addresses().clone();
            warm.insert(self.falcon_address);
            self.warm_addresses = warm;
        }
        changed
    }

    fn run(
        &mut self,
        context: &mut CTX,
        inputs: &CallInputs,
    ) -> Result<Option<InterpreterResult>, String> {
        if inputs.bytecode_address == self.falcon_address {
            let input_bytes = inputs.input.as_bytes(context);
            let output = falcon512_precompile_fn(&input_bytes, inputs.gas_limit, inputs.reservoir)
                .map_err(|e| e.to_string())?;
            let result = precompile_output_to_interpreter_result(output, inputs.gas_limit);
            Ok(Some(result))
        } else {
            self.eth_precompiles.run(context, inputs)
        }
    }

    fn warm_addresses(&self) -> &AddressSet {
        &self.warm_addresses
    }

    fn contains(&self, address: &Address) -> bool {
        *address == self.falcon_address || self.eth_precompiles.contains(address)
    }
}
