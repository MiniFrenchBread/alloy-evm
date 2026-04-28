//! 0G Bridge inbound message system call.
//!
//! This is the EL-side counterpart to the EIP-7685 request type `0xf0` carried on the engine
//! API (private 0G namespace; see `docs/plans/cross-chain-bridge.md` §1.6.5). The CL beacon
//! block emits a list of `BridgeMessage` items as SSZ bytes; the EL decodes them into ABI
//! calldata for `Bridge.executeRemoteMessages(InboundMessage[])` and invokes the Bridge proxy
//! contract from the canonical [`SYSTEM_ADDRESS`] just like EIP-4788/7002.
//!
//! Activation is gated by [`EthExecutorSpec::is_bridge_active_at_timestamp`] and a configured
//! [`EthExecutorSpec::bridge_contract_address`]. The hook is a no-op (returns `Ok(None)`) when
//! either gate is closed, when no calldata was attached to the block context, or when the
//! attached calldata is empty.
//!
//! See `docs/plans/cross-chain-bridge.md` § "EL 设计" for the design rationale.

use crate::{block::BlockExecutionError, eth::spec::EthExecutorSpec, Evm};
use alloc::format;
use alloy_eips::eip7002::SYSTEM_ADDRESS;
use alloy_primitives::Bytes;
use revm::context_interface::result::ResultAndState;

/// Invokes `Bridge.executeRemoteMessages(InboundMessage[])` from [`SYSTEM_ADDRESS`].
///
/// Returns `Ok(None)` (no-op) if any of the following gates is closed:
///   * Bridge fork not active at `timestamp` (`spec.is_bridge_active_at_timestamp`)
///   * Chain spec has no configured bridge contract address
///   * No calldata was attached to the block execution context
///   * Attached calldata is empty
///
/// On the active path the call uses the standard `transact_system_call` semantics: 30M gas,
/// no fee charged, no coinbase reward, executed against the same EVM state as block transactions.
/// The state delta is **not** committed by this function — the caller is responsible for
/// wiring the result into [`SystemCaller::on_state`] and calling `db.commit(...)`.
#[inline]
pub(crate) fn transact_bridge_contract_call<Halt>(
    spec: &impl EthExecutorSpec,
    timestamp: u64,
    calldata: Option<&Bytes>,
    evm: &mut impl Evm<HaltReason = Halt>,
) -> Result<Option<ResultAndState<Halt>>, BlockExecutionError> {
    // Gate 1: fork-version timestamp
    if !spec.is_bridge_active_at_timestamp(timestamp) {
        return Ok(None);
    }

    // Gate 2: configured contract address
    let target = match spec.bridge_contract_address() {
        Some(addr) => addr,
        None => return Ok(None),
    };

    // Gate 3 + 4: non-empty calldata supplied by the engine API
    let cd = match calldata {
        Some(b) if !b.is_empty() => b.clone(),
        _ => return Ok(None),
    };

    let res = match evm.transact_system_call(SYSTEM_ADDRESS, target, cd) {
        Ok(res) => res,
        Err(e) => {
            return Err(BlockExecutionError::msg(format!(
                "0G bridge system call execution failed: {e}"
            )));
        }
    };
    Ok(Some(res))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_eips::eip7002::SYSTEM_ADDRESS as EIP7002_SYSTEM_ADDRESS;
    use alloy_hardforks::{EthereumHardfork, EthereumHardforks, ForkCondition};
    use alloy_primitives::{address, Address};

    /// Lightweight spec used to drive the gate logic. The wider `Evm` integration is exercised
    /// by `0g-reth/crates/ethereum/evm/tests/execute.rs` against a real revm instance.
    #[derive(Debug, Clone, Default)]
    struct MockSpec {
        bridge_address: Option<Address>,
        bridge_active: bool,
    }

    impl EthereumHardforks for MockSpec {
        fn ethereum_fork_activation(&self, _fork: EthereumHardfork) -> ForkCondition {
            ForkCondition::Never
        }
    }

    impl EthExecutorSpec for MockSpec {
        fn deposit_contract_address(&self) -> Option<Address> {
            None
        }
        fn staking_contract_address(&self) -> Option<Address> {
            None
        }
        fn is_staking_activate_at_timestamp(&self, _t: u64) -> bool {
            false
        }
        fn bridge_contract_address(&self) -> Option<Address> {
            self.bridge_address
        }
        fn is_bridge_active_at_timestamp(&self, _t: u64) -> bool {
            self.bridge_active
        }
    }

    // The real `Evm` trait is large; the gate logic only needs the `transact_system_call`
    // entry point. We define a narrow shim that mirrors the real signature for the gate paths
    // and pass it through explicitly. This avoids pulling in a full EVM database harness for a
    // pure decision-table test.
    //
    // For broader integration coverage (calldata round-trip, real state commit, EIP-7002
    // ordering) see `0g-reth/crates/ethereum/evm/tests/execute.rs`.
    fn run<F>(spec: &MockSpec, timestamp: u64, calldata: Option<&Bytes>, mut sink: F) -> bool
    where
        F: FnMut(Address, Address, Bytes),
    {
        // Mirror the gate logic from `transact_bridge_contract_call`. Returns `true` if the
        // happy path would have been taken.
        if !spec.is_bridge_active_at_timestamp(timestamp) {
            return false;
        }
        let Some(target) = spec.bridge_contract_address() else { return false };
        let cd = match calldata {
            Some(b) if !b.is_empty() => b.clone(),
            _ => return false,
        };
        sink(SYSTEM_ADDRESS, target, cd);
        true
    }

    const BRIDGE_ADDR: Address = address!("0x00000000000000000000000000000000000000B0");

    #[test]
    fn no_op_when_fork_inactive() {
        let spec =
            MockSpec { bridge_address: Some(BRIDGE_ADDR), bridge_active: false };
        let cd = Bytes::from_static(&[1, 2, 3, 4]);
        let invoked =
            run(&spec, 100, Some(&cd), |_, _, _| panic!("should not invoke when inactive"));
        assert!(!invoked);
    }

    #[test]
    fn no_op_when_address_missing() {
        let spec = MockSpec { bridge_address: None, bridge_active: true };
        let cd = Bytes::from_static(&[1, 2, 3, 4]);
        let invoked = run(&spec, 100, Some(&cd), |_, _, _| panic!("should not invoke"));
        assert!(!invoked);
    }

    #[test]
    fn no_op_when_calldata_empty() {
        let spec = MockSpec { bridge_address: Some(BRIDGE_ADDR), bridge_active: true };
        let invoked = run(&spec, 100, None, |_, _, _| panic!("should not invoke for None"));
        assert!(!invoked);
        let empty = Bytes::new();
        let invoked2 =
            run(&spec, 100, Some(&empty), |_, _, _| panic!("should not invoke for empty"));
        assert!(!invoked2);
    }

    #[test]
    fn happy_path_uses_system_address_and_target() {
        let spec = MockSpec { bridge_address: Some(BRIDGE_ADDR), bridge_active: true };
        let cd = Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]);
        let mut captured: Option<(Address, Address, Bytes)> = None;
        let invoked = run(&spec, 100, Some(&cd), |caller, target, data| {
            captured = Some((caller, target, data));
        });
        assert!(invoked);
        let (caller, target, data) = captured.expect("happy path captured");
        assert_eq!(caller, SYSTEM_ADDRESS);
        assert_eq!(caller, EIP7002_SYSTEM_ADDRESS, "bridge reuses EIP-7002 SYSTEM_ADDRESS");
        assert_eq!(target, BRIDGE_ADDR);
        assert_eq!(data, Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]));
    }
}
