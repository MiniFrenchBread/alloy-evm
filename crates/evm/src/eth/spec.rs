//! Abstraction over configuration object for [`super::EthBlockExecutor`].

use alloy_eips::eip6110::MAINNET_DEPOSIT_CONTRACT_ADDRESS;
use alloy_hardforks::{EthereumChainHardforks, EthereumHardfork, EthereumHardforks, ForkCondition};
use alloy_primitives::{address, Address};

/// A configuration object for [`super::EthBlockExecutor`]
#[auto_impl::auto_impl(&, Arc)]
pub trait EthExecutorSpec: EthereumHardforks {
    /// Address of deposit contract emitting deposit events.
    ///
    /// Used by [`super::eip6110::parse_deposits_from_receipts`].
    fn deposit_contract_address(&self) -> Option<Address>;

    /// Address of staking contract.
    fn staking_contract_address(&self) -> Option<Address>;

    /// Convenience method to check if staking contract is active at a given timestamp.
    fn is_staking_activate_at_timestamp(&self, timestamp: u64) -> bool;

    /// Address of the Bridge contract used for cross-chain inbound message execution.
    ///
    /// Returning `None` disables the bridge system call regardless of
    /// [`Self::is_bridge_active_at_timestamp`].
    fn bridge_contract_address(&self) -> Option<Address> {
        None
    }

    /// Convenience method to check if the Bridge fork is active at a given timestamp.
    ///
    /// Default implementation returns `false` so chains that have not opted into the bridge
    /// continue to behave exactly as before.
    fn is_bridge_active_at_timestamp(&self, _timestamp: u64) -> bool {
        false
    }
}

/// Basic Ethereum specification.
#[derive(Debug, Clone)]
pub struct EthSpec {
    hardforks: EthereumChainHardforks,
    deposit_contract_address: Option<Address>,
}

impl EthSpec {
    /// Creates [`EthSpec`] for Ethereum mainnet.
    pub fn mainnet() -> Self {
        Self {
            hardforks: EthereumChainHardforks::mainnet(),
            deposit_contract_address: Some(MAINNET_DEPOSIT_CONTRACT_ADDRESS),
        }
    }

    /// Creates [`EthSpec`] for Ethereum Sepolia.
    pub fn sepolia() -> Self {
        Self {
            hardforks: EthereumChainHardforks::sepolia(),
            deposit_contract_address: Some(address!("0x7f02c3e3c98b133055b8b348b2ac625669ed295d")),
        }
    }

    /// Creates [`EthSpec`] for Ethereum Holesky.
    pub fn holesky() -> Self {
        Self {
            hardforks: EthereumChainHardforks::holesky(),
            deposit_contract_address: Some(address!("0x4242424242424242424242424242424242424242")),
        }
    }
}

impl EthereumHardforks for EthSpec {
    fn ethereum_fork_activation(&self, fork: EthereumHardfork) -> ForkCondition {
        self.hardforks.ethereum_fork_activation(fork)
    }
}

impl EthExecutorSpec for EthSpec {
    fn deposit_contract_address(&self) -> Option<Address> {
        self.deposit_contract_address
    }

    fn staking_contract_address(&self) -> Option<Address> {
        None
    }

    fn is_staking_activate_at_timestamp(&self, timestamp: u64) -> bool {
        false
    }
}
