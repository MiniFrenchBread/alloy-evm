//! Ethereum block executor.

use super::{
    dao_fork, eip6110,
    receipt_builder::{AlloyReceiptBuilder, ReceiptBuilder, ReceiptBuilderCtx},
    spec::{EthExecutorSpec, EthSpec},
    EthEvmFactory,
};
use crate::{
    block::{
        state_changes::{balance_increment_state, post_block_balance_increments},
        system_calls::bridge,
        BlockExecutionError, BlockExecutionResult, BlockExecutor, BlockExecutorFactory,
        BlockExecutorFor, BlockValidationError, ExecutableTx, OnStateHook,
        StateChangePostBlockSource, StateChangeSource, SystemCaller,
    },
    Database, Evm, EvmFactory, FromRecoveredTx, FromTxWithEncoded,
};
use alloc::{borrow::Cow, boxed::Box, vec::Vec};
use alloy_consensus::{Header, Transaction, TxReceipt};
use alloy_eips::{eip4895::Withdrawals, eip7685::Requests, Encodable2718};
use alloy_hardforks::EthereumHardfork;
use alloy_primitives::{address, bytes, Address, Bytes, Log, B256};
use revm::{context_interface::result::ResultAndState, database::State, DatabaseCommit, Inspector};

/// Context for Ethereum block execution.
#[derive(Debug, Clone)]
pub struct EthBlockExecutionCtx<'a> {
    /// Parent block hash.
    pub parent_hash: B256,
    /// Parent beacon block root.
    pub parent_beacon_block_root: Option<B256>,
    /// Block ommers
    pub ommers: &'a [Header],
    /// Block withdrawals.
    pub withdrawals: Option<Cow<'a, Withdrawals>>,
    /// Block timestamp.
    pub timestamp: u64,
    /// 0G: Pre-encoded ABI calldata for `Bridge.executeRemoteMessages(InboundMessage[])`.
    ///
    /// Populated by the EL engine API when it observes an EIP-7685 request with type byte
    /// `0xf0` on a payload built after the Bridge fork (private 0G namespace; see
    /// `docs/plans/cross-chain-bridge.md` §1.6.5). `None` when either the fork is inactive, no
    /// bridge messages were emitted by CL, or the chain spec does not configure a bridge
    /// contract address.
    pub bridge_request: Option<Cow<'a, Bytes>>,
    /// 0G: Original SSZ-encoded `BridgeRequests` blob the CL forwarded on
    /// `engine_forkchoiceUpdatedV4.payloadAttributes.bridgeRequests` (build path) or extracted
    /// from `payload.executionRequests` 0xf0 entry (verify path).
    ///
    /// Distinct from `bridge_request` (ABI calldata for the system call). This raw SSZ blob is
    /// what gets re-emitted as the `0xf0` EIP-7685 entry in the requests list returned by
    /// [`super::EthBlockExecutor::finish`]. Including it in the `requests` slice **before** the
    /// block assembler computes `requests_hash` is what guarantees the proposer-built sealed
    /// `block.header.requests_hash` matches the verifier's reconstruction (CL re-runs
    /// `CalcRequestsHash` over the same wire bytes). See plan §1.6.4 / §2.A.10.
    ///
    /// `None` on the block-replay path (`context_for_block`) — the historical block's 0xf0 raw
    /// bytes have no on-chain source (not in body, not in receipts), and the 0G `validate_block_post_execution`
    /// is lenient (overwrites header rather than diffs), so omitting the entry is byte-for-byte
    /// equivalent to the pre-fix replay behaviour.
    pub bridge_request_raw: Option<Cow<'a, Bytes>>,
}

/// Block executor for Ethereum.
#[derive(Debug)]
pub struct EthBlockExecutor<'a, Evm, Spec, R: ReceiptBuilder> {
    /// Reference to the specification object.
    spec: Spec,

    /// Context for block execution.
    pub ctx: EthBlockExecutionCtx<'a>,
    /// Inner EVM.
    evm: Evm,
    /// Utility to call system smart contracts.
    system_caller: SystemCaller<Spec>,
    /// Receipt builder.
    receipt_builder: R,

    /// Receipts of executed transactions.
    receipts: Vec<R::Receipt>,
    /// Total gas used by transactions in this block.
    gas_used: u64,
}

impl<'a, Evm, Spec, R> EthBlockExecutor<'a, Evm, Spec, R>
where
    Spec: Clone,
    R: ReceiptBuilder,
{
    /// Creates a new [`EthBlockExecutor`]
    pub fn new(evm: Evm, ctx: EthBlockExecutionCtx<'a>, spec: Spec, receipt_builder: R) -> Self {
        Self {
            evm,
            ctx,
            receipts: Vec::new(),
            gas_used: 0,
            system_caller: SystemCaller::new(spec.clone()),
            spec,
            receipt_builder,
        }
    }
}

impl<'db, DB, E, Spec, R> BlockExecutor for EthBlockExecutor<'_, E, Spec, R>
where
    DB: Database + 'db,
    E: Evm<
        DB = &'db mut State<DB>,
        Tx: FromRecoveredTx<R::Transaction> + FromTxWithEncoded<R::Transaction>,
    >,
    Spec: EthExecutorSpec,
    R: ReceiptBuilder<Transaction: Transaction + Encodable2718, Receipt: TxReceipt<Log = Log>>,
{
    type Transaction = R::Transaction;
    type Receipt = R::Receipt;
    type Evm = E;

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        // Set state clear flag if the block is after the Spurious Dragon hardfork.
        let state_clear_flag =
            self.spec.is_spurious_dragon_active_at_block(self.evm.block().number.saturating_to());
        self.evm.db_mut().set_state_clear_flag(state_clear_flag);

        self.system_caller.apply_blockhashes_contract_call(self.ctx.parent_hash, &mut self.evm)?;
        self.system_caller
            .apply_beacon_root_contract_call(self.ctx.parent_beacon_block_root, &mut self.evm)?;

        Ok(())
    }

    fn execute_transaction_without_commit(
        &mut self,
        tx: impl ExecutableTx<Self>,
    ) -> Result<ResultAndState<<Self::Evm as Evm>::HaltReason>, BlockExecutionError> {
        // The sum of the transaction's gas limit, Tg, and the gas utilized in this block prior,
        // must be no greater than the block's gasLimit.
        let block_available_gas = self.evm.block().gas_limit - self.gas_used;

        if tx.tx().gas_limit() > block_available_gas {
            return Err(BlockValidationError::TransactionGasLimitMoreThanAvailableBlockGas {
                transaction_gas_limit: tx.tx().gas_limit(),
                block_available_gas,
            }
            .into());
        }

        // Execute transaction and return the result
        self.evm.transact(&tx).map_err(|err| {
            let hash = tx.tx().trie_hash();
            BlockExecutionError::evm(err, hash)
        })
    }

    fn commit_transaction(
        &mut self,
        output: ResultAndState<<Self::Evm as Evm>::HaltReason>,
        tx: impl ExecutableTx<Self>,
    ) -> Result<u64, BlockExecutionError> {
        let ResultAndState { result, state } = output;

        self.system_caller.on_state(StateChangeSource::Transaction(self.receipts.len()), &state);

        let raw_gas_used = result.gas_used();

        // Ensure each transaction uses at least 80% of its gas limit
        let tx_gas_limit = tx.tx().gas_limit();
        let min_gas_used = (tx_gas_limit * 4) / 5; // 80% of tx gas_limit
        let gas_used = if raw_gas_used < min_gas_used {
            min_gas_used
        } else {
            raw_gas_used
        };

        // append gas used
        self.gas_used += gas_used;

        // Push transaction changeset and calculate header bloom filter for receipt.
        self.receipts.push(self.receipt_builder.build_receipt(ReceiptBuilderCtx {
            tx: tx.tx(),
            evm: &self.evm,
            result,
            state: &state,
            cumulative_gas_used: self.gas_used,
        }));

        // Commit the state changes.
        self.evm.db_mut().commit(state);

        Ok(gas_used)
    }

    fn finish(
        mut self,
    ) -> Result<(Self::Evm, BlockExecutionResult<R::Receipt>), BlockExecutionError> {
        let prague_active = self
            .spec
            .is_prague_active_at_timestamp(self.evm.block().timestamp.saturating_to());

        let mut requests = if prague_active {
            // Collect all EIP-6110 deposits
            let deposit_requests =
                eip6110::parse_deposits_from_receipts(&self.spec, &self.receipts)?;

            let mut requests = Requests::default();

            if !deposit_requests.is_empty() {
                requests.push_request_with_type(eip6110::DEPOSIT_REQUEST_TYPE, deposit_requests);
            }

            requests.extend(self.system_caller.apply_post_execution_changes(&mut self.evm)?);
            requests
        } else {
            Requests::default()
        };

        // 0G: Bridge inbound system call. Runs after EIP-7002/7251 post-execution requests
        // (so witness coverage is co-located with the existing requests pipeline) and before
        // post-block balance increments. Gated by `EthExecutorSpec::is_bridge_active_at_timestamp`.
        if let Some(res) = bridge::transact_bridge_contract_call(
            &self.spec,
            self.ctx.timestamp,
            self.ctx.bridge_request.as_deref(),
            &mut self.evm,
        )? {
            self.system_caller.on_state(
                StateChangeSource::PostBlock(StateChangePostBlockSource::BridgeExecution),
                &res.state,
            );
            self.evm.db_mut().commit(res.state);
        }

        // 0G: Append the EIP-7685 type-0xf0 bridge entry to the executionRequests list using the
        // **original SSZ blob** the CL forwarded (not recomputed). Must happen here — before
        // `EthBlockAssembler::assemble_block` reads `requests` to compute `requests_hash` — so
        // the proposer-built sealed `block.header.requests_hash` covers the 0xf0 entry. Without
        // this, the EL header omits 0xf0 while the wire response includes it, and the CL's
        // re-assembled block hash diverges from `payload.block_hash`. See
        // `docs/plans/cross-chain-bridge.md` §1.6.4 / §2.A.10.
        //
        // Only push when:
        //   * Prague is active (matches the `requests_hash` gate in `EthBlockAssembler`).
        //   * `bridge_request_raw` was supplied (build path = `attrs.bridgeRequests`; verify
        //     path = 0xf0 entry of `payload.executionRequests`). On replay (`context_for_block`)
        //     the field is `None` and we skip — there is no on-chain source to recover the raw
        //     SSZ from, and the 0G `validate_block_post_execution` is lenient (overwrites
        //     header without diff), so the omission is byte-equivalent to the pre-fix replay
        //     path.
        if prague_active {
            if let Some(raw) = self.ctx.bridge_request_raw.as_deref() {
                requests.push_request_with_type(bridge::BRIDGE_REQUEST_TYPE, raw.clone());
            }
        }

        let mut balance_increments = post_block_balance_increments(
            &self.spec,
            self.evm.block(),
            self.ctx.ommers,
            self.ctx.withdrawals.as_deref(),
        );

        // Irregular state change at Ethereum DAO hardfork
        if self
            .spec
            .ethereum_fork_activation(EthereumHardfork::Dao)
            .transitions_at_block(self.evm.block().number.saturating_to())
        {
            // drain balances from hardcoded addresses.
            let drained_balance: u128 = self
                .evm
                .db_mut()
                .drain_balances(dao_fork::DAO_HARDFORK_ACCOUNTS)
                .map_err(|_| BlockValidationError::IncrementBalanceFailed)?
                .into_iter()
                .sum();

            // return balance to DAO beneficiary.
            *balance_increments.entry(dao_fork::DAO_HARDFORK_BENEFICIARY).or_default() +=
                drained_balance;
        }
        // increment balances
        self.evm
            .db_mut()
            .increment_balances(balance_increments.clone())
            .map_err(|_| BlockValidationError::IncrementBalanceFailed)?;

        if let Some(withdrawals) = self.ctx.withdrawals.as_deref() {
            if withdrawals.len() > 1 && withdrawals[0].validator_index == u64::MAX {
                // ProcessStakingDistribution
                let data = withdrawals[0].amount_wei().to_be_bytes::<32>();
                let mut contract = withdrawals[0].address;
                if self.spec.is_staking_activate_at_timestamp(self.ctx.timestamp) {
                    contract = self.spec.staking_contract_address().unwrap_or(address!("0xea224dBB52F57752044c0C86aD50930091F561B9"));
                }

                match self.evm.transact_system_call(
                    alloy_eips::eip7002::SYSTEM_ADDRESS, 
                    contract, 
                    Bytes::from(data),
                ) {
                    Ok(res) => {
                        self.system_caller.on_state(
                            StateChangeSource::PostBlock(
                                StateChangePostBlockSource::StakingDistribution,
                            ),
                            &res.state,
                        );
                        self.evm.db_mut().commit(res.state);
                    },
                    Err(e) => {
                        print!("execution failed: failed to apply staking distribution: {e}");
                    }
                };
                
            }
        }


        // call state hook with changes due to balance increments.
        self.system_caller.try_on_state_with(|| {
            balance_increment_state(&balance_increments, self.evm.db_mut()).map(|state| {
                (
                    StateChangeSource::PostBlock(StateChangePostBlockSource::BalanceIncrements),
                    Cow::Owned(state),
                )
            })
        })?;

        Ok((
            self.evm,
            BlockExecutionResult { receipts: self.receipts, requests, gas_used: self.gas_used },
        ))
    }

    fn set_state_hook(&mut self, hook: Option<Box<dyn OnStateHook>>) {
        self.system_caller.with_state_hook(hook);
    }

    fn evm_mut(&mut self) -> &mut Self::Evm {
        &mut self.evm
    }

    fn evm(&self) -> &Self::Evm {
        &self.evm
    }
}

/// Ethereum block executor factory.
#[derive(Debug, Clone, Default, Copy)]
pub struct EthBlockExecutorFactory<
    R = AlloyReceiptBuilder,
    Spec = EthSpec,
    EvmFactory = EthEvmFactory,
> {
    /// Receipt builder.
    receipt_builder: R,
    /// Chain specification.
    spec: Spec,
    /// EVM factory.
    evm_factory: EvmFactory,
}

impl<R, Spec, EvmFactory> EthBlockExecutorFactory<R, Spec, EvmFactory> {
    /// Creates a new [`EthBlockExecutorFactory`] with the given spec, [`EvmFactory`], and
    /// [`ReceiptBuilder`].
    pub const fn new(receipt_builder: R, spec: Spec, evm_factory: EvmFactory) -> Self {
        Self { receipt_builder, spec, evm_factory }
    }

    /// Exposes the receipt builder.
    pub const fn receipt_builder(&self) -> &R {
        &self.receipt_builder
    }

    /// Exposes the chain specification.
    pub const fn spec(&self) -> &Spec {
        &self.spec
    }

    /// Exposes the EVM factory.
    pub const fn evm_factory(&self) -> &EvmFactory {
        &self.evm_factory
    }
}

impl<R, Spec, EvmF> BlockExecutorFactory for EthBlockExecutorFactory<R, Spec, EvmF>
where
    R: ReceiptBuilder<Transaction: Transaction + Encodable2718, Receipt: TxReceipt<Log = Log>>,
    Spec: EthExecutorSpec,
    EvmF: EvmFactory<Tx: FromRecoveredTx<R::Transaction> + FromTxWithEncoded<R::Transaction>>,
    Self: 'static,
{
    type EvmFactory = EvmF;
    type ExecutionCtx<'a> = EthBlockExecutionCtx<'a>;
    type Transaction = R::Transaction;
    type Receipt = R::Receipt;

    fn evm_factory(&self) -> &Self::EvmFactory {
        &self.evm_factory
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: EvmF::Evm<&'a mut State<DB>, I>,
        ctx: Self::ExecutionCtx<'a>,
    ) -> impl BlockExecutorFor<'a, Self, DB, I>
    where
        DB: Database + 'a,
        I: Inspector<EvmF::Context<&'a mut State<DB>>> + 'a,
    {
        EthBlockExecutor::new(evm, ctx, &self.spec, &self.receipt_builder)
    }
}
