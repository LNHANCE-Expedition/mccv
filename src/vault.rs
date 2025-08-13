use bdk_wallet::coin_selection::InsufficientFunds;
use bdk_wallet::error::CreateTxError;
use bdk_wallet::miniscript::descriptor::{Wildcard, DescriptorXKey, DerivPaths};
use bdk_wallet::miniscript::{DefiniteDescriptorKey, Descriptor, MiniscriptKey, DescriptorPublicKey};
use bdk_wallet::miniscript::plan::{AssetProvider, Plan, Assets, TaprootCanSign, TaprootAvailableLeaves, CanSign};
use bdk_wallet::{Wallet, KeychainKind};
use bitcoin::psbt::ExtractTxError;
use bitcoin::taproot::{ControlBlock, TaprootMerkleBranch, TaprootSpendInfo};
use bitcoin::{BlockHash, FeeRate, psbt, Weight, TapTweakHash};
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::{
    Hash,
    sha256,
};

use bitcoin::blockdata::constants::genesis_block;

use bitcoin::consensus::Encodable;

#[cfg(feature = "bitcoind")]
use bitcoin::Block;


use bitcoin::opcodes::all::{
    OP_CSV,
    OP_CHECKSIG,
    OP_NOP4 as OP_CHECKTEMPLATEVERIFY,
    OP_DROP,
};

use bitcoin::bip32::{
    Xpub,
    Xpriv,
    ChildNumber,
    DerivationPath,
    IntoDerivationPath,
    KeySource,
};

use bitcoin::secp256k1::{
    Secp256k1,
    Signing,
    Verification,
    XOnlyPublicKey, PublicKey, Scalar,
};

use bitcoin::{
    Amount,
    script::Builder,
    absolute::LockTime,
    opcodes::OP_TRUE,
    OutPoint,
    relative::LockTime as RelativeLockTime,
    ScriptBuf,
    Script,
    TapNodeHash,
    Transaction,
    Txid,
    transaction::TxIn,
    transaction::TxOut,
    blockdata::locktime::absolute,
    blockdata::locktime::relative,
    blockdata::transaction::Version,
    taproot::{
        LeafVersion,
        TaprootBuilder,
    },
    Witness,
    Psbt,
};
use rayon::prelude::ParallelBridge;
use rusqlite::Row;

use rand::{
    RngCore,
    thread_rng,
};

use rayon::iter::{
    IntoParallelIterator,
    ParallelIterator,
};

use rusqlite::{
    Connection,
    params,
    types::{
        ToSql,
        FromSql,
    },
};

use serde::{
    Deserialize,
    Serialize,
};

use std::iter;

use std::collections::{HashMap, HashSet};
use std::ops::{Deref, DerefMut};

use crate::migrate::{
    configure,
    migrate,
    MigrationError,
};

use crate::bip119::get_default_template;

// struct.unpack(">I", hashlib.sha256(b'mccv').digest()[:4])[0] & 0x7FFFFFFF
const PURPOSE: u32 = 360843587;

pub type Depth = u32;

fn builder_with_capacity(size: usize) -> Builder {
    Builder::from(Vec::with_capacity(size))
}

#[derive(Clone,Copy,Serialize,Deserialize)]
#[serde(transparent)]
pub struct VaultScale(u32);

impl VaultScale {
    pub fn new(scale: u32) -> Self { Self(scale) }

    pub fn from_sat(scale: u32) -> Self { Self(scale) }

    pub fn convert_amount(&self, amount: Amount) -> (VaultAmount, Amount) {
        let quotient  = amount.to_sat() / (self.0 as u64);
        let remainder = amount.to_sat() % (self.0 as u64);

        // FIXME: provide stronger guarantees or make fallible
        debug_assert!((quotient & u64::from(u32::MAX)) == quotient);
        (VaultAmount(quotient as u32), Amount::from_sat(remainder))
    }

    pub fn scale_amount(&self, amount: VaultAmount) -> Amount {
        amount.to_amount(self.0)
    }
}

#[derive(Clone,Serialize,Deserialize)]
pub struct VaultParameters {
    scale: VaultScale,
    /// Maximum value = max * scale
    max: VaultAmount,
    // All coins are always immediately spendable by master_xpub
    cold_xpub: Xpub,
    // Withdrawn coins are spendable by withdrawal_xpub at any time
    hot_xpub: Xpub,
    // Should there be yet another xpub for un-managed funds? probably but not in the vault params
    delay_per_increment: u32,
    max_withdrawal_per_step: VaultAmount,
    max_deposit_per_step: VaultAmount,
    max_depth: Depth,
}

#[derive(Clone,Copy,Debug,Hash,Eq,PartialEq,Serialize,Deserialize)]
#[serde(transparent)]
/// Represents a Bitcoin amount as an integer number of
/// fixed size chunks. The actual number of satoshis represented
/// by a VaultAmount is calculated by multiplying by a scale
pub struct VaultAmount(u32);

impl VaultAmount {
    const ZERO: VaultAmount = VaultAmount(0);

    pub fn new(unscaled_amount: u32) -> Self {
        Self(unscaled_amount)
    }

    pub fn to_sats(&self, scale: u32) -> u64 {
        u64::saturating_mul(self.0 as u64, scale as u64)
    }

    pub fn to_amount(&self, scale: u32) -> Amount {
        Amount::from_sat(self.to_sats(scale))
    }

    pub fn checked_sub(&self, other: VaultAmount) -> Option<VaultAmount> {
        self.0.checked_sub(other.0).map(VaultAmount::new)
    }

    fn to_unscaled_amount(&self) -> u32 {
        self.0
    }

    fn nonzero(&self) -> bool {
        self.0 > 0
    }

    fn iter_from(&self, start: VaultAmount) -> impl Iterator<Item=VaultAmount> {
        (start.0..=self.0)
            .map(|amount| VaultAmount(amount))
    }

    pub fn apply_transition(&self, transition: VaultTransition, max: Option<VaultAmount>) -> Option<VaultAmount> {
        match transition {
            VaultTransition::Deposit(deposit_amount) => {
                let result = *self + deposit_amount;
                if let Some(max) = max {
                    if result > max {
                        None
                    } else {
                        Some(result)
                    }
                } else {
                    Some(result)
                }
            }
            VaultTransition::Withdrawal(withdrawal_amount) => {
                if withdrawal_amount > *self {
                    None
                } else {
                    Some(*self - withdrawal_amount)
                }
            }
        }
    }
}

impl PartialEq<u32> for VaultAmount {
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other
    }
}

impl std::cmp::PartialOrd for VaultAmount {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl std::cmp::Ord for VaultAmount {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl std::ops::Add for VaultAmount {
    type Output = VaultAmount;

    fn add(self, rhs: VaultAmount) -> Self::Output {
        VaultAmount(
            u32::saturating_add(self.0, rhs.0)
        )
    }
}

impl std::ops::Sub for VaultAmount {
    type Output = VaultAmount;

    fn sub(self, rhs: VaultAmount) -> Self::Output {
        VaultAmount(
            u32::saturating_sub(self.0, rhs.0)
        )
    }
}

const PAY_TO_ANCHOR_SCRIPT_BYTES: &[u8] = &[0x51, 0x02, 0x4e, 0x73];

fn ephemeral_anchor() -> TxOut {
    let script_pubkey = ScriptBuf::from_bytes(PAY_TO_ANCHOR_SCRIPT_BYTES.to_vec());

    TxOut {
        value: Amount::from_sat(0),
        script_pubkey,
    }
}

fn dummy_input(lock_time: RelativeLockTime) -> TxIn {
    TxIn {
        previous_output: OutPoint {
            txid: Txid::from_byte_array([0u8; 32]),
            vout: 0,
        },
        script_sig: ScriptBuf::new(),
        sequence: lock_time.to_sequence(),
        witness: Witness::new(),
    }
}

#[derive(Clone,Copy,Debug,Eq,Hash,PartialEq)]
pub enum VaultTransition {
    Deposit(VaultAmount),
    Withdrawal(VaultAmount),
}

impl VaultTransition {
    fn invert(&self) -> VaultTransition {
        match self {
            VaultTransition::Deposit(amount) => VaultTransition::Withdrawal(*amount),
            VaultTransition::Withdrawal(amount) => VaultTransition::Deposit(*amount),
        }
    }

    fn to_signed(&self) -> i64 {
        match self {
            VaultTransition::Deposit(value) => i64::from(value.0),
            VaultTransition::Withdrawal(value) => -i64::from(value.0),
        }
    }
}

impl PartialOrd for VaultTransition {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.to_signed().partial_cmp(&other.to_signed())
    }
}

impl Ord for VaultTransition {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_signed().cmp(&other.to_signed())
    }
}

#[derive(Clone,Debug,Eq,Hash,PartialEq)]
pub struct VaultStateParameters {
    //depth: Depth, // Always implicit in the way we process
    transition: VaultTransition,
    previous_value: VaultAmount,
    parent_transition: Option<VaultTransition>,
}

impl VaultStateParameters {
    // XXX: Assumes we never construct an invalid parameter set! Must enforce this!
    fn get_result_value(&self) -> VaultAmount {
        match self.transition {
            VaultTransition::Deposit(deposit_amount) => self.previous_value + deposit_amount,
            VaultTransition::Withdrawal(withdrawal_amount) => self.previous_value - withdrawal_amount,
        }
    }

    fn get_result(&self) -> Option<(VaultAmount, VaultAmount)> {
        match self.transition {
            VaultTransition::Deposit(value) => Some((self.previous_value + value, VaultAmount(0))),
            VaultTransition::Withdrawal(withdrawal_value) => if self.previous_value >= withdrawal_value {
                Some((self.previous_value - withdrawal_value, withdrawal_value))
            } else {
                None
            }
        }
    }

    fn result_state_value(&self) -> Option<VaultAmount> {
        self.get_result().map(|result| result.0)
    }

    fn withdrawal_value(&self) -> VaultAmount {
        match self.transition {
            VaultTransition::Deposit(_) => VaultAmount(0),
            VaultTransition::Withdrawal(ref value) => *value,
        }
    }

    fn next(&self, transition: VaultTransition, max: VaultAmount) -> Option<Self> {
        self.result_state_value()
            .and_then(|current_value| {
                match transition {
                    VaultTransition::Deposit(deposit_value) => {
                        if current_value + deposit_value <= max {
                            Some(
                                Self {
                                    transition,
                                    previous_value: current_value,
                                    parent_transition: Some(self.transition),
                                }
                            )
                        } else {
                            None
                        }
                    }
                    VaultTransition::Withdrawal(withdrawal_value) => {
                        if current_value >= withdrawal_value {
                            Some(
                                Self {
                                    transition,
                                    previous_value: current_value,
                                    parent_transition: Some(self.transition),
                                }
                            )
                        } else {
                            None
                        }
                    }
                }
            })
    }

    fn assert_valid(&self) {
        match self.transition {
            _ => {},
            VaultTransition::Withdrawal(amount) => {
                assert!(self.previous_value.nonzero());
                assert!(amount <= self.previous_value);
            }
        }
    }
}

impl Ord for VaultStateParameters {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (
            self.parent_transition,
            self.previous_value,
            self.transition,
        ).cmp(&(
            other.parent_transition,
            other.previous_value,
            other.transition,
        ))
    }
}

impl PartialOrd for VaultStateParameters {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

pub type VaultGeneration = HashMap<VaultStateParameters, Transaction>;

pub struct VaultGenerationIterator<'p, 's, C: Verification> {
    parameters: &'p VaultParameters,
    generation: Option<VaultGeneration>,
    secp: &'s Secp256k1<C>,
    depth: Depth,
    done: bool,
}

impl<'a, 's, C: Verification> VaultGenerationIterator<'a, 's, C> {
    // Can't be a std::iter::Iterator unless we copy the vault generation out, blech
    pub fn next(&mut self) -> Option<&VaultGeneration> {
        if self.done {
            return None;
        }

        let next_generation = self.parameters.tx_templates(&self.secp, self.depth, self.generation.as_ref());

        if self.depth > 0 {
            self.depth -= 1;
        } else {
            self.done = true;
        }

        self.generation = Some(next_generation);
        self.generation.as_ref()
    }

    pub fn next_with_depth(&mut self) -> Option<(Depth, &VaultGeneration)> {
        let current_depth = self.depth;

        self.next().map(|generation| (current_depth, generation))
    }
}

// FIXME: ignores network...
pub enum VaultKeyDerivationPathTemplate {
    ColdKey(u32),
    HotKey(u32),
}

impl VaultKeyDerivationPathTemplate {
    pub fn new_hot(account: u32) -> Result<Self, ()> {
        if account < ACCOUNT_MAX {
            Err(())
        } else {
            Ok(Self::HotKey(account))
        }
    }

    pub fn new_cold(account: u32) -> Result<Self, ()> {
        if account < ACCOUNT_MAX {
            Err(())
        } else {
            Ok(Self::ColdKey(account))
        }
    }

    pub fn to_derivation_path(&self) -> DerivationPath {
        let (account, path_type) = match self {
            VaultKeyDerivationPathTemplate::ColdKey(account) => (*account, 0),
            VaultKeyDerivationPathTemplate::HotKey(account) => (*account, 1),
        };

        vec![
            ChildNumber::from_hardened_idx(PURPOSE)
                .expect("hard coded to be a valid hardened index"),
            ChildNumber::from_hardened_idx(account)
                .expect("account number already validated as a valid hardened index"),
            ChildNumber::from_hardened_idx(path_type)
                .expect("hard coded to be a valid hardened index"),
        ]
        .into()
    }
}

impl VaultParameters {
    pub fn new(
            scale: VaultScale,
            max: VaultAmount,
            cold_xpub: Xpub, hot_xpub: Xpub,
            delay_per_increment: u32,
            max_withdrawal_per_step: VaultAmount, max_deposit_per_step: VaultAmount,
            max_depth: Depth,
        ) -> Self {
        Self {
            scale,
            max,
            cold_xpub,
            hot_xpub,
            delay_per_increment,
            max_withdrawal_per_step,
            max_deposit_per_step,
            max_depth,
        }
    }

    // Hot key can trigger recovery. This is fine because if the hot key is compromised your (hot) funds
    // are already at risk, being griefed by your funds being sent to the cold key is the
    // best case scenario.
    fn recovery_key<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth) -> XOnlyPublicKey {
        let path = [
            ChildNumber::from_normal_idx(depth as u32).expect("sane child number")
        ];

        let xpub = self.hot_xpub.derive_pub(secp, &path)
            .expect("recovery key derivation");

        xpub.to_x_only_pub()
    }

    fn master_key_full<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth) -> PublicKey {
        let path = [
            ChildNumber::from_normal_idx(depth as u32).expect("sane child number")
        ];

        let xpub = self.cold_xpub.derive_pub(secp, &path)
            .expect("non-hardened derivation of a reasonable depth shouldn't fail");

        xpub.to_pub().0
    }

    fn master_key<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth) -> XOnlyPublicKey {
        self.master_key_full(secp, depth).x_only_public_key().0
    }

    // Similar to the recovery case, if the hot key is compromised, it's actually best if they
    // initiate a withdrawal so we can recognize the hot key is compromised and initiate a
    // recovery.
    fn withdrawal_key<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth) -> XOnlyPublicKey {
        let path = [
            ChildNumber::from_normal_idx(depth as u32).expect("sane child number")
        ];

        let xpub = self.hot_xpub.derive_pub(secp, &path)
            .expect("non-hardened derivation of a reasonable depth shouldn't fail");

        xpub.to_x_only_pub()
    }

    /// Script for spending an unvault output
    fn withdrawal_script<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, timelock: u32) -> ScriptBuf {
        // TODO: decide if we want to omit the CSV when timelock is 0
        // Conservative estimating the push_int size
        builder_with_capacity(5 + 1 + 33 + 1)
            .push_int(timelock as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_x_only_key(&self.withdrawal_key(secp, depth))
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }

    fn withdrawal_timelock(&self, value: VaultAmount) -> u32 {
        u32::saturating_mul(value.to_unscaled_amount(), self.delay_per_increment)
    }

    /// Script for spending recovering an unvault output to the cold key
    fn recovery_script<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, recovery_tx: &Transaction, input_index: u32) -> ScriptBuf {
        let recovery_template = get_default_template(recovery_tx, input_index);

        builder_with_capacity(33 + 1 + 1 + 33 + 1)
            .push_slice(recovery_template.to_byte_array())
            .push_opcode(OP_CHECKTEMPLATEVERIFY)
            .push_opcode(OP_DROP)
            .push_x_only_key(&self.recovery_key(secp, depth))
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }

    fn withdrawal_output<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, parameter: &VaultStateParameters) -> Option<TxOut> {
        let value = parameter.result_state_value().unwrap_or(VaultAmount(0));
        let withdrawal_amount = parameter.withdrawal_value();

        if !withdrawal_amount.nonzero() {
            return None;
        }

        let master_key = self.master_key(secp, depth);

        let timelock = self.withdrawal_timelock(withdrawal_amount);
        let withdrawal_script = self.withdrawal_script(secp, depth, timelock);

        let withdrawal = TapNodeHash::from_script(&withdrawal_script, LeafVersion::TapScript);

        // Vault output is the first input to the recovery tx, *if* it exists, so the withdrawal
        // output is either the first or second, depending on the presence of the vault output.
        let input_index = if value.nonzero() { 1 } else { 0 };

        let recovery_tx = self.recovery_template(secp, depth + 1, value, withdrawal_amount);
        let recovery_script = self.recovery_script(secp, depth, &recovery_tx, input_index);
        let double_recovery_leaf = TapNodeHash::from_script(recovery_script.as_script(), LeafVersion::TapScript);

        let recovery_node = if value.nonzero() {
            debug_assert!(withdrawal_amount.nonzero());

            let single_recovery_template = self.recovery_template(secp, depth + 1, VaultAmount::ZERO, withdrawal_amount);
            debug_assert!(single_recovery_template != recovery_tx);
            let recovery_script = self.recovery_script(secp, depth, &single_recovery_template, 0);
            let single_recovery_leaf = TapNodeHash::from_script(recovery_script.as_script(), LeafVersion::TapScript);
            
            TapNodeHash::from_node_hashes(single_recovery_leaf, double_recovery_leaf)
        } else {
            // If there's no vault output, then "double_recovery_leaf" is actually just a single
            // recovery leaf, redundant with the other one we might compute in the other branch
            double_recovery_leaf
        };

        let root_node_hash = TapNodeHash::from_node_hashes(recovery_node, withdrawal);

        let script_pubkey = ScriptBuf::new_p2tr(secp, master_key, Some(root_node_hash));

        Some(
            TxOut {
                value: self.scale.scale_amount(value),
                script_pubkey,
            }
        )
    }

    // Spend either a withdrawn balance, the vault balance, or both, to the cold key
    fn recovery_template<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, vault_amount: VaultAmount, withdrawal_amount: VaultAmount) -> Transaction {
        assert!(vault_amount.nonzero() || withdrawal_amount.nonzero());

        let mut input: Vec<TxIn> = Vec::new();
        if vault_amount.nonzero() {
            input.push(dummy_input(relative::LockTime::ZERO));
        }

        if withdrawal_amount.nonzero() {
            input.push(dummy_input(relative::LockTime::ZERO));
        }

        let key = self.recovery_key(secp, depth);

        let script_pubkey = ScriptBuf::new_p2tr(secp, key, None);

        let value = vault_amount + withdrawal_amount;

        let recovery_output = TxOut {
            value: self.scale.scale_amount(value),
            script_pubkey,
        };

        Transaction {
            version: Version::non_standard(3),
            lock_time: LockTime::ZERO,
            input,
            output: vec![recovery_output, ephemeral_anchor()],
        }
    }

    fn vault_output_spend_conditions<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, parameter: &VaultStateParameters, next_states: &HashMap<VaultStateParameters, Transaction>) -> Vec<(VaultOutputSpendCondition, SignedNextStateTemplate)> {
        let mut counter = 0;
        if let Some((value, withdrawal_amount)) = parameter.get_result() {
            let mut transitions: Vec<_> =
            self.state_transitions_single(value, depth + 1)
                .filter_map(|params| {
                    if params.parent_transition != Some(parameter.transition) {
                        return None;
                    }

                    if let Some(next_state) = next_states.get(&params) {
                        // Vault UTXO will always be input 0
                        let next_state_template_hash = get_default_template(&next_state, 0);

                        let transition_script_template = SignedNextStateTemplate {
                            pubkey: self.withdrawal_key(secp, depth),
                            next_state_template_hash,
                        };

                        Some(
                            (
                                match params.transition {
                                    VaultTransition::Withdrawal(amount) =>
                                        VaultOutputSpendCondition::Withdrawal(amount),
                                    VaultTransition::Deposit(amount) =>
                                        VaultOutputSpendCondition::Deposit(amount),
                                },
                                transition_script_template,
                            )
                        )
                    } else {
                        eprintln!("Depth {depth} (Value: {value:?}): No next state for {:?} at depth", params);
                        counter += 1;
                        None
                    }
                })
                .collect();

                if counter > 0 {
                    //eprintln!("counter = {counter}");
                }


            // FIXME: we really need to get consistent about depth + 1 vs depth
            // I think the rule should be, that the transaction spending a txout with depth n is
            // n+1, the txout on transaction at depth n is also n (this seems like a no-brainer but
            // I think I was being inconsistent with things like the recovery tx which is kind of
            // it's own thing, does it belong to this depth?)
            let recovery_tx = self.recovery_template(secp, depth + 1, value, withdrawal_amount);
            // This (the vault) output will always be the first input to the recovery tx
            let recovery_key = self.recovery_key(secp, depth);

            transitions.push(
                (
                    VaultOutputSpendCondition::Recovery {
                        vault_balance: value,
                        withdrawal_amount,
                    },
                    SignedNextStateTemplate {
                        pubkey: recovery_key,
                        next_state_template_hash: get_default_template(&recovery_tx, 0),
                    },
                )
            );

            // Spending path for vault-output-only recovery
            // Only create if there is actually value left in the vault after the withdrawal, and
            // if this is a withdrawal (otherwise this template is redundant)
            if value.nonzero() && withdrawal_amount.nonzero() {
                let recovery_tx = self.recovery_template(secp, depth + 1, value, VaultAmount::ZERO);

                transitions.push(
                    (
                        VaultOutputSpendCondition::Recovery {
                            vault_balance: value,
                            withdrawal_amount: VaultAmount::ZERO,
                        },
                        SignedNextStateTemplate {
                            pubkey: recovery_key,
                            next_state_template_hash: get_default_template(&recovery_tx, 0),
                        },
                    )
                );
            }

            // TODO: pull this code into its own function
            // TODO: add complete drain script, eh, maybe not, cold keys can always do that if it's really
            // desirable, that seems like a case where requiring cold keys makes sense

            transitions
        } else {
            Vec::new()
        }
    }

    // FIXME: should have a starting amount to calculate this
    fn spend_condition_weight(&self, condition: &VaultOutputSpendCondition) -> u32 {
        (match condition {
            VaultOutputSpendCondition::Deposit(amount) => amount.to_unscaled_amount(),
            VaultOutputSpendCondition::Withdrawal(amount) => amount.to_unscaled_amount(),
            VaultOutputSpendCondition::Recovery {..} => 0,
        }) + 1
    }

    fn spend_conditions_into_spend_info<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, conditions: &Vec<(VaultOutputSpendCondition, SignedNextStateTemplate)>) -> VaultOutputSpendInfo {
        let master_key = self.master_key(secp, depth);

        let spend_info = TaprootBuilder::with_huffman_tree(
                conditions.iter().map(|(condition, script)| (self.spend_condition_weight(&condition), script.to_scriptbuf()))
            )
            .expect("taproot tree builder")
            .finalize(secp, master_key)
            .expect("taproot tree finalize");

        VaultOutputSpendInfo {
            spend_info,
            branches: conditions.into_iter().cloned().collect(),
        }
    }

    fn vault_output<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, parameter: &VaultStateParameters, next_states: Option<&HashMap<VaultStateParameters, Transaction>>) -> Option<TxOut> {
        if let Some(next_value) = parameter.result_state_value() {
            if let Some(next_states) = next_states {
                let spend_conditions = self.vault_output_spend_conditions(secp, depth, parameter, next_states);

                let master_key = self.master_key(secp, depth);
                let spend_info = TaprootBuilder::with_huffman_tree(
                        spend_conditions.iter().map(|(condition, script)| (self.spend_condition_weight(&condition), script.to_scriptbuf()))
                    )
                    .expect("taproot tree builder")
                    .finalize(secp, master_key)
                    .expect("taproot tree finalize");

                Some(
                    TxOut {
                        value: self.scale.scale_amount(next_value),
                        script_pubkey: ScriptBuf::new_p2tr_tweaked(spend_info.output_key()),
                    }
                )
            // Final state, only spendable by master
            } else {
                let master_key = self.master_key(secp, depth);

                // TODO: CSFS delegated recursion
                let script_pubkey = ScriptBuf::new_p2tr(secp, master_key, None);

                Some(
                    TxOut {
                        value: self.scale.scale_amount(next_value),
                        script_pubkey,
                    }
                )
            }
        } else {
            None
        }
    }

    fn tx_template<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, parameter: &VaultStateParameters, next_states: Option<&HashMap<VaultStateParameters, Transaction>>) -> Transaction {
        parameter.assert_valid();

        let optional_anchor_output = if let VaultTransition::Withdrawal(_) = parameter.transition {
            Some(ephemeral_anchor())
        } else {
            None
        };

        let output: Vec<TxOut> = iter::empty()
            .chain(
                self.vault_output(secp, depth, parameter, next_states)
            )
            .chain(self.withdrawal_output(secp, depth, parameter))
            .chain(optional_anchor_output)
            .collect();

        Transaction {
            version: Version::non_standard(3),
            lock_time: LockTime::ZERO,
            // Handles input count
            input: self.dummy_inputs(depth, parameter),
            output,
        }
    }

    fn lock_time_for_deposit(&self, amount: &VaultAmount) -> RelativeLockTime {
        RelativeLockTime::ZERO
    }

    fn lock_time_for_withdrawal(&self, amount: &VaultAmount) -> RelativeLockTime {
        let lock_time = u32::saturating_mul(amount.to_unscaled_amount(), self.delay_per_increment);
        let lock_time = u16::try_from(lock_time)
            .expect("lock time should always fit in 16 bits");

        RelativeLockTime::from_height(lock_time)
    }

    fn iter_withdrawal_amounts(&self, depth: Depth) -> impl Iterator<Item=VaultAmount> {
        if depth == 0 {
            1..=0 // XXX: dirty, but will be empty
        } else {
            1..=self.max_withdrawal_per_step.0
        }
        .into_iter()
        .map(|withdrawal_amount| VaultAmount(withdrawal_amount))
    }

    fn iter_deposit_amounts(&self, depth: Depth) -> impl Iterator<Item=VaultAmount> {
        let range = if depth == 0 {
            1..=self.max.0
        } else {
            1..=self.max_deposit_per_step.0
        };

        range
            .into_iter()
            .map(|deposit_amount| VaultAmount(deposit_amount))
    }

    /// Iter transitions depth >= 1
    fn iter_tail_transitions(&self) -> impl Iterator<Item=VaultTransition> {
        let withdrawals = (1..=self.max_withdrawal_per_step.0).rev()
            .map(|withdrawal| VaultTransition::Withdrawal(VaultAmount(withdrawal)));

        let deposits = (1..=self.max_deposit_per_step.0)
            .map(|deposit| VaultTransition::Deposit(VaultAmount(deposit)));

        withdrawals.chain(deposits)
    }

    fn iter_parent_transitions(&self, depth: Depth) -> impl Iterator<Item=Option<VaultTransition>> {
        if depth > 1 {
            let withdrawals = self.iter_withdrawal_amounts(depth)
                .map(|withdrawal| Some(VaultTransition::Withdrawal(withdrawal)));

            let deposits = self.iter_deposit_amounts(depth)
                .map(|deposit| Some(VaultTransition::Deposit(deposit)));

            Either::A(withdrawals.chain(deposits))
        } else {
            Either::B(
                if depth == 1 {
                    Either::A(
                        self.iter_deposit_amounts(depth)
                            .map(|deposit| Some(VaultTransition::Deposit(deposit)))
                    )
                } else {
                    Either::B(std::iter::once(None))
                }
            )
        }
    }

    #[inline]
    fn validate_parameters(&self, parameters: VaultStateParameters, depth: Depth) -> Option<VaultStateParameters> {
        if depth > 0 && parameters.previous_value == VaultAmount::ZERO {
            return None;
        }

        match parameters.parent_transition {
            Some(VaultTransition::Deposit(amount)) => {
                if depth == 0 {
                    return None;
                }

                if amount > parameters.previous_value {
                    return None;
                }
            }
            Some(VaultTransition::Withdrawal(amount)) => {
                if depth == 0 {
                    return None;
                }

                if (amount + parameters.previous_value) > self.max {
                    return None
                }
            }
            None => {
                if depth > 0 {
                    return None;
                }
            }
        }

        match parameters.transition {
            VaultTransition::Deposit(deposit_amount) => {
                if deposit_amount + parameters.previous_value <= self.max {
                    Some(parameters)
                } else {
                    None
                }
            }
            VaultTransition::Withdrawal(withdrawal_amount) => {
                if parameters.previous_value >= withdrawal_amount {
                    Some(parameters)
                } else {
                    None
                }
            }
        }
    }

    fn history_to_parameters(&self, tx: &VaultTransaction, parent_tx: Option<&VaultTransaction>, depth: Depth) -> Option<VaultStateParameters> {
        let previous_value = tx.result_value.apply_transition(
            tx.transition.invert(),
            Some(self.max),
        );

        if let Some(previous_value) = previous_value {
            self.validate_parameters(
                VaultStateParameters {
                    transition: tx.transition,
                    previous_value,
                    parent_transition: parent_tx.map(|tx| tx.transition),
                },
                depth,
            )
        } else {
            None
        }
    }

    fn state_transitions_single(&self, previous_value: VaultAmount, depth: Depth) -> impl Iterator<Item=VaultStateParameters> + '_ {
        self.iter_transitions(depth)
            .filter_map(move |transition| {
                self.validate_parameters(
                    VaultStateParameters {
                        transition,
                        previous_value,
                        parent_transition: None,
                    },
                    depth,
                )
            })
            .flat_map(move |parameters| {
                self.iter_parent_transitions(depth)
                    .filter_map(move |parent_transition|
                        if depth == 0 {
                            Some(parameters.clone())
                        } else {
                            self.validate_parameters(
                                VaultStateParameters {
                                    transition: parameters.transition,
                                    previous_value, // FIXME: is that right?..
                                    parent_transition: parent_transition,
                                },
                                depth
                            )
                        }
                    )
            })
    }

    fn state_transitions(&self, depth: Depth) -> impl ParallelIterator<Item=VaultStateParameters> + '_ {
        let previous_values = if depth == 0 {
            0..=0
        } else {
            1..=self.max.0
        }
        .map(|value| VaultAmount(value));

        let previous_transitions = if depth == 0 {
            Either::A(previous_values.map(|pv| (pv, None)))
        } else if depth == 1 {
            Either::B(
                Either::A(
                    previous_values.map(|pv| (
                            pv,
                            VaultTransition::Deposit(pv),
                        )
                    )
                ),
            )
        } else {
            Either::B(
                Either::B(
                    // FIXME: eugh
                    self.iter_tail_transitions()
                        .flat_map(|transition| 
                            previous_values
                                .filter_map(|pv| {
                                    match transition {
                                        VaultTransition::Deposit(amount) => {
                                            if amount > pv {
                                                None
                                            } else {
                                                Some((pv, transition))
                                            }
                                        }
                                        VaultTransition::Withdrawal(amount) => {
                                            if (amount + pv) > self.max {
                                                None
                                            } else {
                                                Some((pv, transition))
                                            }
                                        }
                                    }
                                })
                        )
                ),
            )
        };

        previous_transitions 
            .flat_map(|(previous_value, parent_transition)| {
                if depth == 0 {
                    Either::A(
                        (0..self.max.0)
                            .map(|amount| VaultTransition::Deposit(
                                    VaultAmount(amount)
                                )
                            )
                } else {
                    Either::B
                    self.iter_tail_transitions()
                }
            })
        range
            .flat_map(move |value| self.state_transitions_single(VaultAmount(value), depth))
            .par_bridge()
    }

    fn dummy_inputs(&self, depth: Depth, parameter: &VaultStateParameters) -> Vec<TxIn> {
        let (input_count, lock_time) = match (depth, &parameter.transition) {
            (0, _) => (1, RelativeLockTime::ZERO),
            (_, VaultTransition::Deposit(ref value)) => (2, self.lock_time_for_deposit(value)),
            (_, VaultTransition::Withdrawal(ref value)) => (1, self.lock_time_for_withdrawal(value)),
        };

        let mut input: Vec<TxIn> = Vec::new();

        for _ in 0..input_count {
            input.push(dummy_input(lock_time));
        }

        input
    }

    fn tx_templates<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, next_states: Option<&HashMap<VaultStateParameters, Transaction>>) -> HashMap<VaultStateParameters, Transaction> {
        if depth == 0 {
            self.state_transitions_single(VaultAmount(0), depth)
                .map(|parameter| (
                        parameter.clone(),
                        self.tx_template(secp, depth, &parameter, next_states)
                    )
                )
                .collect()
        } else {
            self.state_transitions(depth)
                .map(|parameter| (
                        parameter.clone(),
                        self.tx_template(secp, depth, &parameter, next_states)
                    )
                )
                .collect()
        }
    }

    // FIXME: Probably should create some sort of cache structure to pass around
    pub fn templates_at_depth<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth) -> HashMap<VaultStateParameters, Transaction> {
        let mut iter = self.iter_templates(secp);

        loop {
            match iter.next_with_depth() {
                Some((this_depth, generation)) => {
                    if this_depth == depth {
                        return generation.clone();
                    }
                }
                None => unreachable!(),
            }
        }
    }

    pub fn iter_templates<'p, 's, C: Verification>(&'p self, secp: &'s Secp256k1<C>) -> VaultGenerationIterator<'p, 's, C> {
        VaultGenerationIterator {
            parameters: self,
            generation: None,
            secp,
            depth: self.max_depth,
            done: false,
        }
    }
}

// Struct members are the outpoints
enum VaultOutpoints {
    Deposit(VaultAmount),
    /// Any withdrawal that does not completely drain the vault
    /// .0 is the vault outpoint
    /// .1 is the withdrawal outpoint
    Withdrawal(VaultAmount, VaultAmount),
    /// A sweep of a withdrawal to recovery
    Recovery(VaultAmount),
    /// A sweep of the vault to recovery location
    Close(VaultAmount),
}

pub struct VaultTransaction {
    txid: Txid,
    vout: Option<u32>,
    depth: Depth,
    transition: VaultTransition,
    result_value: VaultAmount,
}

impl VaultTransaction {
    pub fn outpoint(&self) -> Option<OutPoint> {
        self.vout
            .map(|vout| OutPoint {
                txid: self.txid,
                vout,
            })
    }

    pub fn into_parameters(&self,
        parent_transition: Option<VaultTransition>, 
        max: Option<VaultAmount>
    ) -> Option<VaultStateParameters> {
        self.result_value
            .apply_transition(
                self.transition.invert(),
                max,
            )
            .map(|previous_value| {
                VaultStateParameters {
                    transition: self.transition,
                    previous_value,
                    parent_transition,
                }
            })
    }
}

#[derive(Debug)]
pub enum VaultInitializationError {
    MigrationError(MigrationError),
    ConfigurationError(rusqlite::Error),
}

#[derive(Debug)]
pub enum VaultDepositError {
    InsufficientFunds(InsufficientFunds),
    TransactionBuildError(CreateTxError),
    VaultClosed,
    VaultOverflow(VaultAmount),
}

/// A local identifier for a vault
pub type VaultId = i64;

const ACCOUNT_MAX: u32 = (1 << 31) - 1;

/// An account identifier as described in BIP-44
pub struct AccountId(u32);

impl AccountId {
    pub fn new(account: u32) -> Option<Self> {
        if account < ACCOUNT_MAX {
            Some(Self(account))
        } else {
            None
        }
    }

    pub fn to_hot_derivation_path(&self) -> DerivationPath {
        VaultKeyDerivationPathTemplate::HotKey(self.0)
            .to_derivation_path()
    }

    pub fn to_cold_derivation_path(&self) -> DerivationPath {
        VaultKeyDerivationPathTemplate::ColdKey(self.0)
            .to_derivation_path()
    }
}

pub struct SqliteVaultStorage {
    sqlite: rusqlite::Connection,
}

#[derive(Debug)]
pub enum SqliteInitializationError {
    MigrationError(MigrationError),
    ConnectionConfigurationError(rusqlite::Error),
}

impl SqliteVaultStorage {
    pub fn from_connection(mut sqlite: rusqlite::Connection) -> Result<Self, SqliteInitializationError> {
        migrate(&mut sqlite)
            .map_err(|e| SqliteInitializationError::MigrationError(e))?;
        configure(&sqlite)
            .map_err(|e| SqliteInitializationError::ConnectionConfigurationError(e))?;

        Ok(SqliteVaultStorage {
            sqlite,
        })
    }
}

impl Deref for SqliteVaultStorage {
    type Target = rusqlite::Connection;

    fn deref(&self) -> &Self::Target {
        &self.sqlite
    }
}

impl DerefMut for SqliteVaultStorage {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.sqlite
    }
}

#[derive(Clone)]
pub struct DepositTransactions {
    pub shape_transaction: Psbt,
    pub deposit_transaction: Transaction,
}

impl DepositTransactions {
    pub fn extract(self) -> Result<(Transaction, Transaction), ExtractTxError> {
        self.shape_transaction
            .extract_tx()
            .map(|shape_transaction| (shape_transaction, self.deposit_transaction))
    }
}

#[cfg(feature = "bitcoind")]
pub fn package_encodable<E, I>(iter: I) -> serde_json::Value
where
    I: IntoIterator<Item = E>,
    E: Encodable,
{
    iter
        .into_iter()
        .map(|e| serialize_hex(&e))
        .collect()
}

impl std::fmt::Debug for DepositTransactions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "shape txid = {}", self.shape_transaction.unsigned_tx.compute_txid())?;
        writeln!(f, "shape tx = {:?}", self.shape_transaction.unsigned_tx)?;
        writeln!(f, "deposit txid = {}", self.deposit_transaction.compute_txid())?;
        writeln!(f, "deposit tx = {:?}", self.deposit_transaction)
    }
}

#[derive(Clone,Hash,Eq,PartialEq)]
struct SignedNextStateTemplate {
    pubkey: XOnlyPublicKey,
    next_state_template_hash: sha256::Hash,
}

impl SignedNextStateTemplate {
    fn to_scriptbuf(&self) -> ScriptBuf {
        // We enforce sequence indirectly via CTV
        builder_with_capacity(33 + 1 + 1 + 33 + 1)
            .push_slice(self.next_state_template_hash.to_byte_array())
            .push_opcode(OP_CHECKTEMPLATEVERIFY)
            .push_opcode(OP_DROP)
            .push_x_only_key(&self.pubkey)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }

    fn into_scriptbuf(self) -> ScriptBuf {
        self.to_scriptbuf()
    }
}

impl PartialEq<Script> for SignedNextStateTemplate {
    fn eq(&self, other: &Script) -> bool {
        self.to_scriptbuf().as_script() == other
    }
}

#[derive(Clone,Hash,Eq,PartialEq)]
enum VaultOutputSpendCondition {
    Deposit(VaultAmount),
    Withdrawal(VaultAmount),
    Recovery {
        vault_balance: VaultAmount,
        withdrawal_amount: VaultAmount,
    },
}

pub struct VaultOutputSpendInfo {
    spend_info: TaprootSpendInfo,
    branches: HashMap<VaultOutputSpendCondition, SignedNextStateTemplate>,
}

pub struct DepositTransaction{
    depth: Depth,
    amount: Amount,
    vault_total: VaultAmount,
    vault_deposit: VaultAmount,
    script_pubkey: ScriptBuf,
    transaction: Transaction,
}

impl DepositTransaction {
    pub fn to_transaction(self) -> Transaction { self.transaction }

    pub fn as_transaction(&self) -> &Transaction { &self.transaction }

    fn deposit_input_mut(&mut self) -> &mut TxIn {
        match self.transaction.input.len() {
            1 => &mut self.transaction.input[0],
            2 => &mut self.transaction.input[1],
            _ => unreachable!("should never have more than 2 inputs or less than 1"),
        }
    }

    pub fn script_pubkey(&self) -> &Script { self.script_pubkey.as_script() }

    pub fn deposit_amount(&self) -> Amount { self.amount }

    pub fn connect_input(&mut self, outpoint: OutPoint) {
        self.deposit_input_mut().previous_output = outpoint;
    }

    pub fn weight(&self) -> Weight { self.transaction.weight() }
}

pub struct Vault {
    id: VaultId,
    parameters: VaultParameters,
    history: Vec<(VaultTransaction, Option<(u32, BlockHash)>)>,
}

#[derive(Debug)]
pub enum CreateVaultError {
    SqliteError(rusqlite::Error),
}

impl Vault {
    pub fn create_new(storage: &mut SqliteVaultStorage, name: &str, parameters: VaultParameters) -> Result<Self, CreateVaultError> {
        let mut statement = storage.prepare(r#"
            insert into
                mccv_vault
            (
                name
            )
            values (?)
            returning id
        "#)
        .map_err(|e| CreateVaultError::SqliteError(e))?;

        let vault_ids: Vec<i64> = statement
            .query_map(
                params![name],
                |row| row.get(0),
            )
            .map_err(|e| CreateVaultError::SqliteError(e))?
            .collect::<rusqlite::Result<Vec<i64>>>()
            .map_err(|e| CreateVaultError::SqliteError(e))?;

        Ok(Self {
            id: vault_ids[0],
            parameters,
            history: Vec::new(),
        })
    }

    pub fn load(id: VaultId, storage: &mut SqliteVaultStorage) -> Result<Self, rusqlite::Error> {
        let _vault_id = storage.query_row("select (id) from mccv_vault", params![id], |row: &Row| -> rusqlite::Result<i64> { row.get(0) })?;

        Ok(Self {
            id,
            parameters: todo!(),
            history: todo!(),
        })
    }

    pub fn list(connection: &mut Connection) -> Result<Vec<(VaultId, String)>, rusqlite::Error> {
        let mut query = connection.prepare(r#"
            select
            (
                id,
                name
            )
            from
                mccv_vault
        "#)?;

        let result = query.query_map(params![], |row| {
            let id: VaultId = row.get(0)?;
            let name: String = row.get(1)?;
            Ok((id, name))
        })?
        .collect::<rusqlite::Result<Vec<(VaultId, String)>>>();
        result
    }

    pub fn store(&self, connection: &mut Connection) -> Result<Self, rusqlite::Error> {
        todo!()
    }

    // FIXME: and parent utxo scripts
    pub fn deposit_transaction_template<C: Verification>(&self, secp: &Secp256k1<C>, deposit_amount: VaultAmount) -> Option<(Option<VaultOutputSpendInfo>, Transaction)> {
        let depth = self.history.len() as Depth;

        let (parameters, outpoint) = match self.history.last() {
            Some((transaction, _)) => {
                let outpoint = transaction.vout
                    .map(|vout| OutPoint {
                        txid: transaction.txid,
                        vout,
                    })?;

                (
                    VaultStateParameters {
                        transition: VaultTransition::Deposit(deposit_amount),
                        previous_value: transaction.result_value,
                        parent_transition: Some(transaction.transition),
                    },
                    Some(outpoint),
                )
            }
            None => (
                VaultStateParameters {
                    transition: VaultTransition::Deposit(deposit_amount),
                    previous_value: VaultAmount(0),
                    parent_transition: None,
                },
                None,
            )
        };

        let transactions = self.parameters.templates_at_depth(secp, dbg!(depth));

        let mut deposit = if let Some(deposit) = transactions.get(dbg!(&parameters)) {
            deposit.clone()
        } else {
            // Why does this function even return an option if we don't use it?
            // TODO: probably should make it fallible with a real error type
            let template_keys: Vec<_> = transactions.keys().collect();
            dbg!(template_keys);
            panic!("never call deposit_transaction_template_impl() with an invalid parameter set")
        };

        outpoint.map(|outpoint| {
            if parameters.previous_value.nonzero() {
                deposit.input[0].previous_output = outpoint;
            }
        });

        let second_to_last_history_tx = if self.history.len() >= 2 {
            Some(&self.history[self.history.len() - 2].0)
        } else {
            None
        };

        let parent_parameters = match (self.history.last(), second_to_last_history_tx) {
            (Some((parent_tx, _confirmations)), Some(grandparent_tx)) => {
                debug_assert!(
                    grandparent_tx.result_value == parent_tx
                        .result_value
                        .apply_transition(
                            parent_tx.transition.invert(),
                            Some(self.parameters.max),
                        ).unwrap()
                );

                let parent_parameters = parent_tx.into_parameters(
                    Some(grandparent_tx.transition),
                    Some(self.parameters.max)
                );
                debug_assert!(parent_parameters.is_some());
                parent_parameters
            }
            (Some((parent_tx, _confirmations)), None) => {
                let parent_parameters = parent_tx.into_parameters(
                    None,
                    Some(self.parameters.max)
                );
                debug_assert!(parent_parameters.is_some());
                parent_parameters
            }
            (None, None) => None,
            (None, Some(_)) => unreachable!("can't have a grandparent without a parent"),
        };

        let spend_info = parent_parameters
            .map(|parent_parameters| {
                debug_assert!(depth > 0, "Depth 0 has no ancestors");

                let templates = self.parameters.templates_at_depth(secp, depth);

                let spend_conditions = self.parameters.vault_output_spend_conditions(secp, depth, &parent_parameters, &templates);


                self.parameters.spend_conditions_into_spend_info(
                    secp,
                    depth - 1,
                    &spend_conditions,
                )
            });

        // Need to generate taproot spend info
        Some((spend_info, deposit))
    }

    pub fn deposit_transaction_script(&self, tx: &Transaction) -> ScriptBuf  {
        let template = get_default_template(&tx, 0);
        builder_with_capacity(33 + 1 + 1 + 33 + 1)
            .push_slice(template.to_byte_array())
            .push_opcode(OP_CHECKTEMPLATEVERIFY)
            .into_script()
    }

    fn get_current_depth(&self) -> Depth {
        self.history.len() as Depth
    }

    // TODO: add current height arg
    pub fn get_confirmed_balance(&self) -> Amount {
        self.history.iter().rev()
            .skip_while(|(_tx, confirmation)| confirmation.is_none())
            .next()
            .map(|(tx, _confirmation)| 
                 self.parameters.scale.scale_amount(tx.result_value)
             )
            .unwrap_or(Amount::ZERO)
    }

    #[cfg(feature = "bitcoind")]
    pub fn apply_block(&mut self, block: &Block, block_height: u32) -> usize {
        // Pretty naive attempt at handling reorgs, will need testing
        let history_iter = self.history.iter_mut()
            // Skip any vault history that already has a confirmation recorded, unless it could be
            // replaced or invalidated by this block
            .skip_while(|history_tx| {
                history_tx.1.map(|(tx_height, _block)| tx_height <= block_height).unwrap_or(false)
            });

        let mut block_txes = block.txdata.iter();

        for (history_tx, ref mut confirmation) in history_iter {
            // clear the previously seen block inclusion
            *confirmation = None;

            while confirmation.is_none() {
                if let Some(block_tx) = block_txes.next() {
                    if block_tx.compute_txid() == history_tx.txid {
                        eprintln!("found tx {}", history_tx.txid);
                        *confirmation = Some((block_height, block.block_hash()));
                        break;
                    }
                } else {
                    break;
                }
            }
        }

        return self.history.len();
    }

    // FIXME: I think this should be refactored into a stateless version on VaultParameters
    //  FIXME: return value should probably also have some kind of token for keeping track of
    //  replacements, preventing invalid deposit transactions from being tracked
    pub fn create_deposit<C: Verification>(&self, secp: &Secp256k1<C>, deposit_amount: VaultAmount) -> Result<DepositTransaction, VaultDepositError> {
        // FIXME: is that the right depth?
        let (spend_info, mut deposit_template) = self.deposit_transaction_template(secp, deposit_amount)
            .ok_or(VaultDepositError::VaultClosed)?;

        // FIXME: index
        let deposit_script = self.deposit_transaction_script(&deposit_template);
        // TODO: timelocked script path allowing the hot key to recover the shaping tx output. It
        // won't have its own fee so it really shouldn't ever be confirmed on its own, but it's a
        // potential griefing vector.
        
        let deposit_script_hash = TapNodeHash::from_script(
            deposit_script.as_script(),
            LeafVersion::TapScript,
        );

        let master = self.parameters.master_key(secp, self.get_current_depth());
        let tweak = TapTweakHash::from_key_and_tweak(master, Some(deposit_script_hash));
        let (_output_key, output_key_parity) = master.add_tweak(secp, &tweak.to_scalar())
            .expect("tap tweak failed"); // XXX: This is ~ what XOnlyPublicKey::tap_tweak() does in newer secp so should be ok

        let script_pubkey = ScriptBuf::new_p2tr(secp, master, Some(deposit_script_hash));

        let shape_witness = {
            let mut witness = Witness::new();

            let control_block = ControlBlock {
                leaf_version: LeafVersion::TapScript,
                output_key_parity,
                internal_key: master,
                merkle_branch: TaprootMerkleBranch::default(),
            };

            witness.push(deposit_script);
            witness.push(control_block.serialize());

            witness
        };

        // Set this now so we can calculate weight correctly
        match deposit_template.input.len() {
            1 => { deposit_template.input[0].witness = shape_witness; }
            2 => { deposit_template.input[1].witness = shape_witness; }
            _ => unreachable!("should never have more than 2 inputs or less than 1"),
        }

        match deposit_template.input.len() {
            1 => { }
            2 => {
                let (history_tx, _) = self.history.last()
                    .expect("deposit template will only have two inputs if depth > 0");

                let second_to_last_history_tx = if self.history.len() >= 2 {
                    Some(&self.history[self.history.len() - 2].0)
                } else {
                    None
                };

                let parent_parameters = self.parameters.history_to_parameters(history_tx, second_to_last_history_tx, self.get_current_depth());

                //let parent_parameters = history_tx.transition
                todo!()
            }
            _ => unreachable!("should never have more than 2 inputs or less than 1"),
        }

        let current_vault_amount = self.history.last()
            .map(|(tx, _)| tx.result_value)
            .unwrap_or(VaultAmount::ZERO);

        // Ensure vault_total <= self.parameters.max
        let vault_total = current_vault_amount + deposit_amount;
        let overflow_amount = vault_total
            .checked_sub(self.parameters.max);
        if let Some(overflow_amount) = overflow_amount {
            if overflow_amount > VaultAmount::ZERO {
                return Err(VaultDepositError::VaultOverflow(overflow_amount));
            }
        }

        Ok(
            DepositTransaction{
                depth: self.get_current_depth(),
                amount: self.parameters.scale.scale_amount(deposit_amount),
                script_pubkey,
                transaction: deposit_template,
                vault_deposit: deposit_amount,
                vault_total,
            }
        )
    }

    // FIXME: return types
    // FIXME: part of me wants to have one add_*_transaction for deposit and withdrawal
    pub fn add_deposit_transaction(&mut self, tx: &DepositTransaction) -> Result<(), ()> {
        if (tx.depth as usize) != self.history.len() {
            return Err(());
        }

        self.history.push(
            (
                VaultTransaction {
                    txid: tx.transaction.compute_txid(),
                    vout: Some(0),
                    depth: tx.depth,
                    transition: VaultTransition::Deposit(tx.vault_deposit),
                    result_value: tx.vault_total,
                },
                None,
            )
        );

        Ok(())
    }

    pub fn to_vault_amount(&self, amount: Amount) -> (VaultAmount, Amount) {
        self.parameters.scale.convert_amount(amount)
    }
}

pub trait VaultDepositor {
    fn create_shape<C: Verification>(&mut self, secp: &Secp256k1<C>, deposit_transaction: &mut DepositTransaction, fee_rate: FeeRate) -> Result<Psbt, VaultDepositError>;
}

impl VaultDepositor for Wallet {
    fn create_shape<C: Verification>(&mut self, secp: &Secp256k1<C>, deposit_transaction: &mut DepositTransaction, fee_rate: FeeRate) -> Result<Psbt, VaultDepositError> {
        let script_pubkey = deposit_transaction.script_pubkey();
        let mut shape_weight = Weight::ZERO;
        // This weight should be correct already 
        let deposit_weight = deposit_transaction.weight();
        let mut fee_amount = fee_rate * (shape_weight + deposit_weight);

        let shape_psbt = loop {
            let mut builder = self.build_tx();
            builder
                .version(3)
                .fee_absolute(Amount::ZERO)
                .add_recipient(script_pubkey, deposit_transaction.deposit_amount() + fee_amount);

            let shape_psbt = builder.finish()
                .map_err(|e| {
                    match e {
                        CreateTxError::CoinSelection(cs) => VaultDepositError::InsufficientFunds(cs),
                        _ => VaultDepositError::TransactionBuildError(e),
                    }
                })?;

            let shape_tx = &shape_psbt.unsigned_tx;

            let index = self.spk_index();
            let satisfaction_weight = shape_tx
                .input
                .iter()
                .flat_map(|txin| {
                    index
                        .txout(txin.previous_output)
                        .map(|((keychain, derivation_index), _txout)| {
                            let descriptor = self.public_descriptor(keychain);

                            let derived = descriptor.at_derivation_index(derivation_index)
                                .expect("this better work"); // FIXME: no panics
                            
                            // TODO: we can do better than this, but this should be fine for now
                            derived.max_weight_to_satisfy()
                                .expect("this better work") // FIXME: no panics
                        })
                })
                .fold(Weight::ZERO, |x, y| x + y);

            shape_weight = shape_tx.weight() + satisfaction_weight;

            let total_weight = shape_weight + deposit_weight;
            let min_fee = total_weight * fee_rate;

            if fee_amount >= min_fee {
                break shape_psbt;
            }

            // Update the absolute fee we must supply
            fee_amount = if fee_amount >= min_fee {
                fee_amount
            } else {
                min_fee
            };
        };

        let shape_txid = shape_psbt.unsigned_tx.compute_txid();

        let (shape_output_index, _shape_txout) = shape_psbt
            .unsigned_tx
            .output
            .iter()
            .enumerate()
            .find(|(_i, txout)| txout.script_pubkey == *script_pubkey)
            .expect("shape psbt must have output we just added to it");

        deposit_transaction.connect_input(OutPoint {
            txid: shape_txid,
            vout: shape_output_index as u32,
        });

        Ok(shape_psbt)
    }
}

enum Either<A, B> {
    A(A),
    B(B),
}

impl<T, A, B> Iterator for Either<A, B>
where
    A: Iterator<Item = T>,
    B: Iterator<Item = T>,
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Either::A(a) => a.next(),
            Either::B(b) => b.next(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client, RpcApi};

    use bdk_wallet::KeychainKind;
    use bdk_wallet::SignOptions;
    use bdk_wallet::Wallet;

    use bitcoin::{
        consensus::encode::serialize_hex,
    };

    use serde::Serialize;

    use std::time::Instant;

    use std::str::FromStr;

    use crate::test_util;

    // master xpriv derived from milk sad key, 
    // XXX: copied in two places
    fn test_xprivs<C: Signing>(secp: &Secp256k1<C>, account: u32) -> (Xpriv, Xpriv) {
        let milk_sad_master = Xpriv::from_str("tprv8ZgxMBicQKsPd1EzCPZcQSPhsotX5HvRDCivA7ASNQFmjWuTsW3WWEwUNKFAZrnD9qpz55rtyLdphqkwRZUqNWYXwSEzd6P4pYvXGByRim3").unwrap();

        let account = AccountId::new(account)
            .expect("Valid account");

        (
            milk_sad_master
                .derive_priv(secp, &account.to_cold_derivation_path())
                .expect("success"),
            milk_sad_master
                .derive_priv(secp, &account.to_hot_derivation_path())
                .expect("success"),
        )
    }

    fn test_parameters<C: Signing>(secp: &Secp256k1<C>) -> VaultParameters {
        let (cold_xpriv, hot_xpriv) = test_xprivs(secp, 0);

        VaultParameters {
            scale: VaultScale::from_sat(100_000_000),
            max: VaultAmount::new(10),
            cold_xpub: Xpub::from_priv(&secp, &cold_xpriv), //
            hot_xpub: Xpub::from_priv(&secp, &hot_xpriv),  //
            delay_per_increment: 36,
            max_withdrawal_per_step: VaultAmount::new(3),
            max_deposit_per_step: VaultAmount::new(3),
            max_depth: 10,
        }
    }

    #[test]
    fn test_vault_amount() {
        assert_eq!(
            VaultAmount(3)
                .apply_transition(
                    VaultTransition::Deposit(VaultAmount(39)),
                    None,
                ),
            Some(VaultAmount(42)),
        );

        assert_eq!(
            VaultAmount(3)
                .apply_transition(
                    VaultTransition::Deposit(VaultAmount(39)),
                    Some(VaultAmount(41)),
                ),
            None,
        );

        assert_eq!(
            VaultAmount(3)
                .apply_transition(
                    VaultTransition::Deposit(VaultAmount(39)),
                    Some(VaultAmount(42)),
                ),
            Some(VaultAmount(42)),
        );

        assert_eq!(
            VaultAmount(3)
                .apply_transition(
                    VaultTransition::Withdrawal(VaultAmount(1)),
                    Some(VaultAmount(42)),
                ),
            Some(VaultAmount(2)),
        );

        assert_eq!(
            VaultAmount(3)
                .apply_transition(
                    VaultTransition::Withdrawal(VaultAmount(1)),
                    None,
                ),
            Some(VaultAmount(2)),
        );

        assert_eq!(
            VaultAmount(3)
                .apply_transition(
                    VaultTransition::Withdrawal(VaultAmount(3)),
                    None,
                ),
            Some(VaultAmount(0)),
        );

        assert_eq!(
            VaultAmount(3)
                .apply_transition(
                    VaultTransition::Withdrawal(VaultAmount(4)),
                    None,
                ),
            None,
        );
    }

    fn deposit(amount: u32) -> VaultTransition {
        VaultTransition::Deposit(VaultAmount(amount))
    }

    fn withdrawal(amount: u32) -> VaultTransition {
        VaultTransition::Withdrawal(VaultAmount(amount))
    }

    #[test]
    fn test_parameter_generation() {
        let secp = Secp256k1::new();
        let (cold_xpriv, hot_xpriv) = test_xprivs(&secp, 0);

        let test_parameters = VaultParameters {
            scale: VaultScale::from_sat(100_000_000),
            max: VaultAmount::new(4),
            cold_xpub: Xpub::from_priv(&secp, &cold_xpriv), //
            hot_xpub: Xpub::from_priv(&secp, &hot_xpriv),  //
            delay_per_increment: 36,
            max_withdrawal_per_step: VaultAmount::new(3),
            max_deposit_per_step: VaultAmount::new(3),
            max_depth: 10,
        };

        let vault = Vault {
            id: 0,
            parameters: test_parameters.clone(),
            history: Vec::new(),
        };

        let mut initial_deposit_amounts: Vec<_> = test_parameters.iter_deposit_amounts(0).collect();
        initial_deposit_amounts.sort();

        assert_eq!(
            initial_deposit_amounts, 
            vec![
                VaultAmount(1),
                VaultAmount(2),
                VaultAmount(3),
                VaultAmount(4),
            ],
        );

        let mut initial_deposits: Vec<_> = test_parameters.iter_transitions(0).collect();

        assert_eq!(
            initial_deposits, 
            vec![
                VaultStateParameters {
                    transition: deposit(1),
                    previous_value: VaultAmount(0),
                    parent_transition: None,
                },
                VaultStateParameters {
                    transition: deposit(2),
                    previous_value: VaultAmount(0),
                    parent_transition: None,
                },
                VaultStateParameters {
                    transition: deposit(3),
                    previous_value: VaultAmount(0),
                    parent_transition: None,
                },
                VaultStateParameters {
                    transition: deposit(4),
                    previous_value: VaultAmount(0),
                    parent_transition: None,
                },
            ],
        );

        let mut deposit_amounts: Vec<_> = test_parameters.iter_deposit_amounts(1).collect();

        assert_eq!(
            deposit_amounts.len(), 
            test_parameters.max_deposit_per_step.to_unscaled_amount() as usize,
        );

        deposit_amounts.sort();
        assert_eq!(
            deposit_amounts,
            vec![
                VaultAmount(1),
                VaultAmount(2),
                VaultAmount(3),
            ],
        );

        
    }

    #[test]
    fn test_simple() {
        let secp = Secp256k1::new();
        let test_parameters = test_parameters(&secp);

        let templates = test_parameters.templates_at_depth(&secp, 0);

        assert_eq!(templates.len(), 10);

        for (params, template) in &templates {
            assert_eq!(template.input.len(), 1);
            assert_eq!(params.previous_value, VaultAmount(0));
        }

        let next_templates = test_parameters.templates_at_depth(&secp, 1);

        eprintln!("foo");
        for (params, _template) in &templates {
            for amount in 1..test_parameters.max_withdrawal_per_step.to_unscaled_amount() {
                if let Some(next) = params.next(VaultTransition::Withdrawal(VaultAmount(amount)), test_parameters.max) {
                    eprintln!("============================ PARAM ============================");
                    // previous_value can only be zero for depth = 0
                    if next.previous_value == VaultAmount::ZERO {
                        continue;
                    }

                    dbg!(next_templates.keys().filter(|params| params.previous_value == next.previous_value).collect::<Vec<_>>());

                    let next = next_templates.get(&dbg!(next));
                    assert!(next.is_some());
                }
            }

            for amount in 1..test_parameters.max_deposit_per_step.to_unscaled_amount() {
                if let Some(next) = params.next(VaultTransition::Deposit(VaultAmount(amount)), test_parameters.max) {
                    // previous_value can only be zero for depth = 0
                    if next.previous_value == VaultAmount::ZERO {
                        continue;
                    }

                    let next = next_templates.get(&dbg!(next));
                    assert!(next.is_some());
                }
            }
        }

        for (params, template) in templates.into_iter() {
            /*
            for withdrawal_amount in test_parameters.max_withdrawal_per_step.iter_from(VaultAmount::ZERO) {
                let next_params = VaultStateParameters {
                    transition: ,
                    previous_value: todo!(),
                    parent_transition: todo!(),
                };
            }

            for deposit_amount in test_parameters.max_withdrawal_per_step.iter_from(VaultAmount::ZERO) {

            }
            */
        }

        todo!("more tests")
    }
}
