#[cfg(feature = "bitcoind")]
use bdk_bitcoind_rpc::bitcoincore_rpc::{Client, RpcApi, self};

use bitcoin::bip32::{
    Xpriv,
    Xpub,
    ChildNumber,
    DerivationPath,
};

#[cfg(feature = "bitcoind")]
use bitcoin::Block;

#[cfg(feature = "bitcoind")]
use bitcoin::consensus::encode::serialize_hex;

use bitcoin::hashes::{
    Hash,
    sha256,
};

use bitcoin::opcodes::all::{
    OP_CSV,
    OP_CHECKSIG,
    OP_NOP4 as OP_CHECKTEMPLATEVERIFY,
    OP_DROP,
};

use bitcoin::secp256k1::{
    constants::SCHNORR_SIGNATURE_SIZE,
    Keypair,
    Message,
    PublicKey,
    Secp256k1,
    Signing,
    Verification,
    XOnlyPublicKey,
};

use bitcoin::taproot::{
    ControlBlock,
    LeafVersion,
    TaprootBuilder,
    TaprootMerkleBranch,
    TaprootSpendInfo,
};

use bitcoin::{
    absolute::LockTime,
    Amount,
    blockdata::locktime::relative,
    blockdata::transaction::Version,
    BlockHash,
    FeeRate,
    key::TapTweak,
    OutPoint,
    psbt,
    ScriptBuf,
    Script,
    Sequence,
    TapLeafHash,
    TapNodeHash,
    taproot,
    TapSighashType,
    transaction,
    Transaction,
    Txid,
    TxIn,
    TxOut,
    script::Builder,
    sighash::Prevouts,
    sighash::SighashCache,
    sighash,
    VarInt,
    Weight,
    Witness,
};

use rayon::iter::{
    IntoParallelIterator,
    ParallelIterator,
};

#[allow(unused_imports)]
use rusqlite::{
    Connection,
    params,
    Row,
    types::{
        ToSql,
        FromSql,
    },
};

use serde::{
    Deserialize,
    Serialize,
};

use std::borrow::Borrow;
use std::iter;

use std::collections::HashMap;
use std::ops::{Deref, DerefMut};

use crate::bip119::get_default_template;

use crate::migrate::{
    configure,
    migrate,
    MigrationError,
};

use crate::wallet::SEGWIT_MARKER_WEIGHT;

// struct.unpack(">I", hashlib.sha256(b'mccv').digest()[:4])[0] & 0x7FFFFFFF
const PURPOSE: u32 = 360843587;

pub type Depth = u32;

fn builder_with_capacity(size: usize) -> Builder {
    Builder::from(Vec::with_capacity(size))
}

/// Store XOnlyPublicKey in 32 bytes instead of 64
///
/// Since it is only constructed from a valid [`XOnlyPublicKey`] it should always be valid
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
struct CompactXOnlyPublicKey([u8; 32]);

impl From<XOnlyPublicKey> for CompactXOnlyPublicKey {
    fn from(value: XOnlyPublicKey) -> Self {
        Self(value.serialize())
    }
}

impl From<CompactXOnlyPublicKey> for XOnlyPublicKey {
    fn from(value: CompactXOnlyPublicKey) -> Self {
        XOnlyPublicKey::from_slice(value.0.as_ref())
            .expect("always valid")
    }
}

#[derive(Clone,Copy,Debug)]
pub enum VaultAmountError {
    OutOfRange,
}

#[derive(Clone,Copy,Debug,Serialize,Deserialize)]
#[serde(transparent)]
pub struct VaultScale(u32);

impl VaultScale {
    pub fn new(scale: u32) -> Self { Self(scale) }

    pub fn from_sat(scale: u32) -> Self { Self(scale) }

    pub fn convert_amount(&self, amount: Amount) -> Result<(VaultAmount, Amount), VaultAmountError> {
        let quotient  = amount.to_sat() / (self.0 as u64);
        let remainder = amount.to_sat() % (self.0 as u64);

        let quotient: u32 = quotient.try_into()
            .map_err(|_| VaultAmountError::OutOfRange)?;

        Ok((VaultAmount(quotient), Amount::from_sat(remainder)))
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

fn dummy_input(lock_time: relative::LockTime) -> TxIn {
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

#[derive(Clone,Copy,Debug,Eq,Hash,PartialEq)]
pub struct VaultStateParameters {
    //depth: Depth, // Always implicit in the way we process
    transition: VaultTransition,
    previous_value: VaultAmount,
    parent_transition: Option<VaultTransition>,
}

impl VaultStateParameters {
    fn get_result(&self) -> (VaultAmount, VaultAmount) {
        match self.transition {
            VaultTransition::Deposit(value) => (self.previous_value + value, VaultAmount::ZERO),
            VaultTransition::Withdrawal(withdrawal_value) =>
                (self.previous_value - withdrawal_value, withdrawal_value),
        }
    }

    #[allow(dead_code)]
    fn next(&self, transition: VaultTransition, parameters: &VaultParameters, depth: Depth) -> Option<Self> {
        let (current_value, _) = self.get_result();

        parameters.validate_parameters(
            Self {
                transition,
                previous_value: current_value,
                parent_transition: Some(self.transition),
            },
            depth,
        )
    }

    fn assert_valid(&self) {
        match self.transition {
            VaultTransition::Withdrawal(amount) => {
                assert!(self.previous_value > VaultAmount::ZERO);
                assert!(amount <= self.previous_value);
            }
            _ => {},
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

#[derive(Clone,Debug)]
struct DepositTransactionTemplateCommon {
    depth: Depth,
    vault_scale: VaultScale,
    vault_output: TxOut,
    vault_deposit: VaultAmount,
    vault_total: VaultAmount,
}

#[derive(Clone,Debug)]
struct InitialDepositTransactionTemplate {
    common: DepositTransactionTemplateCommon,
}

#[derive(Clone,Debug)]
struct TailDepositTransactionTemplate {
    common: DepositTransactionTemplateCommon,
    vault_input_lock_time: relative::LockTime,
}

#[derive(Clone,Debug)]
enum DepositTransactionTemplate {
    InitialDeposit(InitialDepositTransactionTemplate),
    Deposit(TailDepositTransactionTemplate),
}

impl DepositTransactionTemplateCommon {
    fn into_transaction(self, vault_input: Option<TxIn>) -> Transaction {
        let input = iter::empty()
            .chain(Some(dummy_input(relative::LockTime::ZERO)))
            .chain(vault_input)
            .collect();

        Transaction {
            version: transaction::Version::non_standard(3),
            lock_time: LockTime::ZERO,
            input,
            output: vec![self.vault_output],
        }
    }
}

impl InitialDepositTransactionTemplate {
    fn instantiate(self, deposit_input_internal_key: XOnlyPublicKey) -> InitialDepositTransaction {
        InitialDepositTransaction {
            common: DepositTransactionCommon::from_template(self.common, deposit_input_internal_key)
        }
    }
}

impl From<InitialDepositTransactionTemplate> for Transaction {
    fn from(value: InitialDepositTransactionTemplate) -> Self {
        value.common.into_transaction(None)
    }
}

impl TailDepositTransactionTemplate {
    fn intantiate(self, vault_prevout: OutPoint, deposit_input_internal_key: XOnlyPublicKey, signing_info: VaultOutputSigningInfo) -> TailDepositTransaction {
        let common = DepositTransactionCommon::from_template(self.common, deposit_input_internal_key);

        TailDepositTransaction {
            common,
            vault_input: TxIn {
                previous_output: vault_prevout,
                script_sig: ScriptBuf::new(),
                sequence: self.vault_input_lock_time.into(),
                witness: Witness::new(),
            },
            signing_info,
            signature: None,
        }
    }

    // TODO: optimize to eliminate the clone
    fn vault_template_hash(&self) -> sha256::Hash {
        let tx: Transaction = self.clone().common.into_transaction(
            Some(dummy_input(self.vault_input_lock_time))
        );

        get_default_template(&tx, 0)
    }
}

#[derive(Clone,Debug)]
struct DepositTransactionCommon {
    depth: Depth,
    vault_scale: VaultScale,
    vault_deposit: VaultAmount,
    vault_total: VaultAmount,

    deposit_input_internal_key: XOnlyPublicKey,
    deposit_input: Option<(TxOut, TxIn)>,

    vault_output: TxOut,
}

#[derive(Clone,Debug)]
pub struct InitialDepositTransaction {
    common: DepositTransactionCommon,
}

#[derive(Clone,Debug)]
pub struct TailDepositTransaction {
    common: DepositTransactionCommon,

    vault_input: TxIn,
    /// Information required to sign the vault output that this transaction spends
    signing_info: VaultOutputSigningInfo,
    signature: Option<taproot::Signature>,
}

#[derive(Clone,Debug)]
pub enum DepositTransaction {
    InitialDeposit(InitialDepositTransaction),
    Deposit(TailDepositTransaction),
}

impl DepositTransactionCommon {
    fn from_template(common: DepositTransactionTemplateCommon, deposit_input_internal_key: XOnlyPublicKey) -> Self {
        Self {
            depth: common.depth,
            deposit_input: None,
            deposit_input_internal_key,
            vault_scale: common.vault_scale,
            vault_output: common.vault_output,
            vault_deposit: common.vault_deposit,
            vault_total: common.vault_total,
        }
    }

    /// Build a deposit transaction from common elements and an optional vault input
    ///
    /// Whether or not the result is signed depends on the state of the deposit input and the
    /// provided vault_input.
    fn to_transaction(&self, vault_input: Option<TxIn>) -> Result<Transaction, VaultTransactionBuildError> {
        let input = iter::empty()
            .chain(vault_input)
            .chain(
                Some(
                    self.deposit_input.as_ref().map(|(_txout, txin)| txin.clone()).ok_or(VaultTransactionBuildError::MissingInput)?
                )
            )
            .collect();

        Ok(
            Transaction {
                version: transaction::Version::non_standard(3),
                lock_time: LockTime::ZERO,
                input,
                output: vec![self.vault_output.clone()],
            }
        )
    }

    fn template_hash(&self, vault_input: Option<TxIn>, input_index: u32) -> sha256::Hash {
        let input = iter::empty()
            .chain(vault_input)
            .chain(Some(dummy_input(relative::LockTime::ZERO)))
            .collect();

        get_default_template(
            &Transaction {
                version: transaction::Version::non_standard(3),
                lock_time: LockTime::ZERO,
                input,
                output: vec![self.vault_output.clone()],
            },
            input_index
        )
    }
}

impl TailDepositTransaction {
    fn vault_template_hash(&self) -> sha256::Hash {
        get_default_template(
            &Transaction {
                version: transaction::Version::non_standard(3),
                lock_time: LockTime::ZERO,
                input: vec![
                    self.vault_input.clone(),
                    dummy_input(relative::LockTime::ZERO),
                ],
                output: vec![self.common.vault_output.clone()],
            },
            0,
        )
    }
}

#[derive(Clone,Debug)]
pub enum VaultTransactionBuildError {
    // This will always be a deposit input, rename?
    MissingInput,
    NotSigned,
}

impl TryFrom<InitialDepositTransaction> for Transaction {
    type Error = VaultTransactionBuildError;

    fn try_from(value: InitialDepositTransaction) -> Result<Self, Self::Error> {
        Ok(
            Self {
                version: transaction::Version::non_standard(3),
                lock_time: LockTime::ZERO,
                input: vec![
                    value.common.deposit_input.map(|(_txout, txin)| txin).ok_or(VaultTransactionBuildError::MissingInput)?,
                ],
                output: vec![
                    value.common.vault_output
                ],
            }
        )
    }
}

/// Calculate the serialized length of the witness
#[allow(dead_code)]
fn witness_weight(merkle_branches: Option<usize>, stack_item_sizes: &[u64]) -> Weight {
    let control_block_weight = if let Some(merkle_branches) = merkle_branches {
        let cb_length = 33 + 32 * (merkle_branches as u64);
        let len = VarInt(cb_length);

        Weight::from_wu(cb_length + len.size() as u64)
    } else {
        Weight::ZERO
    };

    let stack_item_len = VarInt(stack_item_sizes.len() as u64).size() as u64;

    stack_item_sizes.iter()
        .map(|size| {
            let len = VarInt(*size);

            Weight::from_wu((len.size() as u64 + size) as u64)
        })
        .chain(Some(control_block_weight))
        .chain(Some(Weight::from_wu(stack_item_len)))
        .sum()
}

impl DepositTransaction {
    const DEPOSIT_INPUT_INDEX_INITIAL: usize = 0;
    const DEPOSIT_INPUT_INDEX_TAIL: usize = 1;
    const VAULT_OUTPUT_INDEX: u32 = 0;

    fn vout(&self) -> u32 { Self::VAULT_OUTPUT_INDEX }

    fn common(&self) -> &DepositTransactionCommon {
        match self {
            DepositTransaction::InitialDeposit(deposit) => &deposit.common,
            DepositTransaction::Deposit(deposit) => &deposit.common,
        }
    }

    fn deposit_witness<C: Verification>(&self, secp: &Secp256k1<C>) -> Witness {
        let internal_key = self.common().deposit_input_internal_key;

        let script_hash = TapNodeHash::from(self.deposit_script_hash());

        let (_output_key, output_key_parity) = internal_key.tap_tweak(secp, Some(script_hash));

        let mut witness = Witness::new();

        let control_block = ControlBlock {
            leaf_version: LeafVersion::TapScript,
            output_key_parity,
            internal_key,
            merkle_branch: TaprootMerkleBranch::default(),
        };

        witness.push(self.deposit_script());
        witness.push(control_block.serialize());

        witness
    }

    fn vault_input(&self) -> Option<&TxIn> {
        match self {
            DepositTransaction::InitialDeposit(_deposit) => None,
            DepositTransaction::Deposit(deposit) => Some(&deposit.vault_input),
        }
    }

    /// Builds a [`bitcoin::Transaction`] from this [`Self`]
    ///
    /// Note that the result transaction may be partially or fully signed.
    // XXX: Consider renaming to reduce (my own) confusion
    fn to_unsigned_transaction(&self) -> Result<Transaction, VaultTransactionBuildError> {
        match self {
            DepositTransaction::InitialDeposit(deposit) => {
                deposit.common.to_transaction(None)
            }
            DepositTransaction::Deposit(deposit) => {
                deposit.common.to_transaction(Some(deposit.vault_input.clone()))
            }
        }
    }

    pub fn to_signed_transaction(&self) -> Result<Transaction, VaultTransactionBuildError> {
        match self {
            DepositTransaction::InitialDeposit(deposit) => {
                deposit.common.to_transaction(None)
            }
            DepositTransaction::Deposit(deposit) => {
                if let Some(signature) = deposit.signature {
                    let mut vault_input = deposit.vault_input.clone();
                    vault_input.witness = deposit.signing_info.build_witness(signature);

                    deposit.common.to_transaction(Some(vault_input))
                } else {
                    Err(VaultTransactionBuildError::NotSigned)
                }
            }
        }
    }

    // TODO: Estimate weight without constructing the whole transaction
    pub fn weight<C: Verification>(&self, secp: &Secp256k1<C>) -> Weight {
        let dummy_deposit = {
            let mut dummy = dummy_input(relative::LockTime::ZERO);

            dummy.witness = self.deposit_witness(secp);

            dummy
        };

        let input = match self {
            DepositTransaction::InitialDeposit(_deposit) => vec![dummy_deposit],
            DepositTransaction::Deposit(deposit) => {
                let mut vault_input = deposit.vault_input.clone();

                let dummy_signature = taproot::Signature::from_slice(&[0u8; 64]).expect("valid dummy signature");
                vault_input.witness = deposit.signing_info.build_witness(dummy_signature);

                vec![vault_input, dummy_deposit]
            }
        };

        let tx = Transaction {
            version: transaction::Version::non_standard(3),
            lock_time: LockTime::ZERO,
            input,
            output: vec![self.common().vault_output.clone()],
        };

        tx.weight()
    }

    /// Generates the template hash for the deposit (shape/prepare) transaction input
    fn deposit_template_hash(&self) -> sha256::Hash {
        let deposit_input_index = match self {
            DepositTransaction::InitialDeposit(_) => Self::DEPOSIT_INPUT_INDEX_INITIAL,
            DepositTransaction::Deposit(_) => Self::DEPOSIT_INPUT_INDEX_TAIL,
        };

        self.common().template_hash(
            self.vault_input().cloned(),
            deposit_input_index as u32,
        )
    }

    fn deposit_script(&self) -> ScriptBuf {
        let template_hash = self.deposit_template_hash();

        builder_with_capacity(33 + 1 + 1 + 33 + 1)
            .push_slice(template_hash.to_byte_array())
            .push_opcode(OP_CHECKTEMPLATEVERIFY)
            .into_script()
    }

    // TODO: low priority: optimize without constructing Transaction
    fn compute_txid(&self) -> Result<Txid, VaultTransactionBuildError> {
        let tx: Transaction = self.to_unsigned_transaction()?;

        Ok(tx.compute_txid())
    }

    #[allow(dead_code)]
    // This will be used directly once I defer generation of the deposit input witness
    fn deposit_script_hash(&self) -> TapLeafHash {
        let script = self.deposit_script();

        TapLeafHash::from_script(
            script.as_script(),
            LeafVersion::TapScript,
        )
    }

    // TODO: Devise a better API
    pub fn hot_keypair<C: Signing>(&self, secp: &Secp256k1<C>, xpriv: &Xpriv) -> Result<Keypair, KeypairDerivationError> {
        match self {
            DepositTransaction::InitialDeposit(_) => Err(KeypairDerivationError::NoSigningInfo),
            DepositTransaction::Deposit(deposit) => {
                let parent_depth = deposit.common.depth - 1;
                let keypair = xpriv.derive_priv(secp, &[
                    ChildNumber::from_normal_idx(parent_depth as u32)
                        .expect("assume sane child number")
                ])
                .map(|xpriv| xpriv.to_keypair(secp))
                .map_err(|e| {
                    match e {
                        bitcoin::bip32::Error::MaximumDepthExceeded => KeypairDerivationError::DerivationDepthExceeded,
                        _ => unreachable!("Xpriv derivation can only fail with maximum depth"),
                    }
                })?;

                if deposit.signing_info.pubkey != keypair.x_only_public_key().0 {
                    Err(KeypairDerivationError::WrongKey)
                } else {
                    Ok(keypair)
                }
            }
        }
    }

    // TODO: make it simple for the caller to lookup the correct keys
    pub fn sign_vault_input<C: Signing>(&mut self, secp: &Secp256k1<C>, keys: &Keypair) -> Result<(), DepositSignError> {
        // Had to hoist the into_unsigned_transaction() here because 'self' is already mutably
        // borrowed in the match. Annoying, clean this up later.
        let transaction = self.to_unsigned_transaction()
            .map_err(|e| {
                match e {
                    VaultTransactionBuildError::MissingInput => DepositSignError::NoShapeTransaction,
                    // FIXME: not in love with having yet another panic location
                    VaultTransactionBuildError::NotSigned => unreachable!("to_unsigned_transaction() won't produce this error"),
                }
            })?;

        match self {
            DepositTransaction::InitialDeposit(_) => Ok(()),
            // Previous version returned Err(DepositSignError::NoSignatureNeeded)
            // do we care? should we care? I'm inclined to let it go silently...
            DepositTransaction::Deposit(ref mut deposit) => {
                let prevout_txouts = vec![
                    &deposit.signing_info.vault_prevout,
                    deposit.common.deposit_input
                        .as_ref()
                        .map(|(txout, _txin)| txout)
                        .ok_or(DepositSignError::NoShapeTransaction)?
                ];

                let prevouts = Prevouts::All(&prevout_txouts);

                deposit.signature = Some(deposit.signing_info.sign(secp, keys, &transaction, &prevouts)
                    .map_err(|e| DepositSignError::SighashError(e))?
                );

                Ok(())
            }
        }
    }

    pub fn payment_info<C: Verification>(&self, secp: &Secp256k1<C>) -> (ScriptBuf, Amount) {
        let pubkey = self.common().deposit_input_internal_key;
        let scale = self.common().vault_scale;
        let amount = scale.scale_amount(self.common().vault_deposit);
        let script_hash = TapNodeHash::from(self.deposit_script_hash());
        let script_pubkey = ScriptBuf::new_p2tr(secp, pubkey, Some(script_hash));

        (script_pubkey, amount)
    }

    pub fn connect_input<C: Verification>(&mut self, secp: &Secp256k1<C>, previous_output: OutPoint, txout: TxOut) {
        let deposit_input = TxIn {
            previous_output,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ZERO,
            witness: self.deposit_witness(secp),
        };

        match self {
            DepositTransaction::InitialDeposit(ref mut deposit) => {
                deposit.common.deposit_input = Some((txout, deposit_input));
            }
            DepositTransaction::Deposit(ref mut deposit) => {
                deposit.common.deposit_input = Some((txout, deposit_input));
            }
        }
    }
}

#[derive(Clone,Debug)]
struct WithdrawalTransactionTemplate {
    depth: Depth,
    vault_input_lock_time: relative::LockTime,
    vault_output: Option<TxOut>,
    withdrawal_output: TxOut,

    vault_total: VaultAmount,
    vault_withdrawal: VaultAmount,
}

impl WithdrawalTransactionTemplate {
    fn instantiate(&self, vault_prevout: OutPoint, signing_info: VaultOutputSigningInfo, withdrawal_output_info: WithdrawalOutputInfo) -> WithdrawalTransaction {
        let vault_input = TxIn {
            previous_output: vault_prevout,
            script_sig: ScriptBuf::new(),
            sequence: self.vault_input_lock_time.into(),
            witness: Witness::new(),
        };

        WithdrawalTransaction {
            depth: self.depth,
            vault_total: self.vault_total,
            vault_withdrawal: self.vault_withdrawal,
            signing_info,
            vault_input,
            vault_signature: None,
            vault_output: self.vault_output.clone(),
            withdrawal_output: self.withdrawal_output.clone(),
            withdrawal_output_info,
        }
    }

    // TODO: implement optimized version without constructing the Transaction
    fn vault_template_hash(&self) -> sha256::Hash {
        let output = iter::empty()
            // Vault output
            .chain(self.vault_output.clone())
            .chain(Some(self.withdrawal_output.clone()))
            .chain(Some(ephemeral_anchor()))
            .collect();

        let tx = Transaction {
            version: transaction::Version::non_standard(3),
            lock_time: LockTime::ZERO,
            input: vec![dummy_input(self.vault_input_lock_time)],
            output,
        };

        get_default_template(&tx, 0)
    }
}

#[derive(Clone,Debug)]
struct WithdrawalOutputInfo {
    timelock: relative::LockTime,
    single_recovery_script: ScriptBuf,
    double_recovery_script: Option<ScriptBuf>,
    timelocked_withdrawal_script: ScriptBuf,
    hot_pubkey: XOnlyPublicKey,
    master_pubkey: XOnlyPublicKey,
}

impl WithdrawalOutputInfo {
    fn recovery_node_hash(&self) -> TapNodeHash {
        let single = TapNodeHash::from_script(self.single_recovery_script.as_script(), LeafVersion::TapScript);

        if let Some(ref double) = self.double_recovery_script {
            let double = TapNodeHash::from_script(double.as_script(), LeafVersion::TapScript);
            TapNodeHash::from_node_hashes(single, double)
        } else {
            single
        }
    }

    fn root_node_hash(&self) -> TapNodeHash {
        let recovery = self.recovery_node_hash();

        let timelocked_withdrawal = TapNodeHash::from_script(self.timelocked_withdrawal_script.as_script(), LeafVersion::TapScript);

        TapNodeHash::from_node_hashes(recovery, timelocked_withdrawal)
    }

    fn script_pubkey<C: Verification>(&self, secp: &Secp256k1<C>) -> ScriptBuf {
        let root_node_hash = self.root_node_hash();
        ScriptBuf::new_p2tr(secp, self.master_pubkey, Some(root_node_hash))
    }

    fn timelocked_withdrawal_merkle_branch(&self) -> TaprootMerkleBranch {
        [self.recovery_node_hash()].try_into()
            .expect("single branch cannot overflow max depth")
    }
}

#[derive(Clone,Debug)]
pub struct WithdrawalTransaction {
    depth: Depth,
    vault_input: TxIn,
    vault_signature: Option<taproot::Signature>,
    vault_output: Option<TxOut>,
    withdrawal_output: TxOut,

    vault_total: VaultAmount,
    vault_withdrawal: VaultAmount,

    withdrawal_output_info: WithdrawalOutputInfo,

    /// Information required to sign the vault output that this transaction spends
    signing_info: VaultOutputSigningInfo,
}

impl WithdrawalTransaction {
    fn vout(&self) -> Option<u32> {
        if self.vault_total > VaultAmount::ZERO {
            Some(0)
        } else {
            None
        }
    }

    fn into_transaction(self) -> Transaction {
        let output = iter::empty()
            .chain(self.vault_output)
            .chain(Some(self.withdrawal_output))
            .chain(Some(ephemeral_anchor()))
            .collect();

        Transaction {
            version: transaction::Version::non_standard(3),
            lock_time: LockTime::ZERO,
            input: vec![self.vault_input],
            output,
        }
    }

    // TODO: eliminate need to construct transaction
    fn compute_txid(&self) -> Txid {
        let tx: Transaction = self.clone().into_transaction();

        tx.compute_txid()
    }

    pub fn anchor_outpoint(&self) -> OutPoint {
        OutPoint {
            txid: self.compute_txid(),
            vout: if self.vault_output.is_some() {
                2
            } else {
                1
            },
        }
    }

    pub fn anchor_output_psbt_input(&self) -> psbt::Input {
        psbt::Input {
            witness_utxo: Some(ephemeral_anchor()),
            non_witness_utxo: Some(self.clone().into_transaction()),
            final_script_witness: Some(Witness::new()),
            ..Default::default()
        }
    }

    pub fn hot_keypair<C: Signing>(&self, secp: &Secp256k1<C>, xpriv: &Xpriv) -> Result<Keypair, KeypairDerivationError> {
        let parent_depth = self.depth - 1;
        let keypair = xpriv.derive_priv(secp, &[
            ChildNumber::from_normal_idx(parent_depth as u32)
                .expect("sane child number")
        ])
        .map(|xpriv| xpriv.to_keypair(secp))
        .map_err(|e| {
            match e {
                bitcoin::bip32::Error::MaximumDepthExceeded => KeypairDerivationError::DerivationDepthExceeded,
                _ => unreachable!("Xpriv derivation can only fail with maximum depth"),
            }
        })?;

        if self.signing_info.pubkey != keypair.x_only_public_key().0 {
            Err(KeypairDerivationError::WrongKey)
        } else {
            Ok(keypair)
        }
    }

    // FIXME: Result instead of Option?
    pub fn to_signed_transaction(&self) -> Option<Transaction> {
        let mut vault_input = self.vault_input.clone();
        vault_input.witness = self.signing_info.build_witness(self.vault_signature?);

        let output = iter::empty()
            .chain(self.vault_output.clone())
            .chain(Some(self.withdrawal_output.clone()))
            .chain(Some(ephemeral_anchor()))
            .collect();

        Some(
            Transaction {
                version: transaction::Version::non_standard(3),
                lock_time: LockTime::ZERO,
                input: vec![vault_input],
                output,
            }
        )
    }

    pub fn spend_withdrawal(self) -> WithdrawalSpendTransaction {
        WithdrawalSpendTransaction {
            depth: self.depth,
            prevout: OutPoint {
                txid: self.compute_txid(),
                vout: if self.vault_output.is_some() {
                    1
                } else {
                    0
                },
            },
            withdrawal_output: self.withdrawal_output,
            withdrawal_output_info: self.withdrawal_output_info,
        }
    }

    pub fn weight(&self) -> Weight {
        let serialized_schnorr_sig_len = VarInt(SCHNORR_SIGNATURE_SIZE as u64).size() as u64 + SCHNORR_SIGNATURE_SIZE as u64;
        let script_len = self.signing_info.script.len() as u64;
        let serialized_script_len = VarInt(script_len).size() as u64 + script_len;
        let control_block_len = self.signing_info.control_block.size() as u64;
        let serialized_control_block_len = VarInt(control_block_len).size() as u64 + control_block_len;

        self.clone().into_transaction().weight() +
            if self.vault_signature.is_some() {
                // We've already been signed, rust-bitcoin will
                // calculate the correct weight
                Weight::ZERO
            } else {
                Weight::from_wu(
                    2 + 1 + // Segwit marker + witness item count
                    serialized_schnorr_sig_len +
                    serialized_script_len +
                    serialized_control_block_len
                )
            }
    }

    pub fn sign_vault_input<C: Signing>(&mut self, secp: &Secp256k1<C>, keypair: &Keypair) -> Result<(), WithdrawalSignError> {
        let prevout_txouts = vec![
            &self.signing_info.vault_prevout,
        ];

        // TODO: also check that we actually satisfy the script, probably facilitated by hanging
        // onto the script template instead of the serialized ScriptBuf
        let prevouts = Prevouts::All(&prevout_txouts);

        let transaction = self.clone().into_transaction();

        let signature = self.signing_info.sign(secp, keypair, &transaction, &prevouts)
            .map_err(|e| WithdrawalSignError::SighashError(e))?;

        self.vault_signature = Some(signature);

        Ok(())
    }
}

#[derive(Clone,Debug)]
pub enum WithdrawalSpendError {
    FeeTooLarge,
    SighashError(sighash::TaprootError),
    FeeOverflow,
}

#[derive(Clone,Debug)]
pub struct WithdrawalSpendTransaction {
    depth: Depth,
    prevout: OutPoint,
    withdrawal_output: TxOut,
    withdrawal_output_info: WithdrawalOutputInfo,
}

impl WithdrawalSpendTransaction {
    pub fn timelock(&self) -> relative::LockTime {
        self.withdrawal_output_info.timelock
    }

    pub fn hot_keypair<C: Signing>(&self, secp: &Secp256k1<C>, xpriv: &Xpriv) -> Result<Keypair, KeypairDerivationError> {
        let keypair = xpriv.derive_priv(secp, &[
            ChildNumber::from_normal_idx(self.depth as u32)
                .expect("sane child number")
        ])
        .map(|xpriv| xpriv.to_keypair(secp))
        .map_err(|e| {
            match e {
                bitcoin::bip32::Error::MaximumDepthExceeded => KeypairDerivationError::DerivationDepthExceeded,
                _ => unreachable!("Xpriv derivation can only fail with maximum depth"),
            }
        })?;

        if self.withdrawal_output_info.hot_pubkey != keypair.x_only_public_key().0 {
            Err(KeypairDerivationError::WrongKey)
        } else {
            Ok(keypair)
        }
    }

    pub fn spend<C: Signing + Verification>(&self, secp: &Secp256k1<C>, keypair: &Keypair, script_pubkey: ScriptBuf, min_fee: Amount, min_fee_rate: FeeRate) -> Result<Transaction, WithdrawalSpendError> {
        let mut transaction = Transaction {
            version: transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: self.prevout,
                    script_sig: ScriptBuf::new(),
                    sequence: self.withdrawal_output_info.timelock.into(),
                    witness: Witness::new(),
                },
            ],
            output: vec![
                TxOut {
                    value: self.withdrawal_output.value - min_fee,
                    script_pubkey,
                }
            ],
        };

        if min_fee > self.withdrawal_output.value {
            return Err(WithdrawalSpendError::FeeTooLarge);
        }

        let tap_leaf_hash = TapLeafHash::from_script(
            self
                .withdrawal_output_info
                .timelocked_withdrawal_script
                .as_script(),
            LeafVersion::TapScript,
        );

        let tap_node_hash = self.withdrawal_output_info.root_node_hash();

        let (_output_key, output_key_parity) = self.withdrawal_output_info.master_pubkey.tap_tweak(secp, Some(tap_node_hash));

        let control_block = ControlBlock {
            leaf_version: LeafVersion::TapScript,
            output_key_parity,
            internal_key: self.withdrawal_output_info.master_pubkey,
            merkle_branch: self.withdrawal_output_info.timelocked_withdrawal_merkle_branch(),
        };

        let script_len = self.withdrawal_output_info.timelocked_withdrawal_script.len();
        let control_block_len = control_block.size();

        let weight = transaction.weight()
            + SEGWIT_MARKER_WEIGHT
            + Weight::from_wu(VarInt(3).size() as u64) // 1 witness item
            + Weight::from_wu(VarInt(SCHNORR_SIGNATURE_SIZE as u64).size() as u64)
            + Weight::from_wu(SCHNORR_SIGNATURE_SIZE as u64)
            + Weight::from_wu(VarInt(script_len as u64).size() as u64)
            + Weight::from_wu(script_len as u64)
            + Weight::from_wu(VarInt(control_block_len as u64).size() as u64)
            + Weight::from_wu(control_block_len as u64);

        let fee = min_fee_rate.checked_mul_by_weight(weight)
            .ok_or(WithdrawalSpendError::FeeOverflow)?;

        let fee = std::cmp::max(min_fee, fee);

        transaction.output[0].value = self.withdrawal_output.value - fee;

        let prevout_txouts = vec![
            &self.withdrawal_output,
        ];

        let prevouts = Prevouts::All(&prevout_txouts);

        let sighash = SighashCache::new(&transaction)
            .taproot_signature_hash(0, &prevouts, None, Some((tap_leaf_hash, 0xFFFFFFFF)), TapSighashType::Default)
            .map_err(|e| WithdrawalSpendError::SighashError(e))?;

        // FIXME: seems like there should be shortcuts for a couple of these things?
        let message: Message = sighash.into();
        let signature = secp.sign_schnorr(&message, keypair);

        let signature = taproot::Signature {
            signature,
            sighash_type: TapSighashType::Default,
        };

        transaction.input[0].witness.push(signature.serialize());
        transaction.input[0].witness.push(
            self
                .withdrawal_output_info
                .timelocked_withdrawal_script
                .as_bytes()
        );
        transaction.input[0].witness.push(control_block.serialize());

        Ok(transaction)
    }
}

#[derive(Clone,Debug)]
enum VaultTransactionTemplate {
    Deposit(DepositTransactionTemplate),
    Withdrawal(WithdrawalTransactionTemplate),
}

impl VaultTransactionTemplate {
    fn vault_template_hash(&self) -> sha256::Hash {
        match self {
            VaultTransactionTemplate::Deposit(DepositTransactionTemplate::InitialDeposit(_deposit)) => unreachable!("initial deposit can't be the destination of a vault output"),
            VaultTransactionTemplate::Deposit(DepositTransactionTemplate::Deposit(deposit)) => deposit.vault_template_hash(),
            VaultTransactionTemplate::Withdrawal(withdrawal) => withdrawal.vault_template_hash(),
        }
    }

    #[allow(dead_code)]
    fn into_transition(&self) -> VaultTransition {
        match self {
            VaultTransactionTemplate::Deposit(DepositTransactionTemplate::InitialDeposit(deposit)) =>
                VaultTransition::Deposit(deposit.common.vault_deposit),
            VaultTransactionTemplate::Deposit(DepositTransactionTemplate::Deposit(deposit)) =>
                VaultTransition::Deposit(deposit.common.vault_deposit),
            VaultTransactionTemplate::Withdrawal(withdrawal) => VaultTransition::Withdrawal(withdrawal.vault_withdrawal),
        }
    }

    // FIXME: What to do with invalid transitions? For now, just assume input is valid, beats
    // shoving the validation context down into here
    fn vault_transition_vout(previous_amount: VaultAmount, transition: VaultTransition) -> Option<u32> {
        match transition {
            VaultTransition::Deposit(_) => Some(0),
            VaultTransition::Withdrawal(withdrawal_amount) => {
                if withdrawal_amount < previous_amount {
                    Some(0)
                } else {
                    None
                }
            }
        }
    }

    #[allow(dead_code)]
    fn vault_vout(&self) -> Option<u32> {
        match self {
            VaultTransactionTemplate::Deposit(_deposit) => Some(0),
            VaultTransactionTemplate::Withdrawal(withdrawal) => {
                if withdrawal.vault_total > VaultAmount::ZERO {
                    Some(0)
                } else {
                    None
                }
            }
        }
    }
}

#[derive(Clone,Debug)]
pub enum VaultTransaction {
    Deposit(DepositTransaction),
    Withdrawal(WithdrawalTransaction),
}

impl From<DepositTransaction> for VaultTransaction {
    fn from(deposit: DepositTransaction) -> Self { Self::Deposit(deposit) }
}

impl From<WithdrawalTransaction> for VaultTransaction {
    fn from(withdrawal: WithdrawalTransaction) -> Self { Self::Withdrawal(withdrawal) }
}

type VaultGeneration = HashMap<VaultStateParameters, VaultTransactionTemplate>;

pub struct VaultGenerationIterator<'p, 's, C: Verification> {
    parameters: &'p VaultParameters,
    generation: Option<VaultGeneration>,
    secp: &'s Secp256k1<C>,
    depth: Depth,
    done: bool,
}

impl<'a, 's, C: Verification> VaultGenerationIterator<'a, 's, C> {
    // Can't be a std::iter::Iterator unless we copy the vault generation out, blech
     fn next(&mut self) -> Option<&VaultGeneration> {
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

    fn next_with_depth(&mut self) -> Option<(Depth, &VaultGeneration)> {
        let current_depth = self.depth;

        self.next().map(|generation| (current_depth, generation))
    }
}

// FIXME: ignores network...
pub enum VaultExtendedKeyDerivationPath {
    ColdKey(u32),
    HotKey(u32),
}

impl VaultExtendedKeyDerivationPath {
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
            VaultExtendedKeyDerivationPath::ColdKey(account) => (*account, 0),
            VaultExtendedKeyDerivationPath::HotKey(account) => (*account, 1),
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

#[derive(Debug)]
enum HistoryToParametersError {
    InvalidParentDepth,
    InvalidParameters,
    InconsistentParameters,
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
    fn hot_key<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth) -> XOnlyPublicKey {
        let path = [
            ChildNumber::from_normal_idx(depth as u32).expect("sane child number")
        ];

        let xpub = self.hot_xpub.derive_pub(secp, &path)
            .expect("non-hardened derivation of a reasonable depth shouldn't fail");

        xpub.to_x_only_pub()
    }

    /// Script for spending an unvault output
    fn withdrawal_script<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, timelock: relative::LockTime) -> ScriptBuf {
        // TODO: decide if we want to omit the CSV when timelock is 0
        // Conservative estimating the push_int size
        builder_with_capacity(5 + 1 + 33 + 1)
            .push_int(timelock.to_consensus_u32() as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_x_only_key(&self.hot_key(secp, depth))
            .push_opcode(OP_CHECKSIG)
            .into_script()
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

    // Spend either a withdrawn balance, the vault balance, or both, to the cold key
    fn recovery_template<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, vault_amount: VaultAmount, withdrawal_amount: VaultAmount) -> Transaction {
        assert!(vault_amount > VaultAmount::ZERO || withdrawal_amount > VaultAmount::ZERO);

        let mut input: Vec<TxIn> = Vec::with_capacity(2);
        if vault_amount > VaultAmount::ZERO {
            input.push(dummy_input(relative::LockTime::ZERO));
        }

        if withdrawal_amount > VaultAmount::ZERO {
            input.push(dummy_input(relative::LockTime::ZERO));
        }

        let key = self.recovery_key(secp, depth);

        let script_pubkey = ScriptBuf::new_p2tr(secp, key, None);

        let recovered_value = vault_amount + withdrawal_amount;

        let recovery_output = TxOut {
            value: self.scale.scale_amount(recovered_value),
            script_pubkey,
        };

        Transaction {
            version: Version::non_standard(3),
            lock_time: LockTime::ZERO,
            input,
            output: vec![recovery_output, ephemeral_anchor()],
        }
    }

    fn vault_output_spend_conditions<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, parameter: &VaultStateParameters, next_states: &VaultGeneration) -> Vec<(VaultOutputSpendCondition, SignedNextStateTemplate)> {
        let (vault_value, withdrawal_amount) = parameter.get_result();

        if vault_value <= VaultAmount::ZERO {
            return Vec::new();
        }

        let mut counter = 0;
        let mut transitions: Vec<_> = self
            .state_transitions_single(vault_value, depth + 1)
            .filter_map(|params| {
                if params.parent_transition != Some(parameter.transition) {
                    return None;
                }

                if let Some(next_state) = next_states.get(&params) {
                    // Vault UTXO will always be input 0
                    let next_state_template_hash = next_state.vault_template_hash();

                    let transition_script_template = SignedNextStateTemplate {
                        pubkey: self.hot_key(secp, depth),
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
                    eprintln!("Depth {depth} (Value: {vault_value:?}): No next state for {:?} at depth", params);
                    counter += 1;
                    None
                }
            })
            .collect();

        if counter > 0 {
            //eprintln!("counter = {counter}");
        }

        let recovery_key = self.recovery_key(secp, depth);

        // FIXME: we really need to get consistent about depth + 1 vs depth
        // I think the rule should be, that the transaction spending a txout with depth n is
        // n+1, the txout on transaction at depth n is also n (this seems like a no-brainer but
        // I think I was being inconsistent with things like the recovery tx which is kind of
        // it's own thing, does it belong to this depth?)
        if vault_value > VaultAmount::ZERO {
            let recovery_tx = self.recovery_template(secp, depth + 1, vault_value, VaultAmount::ZERO);
            // This (the vault) output will always be the first input to the recovery tx

            // TODO: intending to split this function into spend condition creation and
            // template/script creation
            transitions.push(
                (
                    VaultOutputSpendCondition::Recovery {
                        recovery_type: RecoveryType::VaultOnly,
                        vault_balance: vault_value,
                        withdrawal_amount: VaultAmount::ZERO,
                    },
                    SignedNextStateTemplate {
                        pubkey: recovery_key,
                        next_state_template_hash: get_default_template(&recovery_tx, 0),
                    },
                )
            );
        }

        // Spending path for vault-output-only recovery
        // Only create if there is actually value left in the vault after the withdrawal, and
        // if this is a withdrawal (otherwise this template is redundant)
        if vault_value > VaultAmount::ZERO && withdrawal_amount > VaultAmount::ZERO {
            let recovery_tx = self.recovery_template(secp, depth + 1, vault_value, withdrawal_amount);

            transitions.push(
                (
                    VaultOutputSpendCondition::Recovery {
                        recovery_type: RecoveryType::VaultWithWithdrawal,
                        vault_balance: vault_value,
                        withdrawal_amount,
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
    }

    fn spend_condition_weight(&self, condition: &VaultOutputSpendCondition) -> u32 {
        (match condition {
            VaultOutputSpendCondition::Deposit(amount) => (self.max_deposit_per_step - *amount).to_unscaled_amount(),
            VaultOutputSpendCondition::Withdrawal(amount) => (self.max_withdrawal_per_step - *amount).to_unscaled_amount(),
            VaultOutputSpendCondition::Recovery {..} => 0,
        }) + 1
    }

    fn vault_output<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, parameter: &VaultStateParameters, next_states: Option<&VaultGeneration>) -> TxOut {
        let (next_value, _) = parameter.get_result();
        assert!(next_value > VaultAmount::ZERO);

        if let Some(next_states) = next_states {
            let spend_conditions = self.vault_output_spend_conditions(secp, depth, parameter, next_states);

            let master_key = self.master_key(secp, depth);
            let spend_info = TaprootBuilder::with_huffman_tree(
                    spend_conditions.iter().map(|(condition, script)| (self.spend_condition_weight(&condition), script.to_scriptbuf()))
                )
                .expect("taproot tree builder")
                .finalize(secp, master_key)
                .expect("taproot tree finalize");

            TxOut {
                value: self.scale.scale_amount(next_value),
                script_pubkey: ScriptBuf::new_p2tr_tweaked(spend_info.output_key()),
            }
        // Final state, only spendable by master
        } else {
            let master_key = self.master_key(secp, depth);

            // TODO: CSFS delegated recursion
            let script_pubkey = ScriptBuf::new_p2tr(secp, master_key, None);

            TxOut {
                value: self.scale.scale_amount(next_value),
                script_pubkey,
            }
        }
    }

    fn deposit_template<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, deposit_amount: VaultAmount, parameter: &VaultStateParameters, next_states: Option<&VaultGeneration>) -> DepositTransactionTemplate {
        let (vault_total, _withdrawal_amount) = parameter.get_result();

        let vault_output = self.vault_output(secp, depth, parameter, next_states);

        let common = DepositTransactionTemplateCommon {
            depth,
            vault_scale: self.scale,
            vault_output,
            vault_deposit: deposit_amount,
            vault_total,
        };

        match parameter.parent_transition {
            None => {
                DepositTransactionTemplate::InitialDeposit(
                    InitialDepositTransactionTemplate { common }
                )
            }
            Some(parent_transition) => {
                let vault_input_lock_time = self.vault_input_lock_time(parent_transition);

                DepositTransactionTemplate::Deposit(
                    TailDepositTransactionTemplate { common, vault_input_lock_time }
                )
            }
        }
    }

    fn withdrawal_output_info<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, withdrawal_amount: VaultAmount, vault_total: VaultAmount) -> WithdrawalOutputInfo {
        let timelock = self.vault_input_lock_time(VaultTransition::Withdrawal(withdrawal_amount));

        // NOTE: The templates are at `depth + 1`, but the scripts are at `depth`
        let master_pubkey = self.master_key(secp, depth);
        let hot_pubkey = self.hot_key(secp, depth);

        let timelocked_withdrawal_script = self.withdrawal_script(secp, depth, timelock);

        let single_recovery_template = self.recovery_template(secp, depth + 1, VaultAmount::ZERO, withdrawal_amount);
        let single_recovery_script = self.recovery_script(secp, depth, &single_recovery_template, 0);

        let double_recovery_script = if vault_total > VaultAmount::ZERO {
            let double_recovery_tx = self.recovery_template(secp, depth + 1, vault_total, withdrawal_amount);

            Some(self.recovery_script(secp, depth, &double_recovery_tx, 1))
        } else {
            None
        };

        WithdrawalOutputInfo {
            single_recovery_script,
            double_recovery_script,
            timelocked_withdrawal_script,
            timelock,
            hot_pubkey,
            master_pubkey,
        }
    }

    /// Generate a single transaction template.
    /// NOTE: assumes that the parameters are valid
    fn transaction_template<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, parameters: &VaultStateParameters, next_states: Option<&VaultGeneration>) -> VaultTransactionTemplate {
        parameters.assert_valid();

        let (vault_total, _withdrawal_amount) = parameters.get_result();

        match parameters.transition {
            VaultTransition::Deposit(deposit_amount) => {
                VaultTransactionTemplate::Deposit(
                    self.deposit_template(secp, depth, deposit_amount, parameters, next_states)
                )
            }
            VaultTransition::Withdrawal(withdrawal_amount) => {
                assert!(VaultAmount::ZERO < withdrawal_amount && withdrawal_amount <= self.max);

                let parent_transition = parameters.parent_transition.expect("withdrawal must have parent transaction");

                let vault_input_lock_time = self.vault_input_lock_time(parent_transition);

                let vault_output = if withdrawal_amount < parameters.previous_value {
                    Some(self.vault_output(secp, depth, parameters, next_states))
                } else {
                    None
                };

                let withdrawal_output_info = self.withdrawal_output_info(secp, depth, withdrawal_amount, vault_total);

                let withdrawal_output = TxOut {
                    value: self.scale.scale_amount(withdrawal_amount),
                    script_pubkey: withdrawal_output_info.script_pubkey(secp),
                };

                VaultTransactionTemplate::Withdrawal(
                    WithdrawalTransactionTemplate {
                        depth,
                        vault_output,
                        withdrawal_output,
                        vault_total,
                        vault_withdrawal: withdrawal_amount,
                        vault_input_lock_time,
                    }
                )
            }
        }
    }

    fn vault_input_lock_time(&self, transition: VaultTransition) -> relative::LockTime {
        match transition {
            VaultTransition::Deposit(_deposit_amount) => relative::LockTime::ZERO,
            VaultTransition::Withdrawal(withdrawal_amount) => {
                let lock_time = u32::saturating_mul(withdrawal_amount.to_unscaled_amount(), self.delay_per_increment);
                let lock_time = u16::try_from(lock_time)
                    .expect("lock time should always fit in 16 bits");

                relative::LockTime::from_height(lock_time)
            }
        }
    }

    /// Iter transitions depth >= 1
    fn iter_tail_transitions(&self) -> impl Iterator<Item=VaultTransition> {
        let withdrawals = (1..=self.max_withdrawal_per_step.0).rev()
            .map(|withdrawal| VaultTransition::Withdrawal(VaultAmount(withdrawal)));

        let deposits = (1..=self.max_deposit_per_step.0)
            .map(|deposit| VaultTransition::Deposit(VaultAmount(deposit)));

        withdrawals.chain(deposits)
    }

    #[inline]
    fn validate_parameters(&self, parameters: VaultStateParameters, depth: Depth) -> Option<VaultStateParameters> {
        if depth > 0 && parameters.previous_value == VaultAmount::ZERO {
            return None;
        }

        if depth == 0 && parameters.parent_transition.is_some() {
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
                if (deposit_amount + parameters.previous_value) > self.max {
                    return None;
                }
            }
            VaultTransition::Withdrawal(withdrawal_amount) => {
                if depth == 0 {
                    return None;
                }

                if parameters.previous_value < withdrawal_amount {
                    return None;
                }
            }
        }

        Some(parameters)
    }

    // FIXME: don't like that we generate *more* transitions than we need then filter, but oh
    // well... for now
    fn state_transitions_single(&self, previous_value: VaultAmount, depth: Depth) -> impl Iterator<Item=VaultStateParameters> {
        self.state_transitions(depth)
            .into_iter()
            .filter(move |parameters| parameters.previous_value == previous_value)
    }

    // FIXME: Would love for this to return an iterator again...
    // but maybe this plays better with rayon
    fn state_transitions(&self, depth: Depth) -> Vec<VaultStateParameters> {
        if depth == 0 {
            (1..=self.max.0)
                .map(|amount| VaultStateParameters {
                    parent_transition: None,
                    previous_value: VaultAmount(0),
                    transition: VaultTransition::Deposit(
                        VaultAmount(amount)
                    ),
                })
                .collect()
        } else if depth == 1 {
            (1..=self.max.0)
                .flat_map(|amount|
                    self.iter_tail_transitions()
                        .filter_map(move |transition|
                             self.validate_parameters(
                                VaultStateParameters {
                                    parent_transition: Some(VaultTransition::Deposit(
                                        VaultAmount(amount)
                                    )),
                                    previous_value: VaultAmount(amount),
                                    transition,
                                },
                                depth,
                            )
                        )
                )
                .collect()
        } else {
            self.iter_tail_transitions()
                .flat_map(|transition| {
                    self.iter_tail_transitions()
                        .map(|transition| Some(transition))
                        .flat_map(move |parent_transition| {
                            (1..=self.max.0)
                                .map(|pv| VaultAmount(pv))
                                .filter_map(move |previous_value| {
                                    self.validate_parameters(
                                        VaultStateParameters {
                                            transition,
                                            previous_value,
                                            parent_transition,
                                        },
                                        depth,
                                    )
                                })
                        })
                })
                .collect()
        }
    }

    fn tx_templates<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, next_states: Option<&VaultGeneration>) -> VaultGeneration {
        self.state_transitions(depth)
            .into_par_iter()
            .map(|parameter| (
                    parameter.clone(),
                    self.transaction_template(secp, depth, &parameter, next_states)
                )
            )
            .collect()
    }

    // TODO: Create some kind of cache structure to speed this up
    fn templates_at_depth<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth) -> VaultGeneration {
        let mut iter = self.iter_templates(secp);

        loop {
            match iter.next_with_depth() {
                Some((this_depth, _generation)) => {
                    if this_depth == depth {
                        return iter.generation
                            // FIXME: maybe eliminate panic, but this *is* safe
                            .expect("iterator must have a valid generation already here");
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

#[derive(Clone, Debug)]
enum VaultHistoryTransactionDetails {
    VaultDeposit {
        deposit_amount: VaultAmount,
        vout: u32,
    },
    VaultWithdrawal {
        withdrawal_amount: VaultAmount,
        vout: Option<u32>,
    },
    #[allow(dead_code)]
    KeySpend {
        // TODO: Is there anything we need to track here? That's kind of final, the vault is closed
    },
    #[allow(dead_code)]
    Recovery {
        /// The TXID of the transaction that recovered the withdrawal output, if relevant
        withdrawal_txid: Option<Txid>,
        /// The TXID of the transaction that recovered the withdrawal output, if relevant
        // FIXME: redundant with VaultHistoryTransaction::txid but it's ok for now
        // I don't want to overcomplicate VaultHistoryTransaction right now.
        // Actually, maybe store this externally, in some other data structure
        vault_txid: Option<Txid>,
    },
}

impl VaultHistoryTransactionDetails {
    fn try_into_transition(&self) -> Option<VaultTransition> {
        match self {
            VaultHistoryTransactionDetails::VaultDeposit { deposit_amount, .. } =>
                Some(VaultTransition::Deposit(*deposit_amount)),
            VaultHistoryTransactionDetails::VaultWithdrawal { withdrawal_amount, .. } =>
                Some(VaultTransition::Withdrawal(*withdrawal_amount)),
            _ => None,
        }
    }
}

#[derive(Clone,Copy,Debug)]
/// Indicates what kind of vault transaction was found that cannot be
/// represented as a [`VaultTransition`].
pub enum InvalidTransitionError {
    KeySpend,
    Recovery,
}

#[derive(Clone,Debug)]
pub struct VaultHistoryTransaction {
    txid: Txid,
    #[allow(dead_code)]
    depth: Depth,
    transition: VaultHistoryTransactionDetails,
    result_value: VaultAmount,
}

impl VaultHistoryTransaction {
    // XXX: I wonder if this awkward abstraction is indicating a design issue
    fn from_transition(previous_value: VaultAmount, transition: VaultTransition, depth: Depth, txid: Txid) -> Self {
        let details = match transition {
            VaultTransition::Deposit(amount) => VaultHistoryTransactionDetails::VaultDeposit {
                deposit_amount: amount,
                vout: 0,
            },
            VaultTransition::Withdrawal(amount) => VaultHistoryTransactionDetails::VaultWithdrawal {
                withdrawal_amount: amount,
                vout: VaultTransactionTemplate::vault_transition_vout(
                    previous_value,
                    transition,
                ),
            },
        };

        let result_value = previous_value
            // FIXME: Should we enforce max?
            .apply_transition(transition, None)
            //FIXME: undesirable panic potential
            .expect("transition should be valid already");

        Self {
            txid,
            depth,
            transition: details,
            result_value,
        }
    }

    /// Get the vault outpoint if it exists
    pub fn outpoint(&self) -> Option<OutPoint> {
        match self.transition {
            VaultHistoryTransactionDetails::VaultDeposit { vout, .. } =>
                Some(OutPoint {txid: self.txid, vout}),
            VaultHistoryTransactionDetails::VaultWithdrawal { vout, .. } =>
                vout.map(|vout| OutPoint{ txid: self.txid, vout}),
            _ => None,
        }
    }

    pub fn into_parameters(&self,
        parent_transition: Option<VaultTransition>,
        max: Option<VaultAmount>
    ) -> Option<VaultStateParameters> {
        let transition = self.transition
            .try_into_transition()?;

        self.result_value
            .apply_transition(
                transition.invert(),
                max,
            )
            .map(|previous_value| {
                VaultStateParameters {
                    transition,
                    previous_value,
                    parent_transition,
                }
            })
    }

    /// Create parameters representing the child transaction with the given transition
    /// Does not validate the resulting parameters against the Vault's constraints
    pub fn to_child_parameters(&self, transition: VaultTransition) -> Result<VaultStateParameters, InvalidTransitionError> {
        let parent_transition = match self.transition {
            VaultHistoryTransactionDetails::VaultDeposit { deposit_amount, .. } => VaultTransition::Deposit(deposit_amount),
            VaultHistoryTransactionDetails::VaultWithdrawal { withdrawal_amount, .. } => VaultTransition::Withdrawal(withdrawal_amount),
            VaultHistoryTransactionDetails::KeySpend {  } => { return Err(InvalidTransitionError::KeySpend) }
            VaultHistoryTransactionDetails::Recovery { .. } => { return Err(InvalidTransitionError::Recovery) }
        };

        Ok(
            VaultStateParameters {
                transition,
                previous_value: self.result_value,
                parent_transition: Some(parent_transition),
            }
        )
    }
}

#[derive(Debug)]
pub enum VaultInitializationError {
    MigrationError(MigrationError),
    ConfigurationError(rusqlite::Error),
}

#[derive(Clone,Copy,Debug)]
pub enum DepositCreationError {
    InsufficientFunds,
    InvalidDepositAmount,
    VaultClosed,
    /// Vault has used all of its available operations, use the cold key to move to a new vault
    VaultExpired,
    VaultOverflow(VaultAmount),
}

#[derive(Clone,Copy,Debug)]
pub enum WithdrawalCreationError {
    InsufficientFunds,
    InvalidWithdrawalAmount,
    MissingTransactionTemplate,
    VaultClosed,
    FeeOverflow,
    MissingSpendInfo,
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
        VaultExtendedKeyDerivationPath::HotKey(self.0)
            .to_derivation_path()
    }

    pub fn to_cold_derivation_path(&self) -> DerivationPath {
        VaultExtendedKeyDerivationPath::ColdKey(self.0)
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

#[cfg(feature = "bitcoind")]
#[derive(Debug)]
pub enum SubmitPackageError {
    RpcError(bitcoincore_rpc::Error),
    Error(serde_json::Value),
}

#[cfg(feature = "bitcoind")]
pub trait SubmitPackage {
    fn submit_package(&self, transactions: &[&Transaction]) -> Result<(), SubmitPackageError>;
}

#[cfg(feature = "bitcoind")]
impl SubmitPackage for Client {
    fn submit_package(&self, transactions: &[&Transaction]) -> Result<(), SubmitPackageError> {
        let transactions: serde_json::Value = transactions
            .into_iter()
            .map(|e| serialize_hex(e))
            .collect();

        let result: serde_json::Value = self.call(
            "submitpackage",
            vec![transactions].as_ref(),
        )
        .map_err(|e| SubmitPackageError::RpcError(e))?;

        if result.get("package_msg") == Some(&"success".into()) {
            Ok(())
        } else {
            Err(SubmitPackageError::Error(result))
        }
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
}

impl PartialEq<Script> for SignedNextStateTemplate {
    fn eq(&self, other: &Script) -> bool {
        self.to_scriptbuf().as_script() == other
    }
}

#[derive(Clone,Hash,Eq,PartialEq)]
enum RecoveryType {
    VaultOnly,
    VaultWithWithdrawal,
}

#[derive(Clone,Hash,Eq,PartialEq)]
enum VaultOutputSpendCondition {
    Deposit(VaultAmount),
    Withdrawal(VaultAmount),
    Recovery {
        recovery_type: RecoveryType,
        vault_balance: VaultAmount,
        withdrawal_amount: VaultAmount,
    },
}

#[derive(Clone,Debug)]
struct VaultOutputSigningInfo {
    pubkey: XOnlyPublicKey,
    control_block: ControlBlock,
    vault_prevout: TxOut,
    //depth: Depth,
    script: ScriptBuf,
}

impl VaultOutputSigningInfo {
    fn sign<C: Signing, T: Borrow<TxOut>>(&self, secp: &Secp256k1<C>, keypair: &Keypair, transaction: &Transaction, prevouts: &Prevouts<T>) -> Result<taproot::Signature, sighash::TaprootError> {
        let tap_leaf_hash = TapLeafHash::from_script(self.script.as_ref(), LeafVersion::TapScript);
        let sighash = SighashCache::new(transaction)
            .taproot_signature_hash(0, prevouts, None, Some((tap_leaf_hash, 0xFFFFFFFF)), TapSighashType::Default)?;

        // FIXME: seems like there should be shortcuts for a couple of these things?
        let message: Message = sighash.into();
        let signature = secp.sign_schnorr(&message, keypair);

        Ok(taproot::Signature {
            signature,
            sighash_type: TapSighashType::Default,
        })
    }

    pub fn build_witness(&self, signature: taproot::Signature) -> Witness {
        let mut witness = Witness::new();
        witness.push(signature.to_vec());
        witness.push(&self.script);
        witness.push(self.control_block.serialize());

        witness
    }
}

pub struct VaultOutputSpendInfo {
    spend_info: TaprootSpendInfo,
    output: TxOut,
    depth: Depth,
    branches: HashMap<VaultOutputSpendCondition, SignedNextStateTemplate>,
}

#[derive(Clone,Debug)]
pub enum DepositSignError {
    NoSignatureNeeded,
    SighashError(sighash::TaprootError),
    NoShapeTransaction,
}

#[derive(Clone,Debug)]
pub enum WithdrawalSignError {
    SighashError(sighash::TaprootError),
}

#[derive(Debug)]
pub enum KeypairDerivationError {
    WrongKey,
    DerivationDepthExceeded,
    NoSigningInfo,
}

pub struct Vault {
    #[allow(dead_code)]
    id: VaultId,
    parameters: VaultParameters,
    history: Vec<(VaultHistoryTransaction, Option<(u32, BlockHash)>)>,
}

#[derive(Debug)]
pub enum CreateVaultError {
    SqliteError(rusqlite::Error),
}

#[derive(Debug)]
enum ConnectForeignTransactionError {
    InvalidWitness,
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

    #[allow(unused)]
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

    pub fn store(&self, _connection: &mut Connection) -> Result<Self, rusqlite::Error> {
        todo!()
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

    // Had to make static to satisfy borrow checker
    // TODO: Handle key spend (master key)
    #[allow(dead_code)]
    fn try_connect_foreign_tx<C: Verification>(secp: &Secp256k1<C>, parameters: &VaultParameters, previous_tx: &VaultHistoryTransaction, transaction: &Transaction, input_index: u32) -> Result<VaultHistoryTransaction, ConnectForeignTransactionError> {
        let depth = previous_tx.depth + 1;

        let template_hash = get_default_template(&transaction, input_index);

        let transitions: Vec<(VaultStateParameters, VaultTransactionTemplate)> = parameters
            .templates_at_depth(secp, depth)
            .into_iter()
            .filter(|(_state, vtt)| vtt.vault_template_hash() == template_hash)
            .collect();

        if transitions.is_empty() {
            let input = &transaction.input[input_index as usize];
            if input.witness.len() > 2 {
                return Err(ConnectForeignTransactionError::InvalidWitness);
            } else if input.witness.len() > 1 {
                if input.witness[1][0] != 0x50 {
                    return Err(ConnectForeignTransactionError::InvalidWitness);
                }
            }

            // Empty witness
            if input.witness.len() < 1 {
                return Err(ConnectForeignTransactionError::InvalidWitness);
            }

            if input.witness[0].len() != 64 && input.witness[0].len() != 65 {
                return Err(ConnectForeignTransactionError::InvalidWitness);
            }

            // Probably should identify if it's a key spend
            todo!("what to do if there is an unknown transition")
        } else {
            let (state, _vault_transaction_template) = transitions
                .into_iter()
                .filter(|(state, _vtt)| state.previous_value == previous_tx.result_value)
                .next()
                .expect("there must be a matching transition");

            Ok(
                // FIXME: should this be from state
                VaultHistoryTransaction::from_transition(
                    state.previous_value,
                    state.transition,
                    depth,
                    transaction.compute_txid()
                )
            )
        }
    }

    #[cfg(feature = "bitcoind")]
    pub fn apply_block<C: Verification>(&mut self, secp: &Secp256k1<C>, block: &Block, block_height: u32) -> usize {
        let mut block_txes = block.txdata.iter();

        let mut previous_tx: Option<&VaultHistoryTransaction> = None;
        let mut iter = self.history.iter_mut();
        while let Some((ref mut history_tx, ref mut confirmation)) = iter.next() {
            if confirmation.map(|(tx_height, _block)| tx_height >= block_height).unwrap_or(true) {
                if confirmation.is_some() {
                    //eprintln!("reorg at height {block_height}!");
                }

                // clear the previously seen block inclusion
                *confirmation = None;

                while confirmation.is_none() {
                    if let Some(block_tx) = block_txes.next() {
                        if block_tx.compute_txid() == history_tx.txid {
                            //eprintln!("found tx {}", history_tx.txid);
                            *confirmation = Some((block_height, block.block_hash()));
                            continue;
                        } else if let Some(previous_tx) = previous_tx {
                            if let Some(history_outpoint) = previous_tx.outpoint() {
                                for (input_index, txin) in block_tx.input.iter().enumerate() {
                                    if txin.previous_output == history_outpoint {
                                        *history_tx = Self::try_connect_foreign_tx(secp, &self.parameters, previous_tx, block_tx, input_index as u32)
                                            // FIXME: a key spend will cause a panic!
                                            .expect("tx can only be spent by a valid transition tx");
                                    }
                                }
                            } else {
                                // If we're here we have (unconfirmed) history after the final
                                // vault transaction and something is very wrong
                                unreachable!("final vault transactions can't have child transactions");
                            }
                        }
                    } else {
                        break;
                    }
                }
            }

            previous_tx = Some(history_tx);
        }

        // If there's more transactions left, process them this way
        while let Some(block_tx) = block_txes.next() {
            // This awkward code ensures we're not holding a reference to self.history
            // (via previous_tx) when we go to append the history item
            let history_item = if let Some((previous_tx, _)) = self.history.last() {
                if let Some(history_outpoint) = previous_tx.outpoint() {
                    // FIXME: will not properly handle a transaction that keyspends both the
                    // withdrawal and vault outputs in the same transaction, but we don't handle
                    // keyspends at all right now.
                    let mut input_iter = block_tx.input.iter().enumerate();
                    loop {
                        if let Some((input_index, txin)) = input_iter.next() {
                            if txin.previous_output == history_outpoint {
                                //eprintln!("foreign transaction {}", block_tx.compute_txid());
                                let history_tx = Self::try_connect_foreign_tx(secp, &self.parameters, &previous_tx, block_tx, input_index as u32)
                                    // FIXME: a key spend will cause a panic!
                                    .expect("tx can only be spent by a valid transition tx");

                                break Some(
                                    (
                                        history_tx,
                                        Some((block_height, block.block_hash())),
                                    )
                                );
                            }
                        } else {
                            break None;
                        }
                    }
                } else {
                    // If we're here we have (unconfirmed) history after the final
                    // vault transaction and something is very wrong
                    unreachable!("final vault transactions can't have child transactions")
                }
            } else {
                None
            };

            if let Some(history_item) = history_item {
                self.history.push(history_item);
            }
        }

        return self.history.len();
    }

    // FIXME: I think this should be refactored into a stateless version on VaultParameters
    //  FIXME: return value should probably also have some kind of token for keeping track of
    //  replacements, preventing invalid deposit transactions from being tracked
    pub fn create_deposit<C: Verification>(&self, secp: &Secp256k1<C>, deposit_amount: VaultAmount) -> Result<DepositTransaction, DepositCreationError> {
        if let Some((tx, _)) = self.history.last() {
            if deposit_amount > self.parameters.max_deposit_per_step {
                return Err(DepositCreationError::InvalidDepositAmount);
            }

            // Ensure vault_total <= self.parameters.max
            let vault_total = tx.result_value + deposit_amount;
            let overflow_amount = vault_total
                .checked_sub(self.parameters.max);

            if let Some(overflow_amount) = overflow_amount {
                if overflow_amount > VaultAmount::ZERO {
                    return Err(DepositCreationError::VaultOverflow(overflow_amount));
                }
            }
        }

        let depth = self.get_current_depth();

        // TODO: let the caller provide this state
        let transactions = self.parameters.templates_at_depth(secp, depth);

        let (parameters, outpoint) = match self.history.last() {
            Some((transaction, _)) => {
                let outpoint = transaction
                    .outpoint()
                    .ok_or(DepositCreationError::VaultClosed)?;

                (
                    transaction
                        .to_child_parameters(VaultTransition::Deposit(deposit_amount))
                        .map_err(|_| DepositCreationError::VaultClosed)?,
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

        let deposit = if let Some(deposit) = transactions.get(&parameters) {
            deposit.clone()
        } else {
            panic!("invalid deposit parameters")
        };

        let master = self.parameters.master_key(secp, depth);

        match deposit {
            VaultTransactionTemplate::Deposit(DepositTransactionTemplate::InitialDeposit(deposit)) =>
                Ok(
                    DepositTransaction::InitialDeposit(
                        deposit.instantiate(master)
                    )
                ),
            VaultTransactionTemplate::Deposit(DepositTransactionTemplate::Deposit(deposit)) => {
                let spend_info = self.last_state_parameters()
                    .expect("transaction history must always be valid")
                    .map(|parent_parameters| {
                        debug_assert!(depth > 0, "Depth 0 has no ancestors");

                        let parent_depth = depth - 1;

                        let parent_templates = self.parameters.templates_at_depth(secp, depth);

                        let parent_txout = self.parameters.vault_output(
                            secp,
                            parent_depth,
                            &parent_parameters,
                            Some(&parent_templates),
                        );

                        let spend_conditions = self.parameters.vault_output_spend_conditions(secp, parent_depth, &parent_parameters, &parent_templates);

                        let master_key = self.parameters.master_key(secp, parent_depth);

                        let spend_info = TaprootBuilder::with_huffman_tree(
                                spend_conditions.iter().map(|(condition, script)| (self.parameters.spend_condition_weight(&condition), script.to_scriptbuf()))
                            )
                            .expect("taproot tree builder")
                            .finalize(secp, master_key)
                            .expect("taproot tree finalize");

                        VaultOutputSpendInfo {
                            spend_info,
                            depth: parent_depth,
                            branches: spend_conditions.into_iter().collect(),
                            output: parent_txout,
                        }
                    })
                    .expect("tail deposits have transaction history");

                let vault_outpoint = outpoint.expect("non-initial deposit must have outpoint of previous vault");

                let branch = spend_info
                    .branches
                    .get(&VaultOutputSpendCondition::Deposit(deposit_amount))
                    .expect("spend condition should exist");

                // TODO: make control_block construction as lazy as possible
                // Low priority, especially if it makes something later on need to be fallible when
                // it wouldn't otherwise be
                let control_block = spend_info.spend_info.control_block(&(
                    branch.to_scriptbuf(),
                    LeafVersion::TapScript
                ))
                .expect("if the branch exists so should the control block");

                let signing_info = VaultOutputSigningInfo {
                    pubkey: self.parameters.hot_key(&secp, spend_info.depth),
                    control_block,
                    vault_prevout: spend_info.output,
                    //depth: spend_info.depth,
                    script: branch.to_scriptbuf(),
                };

                let tail_deposit_tx = deposit.intantiate(vault_outpoint, master, signing_info);

                assert_eq!(
                    branch.next_state_template_hash,
                    tail_deposit_tx.vault_template_hash(),
                );

                Ok(
                    DepositTransaction::Deposit(tail_deposit_tx)
                )
            }
            _ => unreachable!("deposit transaction template must be a deposit transaction..."),
        }
    }

    // FIXME: consider how much validation we want to do here. Maybe we should just ensure
    // self.history is always valid, makes more sense
    fn history_to_parameters(&self, tx: &VaultHistoryTransaction, parent_tx: Option<&VaultHistoryTransaction>) -> Result<VaultStateParameters, HistoryToParametersError> {
        let parent_transition = match parent_tx {
            Some(parent_tx) => Some(
                parent_tx.transition
                    .try_into_transition()
                    .ok_or(HistoryToParametersError::InvalidParentDepth)?
            ),
            None => None,
        };

        let parameters = tx.into_parameters(
            parent_transition,
            Some(self.parameters.max)
        )
        .and_then(|parameters| self.parameters.validate_parameters(parameters, tx.depth))
        .ok_or(HistoryToParametersError::InvalidParameters)?;

        if let Some(parent_tx) = parent_tx {
            if parent_tx.depth + 1 != tx.depth {
                return Err(HistoryToParametersError::InvalidParentDepth);
            }

            let transition = &tx.transition
                .try_into_transition()
                .ok_or(HistoryToParametersError::InvalidParameters)?;

            let expected_parent_result_value = tx
                .result_value
                .apply_transition(
                    transition.invert(),
                    Some(self.parameters.max),
                );

            if let Some(expected_value) = expected_parent_result_value {
                if expected_value != parent_tx.result_value {
                    return Err(HistoryToParametersError::InconsistentParameters);
                }
            } else {
                return Err(HistoryToParametersError::InvalidParameters);
            }
        }

        Ok(parameters)
    }

    fn last_state_parameters(&self) -> Result<Option<VaultStateParameters>, HistoryToParametersError> {
        let parent_tx = if self.history.len() >= 2 {
            Some(&self.history[self.history.len() - 2].0)
        } else {
            None
        };

        if let Some((ref tx, _)) = self.history.last() {
            self.history_to_parameters(tx, parent_tx)
                .map(|parameters| Some(parameters))
        } else {
            Ok(None)
        }
    }

    pub fn create_withdrawal<C: Verification>(&self, secp: &Secp256k1<C>, withdrawal_amount: VaultAmount) -> Result<WithdrawalTransaction, WithdrawalCreationError> {
        let depth = self.get_current_depth();

        let transition = VaultTransition::Withdrawal(withdrawal_amount);
        let current_vault_amount = self.history.last()
            .map(|(tx, _)| tx.result_value)
            .unwrap_or(VaultAmount::ZERO);

        let (last_vault_transaction, _) = self.history.last()
            .ok_or(WithdrawalCreationError::VaultClosed)?;

        let previous_output = last_vault_transaction.outpoint()
            .ok_or(WithdrawalCreationError::VaultClosed)?;

        let vault_total = current_vault_amount.apply_transition(transition, None)
            .ok_or(WithdrawalCreationError::InsufficientFunds)?;

        let parameters = last_vault_transaction
            .to_child_parameters(VaultTransition::Withdrawal(withdrawal_amount))
            .map_err(|_| WithdrawalCreationError::VaultClosed)?;

        // FIXME: maybe this should return a Result<> instead so I can disambiguate cases
        self.parameters.validate_parameters(parameters, depth)
            .ok_or(WithdrawalCreationError::InsufficientFunds)?;

        let templates = self.parameters.templates_at_depth(secp, depth);

        let vault_tx_template = templates.get(&parameters)
            .ok_or(WithdrawalCreationError::MissingTransactionTemplate)?;

        let withdrawal_template = match vault_tx_template {
            VaultTransactionTemplate::Deposit(_) => unreachable!("withdrawal transition must produce a withdrawal transaction template"),
            VaultTransactionTemplate::Withdrawal(withdrawal) => withdrawal,
        };

        let spend_info = self.last_state_parameters()
            .expect("transaction history must always be valid")
            .map(|parent_parameters| {
                debug_assert!(depth > 0, "Depth 0 has no ancestors");

                let parent_depth = depth - 1;

                // TODO: should be able to pass in a cached list
                let templates = self.parameters.templates_at_depth(secp, depth);

                let parent_txout = self.parameters.vault_output(
                    secp,
                    parent_depth,
                    &parent_parameters,
                    Some(&templates),
                );

                let spend_conditions = self.parameters.vault_output_spend_conditions(secp, parent_depth, &parent_parameters, &templates);

                let master_key = self.parameters.master_key(secp, parent_depth);

                let spend_info = TaprootBuilder::with_huffman_tree(
                        spend_conditions.iter().map(|(condition, script)| (self.parameters.spend_condition_weight(&condition), script.to_scriptbuf()))
                    )
                    .expect("taproot tree builder")
                    .finalize(secp, master_key)
                    .expect("taproot tree finalize");

                VaultOutputSpendInfo {
                    spend_info,
                    depth: parent_depth,
                    branches: spend_conditions.into_iter().collect(),
                    output: parent_txout,
                }
            })
            .ok_or(WithdrawalCreationError::MissingSpendInfo)?;

        let branch = spend_info.branches.get(&VaultOutputSpendCondition::Withdrawal(withdrawal_amount))
            .ok_or(WithdrawalCreationError::InvalidWithdrawalAmount)?;

        let control_block = spend_info.spend_info.control_block(&(
                branch.to_scriptbuf(),
                LeafVersion::TapScript
        ))
        .expect("if the branch exists so should the control block");

        assert_eq!(
            branch.next_state_template_hash,
            withdrawal_template.vault_template_hash(),
        );

        let signing_info = VaultOutputSigningInfo {
                pubkey: self.parameters.hot_key(&secp, spend_info.depth),
                control_block,
                vault_prevout: spend_info.output,
                script: branch.to_scriptbuf(),
            };

        let withdrawal_output_info = self.parameters.withdrawal_output_info(secp, depth, withdrawal_amount, vault_total);

        let withdrawal = withdrawal_template.instantiate(previous_output, signing_info, withdrawal_output_info);
        // Need to generate taproot spend info
        Ok(withdrawal)
    }

    pub fn add_transaction(&mut self, tx: VaultTransaction) -> Result<(), ()> {
        let history_tx = match tx {
            VaultTransaction::Deposit(deposit) => {
                if (deposit.common().depth as usize) != self.history.len() {
                    return Err(());
                }

                VaultHistoryTransaction {
                    txid: deposit.compute_txid().map_err(|_| ())?,
                    depth: deposit.common().depth,
                    transition: VaultHistoryTransactionDetails::VaultDeposit {
                        deposit_amount: deposit.common().vault_deposit,
                        vout: deposit.vout(),
                    },
                    result_value: deposit.common().vault_total,
                }
            }
            VaultTransaction::Withdrawal(withdrawal) => {
                if (withdrawal.depth as usize) != self.history.len() {
                    return Err(());
                }

                VaultHistoryTransaction {
                    txid: withdrawal.compute_txid(),
                    depth: withdrawal.depth,
                    transition: VaultHistoryTransactionDetails::VaultWithdrawal {
                        withdrawal_amount: withdrawal.vault_withdrawal,
                        vout: withdrawal.vout(),
                    },
                    result_value: withdrawal.vault_total,
                }
            }
        };

        self.history.push((history_tx, None));

        Ok(())
    }

    pub fn to_vault_amount(&self, amount: Amount) -> Result<(VaultAmount, Amount), VaultAmountError> {
        self.parameters.scale.convert_amount(amount)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use bitcoin::bip32::Xpriv;

    use bitcoin::secp256k1::Signing;

    use std::str::FromStr;

    fn deposit(amount: u32) -> VaultTransition {
        VaultTransition::Deposit(VaultAmount(amount))
    }

    fn withdrawal(amount: u32) -> VaultTransition {
        VaultTransition::Withdrawal(VaultAmount(amount))
    }

    fn v(amount: u32) -> VaultAmount {
        VaultAmount(amount)
    }

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

    #[test]
    fn test_history_to_parameters() {
        let secp = Secp256k1::new();
        let (cold_xpriv, hot_xpriv) = test_xprivs(&secp, 0);

        let parameters = VaultParameters {
            scale: VaultScale::from_sat(100_000_000),
            max: VaultAmount::new(10),
            cold_xpub: Xpub::from_priv(&secp, &cold_xpriv), //
            hot_xpub: Xpub::from_priv(&secp, &hot_xpriv),  //
            delay_per_increment: 36,
            max_withdrawal_per_step: VaultAmount::new(3),
            max_deposit_per_step: VaultAmount::new(3),
            max_depth: 10,
        };

        let dummy_txid = Txid::from_byte_array([0; 32]);

        let vault = Vault {
            id: 0,
            parameters,
            history: Vec::new(),
        };

        let result_parameters = vault.history_to_parameters(
            &VaultHistoryTransaction::from_transition(
                VaultAmount(1),
                VaultTransition::Withdrawal(VaultAmount(1)),
                1,
                dummy_txid,
            ),
            Some(
                &VaultHistoryTransaction::from_transition(
                    VaultAmount::ZERO,
                    VaultTransition::Deposit(VaultAmount(1)),
                    1,
                    dummy_txid,
                )
            ),
        );

        result_parameters.expect_err("Gen 0 has no parents");

        let result_parameters = vault.history_to_parameters(
            &VaultHistoryTransaction::from_transition(
                VaultAmount(1),
                VaultTransition::Withdrawal(VaultAmount(1)),
                0,
                dummy_txid,
            ),
            None,
        );

        result_parameters.expect_err("Gen 0 can't be a withdrawal");

        let result_parameters = vault.history_to_parameters(
            &VaultHistoryTransaction::from_transition(
                VaultAmount(1),
                VaultTransition::Withdrawal(VaultAmount(1)),
                1,
                dummy_txid,
            ),
            Some(&VaultHistoryTransaction::from_transition(
                    VaultAmount(0),
                    VaultTransition::Deposit(VaultAmount(1)),
                    0,
                    dummy_txid,
                ),
            ),
        )
        .unwrap();

        assert_eq!(
            result_parameters,
            VaultStateParameters {
                transition: VaultTransition::Withdrawal(VaultAmount(1)),
                previous_value: VaultAmount(1),
                parent_transition: Some(VaultTransition::Deposit(VaultAmount(1))),
            },
        );

        let result_parameters = vault.history_to_parameters(
            &VaultHistoryTransaction::from_transition(
                VaultAmount(2),
                VaultTransition::Withdrawal(VaultAmount(2)),
                1,
                dummy_txid,
            ),
            Some(
                &VaultHistoryTransaction::from_transition(
                    VaultAmount::ZERO,
                    VaultTransition::Deposit(VaultAmount(1)),
                    0,
                    dummy_txid,
                )
            ),
        );

        result_parameters.expect_err("Can't withdraw more than vault total");

        let result_parameters = vault.history_to_parameters(
            &VaultHistoryTransaction::from_transition(
                VaultAmount(2),
                VaultTransition::Withdrawal(VaultAmount(1)),
                1,
                dummy_txid,
            ),
            Some(
                &VaultHistoryTransaction::from_transition(
                    VaultAmount(0),
                    VaultTransition::Deposit(VaultAmount(2)),
                    0,
                    dummy_txid,
                )
            ),
        )
        .unwrap();

        assert_eq!(
            result_parameters,
            VaultStateParameters {
                transition: VaultTransition::Withdrawal(VaultAmount(1)),
                previous_value: VaultAmount(2),
                parent_transition: Some(VaultTransition::Deposit(VaultAmount(2))),
            },
        );

        let result_parameters = vault.history_to_parameters(
            &VaultHistoryTransaction::from_transition(
                VaultAmount(2),
                VaultTransition::Deposit(VaultAmount(1)),
                1,
                dummy_txid,
            ),
            Some(
                &VaultHistoryTransaction::from_transition(
                    VaultAmount::ZERO,
                    VaultTransition::Deposit(VaultAmount(2)),
                    0,
                    dummy_txid,
                )
            ),
        )
        .unwrap();

        assert_eq!(
            result_parameters,
            VaultStateParameters {
                transition: VaultTransition::Deposit(VaultAmount(1)),
                previous_value: VaultAmount(2),
                parent_transition: Some(VaultTransition::Deposit(VaultAmount(2))),
            },
        );

        // TODO: more tests
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

        let mut initial_deposits = test_parameters.state_transitions(0);
        initial_deposits.sort();

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

        let mut generation = test_parameters.state_transitions(1);
        generation.sort();

        assert_eq!(
            generation,
            vec![
                VaultStateParameters {
                    transition: withdrawal(1),
                    previous_value: VaultAmount(1),
                    parent_transition: Some(deposit(1)),
                },
                VaultStateParameters {
                    transition: deposit(1),
                    previous_value: VaultAmount(1),
                    parent_transition: Some(deposit(1)),
                },
                VaultStateParameters {
                    transition: deposit(2),
                    previous_value: VaultAmount(1),
                    parent_transition: Some(deposit(1)),
                },
                VaultStateParameters {
                    transition: deposit(3),
                    previous_value: VaultAmount(1),
                    parent_transition: Some(deposit(1)),
                },

                VaultStateParameters {
                    transition: withdrawal(2),
                    previous_value: VaultAmount(2),
                    parent_transition: Some(deposit(2)),
                },
                VaultStateParameters {
                    transition: withdrawal(1),
                    previous_value: VaultAmount(2),
                    parent_transition: Some(deposit(2)),
                },
                VaultStateParameters {
                    transition: deposit(1),
                    previous_value: VaultAmount(2),
                    parent_transition: Some(deposit(2)),
                },
                VaultStateParameters {
                    transition: deposit(2),
                    previous_value: VaultAmount(2),
                    parent_transition: Some(deposit(2)),

                },

                VaultStateParameters {
                    transition: withdrawal(3),
                    previous_value: VaultAmount(3),
                    parent_transition: Some(deposit(3)),
                },
                VaultStateParameters {
                    transition: withdrawal(2),
                    previous_value: VaultAmount(3),
                    parent_transition: Some(deposit(3)),
                },
                VaultStateParameters {
                    transition: withdrawal(1),
                    previous_value: VaultAmount(3),
                    parent_transition: Some(deposit(3)),
                },
                VaultStateParameters {
                    transition: deposit(1),
                    previous_value: VaultAmount(3),
                    parent_transition: Some(deposit(3)),
                },

                VaultStateParameters {
                    transition: withdrawal(3),
                    previous_value: VaultAmount(4),
                    parent_transition: Some(deposit(4)),
                },
                VaultStateParameters {
                    transition: withdrawal(2),
                    previous_value: VaultAmount(4),
                    parent_transition: Some(deposit(4)),
                },
                VaultStateParameters {
                    transition: withdrawal(1),
                    previous_value: VaultAmount(4),
                    parent_transition: Some(deposit(4)),
                },
            ],
        );

        let mut generation = test_parameters.state_transitions(2);
        generation.sort();

        assert_eq!(
            generation,
            vec![
                VaultStateParameters {
                    transition: withdrawal(1),
                    previous_value: v(1),
                    parent_transition: Some(withdrawal(3)),
                },
                VaultStateParameters {
                    transition: deposit(1),
                    previous_value: v(1),
                    parent_transition: Some(withdrawal(3)),
                },
                VaultStateParameters {
                    transition: deposit(2),
                    previous_value: v(1),
                    parent_transition: Some(withdrawal(3)),
                },
                VaultStateParameters {
                    transition: deposit(3),
                    previous_value: v(1),
                    parent_transition: Some(withdrawal(3)),
                },

                VaultStateParameters {
                    transition: withdrawal(1),
                    previous_value: v(1),
                    parent_transition: Some(withdrawal(2)),
                },
                VaultStateParameters {
                    transition: deposit(1),
                    previous_value: v(1),
                    parent_transition: Some(withdrawal(2)),
                },
                VaultStateParameters {
                    transition: deposit(2),
                    previous_value: v(1),
                    parent_transition: Some(withdrawal(2)),
                },
                VaultStateParameters {
                    transition: deposit(3),
                    previous_value: v(1),
                    parent_transition: Some(withdrawal(2)),
                },
                VaultStateParameters {
                    transition: withdrawal(2),
                    previous_value: v(2),
                    parent_transition: Some(withdrawal(2)),
                },
                VaultStateParameters {
                    transition: withdrawal(1),
                    previous_value: v(2),
                    parent_transition: Some(withdrawal(2)),
                },
                VaultStateParameters {
                    transition: deposit(1),
                    previous_value: v(2),
                    parent_transition: Some(withdrawal(2)),
                },
                VaultStateParameters {
                    transition: deposit(2),
                    previous_value: v(2),
                    parent_transition: Some(withdrawal(2)),
                },

                VaultStateParameters {
                    transition: withdrawal(1),
                    previous_value: v(1),
                    parent_transition: Some(withdrawal(1)),
                },
                VaultStateParameters {
                    transition: deposit(1),
                    previous_value: v(1),
                    parent_transition: Some(withdrawal(1)),
                },
                VaultStateParameters {
                    transition: deposit(2),
                    previous_value: v(1),
                    parent_transition: Some(withdrawal(1)),
                },
                VaultStateParameters {
                    transition: deposit(3),
                    previous_value: v(1),
                    parent_transition: Some(withdrawal(1)),
                },

                VaultStateParameters {
                    transition: withdrawal(2),
                    previous_value: v(2),
                    parent_transition: Some(withdrawal(1)),
                },
                VaultStateParameters {
                    transition: withdrawal(1),
                    previous_value: v(2),
                    parent_transition: Some(withdrawal(1)),
                },
                VaultStateParameters {
                    transition: deposit(1),
                    previous_value: v(2),
                    parent_transition: Some(withdrawal(1)),
                },
                VaultStateParameters {
                    transition: deposit(2),
                    previous_value: v(2),
                    parent_transition: Some(withdrawal(1)),
                },
                VaultStateParameters {
                    transition: withdrawal(3),
                    previous_value: v(3),
                    parent_transition: Some(withdrawal(1)),
                },
                VaultStateParameters {
                    transition: withdrawal(2),
                    previous_value: v(3),
                    parent_transition: Some(withdrawal(1)),
                },
                VaultStateParameters {
                    transition: withdrawal(1),
                    previous_value: v(3),
                    parent_transition: Some(withdrawal(1)),
                },
                VaultStateParameters {
                    transition: deposit(1),
                    previous_value: v(3),
                    parent_transition: Some(withdrawal(1)),
                },

                VaultStateParameters {
                    transition: withdrawal(1),
                    previous_value: v(1),
                    parent_transition: Some(deposit(1)),
                },
                VaultStateParameters {
                    transition: deposit(1),
                    previous_value: v(1),
                    parent_transition: Some(deposit(1)),
                },
                VaultStateParameters {
                    transition: deposit(2),
                    previous_value: v(1),
                    parent_transition: Some(deposit(1)),
                },
                VaultStateParameters {
                    transition: deposit(3),
                    previous_value: v(1),
                    parent_transition: Some(deposit(1)),
                },

                VaultStateParameters {
                    transition: withdrawal(2),
                    previous_value: v(2),
                    parent_transition: Some(deposit(1)),
                },
                VaultStateParameters {
                    transition: withdrawal(1),
                    previous_value: v(2),
                    parent_transition: Some(deposit(1)),
                },
                VaultStateParameters {
                    transition: deposit(1),
                    previous_value: v(2),
                    parent_transition: Some(deposit(1)),
                },
                VaultStateParameters {
                    transition: deposit(2),
                    previous_value: v(2),
                    parent_transition: Some(deposit(1)),
                },

                VaultStateParameters {
                    transition: withdrawal(3),
                    previous_value: v(3),
                    parent_transition: Some(deposit(1)),
                },
                VaultStateParameters {
                    transition: withdrawal(2),
                    previous_value: v(3),
                    parent_transition: Some(deposit(1)),
                },
                VaultStateParameters {
                    transition: withdrawal(1),
                    previous_value: v(3),
                    parent_transition: Some(deposit(1)),
                },
                VaultStateParameters {
                    transition: deposit(1),
                    previous_value: v(3),
                    parent_transition: Some(deposit(1)),
                },

                VaultStateParameters {
                    transition: withdrawal(3),
                    previous_value: v(4),
                    parent_transition: Some(deposit(1)),
                },
                VaultStateParameters {
                    transition: withdrawal(2),
                    previous_value: v(4),
                    parent_transition: Some(deposit(1)),
                },
                VaultStateParameters {
                    transition: withdrawal(1),
                    previous_value: v(4),
                    parent_transition: Some(deposit(1)),
                },

                VaultStateParameters {
                    transition: withdrawal(2),
                    previous_value: v(2),
                    parent_transition: Some(deposit(2)),
                },
                VaultStateParameters {
                    transition: withdrawal(1),
                    previous_value: v(2),
                    parent_transition: Some(deposit(2)),
                },
                VaultStateParameters {
                    transition: deposit(1),
                    previous_value: v(2),
                    parent_transition: Some(deposit(2)),
                },
                VaultStateParameters {
                    transition: deposit(2),
                    previous_value: v(2),
                    parent_transition: Some(deposit(2)),
                },

                VaultStateParameters {
                    transition: withdrawal(3),
                    previous_value: v(3),
                    parent_transition: Some(deposit(2)),
                },
                VaultStateParameters {
                    transition: withdrawal(2),
                    previous_value: v(3),
                    parent_transition: Some(deposit(2)),
                },
                VaultStateParameters {
                    transition: withdrawal(1),
                    previous_value: v(3),
                    parent_transition: Some(deposit(2)),
                },
                VaultStateParameters {
                    transition: deposit(1),
                    previous_value: v(3),
                    parent_transition: Some(deposit(2)),
                },

                VaultStateParameters {
                    transition: withdrawal(3),
                    previous_value: v(4),
                    parent_transition: Some(deposit(2)),
                },
                VaultStateParameters {
                    transition: withdrawal(2),
                    previous_value: v(4),
                    parent_transition: Some(deposit(2)),
                },
                VaultStateParameters {
                    transition: withdrawal(1),
                    previous_value: v(4),
                    parent_transition: Some(deposit(2)),
                },

                VaultStateParameters {
                    transition: withdrawal(3),
                    previous_value: v(3),
                    parent_transition: Some(deposit(3)),
                },
                VaultStateParameters {
                    transition: withdrawal(2),
                    previous_value: v(3),
                    parent_transition: Some(deposit(3)),
                },
                VaultStateParameters {
                    transition: withdrawal(1),
                    previous_value: v(3),
                    parent_transition: Some(deposit(3)),
                },
                VaultStateParameters {
                    transition: deposit(1),
                    previous_value: v(3),
                    parent_transition: Some(deposit(3)),
                },

                VaultStateParameters {
                    transition: withdrawal(3),
                    previous_value: v(4),
                    parent_transition: Some(deposit(3)),
                },
                VaultStateParameters {
                    transition: withdrawal(2),
                    previous_value: v(4),
                    parent_transition: Some(deposit(3)),
                },
                VaultStateParameters {
                    transition: withdrawal(1),
                    previous_value: v(4),
                    parent_transition: Some(deposit(3)),
                },
            ],
        );
    }

    #[test]
    fn test_simple() {
        let secp = Secp256k1::new();
        let test_parameters = test_parameters(&secp);

        let templates = test_parameters.templates_at_depth(&secp, 0);

        assert_eq!(templates.len(), 10);

        // XXX: Most invalid templates have been made impossible to represent, this test should be
        // modified significantly

        for (params, _template) in &templates {
            assert_eq!(params.previous_value, VaultAmount(0));
            assert_eq!(params.parent_transition, None);
        }

        let next_templates = test_parameters.templates_at_depth(&secp, 1);

        for (params, _template) in &templates {
            for amount in 1..test_parameters.max_withdrawal_per_step.to_unscaled_amount() {
                if let Some(next) = params.next(VaultTransition::Withdrawal(VaultAmount(amount)), &test_parameters, 0) {
                    let _template = next_templates.get(&next)
                        .expect("template exists");
                }
            }

            for amount in 1..test_parameters.max_deposit_per_step.to_unscaled_amount() {
                if let Some(next) = params.next(VaultTransition::Deposit(VaultAmount(amount)), &test_parameters, 0) {
                    let _template = next_templates.get(&next)
                        .expect("template exists");
                }
            }
        }

        let next_next_templates = test_parameters.templates_at_depth(&secp, 2);

        for (params, _template) in &next_templates {
            for amount in 1..test_parameters.max_withdrawal_per_step.to_unscaled_amount() {
                if let Some(next) = params.next(VaultTransition::Withdrawal(VaultAmount(amount)), &test_parameters, 2) {
                    let _template = next_next_templates.get(&next)
                        .expect("template exists");

                    match params.parent_transition {
                        Some(VaultTransition::Deposit(_)) => {}
                        _ => panic!("first transition must be a deposit"),
                    }
                }
            }

            for amount in 1..test_parameters.max_deposit_per_step.to_unscaled_amount() {
                if let Some(next) = params.next(VaultTransition::Deposit(VaultAmount(amount)), &test_parameters, 2) {
                    let _template = next_next_templates.get(&next)
                        .expect("template exists");

                    match params.parent_transition {
                        Some(VaultTransition::Deposit(_)) => {}
                        _ => panic!("first transition must be a deposit"),
                    }
                }
            }
        }

        let last_templates = test_parameters.templates_at_depth(&secp, test_parameters.max_depth);

        // Since depth > 1 parameters should all be the same we're reuse them
        for (params, _template) in &next_next_templates {
            for amount in 1..test_parameters.max_withdrawal_per_step.to_unscaled_amount() {
                if let Some(next) = params.next(VaultTransition::Withdrawal(VaultAmount(amount)), &test_parameters, test_parameters.max_depth) {
                    let _template = last_templates.get(&next)
                        .expect("template exists");
                }
            }

            for amount in 1..test_parameters.max_deposit_per_step.to_unscaled_amount() {
                if let Some(next) = params.next(VaultTransition::Deposit(VaultAmount(amount)), &test_parameters, test_parameters.max_depth) {
                    let _template = last_templates.get(&next)
                        .expect("template exists");
                }
            }
        }
    }
}
