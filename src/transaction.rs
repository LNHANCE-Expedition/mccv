use bitcoin::{
    Amount,
    blockdata::locktime::relative,
    blockdata::locktime::absolute,
    FeeRate,
    OutPoint,
    psbt,
    Sequence,
    sighash,
    script::Builder,
    Script,
    ScriptBuf,
    Txid,
    TxIn,
    TxOut,
    taproot,
    transaction,
    Transaction,
    VarInt,
    Weight,
    Witness,
};

use bitcoin::bip32::{
    Xpriv,
    ChildNumber,
};

use bitcoin::hashes::{
    Hash,
    sha256,
};

use bitcoin::key::{
    TapTweak,
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
    Secp256k1,
    Signing,
    Verification,
    XOnlyPublicKey,
};

use bitcoin::taproot::{
    ControlBlock,
    LeafVersion,
    TapLeafHash,
    TapNodeHash,
    TaprootBuilder,
    TaprootMerkleBranch,
    TaprootSpendInfo,
};

use std::borrow::Borrow;
use std::collections::HashMap;
use std::iter;

use crate::bip119::get_default_template;

use crate::vault::{
    Depth,
    massage_script_map,
    OutputSpendingConditions,
    spend_condition_lookup,
    VaultAmount,
    VaultParameters,
    VaultScale,
    VaultTransition,
};

use crate::wallet::{
    SEGWIT_MARKER_WEIGHT,
    UnderpayingParentTransaction,
};

pub fn builder_with_capacity(size: usize) -> Builder {
    Builder::from(Vec::with_capacity(size))
}

pub fn dummy_input(lock_time: relative::LockTime) -> TxIn {
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

#[derive(Copy, Clone, Debug)]
pub struct TimelockedSpend {
    timelock: relative::LockTime,
    pubkey: XOnlyPublicKey,
}

impl TimelockedSpend {
    pub fn to_scriptbuf(&self) -> ScriptBuf {
        builder_with_capacity(5 + 1 + 33 + 1)
            .push_int(self.timelock.to_consensus_u32() as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_x_only_key(&self.pubkey)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }
}

const PAY_TO_ANCHOR_SCRIPT_BYTES: &[u8] = &[0x51, 0x02, 0x4e, 0x73];

pub fn ephemeral_anchor() -> TxOut {
    let script_pubkey = ScriptBuf::from_bytes(PAY_TO_ANCHOR_SCRIPT_BYTES.to_vec());

    TxOut {
        value: Amount::from_sat(0),
        script_pubkey,
    }
}

pub fn is_ephemeral_anchor(txout: &TxOut) -> bool {
    txout.value == Amount::ZERO
        && txout.script_pubkey.as_script() == Script::from_bytes(PAY_TO_ANCHOR_SCRIPT_BYTES)
}

fn witness_item_weight(len: usize) -> Weight {
    Weight::from_wu_usize(VarInt(len as u64).size() + len)
}

/// Calculate the serialized length of a single transaction input's witness
fn witness_weight(merkle_branches: Option<(usize, usize)>, stack_item_sizes: &[u64]) -> Weight {
    let extra_stack_item_sizes: &[Weight] = if let Some((script_len, merkle_branches)) = merkle_branches {
        let cb_length = 33 + 32 * merkle_branches;

        &[
            witness_item_weight(script_len),
            witness_item_weight(cb_length),
        ]
    } else {
        &[]
    };

    let stack_item_count_len = VarInt(
        stack_item_sizes.len() as u64 +
        extra_stack_item_sizes.len() as u64
    ).size();

    stack_item_sizes.iter()
        .map(|size| witness_item_weight(*size as usize))
        .chain(extra_stack_item_sizes.into_iter().cloned())
        .chain(Some(Weight::from_wu_usize(stack_item_count_len)))
        .sum()
}

pub(crate) struct RecoveryTransactionTemplate {
    recovery_key: XOnlyPublicKey,
    vault_amount: VaultAmount,
    withdrawal_amount: VaultAmount,
    scale: VaultScale,
}

impl RecoveryTransactionTemplate {
    pub fn to_transaction<C: Verification>(&self, secp: &Secp256k1<C>) -> Transaction {
        let recovered_amount = self.vault_amount + self.withdrawal_amount;

        assert!(recovered_amount > VaultAmount::ZERO);

        let mut input: Vec<TxIn> = Vec::with_capacity(2);
        if self.vault_amount > VaultAmount::ZERO {
            input.push(dummy_input(relative::LockTime::ZERO));
        }

        if self.withdrawal_amount > VaultAmount::ZERO {
            input.push(dummy_input(relative::LockTime::ZERO));
        }

        let recovery_output = TxOut {
            value: self.scale.scale_amount(recovered_amount),
            script_pubkey: ScriptBuf::new_p2tr(secp, self.recovery_key, None),
        };

        Transaction {
            version: transaction::Version::non_standard(3),
            lock_time: absolute::LockTime::ZERO,
            input,
            output: vec![recovery_output, ephemeral_anchor()],
        }
    }

    pub fn get_default_template<C: Verification>(&self, secp: &Secp256k1<C>, input_index: u32) -> sha256::Hash {
        // TODO: Do something less wasteful
        let transaction = self.to_transaction(secp);

        get_default_template(&transaction, input_index)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct DepositTransactionTemplateCommon {
    depth: Depth,
    vault_scale: VaultScale,
    pub vault_output: TxOut,
    vault_deposit: VaultAmount,
    vault_total: VaultAmount,
}

#[derive(Clone, Debug)]
pub(crate) struct InitialDepositTransactionTemplate {
    common: DepositTransactionTemplateCommon,
}

#[derive(Clone, Debug)]
pub(crate) struct TailDepositTransactionTemplate {
    common: DepositTransactionTemplateCommon,
    vault_input_lock_time: relative::LockTime,
}

#[derive(Clone, Debug)]
pub(crate) enum DepositTransactionTemplate {
    InitialDeposit(InitialDepositTransactionTemplate),
    Deposit(TailDepositTransactionTemplate),
}

impl DepositTransactionTemplate {
    fn common(&self) -> &DepositTransactionTemplateCommon {
        match self {
            DepositTransactionTemplate::InitialDeposit(deposit) => &deposit.common,
            DepositTransactionTemplate::Deposit(deposit) => &deposit.common,
        }
    }
}

impl DepositTransactionTemplateCommon {
    // XXX: Should it return InitialDepositTransactionTemplate instead?
    // I think this makes sense for now
    pub fn into_initial_deposit_template(self) -> DepositTransactionTemplate {
        DepositTransactionTemplate::InitialDeposit(
            InitialDepositTransactionTemplate { common: self }
        )
    }

    pub fn into_tail_deposit_template(self, vault_input_lock_time: relative::LockTime) -> DepositTransactionTemplate {
        DepositTransactionTemplate::Deposit(
            TailDepositTransactionTemplate { common: self, vault_input_lock_time }
        )
    }

    fn to_transaction(self, vault_input: Option<TxIn>) -> Transaction {
        let input = iter::empty()
            .chain(vault_input)
            .chain(Some(dummy_input(relative::LockTime::ZERO)))
            .collect();

        Transaction {
            version: transaction::Version::non_standard(3),
            lock_time: absolute::LockTime::ZERO,
            input,
            output: vec![self.vault_output],
        }
    }
}

impl InitialDepositTransactionTemplate {
    pub fn instantiate(self, deposit_input_internal_key: XOnlyPublicKey) -> InitialDepositTransaction {
        InitialDepositTransaction {
            common: DepositTransactionCommon::from_template(self.common, deposit_input_internal_key)
        }
    }

    pub fn vault_output(&self) -> &TxOut { &self.common.vault_output }
}

impl From<InitialDepositTransactionTemplate> for Transaction {
    fn from(value: InitialDepositTransactionTemplate) -> Self {
        value.common.to_transaction(None)
    }
}

#[derive(Clone,Debug)]
pub struct DepositTransactionCommon {
    depth: Depth,
    vault_scale: VaultScale,
    vault_deposit: VaultAmount,
    #[allow(dead_code)]
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
                lock_time: absolute::LockTime::ZERO,
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

#[derive(Debug)]
pub enum KeypairDerivationError {
    WrongKey,
    DerivationDepthExceeded,
    NoSigningInfo,
}

impl std::fmt::Display for KeypairDerivationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongKey => write!(f, "wrong key"),
            Self::DerivationDepthExceeded => write!(f, "maximum derivation depth exceeded"),
            Self::NoSigningInfo => write!(f, "no signing info available"),
        }
    }
}

impl std::error::Error for KeypairDerivationError { }

#[derive(Clone, Debug)]
pub enum DepositSignError {
    NoSignatureNeeded,
    SighashError(sighash::TaprootError),
    NoShapeTransaction,
}

impl DepositTransaction {
    const DEPOSIT_INPUT_INDEX_INITIAL: usize = 0;
    const DEPOSIT_INPUT_INDEX_TAIL: usize = 1;

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
            lock_time: absolute::LockTime::ZERO,
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

                Ok(keypair)
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

                let prevouts = sighash::Prevouts::All(&prevout_txouts);

                deposit.signature = Some(deposit.signing_info.sign(secp, keys, &transaction, 0, &prevouts)
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

impl DepositTransactionCommon {
    pub fn from_template(common: DepositTransactionTemplateCommon, deposit_input_internal_key: XOnlyPublicKey) -> Self {
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
                lock_time: absolute::LockTime::ZERO,
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
                lock_time: absolute::LockTime::ZERO,
                input,
                output: vec![self.vault_output.clone()],
            },
            input_index
        )
    }
}

impl TailDepositTransaction {
    #[allow(dead_code)]
    fn vault_template_hash(&self) -> sha256::Hash {
        get_default_template(
            &Transaction {
                version: transaction::Version::non_standard(3),
                lock_time: absolute::LockTime::ZERO,
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
pub(crate) enum VaultTransactionTemplate {
    Deposit(DepositTransactionTemplate),
    Withdrawal(WithdrawalTransactionTemplate),
}

impl VaultTransactionTemplate {
    pub fn vault_template_hash(&self) -> sha256::Hash {
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

    #[allow(dead_code)]
    fn vault_total(&self) -> VaultAmount {
        match self {
            VaultTransactionTemplate::Deposit(deposit) => deposit.common().vault_total,
            VaultTransactionTemplate::Withdrawal(withdrawal) => withdrawal.vault_total,
        }
    }
}

#[derive(Clone,Debug)]
pub(crate) struct WithdrawalTransactionTemplate {
    depth: Depth,
    vault_input_lock_time: relative::LockTime,
    vault_output: Option<TxOut>,
    pub withdrawal_output: TxOut,

    vault_total: VaultAmount,
    vault_withdrawal: VaultAmount,
}

impl WithdrawalTransactionTemplate {
    pub fn instantiate(&self, vault_prevout: OutPoint, signing_info: VaultOutputSigningInfo, withdrawal_output_info: WithdrawalOutputSpendInfo) -> WithdrawalTransaction {
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
            lock_time: absolute::LockTime::ZERO,
            input: vec![dummy_input(self.vault_input_lock_time)],
            output,
        };

        get_default_template(&tx, 0)
    }
}

// TODO: consider implementing [`OutputSpendingConditions`] so we can consolidate some things
#[derive(Clone,Debug)]
pub struct WithdrawalOutputSpendInfo {
    timelock: relative::LockTime,
    txout: TxOut,
    single_recovery_script: ScriptBuf,
    double_recovery_script: Option<ScriptBuf>,
    timelocked_withdrawal_script: ScriptBuf,
    hot_pubkey: XOnlyPublicKey,
    master_pubkey: XOnlyPublicKey,
    taproot_info: TaprootSpendInfo,
}

impl WithdrawalOutputSpendInfo {
    pub fn from_parameters<C: Verification>(secp: &Secp256k1<C>, parameters: &VaultParameters, depth: Depth, timelock: relative::LockTime, vault_amount: VaultAmount, withdrawal_amount: VaultAmount) -> Self {
        let master_pubkey = parameters.master_key(secp, depth);
        let hot_pubkey = parameters.hot_key(secp, depth);
        let recovery_key = parameters.recovery_key(secp, depth + 1);

        let timelocked_withdrawal_script = TimelockedSpend { pubkey: hot_pubkey, timelock };
        let timelocked_withdrawal_script = timelocked_withdrawal_script.to_scriptbuf();

        // NOTE: The templates are at `depth + 1`, but the scripts are at `depth`
        // FIXME:this could all be pretty lazily created imho, but let's not create more work for
        // ourselves right now
        let single_recovery_template = RecoveryTransactionTemplate { recovery_key, vault_amount: VaultAmount::ZERO, withdrawal_amount, scale: parameters.scale };
        let single_recovery_script = SignedNextStateTemplate {
            pubkey: hot_pubkey,
            next_state_template_hash: single_recovery_template.get_default_template(secp, 0),
        };
        let single_recovery_script = single_recovery_script.to_scriptbuf();

        let double_recovery_script = if vault_amount > VaultAmount::ZERO {
            let double_recovery_template = RecoveryTransactionTemplate { recovery_key, vault_amount, withdrawal_amount, scale: parameters.scale };

            Some(
                SignedNextStateTemplate {
                    pubkey: hot_pubkey,
                    next_state_template_hash: double_recovery_template.get_default_template(secp, 1),
                }
                .to_scriptbuf()
            )
        } else {
            None
        };

        const SCRIPT_EXPECT_MSG: &str = "hard coded script construction succeeds";

        let taproot_builder = if let Some(ref double_recovery) = double_recovery_script {
            TaprootBuilder::new()
                .add_leaf(2, single_recovery_script.clone())
                    .expect(SCRIPT_EXPECT_MSG)
                .add_leaf(2, double_recovery.clone())
                    .expect(SCRIPT_EXPECT_MSG)
                .add_leaf(1, timelocked_withdrawal_script.clone())
                    .expect(SCRIPT_EXPECT_MSG)
        } else {
            TaprootBuilder::new()
                .add_leaf(1, single_recovery_script.clone())
                    .expect(SCRIPT_EXPECT_MSG)
                .add_leaf(1, timelocked_withdrawal_script.clone())
                    .expect(SCRIPT_EXPECT_MSG)
        };

        let taproot_info = taproot_builder
            .finalize(secp, master_pubkey)
                .expect("finalize"); // FIXME: 80% sure this can only fail if our script construction is wrong

        let txout = TxOut {
            value: parameters.scale.scale_amount(withdrawal_amount),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(
                taproot_info.output_key(),
            ),
        };

        WithdrawalOutputSpendInfo {
            timelock,
            txout,
            single_recovery_script,
            double_recovery_script,
            timelocked_withdrawal_script,
            hot_pubkey,
            master_pubkey,
            taproot_info,
        }
    }

    pub fn master_pubkey(&self) -> XOnlyPublicKey { self.master_pubkey }

    pub fn spend_condition_lookup(&self) -> HashMap<TaprootMerkleBranch, (WithdrawalSpendingCondition, &Script)> {
        let conditions = |s: &Script| {
            if s == self.timelocked_withdrawal_script.as_script() {
                Some(
                    (
                        WithdrawalSpendingCondition::TimelockedSpend,
                        self.timelocked_withdrawal_script.as_script(),
                    )
                )
            } else if s == self.single_recovery_script.as_script() {
                Some(
                    (
                        WithdrawalSpendingCondition::RecoveryWithdrawalOnly,
                        self.single_recovery_script.as_script(),
                    )
                )
            } else if let Some(ref double_recovery_script) = self.double_recovery_script {
                if s == double_recovery_script.as_script() {
                    Some(
                        (
                            WithdrawalSpendingCondition::Recovery,
                            double_recovery_script.as_script()
                        )
                    )
                } else {
                    None
                }
            } else {
                None
            }
        };

        spend_condition_lookup(
            self.taproot_info.script_map()
                .iter()
                .map(massage_script_map),
                conditions,
        )
    }

    pub fn into_withdrawal_template(&self, depth: Depth, vault_output_spend_info: Option<VaultOutputSpendInfo>, vault_input_lock_time: relative::LockTime, vault_total: VaultAmount, withdrawal_amount: VaultAmount, scale: VaultScale) -> WithdrawalTransactionTemplate {
        let withdrawal_output = TxOut {
            value: scale.scale_amount(withdrawal_amount),
            script_pubkey: self.script_pubkey(),
        };

        WithdrawalTransactionTemplate {
            depth,
            vault_output: vault_output_spend_info.map(|info| info.output),
            withdrawal_output,
            vault_total,
            vault_withdrawal: withdrawal_amount,
            vault_input_lock_time,
        }
    }

    pub fn to_signing_info<C: Verification>(&self, secp: &Secp256k1<C>, prevout: TxOut, condition: WithdrawalSpendingCondition) -> Option<WithdrawalOutputSigningInfo> {
        let (_output_key, output_key_parity) =
            self.master_pubkey
            .tap_tweak(
                secp,
                Some(self.root_node_hash())
            );

        let script = self.script(condition)?;

        let control_block = ControlBlock {
            leaf_version: LeafVersion::TapScript,
            output_key_parity,
            internal_key: self.master_pubkey,
            merkle_branch: self.merkle_branch(script.to_owned())?,
        };

        Some(
            WithdrawalOutputSigningInfo {
                pubkey: self.hot_pubkey,
                control_block: control_block,
                // XXX: note this name is misleading, since we typedef'd VaultOutputSigningInfo to
                // WithdrawalOutputSigningInfo
                vault_prevout: prevout,
                script: script.to_owned(),
            }
        )
    }

    fn script(&self, condition: WithdrawalSpendingCondition) -> Option<&Script> {
        match condition {
            WithdrawalSpendingCondition::Recovery => self.double_recovery_script.as_ref().map(|script| script.as_script()),
            WithdrawalSpendingCondition::RecoveryWithdrawalOnly => Some(&self.single_recovery_script),
            WithdrawalSpendingCondition::TimelockedSpend => Some(&self.timelocked_withdrawal_script),
        }
    }

    pub fn root_node_hash(&self) -> TapNodeHash {
        self.taproot_info.merkle_root()
            .expect("must have merkle root")
    }

    pub fn script_pubkey(&self) -> ScriptBuf {
        ScriptBuf::new_p2tr_tweaked(self.taproot_info.output_key())
    }

    fn merkle_branch(&self, script: ScriptBuf) -> Option<TaprootMerkleBranch> {
        self.taproot_info
            .script_map()
            .get(
                &(
                    script,
                    LeafVersion::TapScript,
                )
            )?
            .iter()
            .next()
            .cloned()
    }

    fn timelocked_withdrawal_merkle_branch(&self) -> TaprootMerkleBranch {
        self.merkle_branch(self.timelocked_withdrawal_script.clone())
            .expect("withdrawal condition always exists")
    }
}

#[derive(Clone)]
pub enum WithdrawalSpendingCondition {
    /// Recovery transaction spending the withdrawal output with the vault output
    Recovery,
    // FIXME: Do we need to care if the vault output is present? Too tired to figure it out right
    // now...
    /// Recovery transaction only spending the withdrawal output, regardless of if the vault output
    /// is present
    RecoveryWithdrawalOnly,
    /// Spends the withdrawal output using the hot key to any transaction after a timelock  
    TimelockedSpend,
}

impl OutputSpendingConditions<WithdrawalSpendingCondition> for WithdrawalOutputSpendInfo {
    type SpendingCondition = WithdrawalOutputSigningInfo;

	fn get_spending_condition(&self, selector: WithdrawalSpendingCondition) -> Option<Self::SpendingCondition> {
        let script = (
            self.script(selector)?.to_owned(),
            LeafVersion::TapScript,
        );

        let control_block = self.taproot_info.control_block(&script)?;

        Some(
            WithdrawalOutputSigningInfo {
                // FIXME: pubkey, is that right?
                pubkey: self.hot_pubkey,
                control_block,
                vault_prevout: self.txout.clone(),
                script: script.0,
            }
        )
    }
}

#[allow(dead_code)]
#[derive(Clone,Debug)]
pub struct WithdrawalTransaction {
    depth: Depth,
    vault_input: TxIn,
    vault_signature: Option<taproot::Signature>,
    vault_output: Option<TxOut>,
    withdrawal_output: TxOut,

    vault_total: VaultAmount,
    vault_withdrawal: VaultAmount,

    withdrawal_output_info: WithdrawalOutputSpendInfo,

    /// Information required to sign the vault output that this transaction spends
    signing_info: VaultOutputSigningInfo,
}

#[derive(Clone, Debug)]
pub enum WithdrawalSignError {
    SighashError(sighash::TaprootError),
}

impl WithdrawalTransaction {
    fn into_transaction(self) -> Transaction {
        let output = iter::empty()
            .chain(self.vault_output)
            .chain(Some(self.withdrawal_output))
            .chain(Some(ephemeral_anchor()))
            .collect();

        Transaction {
            version: transaction::Version::non_standard(3),
            lock_time: absolute::LockTime::ZERO,
            input: vec![self.vault_input],
            output,
        }
    }

    // TODO: eliminate need to construct transaction
    pub(crate) fn compute_txid(&self) -> Txid {
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

        Ok(keypair)
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
                lock_time: absolute::LockTime::ZERO,
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
        let prevouts = sighash::Prevouts::All(&prevout_txouts);

        let transaction = self.clone().into_transaction();

        let signature = self.signing_info.sign(secp, keypair, &transaction, 0, &prevouts)
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
    withdrawal_output_info: WithdrawalOutputSpendInfo,
}

impl WithdrawalSpendTransaction {
    pub fn value(&self) -> Amount { self.withdrawal_output.value }

    pub fn timelock(&self) -> relative::LockTime {
        self.withdrawal_output_info.timelock
    }

    pub(crate) fn prevout(&self) -> OutPoint { self.prevout }

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
        if min_fee > self.withdrawal_output.value {
            return Err(WithdrawalSpendError::FeeTooLarge);
        }

        let mut transaction = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
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
                    // The output value will be modified with the fee
                    // later.
                    value: self.withdrawal_output.value,
                    script_pubkey,
                }
            ],
        };

        let tap_leaf_hash = TapLeafHash::from_script(
            self
                .withdrawal_output_info
                .timelocked_withdrawal_script
                .as_script(),
            LeafVersion::TapScript,
        );

        assert_eq!(
            self.withdrawal_output_info.script_pubkey(),
            self.withdrawal_output.script_pubkey,
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
            + Weight::from_wu(VarInt(3).size() as u64) // 3 witness items
            + Weight::from_wu(VarInt(SCHNORR_SIGNATURE_SIZE as u64).size() as u64)
            + Weight::from_wu(SCHNORR_SIGNATURE_SIZE as u64)
            + Weight::from_wu(VarInt(script_len as u64).size() as u64)
            + Weight::from_wu(script_len as u64)
            + Weight::from_wu(VarInt(control_block_len as u64).size() as u64)
            + Weight::from_wu(control_block_len as u64);

        let fee = min_fee_rate.checked_mul_by_weight(weight)
            .ok_or(WithdrawalSpendError::FeeOverflow)?;

        let fee = std::cmp::max(min_fee, fee);

        transaction.output[0].value = self.withdrawal_output.value
            .checked_sub(fee)
            .ok_or(WithdrawalSpendError::FeeTooLarge)?;

        let prevout_txouts = vec![
            &self.withdrawal_output,
        ];

        let prevouts = sighash::Prevouts::All(&prevout_txouts);

        let sighash = sighash::SighashCache::new(&transaction)
            .taproot_signature_hash(0, &prevouts, None, Some((tap_leaf_hash, 0xFFFFFFFF)), sighash::TapSighashType::Default)
            .map_err(|e| WithdrawalSpendError::SighashError(e))?;

        // FIXME: seems like there should be shortcuts for a couple of these things?
        let message: Message = sighash.into();
        let signature = secp.sign_schnorr(&message, keypair);

        let signature = taproot::Signature {
            signature,
            sighash_type: sighash::TapSighashType::Default,
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
pub enum RecoveryTransactionInput {
    /// Deposit or Withdrawal vault output without withdrawal output
    /// u32 is the vault output
    VaultOnly(VaultOutputSigningInfo, u32),
    // u32 is the vout, it can vary depending on whether the withdrawal
    // had a vault output or not.
    WithdrawalOnly(WithdrawalOutputSigningInfo, u32),
    Withdrawal {
        vault: VaultOutputSigningInfo,
        vault_vout: u32,
        withdrawal: WithdrawalOutputSigningInfo,
        withdrawal_vout: u32,
    },
}

// FIXME: Refine this a little bit
#[derive(Clone, Debug)]
pub struct RecoveryTransaction {
    depth: Depth,

    prevout_txid: Txid,
    input: RecoveryTransactionInput,

    // TODO: Evaluate constructing this on demand instead
    output: TxOut,

    // FIXME: pretty goofy, should probably use an enum parallel to RecoveryTransactionSigningInfo
    vault_signature: Option<taproot::Signature>,
    withdrawal_signature: Option<taproot::Signature>,
}

impl RecoveryTransaction {
    pub fn new<C: Verification>(secp: &Secp256k1<C>, depth: Depth, prevout_txid: Txid, recovery_key: XOnlyPublicKey, input: RecoveryTransactionInput, recovered_value: VaultAmount, scale: VaultScale) -> Self {
        let script_pubkey = ScriptBuf::new_p2tr(secp, recovery_key, None);

        let recovery_output = TxOut {
            value: scale.scale_amount(recovered_value),
            script_pubkey,
        };

        Self {
            depth,
            prevout_txid,
            input,
            output: recovery_output,
            vault_signature: None,
            withdrawal_signature: None,
        }
    }

    pub(crate) fn to_unsigned_transaction(&self) -> Transaction {
        let mk_input = |txid, vout| TxIn {
            previous_output: OutPoint { txid, vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ZERO,
            witness: Witness::new(),
        };

        let input = match &self.input {
            RecoveryTransactionInput::VaultOnly(_vault, vault_vout) => vec![
                mk_input(self.prevout_txid, *vault_vout),
            ],
            RecoveryTransactionInput::WithdrawalOnly(_withdrawal, vout) => vec![
                mk_input(self.prevout_txid, *vout),
            ],
            RecoveryTransactionInput::Withdrawal { vault_vout, withdrawal_vout, .. } => vec![
                mk_input(self.prevout_txid, *vault_vout),
                mk_input(self.prevout_txid, *withdrawal_vout),
            ],
        };

        Transaction {
            version: transaction::Version::non_standard(3),
            lock_time: absolute::LockTime::ZERO,
            input,
            output: vec![
                self.output.clone(),
                ephemeral_anchor(),
            ],
        }
    }

    // TODO: Devise a better API
    pub fn hot_keypair<C: Signing>(&self, secp: &Secp256k1<C>, xpriv: &Xpriv) -> Result<Keypair, KeypairDerivationError> {
        let parent_depth = self.depth - 1;

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

        // TODO: Validate derived key's pubkey
        Ok(keypair)
    }

    pub fn sign<C: Signing>(&mut self, secp: &Secp256k1<C>, keypair: &Keypair) -> Result<(), SignRecoveryError> {
        let inputs = match &self.input {
            RecoveryTransactionInput::VaultOnly(vault, _vout) =>
                vec![&vault.vault_prevout],
            RecoveryTransactionInput::WithdrawalOnly(withdrawal, _vout) =>
                vec![&withdrawal.vault_prevout],
            RecoveryTransactionInput::Withdrawal { vault, withdrawal, .. } =>
                vec![
                    &vault.vault_prevout,
                    // FIXME: Slightly poorly named here, this is the withdrawal prevout...
                    // Maybe VaultOutputSigningInfo should be renamed...
                    // The key in this case is that it has the signing info we need
                    &withdrawal.vault_prevout,
                ],
        };

        let prevouts = sighash::Prevouts::All(&inputs);

        let transaction = self.to_unsigned_transaction();

        (self.vault_signature, self.withdrawal_signature) = match &self.input {
            RecoveryTransactionInput::VaultOnly(vault, _vout) => {
                (
                    Some(vault.sign(secp, keypair, &transaction, 0, &prevouts).map_err(SignRecoveryError::SignError)?),
                    None,
                )
            }
            RecoveryTransactionInput::WithdrawalOnly(withdrawal, _vout) => {
                (
                    None,
                    Some(withdrawal.sign(secp, keypair, &transaction, 0, &prevouts).map_err(SignRecoveryError::SignError)?),
                )
            }
            RecoveryTransactionInput::Withdrawal { vault, withdrawal, .. } => {
                // TODO: remove hard coded vault input indices, not a huge deal but I would like to
                // centralize them more
                (
                    Some(vault.sign(secp, keypair, &transaction, 0, &prevouts).map_err(SignRecoveryError::SignError)?),
                    Some(withdrawal.sign(secp, keypair, &transaction, 1, &prevouts).map_err(SignRecoveryError::SignError)?),
                )
            }
        };

        Ok(())
    }

    pub fn into_signed_transaction(self) -> Result<Transaction, ToSignedRecoveryTransactionError> {
        // TODO: don't like taking the mut Transaction, would rather have optional params to
        // to_unsigned_transaction to populate witnesses, but I think I want to figure out the
        // types I'm going to use to represent signatures
        // would rather centralize info about the transaction structure
        let mut tx = self.to_unsigned_transaction();
        match &self.input {
            RecoveryTransactionInput::VaultOnly(vault, _vout) => {
                let vault_signature = self.vault_signature
                    .ok_or(ToSignedRecoveryTransactionError::MissingSignature)?;

                tx.input[0].witness = vault.build_witness(vault_signature);

                Ok(tx)
            }
            RecoveryTransactionInput::WithdrawalOnly(withdrawal, _vout) => {
                let withdrawal_signature = self.withdrawal_signature
                    .ok_or(ToSignedRecoveryTransactionError::MissingSignature)?;

                tx.input[0].witness = withdrawal.build_witness(withdrawal_signature);

                Ok(tx)
            }
            RecoveryTransactionInput::Withdrawal { vault, withdrawal, .. } => {
                let vault_signature = self.vault_signature
                    .ok_or(ToSignedRecoveryTransactionError::MissingSignature)?;

                let withdrawal_signature = self.withdrawal_signature
                    .ok_or(ToSignedRecoveryTransactionError::MissingSignature)?;

                tx.input[0].witness = vault.build_witness(vault_signature);
                tx.input[1].witness = withdrawal.build_witness(withdrawal_signature);

                Ok(tx)
            }
        }
    }
}

impl UnderpayingParentTransaction for RecoveryTransaction {
    fn anchor_outpoint(&self) -> OutPoint {
        // FIXME: wasteful
        let tx = self.to_unsigned_transaction();
        OutPoint {
            txid: tx.compute_txid(),
            vout: 1,
        }
    }

    fn anchor_output_psbt_input(&self) -> psbt::Input {
        // FIXME: wasteful
        let tx = self.to_unsigned_transaction();

        psbt::Input {
            witness_utxo: Some(ephemeral_anchor()),
            non_witness_utxo: Some(tx),
            final_script_witness: Some(Witness::new()),
            ..Default::default()
        }
    }

    fn weight(&self) -> Weight {
        // FIXME: wasteful
        let tx = self.to_unsigned_transaction();

        let mut weight = tx.weight() + SEGWIT_MARKER_WEIGHT;

        match &self.input {
            RecoveryTransactionInput::VaultOnly(vault, _vout) => {
                let mb_len = vault.control_block.merkle_branch.len();
                weight += witness_weight(Some((vault.script.len(), mb_len)), &[
                    SCHNORR_SIGNATURE_SIZE as u64,
                ]);
                // Only one input
                weight += Weight::from_wu_usize(VarInt(1).size());
            }
            RecoveryTransactionInput::WithdrawalOnly(withdrawal, _) => {
                let mb_len = withdrawal.control_block.merkle_branch.len();
                weight += witness_weight(Some((withdrawal.script.len(), mb_len)), &[
                    SCHNORR_SIGNATURE_SIZE as u64,
                ]);
                // Only one input
                weight += Weight::from_wu_usize(VarInt(1).size());
            }
            RecoveryTransactionInput::Withdrawal { vault, withdrawal, .. } => {
                let v_mb_len = vault.control_block.merkle_branch.len();
                weight += witness_weight(Some((vault.script.len(), v_mb_len)), &[
                    SCHNORR_SIGNATURE_SIZE as u64,
                ]);

                let w_mb_len = withdrawal.control_block.merkle_branch.len();
                weight += witness_weight(Some((withdrawal.script.len(), w_mb_len)), &[
                    SCHNORR_SIGNATURE_SIZE as u64,
                ]);

                // 2 inputs
                weight += Weight::from_wu_usize(VarInt(2).size());
            }
        }

        weight
    }
}

#[derive(Clone,Copy,Debug)]
pub enum ToSignedRecoveryTransactionError {
    MissingSignature,
}

impl std::fmt::Display for ToSignedRecoveryTransactionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSignature => write!(f, "signature missing"),
        }
    }
}

impl std::error::Error for ToSignedRecoveryTransactionError { }

#[derive(Clone,Debug)]
pub enum SignRecoveryError {
    SignError(sighash::TaprootError),
}

impl std::fmt::Display for SignRecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SignError(e) => write!(f, "error signing recovery transaction: {e}"),
        }
    }
}

impl std::error::Error for SignRecoveryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SignError(ref e) => Some(e),
        }
    }
}

impl TailDepositTransactionTemplate {
    pub fn instantiate(self, vault_prevout: OutPoint, deposit_input_internal_key: XOnlyPublicKey, signing_info: VaultOutputSigningInfo) -> TailDepositTransaction {
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
        let tx: Transaction = self.clone().common.to_transaction(
            Some(dummy_input(self.vault_input_lock_time))
        );

        get_default_template(&tx, 0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultOutputSigningInfo {
    pubkey: XOnlyPublicKey,
    control_block: ControlBlock,
    vault_prevout: TxOut,
    //depth: Depth,
    script: ScriptBuf,
}

pub type WithdrawalOutputSigningInfo = VaultOutputSigningInfo;

impl VaultOutputSigningInfo {
    pub fn new(pubkey: XOnlyPublicKey, control_block: ControlBlock, vault_prevout: TxOut, script: ScriptBuf) -> Self {
        VaultOutputSigningInfo {
            pubkey,
            control_block,
            vault_prevout,
            script,
        }
    }

    fn sign<C: Signing, T: Borrow<TxOut>>(&self, secp: &Secp256k1<C>, keypair: &Keypair, transaction: &Transaction, input_index: usize, prevouts: &sighash::Prevouts<T>) -> Result<taproot::Signature, sighash::TaprootError> {
        let tap_leaf_hash = TapLeafHash::from_script(self.script.as_ref(), LeafVersion::TapScript);
        let sighash = sighash::SighashCache::new(transaction)
            .taproot_signature_hash(input_index, prevouts, None, Some((tap_leaf_hash, 0xFFFFFFFF)), sighash::TapSighashType::Default)?;

        // FIXME: seems like there should be shortcuts for a couple of these things?
        let message: Message = sighash.into();
        let signature = secp.sign_schnorr(&message, keypair);

        Ok(taproot::Signature {
            signature,
            sighash_type: sighash::TapSighashType::Default,
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
    hot_pubkey: XOnlyPublicKey,
    #[allow(dead_code)]
    // Redundant with [`spend_info.internal_key()`] but I prefer to retain the "cold" name to
    // remember vault semantics
    cold_pubkey: XOnlyPublicKey,
    spend_info: TaprootSpendInfo,
    output: TxOut,
    #[allow(dead_code)]
    depth: Depth,
    branches: HashMap<VaultOutputSpendCondition, SignedNextStateTemplate>,
}

#[derive(Clone, Copy, Hash, Eq, PartialEq)]
pub struct SignedNextStateTemplate {
    pub pubkey: XOnlyPublicKey,
    pub next_state_template_hash: sha256::Hash,
}

impl SignedNextStateTemplate {
    pub fn to_scriptbuf(&self) -> ScriptBuf {
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
        // TODO: Obvious optimization target
        self.to_scriptbuf().as_script() == other
    }
}

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum RecoveryType {
    VaultOnly,
    VaultWithWithdrawal,
}

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum VaultOutputSpendCondition {
    Deposit(VaultAmount),
    Withdrawal(VaultAmount),
    // FIXME: Seems like recovery_type should just be RecoveryDetails with a variant for vault
    // only, withdrawal only, and both?
    Recovery {
        recovery_type: RecoveryType,
        /// The vault balance prior to this recovery
        vault_balance: VaultAmount,
        /// The withdrawal amount prior to this recovery
        withdrawal_amount: VaultAmount,
    },
}

impl VaultOutputSpendInfo {
    pub fn new<C: Verification>(
        secp: &Secp256k1<C>,
        parameters: &VaultParameters,
        depth: Depth,
        // XXX: On the fence on just treating an empty vec as None, eliminate the Option
        spend_conditions: Option<Vec<(VaultOutputSpendCondition, SignedNextStateTemplate)>>,
        next_value: VaultAmount,
    ) -> Self {
        let master_key = parameters.master_key(secp, depth);
        let cold_pubkey = master_key;
        let hot_pubkey = parameters.hot_key(secp, depth);

        if let Some(spend_conditions) = spend_conditions {
            let spend_info = TaprootBuilder::with_huffman_tree(
                spend_conditions.iter().map(|(condition, script)| (parameters.spend_condition_weight(&condition), script.to_scriptbuf()))
                )
                .expect("huffman tree")
                .finalize(secp, master_key)
                .expect("finalize");

            let output = TxOut {
                value: parameters.scale.scale_amount(next_value),
                script_pubkey: ScriptBuf::new_p2tr_tweaked(spend_info.output_key()),
            };

            VaultOutputSpendInfo {
                spend_info,
                depth,
                branches: spend_conditions.into_iter().collect(),
                output,
                hot_pubkey,
                cold_pubkey,
            }
        } else {
            // Final state, only spendable by master
            // TODO: CSFS delegated recursion
            let script_pubkey = ScriptBuf::new_p2tr(secp, master_key, None);

            VaultOutputSpendInfo {
                spend_info: TaprootSpendInfo::new_key_spend(secp, master_key, None),
                depth,
                branches: iter::empty().collect(),
                output: TxOut {
                    value: parameters.scale.scale_amount(next_value),
                    script_pubkey,
                },
                hot_pubkey,
                cold_pubkey,
            }
        }
    }
    pub fn to_deposit_common(&self, vault_deposit: VaultAmount, vault_total: VaultAmount, vault_scale: VaultScale) -> DepositTransactionTemplateCommon {
        DepositTransactionTemplateCommon {
            depth: self.depth,
            vault_scale: vault_scale,
            vault_output: self.output.clone(),
            vault_deposit,
            vault_total,
        }
    }

    pub fn spend_condition_lookup(&self) -> HashMap<TaprootMerkleBranch, (VaultOutputSpendCondition, SignedNextStateTemplate)> {
        let spend_conditions = self.branches.iter()
            .map(|(condition, template)| (template.to_scriptbuf(), (condition, template)))
            .collect::<HashMap<_, _>>();

        let conditions = |script: &Script| -> Option<(VaultOutputSpendCondition, SignedNextStateTemplate)> {
            spend_conditions.get(script)
                .map(|(condition, template)| (**condition, **template))
        };

        spend_condition_lookup(
            self.spend_info.script_map()
                .iter()
                .map(massage_script_map),
            conditions,
        )
    }
}

impl OutputSpendingConditions<VaultOutputSpendCondition> for VaultOutputSpendInfo {
    type SpendingCondition = VaultOutputSigningInfo;

    fn get_spending_condition(&self, selector: VaultOutputSpendCondition) -> Option<Self::SpendingCondition> {
        let branch = self
            .branches
            .get(&selector)?;

        let control_block = self.spend_info.control_block(&(
            branch.to_scriptbuf(),
            LeafVersion::TapScript
        ))?;

        Some(
            VaultOutputSigningInfo {
                pubkey: self.hot_pubkey,
                control_block,
                vault_prevout: self.output.clone(),
                script: branch.to_scriptbuf(),
            }
        )
    }
}
