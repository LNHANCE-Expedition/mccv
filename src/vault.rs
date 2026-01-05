#[cfg(feature = "bitcoind")]
use bdk_bitcoind_rpc::bitcoincore_rpc::{Client, RpcApi, self};

use bitcoin::bip32::{
    Xpub,
    ChildNumber,
    DerivationPath,
};

#[cfg(feature = "bitcoind")]
use bitcoin::Block;

#[cfg(feature = "bitcoind")]
use bitcoin::consensus::encode::serialize_hex;

use bitcoin::secp256k1::{
    PublicKey,
    Secp256k1,
    Verification,
    XOnlyPublicKey,
};

use bitcoin::taproot::{
    ControlBlock,
    LeafVersion,
    TaprootMerkleBranch,
    TAPROOT_ANNEX_PREFIX,
};

use bitcoin::{
    absolute::LockTime,
    Amount,
    blockdata::locktime::relative,
    blockdata::transaction::Version,
    OutPoint,
    ScriptBuf,
    Script,
    taproot,
    Transaction,
    Txid,
    TxIn,
    TxOut,
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

use std::collections::{hash_map, HashMap, HashSet, BTreeSet, BTreeMap};
use std::iter;
use std::ops::Deref;
use std::rc::Rc;

use crate::bip119::get_default_template;

use crate::storage::{
    Change,
    ChangeLog,
};

use crate::cache::{
    AddTransactionStateCache,
    VaultTemplateCache,
};

use crate::transaction::{
    DepositTransaction,
    DepositTransactionTemplate,
    dummy_input,
    ephemeral_anchor,
    is_ephemeral_anchor,
    RecoveryTransaction,
    RecoveryTransactionInput,
    RecoveryType,
    SignedNextStateTemplate,
    VaultOutputSpendCondition,
    VaultOutputSpendInfo,
    VaultTransactionTemplate,
    WithdrawalOutputSpendInfo,
    WithdrawalSpendingCondition,
    WithdrawalTransaction,
};

use crate::chain::{
    AddBlockError,
    AddTransactionError,
    AddTransactionSuccess,
    ChainTipState,
    ConnectTransactionSuccess,
    ContractInputs,
    ContractOutputs,
    ContractTransaction,
    ContractTransactionConnector,
    Either,
    UtxoSelector,
};

pub use crate::chain::{
    ContractState,
};

// struct.unpack(">I", hashlib.sha256(b'mccv').digest()[:4])[0] & 0x7FFFFFFF
const PURPOSE: u32 = 360843587;

pub type Depth = u32;

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

#[derive(Clone,Copy,Debug,Eq,PartialEq,Serialize,Deserialize)]
#[serde(transparent)]
pub struct VaultScale(u32);

impl VaultScale {
    pub const fn new(scale: u32) -> Self { Self(scale) }

    pub const fn from_sat(scale: u32) -> Self { Self(scale) }

    pub fn to_sat(&self) -> u32 { self.0 }

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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VaultParameters {
    pub scale: VaultScale,
    /// Maximum value = max * scale
    pub max: VaultAmount,
    // All coins are always immediately spendable by master_xpub
    pub cold_xpub: Xpub,
    // Withdrawn coins are spendable by withdrawal_xpub at any time
    pub hot_xpub: Xpub,
    // Should there be yet another xpub for un-managed funds? probably but not in the vault params
    pub delay_per_increment: u32,
    pub max_withdrawal_per_step: VaultAmount,
    pub max_deposit_per_step: VaultAmount,
    pub max_depth: Depth,
}

#[derive(Clone,Copy,Debug,Hash,Eq,PartialEq,Serialize,Deserialize)]
#[serde(transparent)]
/// Represents a Bitcoin amount as an integer number of
/// fixed size chunks. The actual number of satoshis represented
/// by a VaultAmount is calculated by multiplying by a scale
pub struct VaultAmount(u32);

impl VaultAmount {
    pub const ZERO: VaultAmount = VaultAmount(0);

    pub const fn new(unscaled_amount: u32) -> Self {
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

    pub(crate) fn to_unscaled_amount(&self) -> u32 {
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

#[derive(Clone,Copy,Debug,Eq,Hash,PartialEq)]
pub enum VaultTransition {
    Deposit(VaultAmount),
    Withdrawal(VaultAmount),
}

impl VaultTransition {
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct VaultStateParameters {
    transition: VaultTransition,
    previous_value: VaultAmount,
    parent_transition: Option<VaultTransition>,
}

impl VaultStateParameters {
    pub fn result_value(&self) -> VaultAmount {
        match self.transition {
            VaultTransition::Deposit(deposit) => self.previous_value + deposit,
            VaultTransition::Withdrawal(withdrawal) => self.previous_value - withdrawal,
        }
    }

    #[allow(dead_code)]
    fn next(&self, transition: VaultTransition, parameters: &VaultParameters, depth: Depth) -> Option<Self> {
        parameters.validate_parameters(
            Self {
                transition,
                previous_value: self.result_value(),
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

pub(crate) trait OutputSpendingConditions<T> {
	type SpendingCondition;

    // FIXME: name is sketchy
	fn get_spending_condition(&self, selector: T) -> Option<Self::SpendingCondition>;
}

#[derive(Debug)]
pub enum GetVaultTemplateError {
    InvalidVaultDepth,
    InvalidParameters,
}

pub(crate) trait VaultTemplates {
    type Templates: Deref<Target = VaultGeneration>;

    #[allow(dead_code)]
    fn get<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, parameters: &VaultStateParameters) -> Result<VaultTransactionTemplate, GetVaultTemplateError>;

    fn get_generation<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth) -> Option<Self::Templates>;
}

pub struct Context(VaultParameters, VaultTemplateCache, AddTransactionStateCache);

// FIXME: Don't love that this had to be public because VaultTemplates is in the public interface.
// Consider wrapping this in a newtype to protect it.
pub(crate) type VaultGeneration = HashMap<VaultStateParameters, VaultTransactionTemplate>;

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

    pub(crate) fn master_key<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth) -> XOnlyPublicKey {
        self.master_key_full(secp, depth).x_only_public_key().0
    }

    // Similar to the recovery case, if the hot key is compromised, it's actually best if they
    // initiate a withdrawal so we can recognize the hot key is compromised and initiate a
    // recovery.
    pub(crate) fn hot_key<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth) -> XOnlyPublicKey {
        let path = [
            ChildNumber::from_normal_idx(depth as u32).expect("sane child number")
        ];

        let xpub = self.hot_xpub.derive_pub(secp, &path)
            .expect("non-hardened derivation of a reasonable depth shouldn't fail");

        xpub.to_x_only_pub()
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
        let vault_value = parameter.result_value();
        let withdrawal_amount = match parameter.transition {
            VaultTransition::Withdrawal(withdrawal) => withdrawal,
            _ => VaultAmount::ZERO,
        };

        if vault_value <= VaultAmount::ZERO {
            return Vec::new();
        }

        let mut counter = 0;
        let mut transitions: Vec<_> = self
            .state_transitions_single(vault_value, depth + 1)
            .filter_map(|params| {
                match (parameter.transition, params.parent_transition) {
                    (_, None) => { return None; }
                    (transition, Some(parent_transition)) => if transition != parent_transition { return None; }
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
                        // FIXME: I think this is a bug! withdrawal_amount should reflect the
                        // amount of the withdrawal output, even if we're ignoring it!
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

    pub(crate) fn spend_condition_weight(&self, condition: &VaultOutputSpendCondition) -> u32 {
        (match condition {
            VaultOutputSpendCondition::Deposit(amount) => (self.max_deposit_per_step - *amount).to_unscaled_amount(),
            VaultOutputSpendCondition::Withdrawal(amount) => (self.max_withdrawal_per_step - *amount).to_unscaled_amount(),
            VaultOutputSpendCondition::Recovery {..} => 0,
        }) + 1
    }

    // FIXME: I think we should just return the spend conditions as well, this is nearly duplicated
    // everywhere we build a VaultOutputSpendInfo
    fn vault_output<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, parameters: &VaultStateParameters, next_states: Option<&VaultGeneration>) -> VaultOutputSpendInfo {
        let next_value = parameters.result_value();
        assert!(next_value > VaultAmount::ZERO);

        let conditions = if let Some(next_states) = next_states {
            Some(
                self.vault_output_spend_conditions(secp, depth, &parameters, next_states)
            )

        } else {
            None
        };

        VaultOutputSpendInfo::new(
            secp,
            self,
            depth,
            conditions,
            next_value,
        )
    }

    fn deposit_template<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, deposit_amount: VaultAmount, parameter: &VaultStateParameters, next_states: Option<&VaultGeneration>) -> DepositTransactionTemplate {
        let vault_total = parameter.result_value();

        let vault_output = self.vault_output(secp, depth, parameter, next_states);

        let common = vault_output.to_deposit_common(deposit_amount, vault_total, self.scale);

        match parameter.parent_transition {
            None => common.into_initial_deposit_template(),
            Some(parent_transition) => {
                let lock_time = self.vault_input_lock_time(parent_transition);

                common.into_tail_deposit_template(lock_time)
            }
        }
    }

    fn withdrawal_output_info<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, withdrawal_amount: VaultAmount, vault_total: VaultAmount) -> WithdrawalOutputSpendInfo {
        let timelock = self.vault_input_lock_time(VaultTransition::Withdrawal(withdrawal_amount));

        WithdrawalOutputSpendInfo::from_parameters(
            secp,
            self,
            depth,
            timelock,
            vault_total,
            withdrawal_amount,
        )
    }

    /// Generate a single transaction template.
    /// NOTE: assumes that the parameters are valid
    fn transaction_template<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, parameters: &VaultStateParameters, next_states: Option<&VaultGeneration>) -> VaultTransactionTemplate {
        parameters.assert_valid();

        let vault_total = parameters.result_value();

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

                let vault_output_spend_info = if withdrawal_amount < parameters.previous_value {
                    Some(self.vault_output(secp, depth, parameters, next_states))
                } else {
                    None
                };

                let withdrawal_output_info = self.withdrawal_output_info(secp, depth, withdrawal_amount, vault_total);

                VaultTransactionTemplate::Withdrawal(
                    withdrawal_output_info
                        .into_withdrawal_template(
                            depth,
                            vault_output_spend_info,
                            vault_input_lock_time,
                            vault_total,
                            withdrawal_amount,
                            self.scale
                        )
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

    pub(crate) fn tx_templates<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, next_states: Option<&VaultGeneration>) -> VaultGeneration {
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

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum VaultHistoryTransactionDetails {
    VaultDeposit {
        deposit_amount: VaultAmount,
        vault_vout: u32,
    },
    VaultWithdrawal {
        withdrawal_amount: VaultAmount,
        vault_vout: Option<u32>,
        withdrawal_vout: u32,
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

#[derive(Clone,Copy,Debug)]
/// Indicates what kind of vault transaction was found that cannot be
/// represented as a [`VaultTransition`].
pub enum InvalidTransitionError {
    KeySpend,
    Recovery,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultHistoryTransaction {
    txid: Txid,
    #[allow(dead_code)]
    depth: Depth,
    details: VaultHistoryTransactionDetails,
    result_value: VaultAmount,
}

impl VaultHistoryTransaction {
    #[allow(dead_code)]
    pub(crate) fn new(txid: Txid, depth: Depth, details: VaultHistoryTransactionDetails, result_value: VaultAmount) -> Self {
        VaultHistoryTransaction {
            txid,
            depth,
            details,
            result_value,
        }
    }

    /// Get the vault outpoint if it exists
    pub fn vault_outpoint(&self) -> Option<OutPoint> {
        match self.details {
            VaultHistoryTransactionDetails::VaultDeposit { vault_vout: vout, .. } =>
                Some(OutPoint {txid: self.txid, vout}),
            VaultHistoryTransactionDetails::VaultWithdrawal { vault_vout: vout, .. } =>
                vout.map(|vout| OutPoint{ txid: self.txid, vout}),
            _ => None,
        }
    }
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

#[derive(Clone,Copy,Debug)]
pub enum RecoveryCreationError {
    VaultUnopened,
    VaultClosed,
    MaxDepth,
    HistoryError,
    UnrecoverableLastTransaction,
    // Generalization of VaultUnopened, VaultClosed, and UnrecoverableLastTransaction
    // Might eliminate those variants, I don't think we care about the reason that much, plus it's
    // harder to distinguish in the new model
    NoOutputs,
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

// FIXME: does it actually just make sense for (C, T) to be T?
pub(crate) fn spend_condition_lookup<'a, Ss, C, Cs, T>(scripts: Ss, conditions: Cs) -> HashMap<TaprootMerkleBranch, (C, T)>
where
    Ss: IntoIterator<Item = ((&'a Script, LeafVersion), &'a BTreeSet<TaprootMerkleBranch>)>,
    Cs: Fn(&Script) -> Option<(C, T)>,
    T: Clone,
    C: Clone,
{
    scripts.into_iter()
        .flat_map(|((script, _leaf_version), merkle_branches)| {
            conditions(script)
                .into_iter()
                .flat_map(|(condition, template)| {
                    merkle_branches
                        .iter()
                        .map(move |branch|
                            (
                                branch.clone(),
                                (
                                    condition.clone(),
                                    template.clone(),
                                ),
                            )
                        )
                    }
                )
        })
        .collect()
}

pub(crate) fn massage_script_map<'a>(arg: (&'a (ScriptBuf, LeafVersion), &'a BTreeSet<TaprootMerkleBranch>)) -> ((&'a Script, LeafVersion), &'a BTreeSet<TaprootMerkleBranch>) {
    ((arg.0.0.as_script(), arg.0.1), arg.1)
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub(crate) enum RecoveryInput {
    None,
    Ignored(VaultAmount),
    Spent(VaultAmount),
}

impl RecoveryInput  {
    fn from_amount(amount: VaultAmount, spent: bool) -> Self {
        if amount == VaultAmount::ZERO {
            Self::None
        } else if spent {
            Self::Spent(amount)
        } else {
            Self::Ignored(amount)
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub(crate) enum VaultTransactionMetadata {
    InitialDeposit(VaultAmount),
    Deposit {
        previous_value: VaultAmount,
        deposit: VaultAmount,
    },
    Withdrawal {
        previous_value: VaultAmount,
        withdrawal: VaultAmount,
    },
    WithdrawalSpend {
        withdrawal_vins: BTreeSet<u32>,
    },
    Recovery {
        vault_output_value: RecoveryInput,
        withdrawal_output_value: RecoveryInput,
    },
    KeySpend,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub struct VaultStateTransaction {
    txid: Txid,
    transaction: Transaction,
    // Depth of vault transaction from initial deposit
    depth: Depth,
    metadata: VaultTransactionMetadata,
    /// Key: parent txid
    parents: BTreeMap<Txid, Rc<VaultStateTransaction>>,
}

impl ContractTransaction for VaultStateTransaction {
    fn txid(&self) -> Txid { self.txid }
}

impl VaultStateTransaction {
    fn input_utxos(&self) -> impl Iterator<Item = (u32, VaultStateUtxo)> {
        match &self.metadata {
            VaultTransactionMetadata::InitialDeposit(_) => {
                assert!(self.parents.is_empty(), "Initial deposit has no tracked parents");

                Either::A(iter::empty())
            }
            VaultTransactionMetadata::Deposit { .. } => {
                let (_parent_txid, parent) = self.parents.iter().next().expect("Deposit must have parent");

                Either::B(Either::A(iter::once((0, VaultStateUtxo(parent.clone(), VaultStateOutput::Vault)))))
            }
            VaultTransactionMetadata::Withdrawal { .. } => {
                let (_parent_txid, parent) = self.parents.iter().next().expect("Deposit must have parent");

                Either::B(Either::B(Either::A(iter::once((0, VaultStateUtxo(parent.clone(), VaultStateOutput::Vault))))))
            }
            VaultTransactionMetadata::KeySpend => todo!("keyspend"),
            VaultTransactionMetadata::Recovery{ vault_output_value, withdrawal_output_value } => {
                let (_parent_txid, parent) = self.parents.iter().next().expect("Recovery must have parent");

                Either::B(Either::B(Either::B(Either::A(
                    iter::empty()
                        .chain(
                            match vault_output_value {
                                RecoveryInput::Spent(_) => Some(
                                    VaultStateUtxo(parent.clone(), VaultStateOutput::Vault)        
                                ),
                                _ => None
                            }
                        )
                        .chain(
                            match withdrawal_output_value {
                                RecoveryInput::Spent(_) => Some(
                                    VaultStateUtxo(parent.clone(), VaultStateOutput::Vault)        
                                ),
                                _ => None
                            }
                        )
                        .enumerate()
                        .map(|(input_index, utxo)| (input_index as u32, utxo))
                ))))
            },
            VaultTransactionMetadata::WithdrawalSpend { withdrawal_vins } => {
                let inputs: Vec<_> = withdrawal_vins
                    .into_iter()
                    .map(|vin| {
                        let input = &self.transaction.input[*vin as usize];

                        let parent = &self.parents[&input.previous_output.txid];

                        (*vin, VaultStateUtxo(parent.clone(), VaultStateOutput::Withdrawal))
                    })
                    .collect();

                Either::B(Either::B(Either::B(Either::B(
                    inputs.into_iter()
                ))))
            }
        }
    }

    #[allow(dead_code)]
    fn output_type(&self, vout: u32) -> Option<VaultStateOutput> {
        match (&self.metadata, vout) {
            (VaultTransactionMetadata::InitialDeposit(_), 0) |
            (VaultTransactionMetadata::Deposit { .. },    0) =>
                Some(VaultStateOutput::Vault),
            (VaultTransactionMetadata::Withdrawal { previous_value, withdrawal }, vout) => {
                if previous_value > withdrawal {
                    if vout == 0 {
                        Some(VaultStateOutput::Vault)
                    } else if vout == 1 {
                        Some(VaultStateOutput::Withdrawal)
                    } else {
                        None
                    }
                } else if vout == 0 {
                    Some(VaultStateOutput::Vault)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn outputs(&self) -> impl Iterator<Item=VaultStateOutput> {
        match &self.metadata {
            VaultTransactionMetadata::InitialDeposit(_) |
            VaultTransactionMetadata::Deposit { .. } =>
                iter::empty()
                    .chain(Some(VaultStateOutput::Vault))
                    .chain(None),
            VaultTransactionMetadata::Withdrawal { previous_value, withdrawal } =>
                iter::empty()
                    .chain(
                        if previous_value > withdrawal {
                            Some(VaultStateOutput::Vault)
                        } else {
                            None
                        }
                    )
                    .chain(Some(VaultStateOutput::Withdrawal)),
            _ => iter::empty().chain(None).chain(None),
        }
    }

    fn output_index(&self, output: VaultStateOutput) -> Option<u32> {
        match (&self.metadata, output) {
            (VaultTransactionMetadata::InitialDeposit(_), VaultStateOutput::Vault) |
            (VaultTransactionMetadata::Deposit{ .. }, VaultStateOutput::Vault) =>
                Some(0),
            (VaultTransactionMetadata::Withdrawal { previous_value, withdrawal }, VaultStateOutput::Vault) =>
                if previous_value > withdrawal {
                    Some(0)
                } else {
                    None
                },
            (VaultTransactionMetadata::Withdrawal { previous_value, withdrawal }, VaultStateOutput::Withdrawal) =>
                if previous_value > withdrawal {
                    Some(1)
                } else {
                    Some(0)
                },
            _ => None,
        }
    }

    fn outpoint(&self, output: VaultStateOutput) -> Option<OutPoint> {
        self.output_index(output)
            .map(|index| OutPoint {
                txid: self.transaction.compute_txid(),
                vout: index,
            })
    }

    fn txout(&self, output: VaultStateOutput) -> Option<&TxOut> {
        self.output_index(output)
            .map(|index| &self.transaction.output[index as usize])
    }

    fn vault_input(&self) -> Option<&TxIn> {
        match &self.metadata {
            VaultTransactionMetadata::InitialDeposit(_) => None,
            VaultTransactionMetadata::Deposit { .. } => Some(&self.transaction.input[0]),
            VaultTransactionMetadata::Withdrawal { .. } => Some(&self.transaction.input[0]),
            VaultTransactionMetadata::WithdrawalSpend { .. } => None,
            // The only two call sites for vault_input are in Deposit and Withdrawal so this is ok
            // for now
            // TODO: Implement though
            VaultTransactionMetadata::Recovery { .. } => todo!("not really a case we care about either, but it probably would be good to retain this info"),
            VaultTransactionMetadata::KeySpend => todo!("not really a case we care about, but it probably would be good to retain this info"),
        }
    }

    fn vault_input_prevout(&self) -> Option<(u32, Rc<VaultStateTransaction>)> {
        let prevout = &self.vault_input()?.previous_output;
        let parent = self.parents.get(&prevout.txid)
            // We don't *have to* panic here, but I think this is a good invariant to assert...
            .expect("vault state transaction must have valid parents");

        Some((prevout.vout, parent.clone()))
    }

    fn vault_transition(&self) -> Option<VaultTransition> {
        match self.metadata.clone() {
            VaultTransactionMetadata::InitialDeposit(deposit) => Some(VaultTransition::Deposit(deposit)),
            VaultTransactionMetadata::Deposit { deposit, .. } => Some(VaultTransition::Deposit(deposit)),
            VaultTransactionMetadata::Withdrawal { withdrawal, .. } => Some(VaultTransition::Withdrawal(withdrawal)),
            _ => None,
        }
    }

    fn result_value(&self) -> Option<VaultAmount> {
        match self.metadata.clone() {
            VaultTransactionMetadata::InitialDeposit(deposit) => Some(deposit),
            VaultTransactionMetadata::Deposit { previous_value, deposit } => Some(previous_value + deposit),
            VaultTransactionMetadata::Withdrawal { previous_value, withdrawal } => Some(previous_value - withdrawal),
            _ => None,
        }
    }

    fn withdrawal_amount(&self) -> VaultAmount {
        match self.metadata.clone() {
            VaultTransactionMetadata::Withdrawal { withdrawal, .. } => withdrawal,
            _ => VaultAmount::ZERO
        }
    }

    fn vault_state_parameters(&self) -> Option<VaultStateParameters> {
        match self.metadata.clone() {
            VaultTransactionMetadata::InitialDeposit(deposit) => Some(
                VaultStateParameters {
                    transition: VaultTransition::Deposit(deposit),
                    previous_value: VaultAmount::ZERO,
                    parent_transition: None,
                }
            ),
            VaultTransactionMetadata::Deposit { deposit, previous_value } => Some(
                self.vault_input_prevout()
                    .and_then(|(_vout, parent)| parent.vault_transition())
                    .map(|parent_transition|
                        VaultStateParameters {
                            transition:
                                VaultTransition::Deposit(deposit),
                            previous_value,
                            parent_transition:
                                Some(parent_transition),
                        }
                    )
                    // XXX: I think I'd rather panic here if we have some invalid state, but I'm
                    // kinda on the fence right now...
                    .expect("vault deposit output has valid transition")
            ),
            VaultTransactionMetadata::Withdrawal { previous_value, withdrawal } => Some(
                self.vault_input_prevout()
                    .and_then(|(_vout, parent)| parent.vault_transition())
                    .map(|parent_transition|
                         VaultStateParameters {
                            transition:
                                VaultTransition::Withdrawal(withdrawal),
                            previous_value,
                            parent_transition:
                                Some(parent_transition),
                        }
                    )
                    // XXX: I think I'd rather panic here if we have some invalid state, but I'm
                    // kinda on the fence right now...
                    .expect("vault deposit output has valid transition")
            ),
            _ => None
        }
    }
}

#[derive(Debug)]
#[cfg(feature = "bitcoind")]
pub enum ApplyBlockError {
    AddBlockError(AddBlockError),
    AddTransactionError(AddTransactionError<ConnectVaultTransactionError>),
    InternalError,
}

// Kind of annoying how much must be copied. the Control block can be up to 4KiB + 33B
#[allow(dead_code)]
enum TaprootWitness<'a> {
    Keyspend {
        signature: taproot::Signature,
        annex: Option<&'a [u8]>,
    },
    ScriptSpend {
        script: &'a Script,
        control_block: ControlBlock,
        annex: Option<&'a [u8]>,
    },
}

#[derive(Debug)]
enum TaprootWitnessError {
    InvalidSignature,
    EmptyWitness,
    #[allow(dead_code)]
    InvalidControlBlock(bitcoin::taproot::TaprootError),
    InvalidWitness,
}

impl<'a> TryFrom<&'a Witness> for TaprootWitness<'a> {
    type Error = TaprootWitnessError;

    fn try_from(witness: &'a Witness) -> Result<Self, Self::Error> {
        let last = witness
            .last()
            .ok_or(TaprootWitnessError::EmptyWitness)?;

        let last_non_annex_index = if last.len() > 0 && last[0] == TAPROOT_ANNEX_PREFIX {
            witness.len() - 2
        } else {
            witness.len() - 1
        };

        if last_non_annex_index == 0 {
            let signature = taproot::Signature::from_slice(&witness[0])
                .map_err(|_| TaprootWitnessError::InvalidSignature)?;

            Ok(TaprootWitness::Keyspend { signature, annex: witness.taproot_annex() })
        } else {
            if last_non_annex_index < 1 {
                return Err(TaprootWitnessError::InvalidWitness);
            }

            let control_block = ControlBlock::decode(&witness[last_non_annex_index])
                .map_err(TaprootWitnessError::InvalidControlBlock)?;

            let script = Script::from_bytes(&witness[last_non_annex_index - 1]);

            Ok(TaprootWitness::ScriptSpend {
                script,
                control_block,
                annex: witness.taproot_annex(),
            })
        }
    }
}

/// The public add_transaction result Ok type
#[derive(Debug, Eq, PartialEq)]
pub enum AddTransactionStatus {
    /// Provided transaction is already tracked in the vault state
    DuplicateTransaction,
    /// Provided transaction has been added to the vault state
    TransactionAdded,
    /// The provided transaction is irrelevant to this vault
    TransactionIgnored,
}

enum OutputInfo {
    Vault(VaultOutputSpendInfo),
    Withdrawal(WithdrawalOutputSpendInfo),
}

#[allow(dead_code)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum MatchWildcard {
    None,
    AnyDeposit,
    Anything,
}

impl MatchWildcard {
    fn half_merge(&self, a: VaultTransactionMetadata, b: VaultTransactionMetadata) -> Result<VaultTransactionMetadata, ()>
    {
        if a == b {
            return Ok(a);
        }

        match (a, &b) {
            (
                VaultTransactionMetadata::WithdrawalSpend{ withdrawal_vins: mut a_vins },
                VaultTransactionMetadata::WithdrawalSpend{ withdrawal_vins: b_vins },
            ) => {
                a_vins.extend(b_vins.into_iter());
                return Ok(
                    VaultTransactionMetadata::WithdrawalSpend{ withdrawal_vins: a_vins }
                );
            }
            _ => { }
        }

        match (self, b.clone()) {
            (MatchWildcard::AnyDeposit, VaultTransactionMetadata::InitialDeposit(_)) =>
                Ok(b),
            (MatchWildcard::AnyDeposit, VaultTransactionMetadata::Deposit{ .. }) =>
                Ok(b),
            _ => Err(()),
        }
    }

    fn merge(a: VaultTransactionMetadata, a_wildcard: MatchWildcard, b: VaultTransactionMetadata, b_wildcard: MatchWildcard) -> Result<(VaultTransactionMetadata, MatchWildcard), ()>
    {
        let a_result = a_wildcard.half_merge(a.clone(), b.clone());
        let b_result = b_wildcard.half_merge(b, a);

        let stricter_match = match (a_wildcard, b_wildcard) {
            (MatchWildcard::AnyDeposit, MatchWildcard::AnyDeposit) => MatchWildcard::AnyDeposit,
            (MatchWildcard::Anything, MatchWildcard::AnyDeposit) => MatchWildcard::AnyDeposit,
            (MatchWildcard::AnyDeposit, MatchWildcard::Anything) => MatchWildcard::AnyDeposit,
            (MatchWildcard::Anything, MatchWildcard::Anything) => MatchWildcard::Anything,
            _ => MatchWildcard::None,
        };

        match (a_result, b_result) {
            (Ok(result), _) => Ok((result, stricter_match)),
            (_, Ok(result)) => Ok((result, stricter_match)),
            _ => Err(())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum VaultStateOutput {
    Vault,
    Withdrawal,
}

#[derive(Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct VaultStateUtxo(Rc<VaultStateTransaction>, VaultStateOutput);

impl std::fmt::Debug for VaultStateUtxo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VaultStateUtxo({}, {:?})", self.0.txid, self.1)
    }
}

impl From<(Rc<VaultStateTransaction>, VaultStateOutput)> for VaultStateUtxo {
    fn from((tx, output): (Rc<VaultStateTransaction>, VaultStateOutput)) -> Self {
        VaultStateUtxo(tx, output)
    }
}

trait VaultUtxos {
    fn best_vault_utxo(self) -> Option<VaultStateUtxo>;
}

impl VaultUtxos for &BTreeSet<VaultStateUtxo> {
    fn best_vault_utxo(self) -> Option<VaultStateUtxo> {
        // TODO: Do better than just the first
        self.iter()
            .filter(|VaultStateUtxo(_tx, output)| match output {
                VaultStateOutput::Vault => true,
                _ => false,
            })
            .next()
            .cloned()
    }
}

impl ContractInputs for VaultStateTransaction {
    fn inputs(&self) -> BTreeSet<(u32, OutPoint)> {
        VaultStateTransaction::input_utxos(self)
            .into_iter()
            .map(|(input_index, _utxo)| (
                input_index,
                self.transaction.input[input_index as usize].previous_output,
                )
            )
            .collect()
    }
}

impl ContractOutputs for VaultStateTransaction {
    type OutputMetadata = VaultStateOutput;

    fn outputs(&self) -> BTreeMap<u32, Self::OutputMetadata> {
        VaultStateTransaction::outputs(self)
            .enumerate()
            .map(|(vout, metadata)| (vout as u32, metadata))
            .collect()
    }
}

#[derive(Debug)]
pub enum ConnectVaultTransactionError {
    Placeholder,
    InvalidTransaction,
}

impl ContractTransactionConnector for Context {
    type Transaction = VaultStateTransaction;
    type OutputMetadata = VaultStateOutput;

    type Error = ConnectVaultTransactionError;

    fn connect<C: Verification>(&self, secp: &Secp256k1<C>, state: &ChainTipState<Self::Transaction, Self::OutputMetadata>, transaction: &bitcoin::Transaction)
        -> Result<
            ConnectTransactionSuccess<Self::Transaction, Self::OutputMetadata>,
            Self::Error
        >
    {
        let vault_inputs: Vec<_> = transaction.input
            .iter()
            .enumerate()
            .filter_map(|(index, input)| {
                let tx = state.transaction(input.previous_output.txid)?;
                let vout = input.previous_output.vout as usize;

                match tx.transaction.output.get(vout) {
                    // Ignore anchor outputs
                    Some(txout) => {
                        if is_ephemeral_anchor(txout) {
                            return None;
                        }
                    }
                    None => {
                        return Some(
                            Err(ConnectVaultTransactionError::InvalidTransaction)
                        );
                    }
                };

                // Ignore spends of recovery txes, key spend txes, and withdrawal spends, spending
                // of these outputs is outside of our tracking.
                match tx.metadata {
                    VaultTransactionMetadata::Recovery { .. } => { return None; }
                    VaultTransactionMetadata::KeySpend => { return None; }
                    VaultTransactionMetadata::WithdrawalSpend { .. } => { return None; }
                    _ => { }
                }

                Some(Ok((index, input, tx)))
            })
            .collect::<Result<_, _>>()?;

        if vault_inputs.is_empty() {
            // Maybe it's an initial deposit
            if transaction.output.len() == 1 {
                if let Some(deposit_amount) = 
                    self.2.get_initial_deposit_amount(&transaction.output[0]) {

                    let vault_state_transaction = VaultStateTransaction {
                        txid: transaction.compute_txid(),
                        transaction: transaction.clone(),
                        depth: 0,
                        metadata: VaultTransactionMetadata::InitialDeposit(deposit_amount),
                        parents:
                            vault_inputs
                                .iter()
                                .map(|(_, _, tx)| (tx.transaction.compute_txid(), (*tx).clone()))
                                .collect()

                    };
                    let inputs = vault_state_transaction
                        .inputs()
                        .into_iter()
                        .map(|(_input_index, outpoint)| outpoint)
                        .collect();

                    let outputs =
                        ContractOutputs::outputs(&vault_state_transaction);

                    return Ok(
                        ConnectTransactionSuccess::Connect {
                            inputs,
                            transaction: vault_state_transaction,
                            outputs,
                        }
                    );
                }
            }

            return Ok(ConnectTransactionSuccess::Ignore);
        }

        // FIXME: awful name
        let parent_prevouts: HashMap<_, _> = vault_inputs.iter()
            .map(|(i, input, input_tx)| (input.previous_output, (*i, input_tx)))
            .collect();

        let mut parent_metadata: Vec<_> = parent_prevouts
            .iter()
            .map(|(prevout, (i, input_tx))| {
                let vault_state_parameters = input_tx.vault_state_parameters()
                    .ok_or(ConnectVaultTransactionError::InvalidTransaction)?;

                let next_states = self.1.get_generation(secp, input_tx.depth + 1)
                    // FIXME: error variant?
                    // FIXME: a max_depth transaction being spent by a keyspend would probably trip
                    // this, but it shouldn't
                    // Actually we wrap next_states in an Option anyway.
                    // Probably can just ignore if it returns None
                    .ok_or(ConnectVaultTransactionError::InvalidTransaction)?;

                let spend_conditions = match input_tx.metadata {
                    VaultTransactionMetadata::InitialDeposit(_amount) => OutputInfo::Vault(
                        self.0.vault_output(secp, input_tx.depth, &vault_state_parameters, Some(&next_states))
                    ),
                    VaultTransactionMetadata::Deposit { .. } => OutputInfo::Vault(
                        self.0.vault_output(secp, input_tx.depth, &vault_state_parameters, Some(&next_states))
                    ),
                    VaultTransactionMetadata::Withdrawal { previous_value, withdrawal } => {
                        let result_value = previous_value - withdrawal;

                        if result_value > VaultAmount::ZERO {
                            if prevout.vout == 0 {
                                OutputInfo::Vault(
                                    self.0.vault_output(secp, input_tx.depth, &vault_state_parameters, Some(&next_states))
                                )
                            } else if prevout.vout == 1 {
                                OutputInfo::Withdrawal(
                                    self.0.withdrawal_output_info(secp, input_tx.depth, withdrawal, previous_value - withdrawal)
                                )
                            } else {
                                // FIXME: is it really unreachable? probably should return
                                // InvalidTransaction instead!
                                unreachable!()
                            }
                        } else {
                            if prevout.vout == 0 {
                                OutputInfo::Withdrawal(
                                    self.0.withdrawal_output_info(secp, input_tx.depth, withdrawal, previous_value - withdrawal)
                                )
                            } else {
                                // FIXME: See above
                                unreachable!()
                            }
                        }
                    }
                    VaultTransactionMetadata::WithdrawalSpend { .. } =>
                        unreachable!("withdrawal spend transactions should be ignored before here"),
                    VaultTransactionMetadata::Recovery { .. } =>
                        unreachable!("recovery transactions should be ignored before here"),
                    VaultTransactionMetadata::KeySpend =>
                        unreachable!("keyspend transactions should be ignored before here"),
                };

                let input = transaction.input.get(*i)
                    .ok_or(ConnectVaultTransactionError::InvalidTransaction)?;

                let witness = TaprootWitness::try_from(&input.witness)
                    .map_err(|_| ConnectVaultTransactionError::InvalidTransaction)?;

                let metadata = match witness {
                    TaprootWitness::Keyspend { .. } => 
                        VaultTransactionMetadata::KeySpend,
                    TaprootWitness::ScriptSpend { script, control_block, .. } => {
                        match spend_conditions {
                            OutputInfo::Vault(conditions) => {
                                let conditions_lookup = conditions.spend_condition_lookup();

                                let (condition, script_template) = conditions_lookup.get(&control_block.merkle_branch)
                                    .ok_or(ConnectVaultTransactionError::InvalidTransaction)?;

                                if script_template != script {
                                    return Err(ConnectVaultTransactionError::InvalidTransaction);
                                }

                                match condition {
                                    VaultOutputSpendCondition::Deposit(amount) => {
                                        let previous_value = input_tx.result_value()
                                            .ok_or(ConnectVaultTransactionError::InvalidTransaction)?;
                                        VaultTransactionMetadata::Deposit{ previous_value, deposit: *amount }
                                    }
                                    VaultOutputSpendCondition::Withdrawal(amount) => {
                                        let previous_value = input_tx.result_value()
                                            .ok_or(ConnectVaultTransactionError::InvalidTransaction)?;

                                        VaultTransactionMetadata::Withdrawal{ previous_value, withdrawal: *amount }
                                    }
                                    VaultOutputSpendCondition::Recovery { recovery_type, vault_balance, withdrawal_amount } => {
                                        let (vault_output_value, withdrawal_output_value) = match recovery_type {
                                            RecoveryType::VaultOnly => (
                                                RecoveryInput::Spent(*vault_balance),
                                                if *withdrawal_amount > VaultAmount::ZERO {
                                                    RecoveryInput::Ignored(*withdrawal_amount)
                                                } else {
                                                    RecoveryInput::None
                                                },
                                            ),
                                            RecoveryType::VaultWithWithdrawal => (
                                                RecoveryInput::Spent(*vault_balance),
                                                RecoveryInput::Spent(*withdrawal_amount),
                                            ),
                                        };

                                        VaultTransactionMetadata::Recovery {
                                            vault_output_value,
                                            withdrawal_output_value
                                        }
                                    }
                                }
                            }
                            OutputInfo::Withdrawal(conditions) => {
                                // XXX: Annoyingly similar to the Deposit arm, but I wasn't able to
                                // write a function that handled both cases
                                // Could work around it with a newtype for &Script but that's
                                // annoying and heavy, and ultimately it's only a few repeated
                                // lines. If there's a way to use Deref or AsRef to make it work
                                // though, that would be great...
                                let conditions_lookup = conditions.spend_condition_lookup();

                                let (condition, script_template) = conditions_lookup.get(&control_block.merkle_branch)
                                    .ok_or(ConnectVaultTransactionError::InvalidTransaction)?;

                                if *script_template != script {
                                    return Err(ConnectVaultTransactionError::InvalidTransaction);
                                }

                                let previous_amount = input_tx.result_value();
                                let withdrawal_amount = input_tx.withdrawal_amount();

                                match condition {
                                    WithdrawalSpendingCondition::Recovery =>
                                        VaultTransactionMetadata::Recovery {
                                            vault_output_value:
                                                RecoveryInput::from_amount(
                                                    previous_amount.expect("dual recovery must have dual outputs"),
                                                    true,
                                                ),
                                            withdrawal_output_value:
                                                RecoveryInput::from_amount(
                                                    withdrawal_amount,
                                                    true,
                                            ),
                                        },
                                    WithdrawalSpendingCondition::RecoveryWithdrawalOnly =>
                                        VaultTransactionMetadata::Recovery {
                                            vault_output_value:
                                                RecoveryInput::from_amount(
                                                    // FIXME: Concerned that I've made a mistake with how I'm identifying the spending condition. Double check that anything committed to is also accounted for in this
                                                    previous_amount.unwrap_or(VaultAmount::ZERO),
                                                    false,
                                                ),
                                            withdrawal_output_value:
                                                RecoveryInput::from_amount(
                                                    withdrawal_amount,
                                                    true,
                                                ),
                                        },
                                    WithdrawalSpendingCondition::TimelockedSpend =>
                                        VaultTransactionMetadata::WithdrawalSpend { withdrawal_vins: iter::once(*i as u32).collect() }
                                }
                            },
                        }
                    }
                };

                Ok((*i, prevout, input_tx, metadata, MatchWildcard::None))
            })
            .collect::<Result<_, _>>()?;

        parent_metadata.sort_by_key(|(i, _, _, _, _)| *i);

        let (metadata, _) = parent_metadata
            .iter()
            .fold(
                Ok(None),
                |previous: Result<Option<(VaultTransactionMetadata, _)>, _>, (_, _, _, metadata, wildcard)| {
                    let previous = previous?;

                    if let Some((previous, previous_wildcard)) = previous {
                        // FIXME: This doesn't currently allow keyspends, and will probably choke
                        // on combined spends with multiple 
                        // MatchWildcard::Anything will permit this, but TODO
                        MatchWildcard::merge(metadata.clone(), *wildcard, previous, previous_wildcard)

                            .map(|(metadata, wildcard)| Some((metadata, wildcard)))
                            // FIXME: maybe add an error reason sub-variant
                            .map_err(|_| ConnectVaultTransactionError::InvalidTransaction)
                    } else {
                        Ok(Some((metadata.clone(), *wildcard)))
                    }
                }
            )?
            .ok_or(ConnectVaultTransactionError::InvalidTransaction)?;

        let depth = parent_metadata
            .iter()
            .map(|(_, _, tx, _, _)| tx.depth + 1)
            .fold(0 as Depth, |a, b| std::cmp::max(a, b));

        let vault_state_transaction = VaultStateTransaction {
                txid: transaction.compute_txid(),
                transaction: transaction.clone(),
                depth,
                metadata,
                parents:
                    vault_inputs
                        .iter()
                        .map(|(_, _, tx)| (tx.transaction.compute_txid(), (*tx).clone()))
                        .collect()

            };

        let inputs = vault_state_transaction
            .inputs()
            .into_iter()
            .map(|(_input_index, outpoint)| outpoint);
        let outputs = ContractOutputs::outputs(&vault_state_transaction);

        Ok(
            ConnectTransactionSuccess::Connect {
                inputs: inputs.collect(),
                transaction: vault_state_transaction,
                outputs: outputs,
            }
        )
    }
}

pub struct VaultState(ContractState<VaultStateTransaction, VaultStateOutput>);

impl VaultState {
    pub(crate) fn new() -> Self { Self(ContractState::new()) }
}

pub struct Vault {
    parameters: VaultParameters,
    state: VaultState,
}

impl Vault {
    pub fn new(parameters: VaultParameters, state: VaultState) -> Self {
        Self {
            parameters,
            state,
        }
    }

    pub fn new_unpersisted(id: VaultId, parameters: VaultParameters) -> (Self, ChangeLog) {
        let state = VaultState::new();
        (
            Vault::new(parameters, state),
            ChangeLog::new(id),
        )
    }

    pub fn parameters(&self) -> &VaultParameters { &self.parameters }

    /// Return the confirmed balance of the vault by a given height, or any height
    pub fn confirmed_balance(&self, max_height: Option<u32>) -> Amount {
        self.state.0.longest_chain_tip()
            .map(|(_block, state)| {
                state.utxos(
                    UtxoSelector::Confirmed(max_height)
                )
                .iter()
                .map(|(_, tx, output, _)| {
                    match output {
                        VaultStateOutput::Vault => {
                            let vault_amount = tx.result_value().unwrap_or(VaultAmount::ZERO);

                            self.parameters.scale.scale_amount(vault_amount)
                        }
                        _ => Amount::ZERO,
                    }
                })
                .sum()
            })
            .unwrap_or(Amount::ZERO)
    }

    // FIXME: this should probably be on ContractState
    #[cfg(feature = "bitcoind")]
    pub fn apply_block<C: Verification>(&mut self, secp: &Secp256k1<C>, context: &Context, block: &Block, block_height: u32, changelog: &mut ChangeLog) -> Result<(), ApplyBlockError> {
        let block_hash = block.block_hash();
        let parent_block_hash = block.header.prev_blockhash;

        let seen_block = self.state.0.add_block(block_height, block_hash, parent_block_hash)
            .map_err(ApplyBlockError::AddBlockError)?;

        changelog.add(Change::AddBlock { height: block_height, block_hash, parent_block_hash });

        self.state.0.normalize();

        let state = self.state.0.get_tip_mut(&seen_block)
            .expect("block was just added");

        for transaction in &block.txdata {
            let txid = transaction.compute_txid();
            let add_result = state.add(secp, context, txid, transaction, block_height);

            // TODO: Re-evaluate error variants
            match add_result {
                Ok(AddTransactionSuccess::TransactionAdded(tx)) => {
                    changelog.add(Change::AddTransaction(tx.clone()));
                    changelog.add(Change::Confirm(txid, block_hash, block_height));
                },
                Ok(AddTransactionSuccess::TransactionIgnored) => { }
                Err(AddTransactionError::InternalError) => { return Err(ApplyBlockError::InternalError); },
                // TODO: Could pass through the connect error, in a new variant, why not?
                Err(AddTransactionError::ConnectError(_e)) => { return Err(ApplyBlockError::InternalError); }
                Err(AddTransactionError::MissingInputs) => { return Err(ApplyBlockError::InternalError); }
            }
        }

        Ok(())
    }

    fn utxos(&self, selector: UtxoSelector) -> BTreeSet<VaultStateUtxo> {
        self.state.0.longest_chain_tip()
            .map(|(_tip, state)| {
                state.utxos(selector)
                    .into_iter()
                    .map(|(_, tx, metadata, _)| VaultStateUtxo(tx, *metadata))
                    .collect()
            })
            .unwrap_or_else(|| BTreeSet::new())
    }

    pub fn create_recovery<C: Verification>(&self, secp: &Secp256k1<C>) -> Result<RecoveryTransaction, RecoveryCreationError> {
        // TODO: We need to detect and track which outputs on the last transaction are still unspent
        // For now, just assume the vault has the correct state info (as long as it's been fed recent
        // blocks)

        let utxos = self.utxos(
            UtxoSelector::any_confirmed(),
        );

        let utxos = utxos
            .iter()
            .filter(|VaultStateUtxo(_tx, output)| match output {
                VaultStateOutput::Vault => true,
                VaultStateOutput::Withdrawal => true,
            });

        let mut sorted_utxos: HashMap<Rc<VaultStateTransaction>, HashSet<VaultStateOutput>> = HashMap::new();

        for utxo in utxos {
            match sorted_utxos.entry(utxo.0.clone()) {
                hash_map::Entry::Occupied(mut entry) => { entry.get_mut().insert(utxo.1); }
                hash_map::Entry::Vacant(entry) => {
                    entry.insert(
                        iter::once(utxo.1).collect()
                    );
                }
            }
        }

        let utxos = sorted_utxos.iter()
            .map(|(tx, outputs)| {
                let value = outputs.iter().map(|utxo| {
                    tx.txout(*utxo)
                        .expect("valid output type")
                        .value
                })
                .fold(Amount::ZERO, std::ops::Add::add);

                (tx, outputs, value)
            })
            .max_by(|a, b| a.2.cmp(&b.2));

        let (tx, _outputs, _value) = utxos.ok_or(RecoveryCreationError::NoOutputs)?;

        let depth = tx.depth + 1;
        let parent_depth = tx.depth;

        let recovery_key = self.parameters.recovery_key(secp, depth);

        if depth > self.parameters.max_depth {
            return Err(RecoveryCreationError::MaxDepth);
        }

        let parent_parameters = tx.vault_state_parameters()
            .ok_or(RecoveryCreationError::HistoryError)?;

        let parent_result = tx.result_value()
            .unwrap_or(VaultAmount::ZERO);

        // FIXME: We can do this more efficiently by using `templates` to generate
        // `parent_templates`, but not right now...
        let parent_templates = self.parameters.templates_at_depth(secp, parent_depth);

        let parent_template = parent_templates.get(&parent_parameters)
            .expect("last state must have valid template");

        let templates = self.parameters.templates_at_depth(secp, depth);

        // FIXME: This shouldn't be run unconditionally. It will panic for vault states that have
        // no vault output (complete withdrawals)
        let parent_output_info = self.parameters.vault_output(
            secp,
            parent_depth,
            &parent_parameters,
            Some(&templates),
        );

        match tx.metadata {
            VaultTransactionMetadata::InitialDeposit(_deposit) => {
                let vault_signing_info = parent_output_info.get_spending_condition(
                    VaultOutputSpendCondition::Recovery {
                        recovery_type: RecoveryType::VaultOnly,
                        vault_balance: parent_result,
                        withdrawal_amount: VaultAmount::ZERO,
                    }
                )
                .expect("spend condition should exist");

                Ok(
                    RecoveryTransaction::new(
                        secp,
                        depth,
                        tx.transaction.compute_txid(),
                        recovery_key,
                        RecoveryTransactionInput::VaultOnly(
                            vault_signing_info,
                            tx.output_index(VaultStateOutput::Vault)
                                .expect("deposit must have vault output"),
                        ),
                        parent_result,
                        self.parameters.scale,
                    )
                )
            }
            VaultTransactionMetadata::Deposit { .. } => {
                let vault_signing_info = parent_output_info.get_spending_condition(
                    VaultOutputSpendCondition::Recovery {
                        recovery_type: RecoveryType::VaultOnly,
                        vault_balance: parent_result,
                        withdrawal_amount: VaultAmount::ZERO,
                    }
                )
                .expect("spend condition should exist");

                Ok(
                    RecoveryTransaction::new(
                        secp,
                        depth,
                        tx.transaction.compute_txid(),
                        recovery_key,
                        RecoveryTransactionInput::VaultOnly(
                            vault_signing_info,
                            tx.output_index(VaultStateOutput::Vault)
                                .expect("deposit must have vault output"),
                        ),
                        parent_result,
                        self.parameters.scale,
                    )
                )
            }
            VaultTransactionMetadata::Withdrawal { withdrawal, previous_value } => {
                // TODO: We can also derive this from the UTXOs we have, probably would be cleaner,
                // but I already wrote this code and don't want to think about it more right now
                let (vault_recovery_type, recovery_amount) = if parent_result > VaultAmount::ZERO && withdrawal > VaultAmount::ZERO {
                    (Some(RecoveryType::VaultWithWithdrawal), previous_value)
                } else if parent_result > VaultAmount::ZERO {
                    (Some(RecoveryType::VaultOnly), previous_value)
                } else if withdrawal > VaultAmount::ZERO {
                    (None, withdrawal)
                } else {
                    unreachable!("previous transaction must have a nonzero vault or withdrawal output");
                };

                let vault_signing_info = if let Some(vault_recovery_type) = vault_recovery_type {
                    parent_output_info.get_spending_condition(
                        VaultOutputSpendCondition::Recovery {
                            recovery_type: vault_recovery_type,
                            vault_balance: parent_result,
                            withdrawal_amount: withdrawal,
                        }
                    )
                } else {
                    None
                };

                // FIXME: gross!
                let withdrawal_prevout = match parent_template {
                    VaultTransactionTemplate::Deposit(_) => unreachable!("cannot have a deposit template for a withdrawal state"),
                    VaultTransactionTemplate::Withdrawal(withdrawal) => withdrawal.withdrawal_output.clone(),
                };

                // TODO: Did my refactoring work create any opportunity to clean this up?
                let withdrawal_output_info = self.parameters.withdrawal_output_info(secp, parent_depth, withdrawal, parent_result);

                let withdrawal_script_pubkey = withdrawal_output_info.script_pubkey();

                debug_assert_eq!(withdrawal_script_pubkey, withdrawal_prevout.script_pubkey);
                let calculated_script_pubkey = ScriptBuf::new_p2tr(secp, withdrawal_output_info.master_pubkey(), Some(withdrawal_output_info.root_node_hash()));
                debug_assert_eq!(withdrawal_script_pubkey, calculated_script_pubkey);

                debug_assert_eq!(
                    self.parameters.master_key(&secp, parent_depth),
                    withdrawal_output_info.master_pubkey(),
                );

                let withdrawal_spending_condition = withdrawal_output_info.get_spending_condition(
                    WithdrawalSpendingCondition::Recovery,
                ).
                unwrap_or(
                    withdrawal_output_info.get_spending_condition(
                        WithdrawalSpendingCondition::RecoveryWithdrawalOnly,
                    )
                    .expect("Withdrawal output will always have a withdrawal-only spend path")
                );

                let withdrawal_signing_info = withdrawal_output_info
                    .to_signing_info(secp, withdrawal_prevout.clone(), WithdrawalSpendingCondition::Recovery)
                    .or_else(|| withdrawal_output_info
                        .to_signing_info(secp, withdrawal_prevout.clone(), WithdrawalSpendingCondition::RecoveryWithdrawalOnly)
                    )
                    .expect("withdrawal output must have either double or single withdrawal spend condition");

                debug_assert_eq!(withdrawal_script_pubkey, calculated_script_pubkey);

                // FIXME: eliminate the other one entirely
                assert_eq!(
                    withdrawal_spending_condition,
                    withdrawal_signing_info,
                );

                let input = if let Some(vault_signing_info) = vault_signing_info {
                    RecoveryTransactionInput::Withdrawal {
                        vault: vault_signing_info,
                        vault_vout: 
                            tx.output_index(VaultStateOutput::Vault)
                                // TODO: I think we can eliminate this pretty easily
                                .expect("has vault output if we have vault signing info"),
                        withdrawal: withdrawal_signing_info,
                        withdrawal_vout: 
                            tx.output_index(VaultStateOutput::Withdrawal)
                                .expect("Withdrawal tx has withdrawal output"),
                    }
                } else {
                    RecoveryTransactionInput::WithdrawalOnly(
                        withdrawal_signing_info,
                        tx.output_index(VaultStateOutput::Withdrawal)
                            .expect("Withdrawal tx has withdrawal output"),
                    )
                };

                Ok(
                    RecoveryTransaction::new(
                        secp,
                        depth,
                        tx.transaction.compute_txid(),
                        recovery_key,
                        input,
                        recovery_amount,
                        self.parameters.scale,
                    )
                )
            }

            // XXX: UTXO filtering above should ensure these are unreachable
            VaultTransactionMetadata::WithdrawalSpend { .. } => unreachable!(),
            VaultTransactionMetadata::Recovery { .. } => unreachable!(),
            VaultTransactionMetadata::KeySpend => unreachable!(),
        }
    }

    // FIXME: I think this should be refactored into a stateless version on VaultParameters
    //  FIXME: return value should probably also have some kind of token for keeping track of
    //  replacements, preventing invalid deposit transactions from being tracked
    pub fn create_deposit<C: Verification>(&self, secp: &Secp256k1<C>, deposit_amount: VaultAmount) -> Result<DepositTransaction, DepositCreationError> {
        if deposit_amount > self.parameters.max_deposit_per_step {
            return Err(DepositCreationError::InvalidDepositAmount);
        }

        let utxos = self.utxos(
            UtxoSelector::any_confirmed(),
        );

        let vault_utxo = utxos.best_vault_utxo();

        let current_vault_value = vault_utxo
            .as_ref()
            .and_then(|VaultStateUtxo(tx, _)| tx.result_value())
            .unwrap_or(VaultAmount::ZERO);

        let result_vault_value = current_vault_value + deposit_amount;
        if result_vault_value > self.parameters.max {
            let overflow_amount = result_vault_value
                .checked_sub(self.parameters.max);

            if let Some(overflow_amount) = overflow_amount {
                if overflow_amount > VaultAmount::ZERO {
                    return Err(DepositCreationError::VaultOverflow(overflow_amount));
                }
            }
        }

        let (parameters, depth, outpoint) = match vault_utxo.as_ref() {
            Some(VaultStateUtxo(tx, _output)) => {
                let parent_parameters = tx.vault_state_parameters()
                    .expect("deposit parent must have valid parameters");

                // FIXME: confirm depth calculation
                (
                    parent_parameters.next(
                        VaultTransition::Deposit(deposit_amount),
                        &self.parameters,
                        tx.depth + 1,
                    )
                    .ok_or(DepositCreationError::VaultClosed)?,
                    tx.depth + 1,
                    Some(
                        tx.outpoint(VaultStateOutput::Vault)
                            // XXX: I think the expect is a good sanity check here
                            .expect("must have vault output")
                    ),
                )
            }
            None => (
                VaultStateParameters {
                    transition: VaultTransition::Deposit(deposit_amount),
                    previous_value: VaultAmount(0),
                    parent_transition: None,
                },
                0,
                None,
            ),
        };

        // TODO: let the caller provide this state
        let transactions = self.parameters.templates_at_depth(secp, depth);

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
                debug_assert!(depth > 0, "Depth 0 has no ancestors");

                let spend_info = vault_utxo
                    .as_ref()
                    .and_then(|VaultStateUtxo(tx, _)| tx.vault_state_parameters())
                    .map(|parent_parameters| {
                        let parent_depth = depth - 1;

                        let parent_templates = self.parameters.templates_at_depth(secp, depth);

                        self.parameters.vault_output(
                            secp,
                            parent_depth,
                            &parent_parameters,
                            Some(&parent_templates),
                        )
                    })
                    // FIXME: consider making an error variant
                    .expect("tail deposits have transaction history");

                let vault_outpoint = outpoint.expect("non-initial deposit must have outpoint of previous vault");

                let signing_info = spend_info.get_spending_condition(
                    VaultOutputSpendCondition::Deposit(deposit_amount)
                )
                .expect("spend condition should exist");

                let tail_deposit_tx = deposit.instantiate(vault_outpoint, master, signing_info);

                Ok(
                    DepositTransaction::Deposit(tail_deposit_tx)
                )
            }
            _ => unreachable!("deposit transaction template must be a deposit transaction..."),
        }
    }

    pub fn create_withdrawal<C: Verification>(&self, secp: &Secp256k1<C>, withdrawal_amount: VaultAmount) -> Result<WithdrawalTransaction, WithdrawalCreationError> {
        let utxos = self.utxos(
            UtxoSelector::any_confirmed(),
        );

        // TODO: Find smallest UTXO larger than or equal to requested withdrawal
        let vault_utxo = utxos.best_vault_utxo();

        let current_vault_value = vault_utxo
            .as_ref()
            .and_then(|VaultStateUtxo(tx, _)| tx.result_value())
            .unwrap_or(VaultAmount::ZERO);

        let depth = vault_utxo
            .as_ref()
            .map(|VaultStateUtxo(tx, _)| tx.depth + 1)
            .ok_or(WithdrawalCreationError::InsufficientFunds)?;

        let transition = VaultTransition::Withdrawal(withdrawal_amount);

        let previous_output = vault_utxo
            .as_ref()
            .and_then(|VaultStateUtxo(tx, _)| tx.outpoint(VaultStateOutput::Vault))
            .ok_or(WithdrawalCreationError::VaultClosed)?;

        let vault_total = current_vault_value.apply_transition(transition, None)
            .ok_or(WithdrawalCreationError::InsufficientFunds)?;

        let parameters = vault_utxo
            .as_ref()
            .and_then(|VaultStateUtxo(tx, _)| tx.vault_state_parameters())
            .and_then(|parameters| parameters
                .next(VaultTransition::Withdrawal(withdrawal_amount), &self.parameters, depth)
            )
            .ok_or(WithdrawalCreationError::VaultClosed)?;

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

        let spend_info = vault_utxo
            .and_then(|VaultStateUtxo(tx, _)| tx.vault_state_parameters())
            .map(|parent_parameters| {
                debug_assert!(depth > 0, "Depth 0 has no ancestors");

                let parent_depth = depth - 1;

                // TODO: should be able to pass in a cached list
                let templates = self.parameters.templates_at_depth(secp, depth);

                self.parameters.vault_output(
                    secp,
                    parent_depth,
                    &parent_parameters,
                    Some(&templates),
                )
            })
            .ok_or(WithdrawalCreationError::MissingSpendInfo)?;

        let signing_info = spend_info.get_spending_condition(VaultOutputSpendCondition::Withdrawal(withdrawal_amount))
            .ok_or(WithdrawalCreationError::InvalidWithdrawalAmount)?;

        let withdrawal_output_info = self.parameters.withdrawal_output_info(secp, depth, withdrawal_amount, vault_total);

        let withdrawal = withdrawal_template.instantiate(previous_output, signing_info, withdrawal_output_info);

        // Need to generate taproot spend info
        Ok(withdrawal)
    }

    pub fn context<C: Verification>(&self, secp: &Secp256k1<C>) -> Context {
        let templates = VaultTemplateCache::new(self.parameters);
        let cache = AddTransactionStateCache::new(secp, &templates);

        Context(self.parameters, templates, cache)
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
