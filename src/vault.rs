use bdk_wallet::error::CreateTxError;
use bdk_wallet::{Wallet, KeychainKind};
use bitcoin::FeeRate;
use bitcoin::hashes::{
    Hash,
    sha256::Hash as Sha256,
};

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
};

use bitcoin::secp256k1::{
    Secp256k1,
    Signing,
    Verification,
    XOnlyPublicKey,
};

use bitcoin::{
    Amount,
    script::Builder,
    consensus::Encodable,
    absolute::LockTime,
    opcodes::OP_TRUE,
    OutPoint,
    relative::LockTime as RelativeLockTime,
    ScriptBuf,
    TapNodeHash,
    Transaction,
    Txid, 
    transaction::TxIn,
    transaction::TxOut,
    blockdata::transaction::Version,
    taproot::{
        LeafVersion,
        TaprootBuilder,
    },
    Witness,
    Psbt,
};

use crate::migrate::{
    configure,
    migrate,
    MigrationError,
};

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
};

use serde::{
    Deserialize,
    Serialize,
};

use std::io::Write;

use std::collections::HashMap;

pub type Depth = u32;

fn builder_with_capacity(size: usize) -> Builder {
    Builder::from(Vec::with_capacity(size))
}

#[derive(Clone,Serialize,Deserialize)]
pub struct VaultParameters {
    scale: u32,
    /// Maximum value = max * scale
    max: VaultAmount,
    // All coins are always immediately spendable by master_xpub
    master_xpub: Xpub,
    // Coins "recovered" from a bad withdrawal spendable by this xpub
    recovery_xpub: Xpub,
    // Withdrawn coins are spendable by withdrawal_xpub at any time
    withdrawal_xpub: Xpub,
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

    fn to_sats(&self, scale: u32) -> u64 {
        u64::saturating_mul(self.0 as u64, scale as u64)
    }

    fn to_amount(&self, scale: u32) -> Amount {
        Amount::from_sat(self.to_sats(scale))
    }

    fn to_unscaled_amount(&self) -> u32 {
        self.0
    }

    fn nonzero(&self) -> bool {
        self.0 > 0
    }

    fn iter_from(&self, start: VaultAmount) -> impl ParallelIterator<Item=VaultAmount> {
        (start.0..=self.0)
            .into_par_iter()
            .map(|amount| VaultAmount(amount))
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

fn get_default_template(transaction: &Transaction, input_index: u32) -> std::io::Result<Sha256> {
    let mut sha256 = Sha256::engine();

    transaction.version.consensus_encode(&mut sha256)?;
    transaction.lock_time.consensus_encode(&mut sha256)?;

    let any_script_sigs = transaction.input.iter()
        .any(|input| !input.script_sig.is_empty());

    if any_script_sigs {
        let mut script_sig_sha256 = Sha256::engine();

        for input in transaction.input.iter() {
            input.script_sig.consensus_encode(&mut script_sig_sha256)?;
        }

        let script_sig_sha256 = Sha256::from_engine(script_sig_sha256);
        script_sig_sha256.consensus_encode(&mut sha256)?;
    }

    let vin_count: u32 = transaction.input.len() as u32;
    sha256.write(&vin_count.to_le_bytes())?;

    {
        let mut sequences_sha256 = Sha256::engine();
        for input in transaction.input.iter() {
            let sequence: u32 = input.sequence.to_consensus_u32();
            sequences_sha256.write(&sequence.to_le_bytes())?;
        }
        let sequences_sha256 = Sha256::from_engine(sequences_sha256);
        sequences_sha256.consensus_encode(&mut sha256)?;
    }

    let vout_count: u32 = transaction.output.len() as u32;
    sha256.write(&vout_count.to_le_bytes())?;

    {
        let mut outputs_sha256 = Sha256::engine();
        for output in transaction.output.iter() {
            output.consensus_encode(&mut outputs_sha256)?;
        }

        let outputs_sha256 = Sha256::from_engine(outputs_sha256);
        outputs_sha256.consensus_encode(&mut sha256)?;
    }

    sha256.write(&input_index.to_le_bytes())?;

    Ok(Sha256::from_engine(sha256))
}

fn ephemeral_anchor() -> TxOut {
    let mut script_pubkey = ScriptBuf::new();
    script_pubkey.push_opcode(OP_TRUE);

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

#[derive(Clone,Eq,PartialEq,Hash)]
pub enum VaultBalanceChange {
    Deposit(VaultAmount),
    Withdrawal(VaultAmount)
}

#[derive(Clone,Eq,PartialEq,Hash)]
pub enum VaultTransition {
    Deposit(VaultAmount),
    Withdrawal(VaultAmount),
}

impl VaultTransition {
    fn next_value(&self, initial_value: VaultAmount) -> VaultAmount {
        match self {
            VaultTransition::Deposit(ref value) => {
                initial_value + *value
            }
            VaultTransition::Withdrawal(ref value) => {
                initial_value - *value
            }
        }
    }
}

#[derive(Clone,Eq,PartialEq,Hash)]
pub struct VaultStateParameters {
    //depth: Depth, // Always implicit in the way we process
    transition: VaultTransition,
    parent_state_value: VaultAmount,
}

impl VaultStateParameters {
    fn result_state_value(&self) -> VaultAmount {
        self.transition.next_value(self.parent_state_value)
    }

    fn withdrawal_value(&self) -> VaultAmount {
        match self.transition {
            VaultTransition::Deposit(_) => VaultAmount(0),
            VaultTransition::Withdrawal(ref value) => *value,
        }
    }
}

type VaultGeneration = HashMap<VaultStateParameters, Transaction>;

impl VaultParameters {
    fn recovery_key<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth) -> XOnlyPublicKey {

        let path = [
            ChildNumber::from_normal_idx(depth as u32).expect("sane child number")
        ];

        let xpub = self.recovery_xpub.derive_pub(secp, &path)
            .expect("recovery key derivation");

        xpub.to_x_only_pub()
    }

    fn master_key<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth) -> XOnlyPublicKey {
        let path = [
            ChildNumber::from_normal_idx(depth as u32).expect("sane child number")
        ];

        let xpub = self.master_xpub.derive_pub(secp, &path)
            .expect("master key derivation");

        xpub.to_x_only_pub()
    }

    fn withdrawal_key<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth) -> XOnlyPublicKey {
        let path = [
            ChildNumber::from_normal_idx(depth as u32).expect("sane child number")
        ];

        let xpub = self.withdrawal_xpub.derive_pub(secp, &path)
            .expect("withdrawal key derivation");

        xpub.to_x_only_pub()
    }

    fn withdrawal_script<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, timelock: u32) -> ScriptBuf {
        // TODO: decide if we want to omit the CSV when timelock is 0
        // Conservative estimating the push_int size
        builder_with_capacity(5 + 1 + 33 + 1)
            .push_int(timelock as i64)
            .push_opcode(OP_CSV)
            .push_x_only_key(&self.withdrawal_key(secp, depth))
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }

    fn withdrawal_timelock(&self, value: VaultAmount) -> u32 {
        u32::saturating_mul(value.to_unscaled_amount(), self.delay_per_increment)
    }

    fn withdrawal_output<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, value: VaultAmount, withdrawal_amount: VaultAmount) -> TxOut {
        let master_key = self.master_key(secp, depth);
        let recovery_tx = self.recovery_template(secp, depth + 1, value, withdrawal_amount);

        let timelock = self.withdrawal_timelock(value);
        let withdrawal_script = self.withdrawal_script(secp, depth, timelock);

        let withdrawal = TapNodeHash::from_script(&withdrawal_script, LeafVersion::TapScript);
        let input_index = if recovery_tx.input.len() == 1 {
            0
        } else {
            1
        };

        let recovery_template = get_default_template(&recovery_tx, input_index)
            .expect("recovery tx template");

        let recovery_script = builder_with_capacity(33 + 1 + 1 + 33 + 1)
            .push_slice(recovery_template.to_byte_array())
            .push_opcode(OP_CHECKTEMPLATEVERIFY)
            .push_opcode(OP_DROP)
            .push_x_only_key(&self.withdrawal_key(secp, depth))
            .push_opcode(OP_CHECKSIG);

        let recovery = TapNodeHash::from_script(&recovery_script.as_script(), LeafVersion::TapScript);

        let root_node_hash = TapNodeHash::from_node_hashes(recovery, withdrawal);

        let script_pubkey = ScriptBuf::new_p2tr(secp, master_key, Some(root_node_hash));

        TxOut {
            value: value.to_amount(self.scale),
            script_pubkey,
        }
    }

    fn recovery_template<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, vault_amount: VaultAmount, withdrawal_amount: VaultAmount) -> Transaction {
        assert!(vault_amount.nonzero() || withdrawal_amount.nonzero());
        let mut input: Vec<TxIn> = Vec::new();
        if vault_amount.nonzero() {
            input.push(dummy_input(RelativeLockTime::ZERO));
        }

        if withdrawal_amount.nonzero() {
            input.push(dummy_input(RelativeLockTime::ZERO));
        }

        let mut output: Vec<TxOut> = Vec::new();

        let key = self.recovery_key(secp, depth);

        let script_pubkey = ScriptBuf::new_p2tr(secp, key, None);

        let value = vault_amount + withdrawal_amount;

        let recovery_output = TxOut {
            value: value.to_amount(self.scale),
            script_pubkey,
        };

        output.push(recovery_output);
        output.push(ephemeral_anchor());

        Transaction {
            version: Version::non_standard(3),
            lock_time: LockTime::ZERO,
            input,
            output,
        }
    }

    // FIXME: should the terminal state just be all funds spendable by recovery or master?
    fn terminal_tx_template<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, parameter: &VaultStateParameters) -> Transaction {
        let next_value = parameter.result_state_value();
        let withdrawal_amount = parameter.withdrawal_value();

        let mut output: Vec<TxOut> = Vec::new();

        let key = self.recovery_key(secp, depth + 1);

        assert!(next_value.nonzero() || withdrawal_amount.nonzero());

        if next_value.nonzero() {
            // FIXME: should have master key with recovery alternate spending path
            let script_pubkey = ScriptBuf::new_p2tr(secp, key, None);

            let recovery_output = TxOut {
                value: next_value.to_amount(self.scale),
                script_pubkey,
            };
            output.push(recovery_output);
        }

        if withdrawal_amount.nonzero() {
            let withdrawal_output = self.withdrawal_output(secp, depth, next_value, withdrawal_amount);
            output.push(withdrawal_output);
        }
        output.push(ephemeral_anchor());

        Transaction {
            version: Version::non_standard(3),
            lock_time: LockTime::ZERO,
            input: self.dummy_inputs(depth, parameter),
            output,
        }
    }

    fn vault_scripts<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, value: VaultAmount, withdrawal_amount: VaultAmount, next_states: &HashMap<VaultStateParameters, Transaction>) -> Vec<(u32, ScriptBuf)> {
        let mut vault_scripts: Vec<(u32, ScriptBuf)> = self.state_transitions_single(value)
                .filter_map(|params| {
                    if let Some(next_state) = next_states.get(&params) {
                        let weight = match params.transition {
                            VaultTransition::Withdrawal(ref amount) => {
                                self.max_withdrawal_per_step - *amount
                            }
                            VaultTransition::Deposit(ref amount) => {
                                self.max_deposit_per_step - *amount
                            }
                        } + VaultAmount(1);

                        // Vault UTXO will always be input 0
                        let next_state_template = get_default_template(&next_state, 0)
                            .expect("vault tx template");

                        // uh checksequence? I guess we already enforce sequence by CTV
                        let transition_script = builder_with_capacity(33 + 1 + 1 + 33 + 1)
                            .push_slice(next_state_template.to_byte_array())
                            .push_opcode(OP_CHECKTEMPLATEVERIFY)
                            .push_opcode(OP_DROP)
                            .push_x_only_key(&self.withdrawal_key(secp, depth))
                            .push_opcode(OP_CHECKSIG);

                        Some((weight.to_unscaled_amount(), transition_script.into_script()))
                    } else {
                        eprintln!("No next state");
                        None
                    }
                })
                .collect();

        // FIXME: we really need to get consistent about depth + 1 vs depth
        let recovery_tx = self.recovery_template(secp, depth + 1, value, withdrawal_amount);

        let recovery_template = get_default_template(&recovery_tx, 0).expect("recovery template");

        let recovery_script = builder_with_capacity(33 + 1 + 1 + 33 + 1)
            .push_slice(recovery_template.to_byte_array())
            .push_opcode(OP_CHECKTEMPLATEVERIFY)
            .push_opcode(OP_DROP)
            .push_x_only_key(&self.recovery_key(secp, depth))
            .push_opcode(OP_CHECKSIG);

        // FIXME: recovery weight
        vault_scripts.push((1, recovery_script.into_script()));

        // Spending path for vault-output-only recovery
        // Only create if there is actually value left in the vault after the withdrawal
        if value > withdrawal_amount {
            let recovery_tx = self.recovery_template(secp, depth + 1, value - withdrawal_amount, VaultAmount(0));

            let recovery_template = get_default_template(&recovery_tx, 0).expect("recovery template");

            let recovery_script = builder_with_capacity(33 + 1 + 1 + 33 + 1)
                .push_slice(recovery_template.to_byte_array())
                .push_opcode(OP_CHECKTEMPLATEVERIFY)
                .push_opcode(OP_DROP)
                .push_x_only_key(&self.recovery_key(secp, depth))
                .push_opcode(OP_CHECKSIG);

            // FIXME: recovery weight
            vault_scripts.push((1, recovery_script.into_script()));
        }

        // TODO: pull this code into its own function
        // TODO: add complete drain script

        vault_scripts
    }

    fn initial_script_pubkey<C: Verification>(&self, secp: &Secp256k1<C>, value: VaultAmount, next_states: &HashMap<VaultStateParameters, Transaction>) -> ScriptBuf {
        let master_key = self.master_key(secp, 0);
        let vault_scripts = self.vault_scripts(secp, 0, value, VaultAmount(0), next_states);
        
        let spend_info = TaprootBuilder::with_huffman_tree(vault_scripts)
            .expect("taproot tree builder")
            .finalize(secp, master_key)
            .expect("taproot tree finalize");

        ScriptBuf::new_p2tr(secp, spend_info.internal_key(), spend_info.merkle_root())
    }

    // FIXME: probably easiest to just specify the previous transition?
    //fn tx_template<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, input_count: usize, lock_time: RelativeLockTime, value: VaultAmount, withdrawal_amount: VaultAmount, next_states: &HashMap<VaultStateParameters, Transaction>) -> Transaction {
    fn tx_template<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, parameter: &VaultStateParameters, next_states: &HashMap<VaultStateParameters, Transaction>) -> Transaction {
        let next_value = parameter.result_state_value();
        let withdrawal_amount = parameter.withdrawal_value();

        assert!(next_value.nonzero() || withdrawal_amount.nonzero());

        let mut output: Vec<TxOut> = Vec::new();

        let master_key = self.master_key(secp, depth);

        if next_value.nonzero() {
            let vault_scripts = self.vault_scripts(secp, depth, next_value, withdrawal_amount, next_states);

            let spend_info = TaprootBuilder::with_huffman_tree(vault_scripts)
                .expect("taproot tree builder")
                .finalize(secp, master_key)
                .expect("taproot tree finalize");

            let vault_output = TxOut {
                value: next_value.to_amount(self.scale),
                // FIXME: obviously redundant with the TaprootBuilder...
                script_pubkey: ScriptBuf::new_p2tr(secp, spend_info.internal_key(), spend_info.merkle_root()),
            };
            output.push(vault_output);
        }

        if withdrawal_amount.nonzero() {
            let withdrawal_output = self.withdrawal_output(secp, depth, next_value, withdrawal_amount);
            output.push(withdrawal_output);
        }
        output.push(ephemeral_anchor());

        Transaction {
            version: Version::non_standard(3),
            lock_time: LockTime::ZERO,
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
            .expect("16 bit lock time");

        RelativeLockTime::from_height(lock_time)
    }

    fn state_transitions_single(&self, previous_value: VaultAmount) -> impl ParallelIterator<Item=VaultStateParameters> + '_ {
        let withdrawals = self.max_withdrawal_per_step
            .iter_from(VaultAmount(1))
            .filter_map(move |withdrawal| {
                if previous_value >= withdrawal {
                    Some(
                        VaultStateParameters {
                            transition: VaultTransition::Withdrawal(withdrawal),
                            parent_state_value: previous_value,
                        }
                    )
                } else {
                    None
                }
            });

        let deposits = self.max_deposit_per_step
            .iter_from(VaultAmount(1))
            .filter_map(move |deposit| {
                let result_value = previous_value + deposit;
                if result_value < self.max {
                    Some(
                        VaultStateParameters{
                            transition: VaultTransition::Deposit(deposit),
                            parent_state_value: previous_value,
                        }
                    )
                } else {
                    None
                }
            });

        withdrawals.chain(deposits)
    }

    fn state_transitions(&self) -> impl ParallelIterator<Item=VaultStateParameters> + '_ {
        let withdrawals = self.max_withdrawal_per_step
            .iter_from(VaultAmount(1))
            .flat_map(move |withdrawal| {
                self.max
                    .iter_from(VaultAmount(1))
                    .filter_map(move |previous_value| {
                    if previous_value >= withdrawal {
                        Some(
                            VaultStateParameters {
                                transition: VaultTransition::Withdrawal(withdrawal),
                                parent_state_value: previous_value,
                            }
                        )
                    } else {
                        None
                    }
                })
            });

        let deposits = self.max_deposit_per_step
            .iter_from(VaultAmount(1))
            .flat_map(move |deposit| {
                self.max
                    .iter_from(VaultAmount(1))
                    .filter_map(move |previous_value| {
                        let result_value = previous_value + deposit;
                        if result_value < self.max {
                            Some(
                                VaultStateParameters{
                                    transition: VaultTransition::Deposit(deposit),
                                    parent_state_value: previous_value,
                                }
                            )
                        } else {
                            None
                        }
                    })
            });

        withdrawals.chain(deposits)
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

    fn terminal_tx_templates<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth) -> HashMap<VaultStateParameters, Transaction> {
        self.state_transitions()
            .map(|parameter| 
                (parameter.clone(), self.terminal_tx_template(secp, depth, &parameter))
            )
            .collect()
    }

    fn tx_templates<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, next_states: &HashMap<VaultStateParameters, Transaction>) -> HashMap<VaultStateParameters, Transaction> {
        if depth == 0 {
            self.state_transitions_single(VaultAmount(0))
                .map(|parameter| (
                        parameter.clone(),
                        self.tx_template(secp, depth, &parameter, next_states)
                    )
                )
                .collect()
        } else {
            self.state_transitions()
                .map(|parameter| (
                        parameter.clone(),
                        self.tx_template(secp, depth, &parameter, next_states)
                    )
                )
                .collect()
        }
    }

    pub fn templates_at_depth<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth) -> (Option<HashMap<VaultStateParameters, Transaction>>, HashMap<VaultStateParameters, Transaction>) {
        let mut next_state = self.terminal_tx_templates(&secp, self.max_depth);

        let mut i = self.max_depth - 1;
        while i >= depth {
            // tx_templates handles when depth == 0 specially for us
            next_state = self.tx_templates(&secp, i, &next_state);

            i -= 1;
        }

        // FIXME: get parent state, but how?
        if i >= 0 {
            let previous_state = self.tx_templates(&secp, i, &next_state);

            (Some(previous_state), next_state)
        } else {
            (None, next_state)
        }
    }

    pub fn from_xpriv<C: Signing>(secp: &Secp256k1<C>, xpriv: &Xpriv, vault_number: u32) -> Self {
        let h = |x: u32| ChildNumber::from_hardened_idx(x).expect("in range");

        let master_xpriv = xpriv.derive_priv(secp, &[h(69), h(vault_number), h(0)])
            .expect("derive master xpriv");

        let recovery_xpriv = xpriv.derive_priv(secp, &[h(69), h(vault_number), h(1)])
            .expect("derive recovery xpriv");

        let withdrawal_xpriv = xpriv.derive_priv(secp, &[h(69), h(vault_number), h(2)])
            .expect("derive withdrawal xpriv");

        let master_xpub = Xpub::from_priv(secp, &master_xpriv);
        let recovery_xpub = Xpub::from_priv(secp, &recovery_xpriv);
        let withdrawal_xpub = Xpub::from_priv(secp, &withdrawal_xpriv);

        let delay_per_increment = 6 * 6; // ~6 hours

        // Vault max size = 1 Bitcoin
        let max = VaultAmount(100);
        let scale = 1_000_000; // million sats
        
        let max_withdrawal_per_step = VaultAmount(8);
        let max_deposit_per_step = VaultAmount(8);

        let max_depth = 10;

        VaultParameters {
            scale,
            max,
            master_xpub,
            recovery_xpub,
            withdrawal_xpub,
            delay_per_increment,
            max_withdrawal_per_step,
            max_deposit_per_step,
            max_depth,
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
    /// A sweep of the vault to recovery location
    Close(VaultAmount),
}

pub struct VaultTransaction {
    txid: Txid,
    depth: Depth,
    outpoints: VaultOutpoints,
    /// Vault amount resulting from this transaction
    value: VaultAmount,
}

#[derive(Clone,Copy,Debug)]
pub enum VaultTransactionToStateParametersError {
    CloseTransaction,
}

impl TryFrom<&VaultTransaction> for VaultStateParameters {
    type Error = VaultTransactionToStateParametersError;

    fn try_from(transaction: &VaultTransaction) -> Result<Self, Self::Error> {
        let (initial_amount, transition) = match transaction.outpoints {
            // FIXME: maybe assert that transaction.value >= amount?
            VaultOutpoints::Deposit(amount) => (transaction.value - amount, VaultTransition::Deposit(amount)),
            VaultOutpoints::Withdrawal(amount, withdrawal_amount) => (amount + withdrawal_amount, VaultTransition::Withdrawal(withdrawal_amount)),
            VaultOutpoints::Close(_amount) => {
                return Err(VaultTransactionToStateParametersError::CloseTransaction);
            }
        };

        Ok(Self {
            transition,
            parent_state_value: initial_amount,
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
    TransactionBuildError(CreateTxError),
    VaultClosed,
}

pub struct Vault {
    parameters: VaultParameters,
    history: Vec<VaultTransaction>,
}

impl Vault {
    pub fn init(&self, connection: &mut Connection) -> Result<(), VaultInitializationError> {
        migrate(connection)
            .map_err(|e| VaultInitializationError::MigrationError(e))?;
        configure(&connection)
            .map_err(|e| VaultInitializationError::ConfigurationError(e))
    }

    pub fn new(parameters: VaultParameters, history: Vec<VaultTransaction>) -> Self {
        Self {
            parameters,
            history,
        }
    }

    pub fn load(connection: &mut Connection) -> Result<Self, rusqlite::Error> {
        todo!()
    }

    // FIXME: and parent utxo scripts
    pub fn deposit_transaction_template<C: Verification>(&self, secp: &Secp256k1<C>, deposit_amount: VaultAmount) -> Option<Transaction> {
        let depth = self.history.len() as Depth;

        let transactions = self.parameters.templates_at_depth(secp, depth);

        let parameters = match self.history.last() {
            //Some(transaction) => VaultStateParameters::try_from(transaction).ok(),
            Some(transaction) => Some(
                VaultStateParameters {
                    transition: VaultTransition::Deposit(deposit_amount),
                    parent_state_value: transaction.value,
                }
            ),
            None => Some(
                VaultStateParameters {
                        transition: VaultTransition::Deposit(deposit_amount),
                        parent_state_value: VaultAmount(0),
                }
            ),
        };

        // Could underflow if depth check is not followed
        let parent_index = self.history.len() - 1;

        let parameters = match self.history.get(parent_index) {
            //Some(transaction) => VaultStateParameters::try_from(transaction).ok(),
            Some(transaction) => Some(
                VaultStateParameters {
                    transition: VaultTransition::Deposit(deposit_amount),
                    parent_state_value: transaction.value,
                }
            ),
            None => Some(
                VaultStateParameters {
                        transition: VaultTransition::Deposit(deposit_amount),
                        parent_state_value: VaultAmount(0),
                }
            ),
        };

        // FIXME: I think I fucked up here anyway, the last tx state parameters 
        // we need to also see if we have a timelock from the parent transaction...

        // FIXME!!!!!
        parameters.and_then(|parameters| transactions.1.get(&parameters).cloned())
    }

    pub fn get_vault_utxo_witness<C: Verification>(&self, secp: &Secp256k1<C>, parameters: VaultStateParameters) -> Option<Transaction> {
        let depth = self.history.len() as Depth;

        if depth < 1 {
            return None;
        }

        /*
        let transactions = self.parameters.templates_at_depth(secp, depth - 1);

        let parameters = match self.history.last() {
            Some(transaction) => VaultStateParameters::try_from(transaction).ok(),
            None => Some(
                VaultStateParameters {
                        transition: VaultTransition::Deposit(deposit_amount),
                        initial_amount: VaultAmount(0),
                }
            ),
        };

        parameters.and_then(|parameters| transactions.get(&parameters).cloned())
        */
        todo!()
    }

    pub fn create_deposit<C: Verification>(&self, secp: &Secp256k1<C>, wallet: &mut Wallet, deposit_amount: VaultAmount, fee_rate: FeeRate) -> Result<(Psbt, Psbt), VaultDepositError> {
        let mut template = self.deposit_transaction_template(secp, deposit_amount)
            .ok_or(VaultDepositError::VaultClosed)?;

        // TODO: add parent utxo witness

        let address = wallet.reveal_next_address(KeychainKind::Internal);
        let mut builder = wallet.build_tx();
        builder
            .fee_absolute(Amount::from_sat(0))
            .add_recipient(address.script_pubkey(), deposit_amount.to_amount(self.parameters.scale));

        let shape_tx = builder.finish()
            .map_err(|e| VaultDepositError::TransactionBuildError(e))?;

        todo!()
    }
}

fn vault_generation_filter(current_amount: VaultAmount, previous_amount: Option<VaultAmount>) -> impl Fn(&VaultStateParameters, &mut Transaction) -> bool {
    // FIXME: Make sure we're thinking about generations correctly
    move |params: &VaultStateParameters, _tx: &mut Transaction| -> bool {
        if let Some(previous_amount) = previous_amount {
            params.result_state_value() == current_amount
                && params.parent_state_value == previous_amount
        } else {
            params.result_state_value() == current_amount
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::test_util;

    use std::str::FromStr;
    use bdk_electrum::{
        electrum_client::ElectrumApi,
    };

    use bdk_wallet::KeychainKind;
    use bdk_wallet::Wallet;

    use electrsd::bitcoind::bitcoincore_rpc::{
        RpcApi,
    };

    #[test]
    fn test_ctv() {
        for (tx, index, result) in test_util::get_ctv_test_vectors() {
            assert_eq!(get_default_template(&tx, index).unwrap(), result);
        }
    }

    fn test_xpubs() -> (Xpub, Xpub, Xpub) {
        (
            Xpub::from_str("tpubDCjgmQsPz1xamjuPHqwFkdU2DfHe9oz4VSgzJD1JDWZWM1pYyk82WMN7zyQRN85F5Yx8Rs2xeGC4eZ5un27LqPu74BDQZcWkqkhnVmbWmMB").unwrap(), // Master Xpub
            Xpub::from_str("tpubDCjgmQsPz1xarEYG4eya8HegHuun3QU5VAJKo8oPwVgMoQb961aP7nv5J9PH9jjj74MzPp1U5YzzjdZF3gFANtMNuMKyrSYKmJt7jQMonM1").unwrap(), // Recovery Xpub
            Xpub::from_str("tpubDCjgmQsPz1xatYi9cSP3ov2CWMFcnh5FNzTtLykxpHYZXaGuYMRCgpThcmXFAHBKrR6Za69v7CcMqvEfT7wrQtWxZr4EW58NusmAGhUtj2F").unwrap(), // Withdrawal Xpub
        )
    }

    fn test_parameters() -> VaultParameters {
        let (master_xpub, recovery_xpub, withdrawal_xpub) = test_xpubs();

        VaultParameters {
            scale: 100_000_000,
            max: VaultAmount(10),
            master_xpub,
            recovery_xpub,
            withdrawal_xpub,
            delay_per_increment: 36,
            max_withdrawal_per_step: VaultAmount(3),
            max_deposit_per_step: VaultAmount(3),
            max_depth: 10,
        }
    }

    #[test]
    fn test_simple() {
        let secp = Secp256k1::new();
        let test_parameters = test_parameters();

        let (_parent_templates, templates) = test_parameters.templates_at_depth(&secp, 0);

        for (params, template) in templates.into_iter() {
            assert_eq!(template.input.len(), 1);
            assert_eq!(params.parent_state_value, VaultAmount(0));
        }
    }

    #[test]
    fn test_deposit() {
        let secp = Secp256k1::new();

        let (electrum, electrsd, bitcoind) = test_util::get_test_daemons();
        let test_parameters = test_parameters();

        let (mut wallet, mut sqlite) = test_util::load_wallet();

        test_util::generate_to_wallet(&bitcoind, &electrum, &mut wallet, 100);

        std::thread::sleep(std::time::Duration::from_secs(30));

        test_util::full_scan(&electrum, &mut wallet, &mut sqlite);

        let balance = wallet.balance();

        assert_eq!(balance.confirmed.to_sat(), 50 * 100_000_000);

        let vault = Vault::new(test_parameters, Vec::new());

        vault.init(&mut sqlite)
            .expect("vault init");

        //vaultinitial_script_pubkey(&secp, VaultAmount(5), next_states: &HashMap<VaultStateParameters, Transaction>) -> ScriptBuf {

        todo!()
    }

}
