use bitcoin::bip32::{
    ExtendedPubKey,
    ExtendedPrivKey,
    DerivationPath,
    ChildNumber,
};

use bitcoin::hashes::{
    Hash,
    HashEngine,
    sha256::Hash as Sha256,
    sha256::HashEngine as Sha256Engine,
};

use bitcoin::opcodes::all::{
    OP_CSV,
    OP_CHECKSIGVERIFY,
    OP_CHECKSIG,
    OP_NOP4 as OP_CHECKTEMPLATEVERIFY,
};

use bitcoin::secp256k1::{
    Secp256k1,
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
    Sequence,
    TapLeafHash,
    TapNodeHash,
    Transaction,
    Txid, 
    transaction::TxIn,
    transaction::TxOut,
    VarInt,
    blockdata::transaction::Version,
    taproot::{
        LeafVersion,
        TapLeaf,
        TapTree,
        TaprootBuilder,
    },
    Witness,
};

use std::io::Write;

type Depth = u32;

struct VaultParameters {
    increment: u64,
    /// Maximum value = max * increment
    max: u32,
    // All coins are always immediately spendable by master_xpub
    master_xpub: ExtendedPubKey,
    // Coins "recovered" from a bad withdrawal spendable by this xpub
    recovery_xpub: ExtendedPubKey,
    // Withdrawn coins are spendable by withdrawal_xpub at any time
    withdrawal_xpub: ExtendedPubKey,
    // Should there be yet another xpub for un-managed funds? probably but not in the vault params
    delay_per_increment: u32,
    max_withdrawal_per_step: u32,
    max_added_per_step: u32,
    max_depth: Depth,
}

#[derive(Clone,Copy,Debug)]
struct VaultAmount {
    /// The scale of the amount, in satoshis
    increment: u64,
    /// The amount being represented, without scale
    amount: u32,
}

impl VaultAmount {
    fn to_sats(&self) -> u64 {
        u64::saturating_mul(self.amount as u64, self.increment)
    }
}

impl std::ops::Add<u32> for VaultAmount {
    type Output = VaultAmount;

    fn add(self, rhs: u32) -> Self::Output {
        VaultAmount {
            amount: u32::saturating_add(self.amount, rhs),
            increment: self.increment,
        }
    }
}

impl std::ops::Sub<u32> for VaultAmount {
    type Output = Self;

    fn sub(self, rhs: u32) -> Self::Output {
        VaultAmount {
            amount: u32::saturating_sub(self.amount, rhs),
            increment: self.increment,
        }
    }
}

impl Into<Amount> for VaultAmount {
    fn into(self) -> Amount {
        Amount::from_sat(self.to_sats())
    }
}

fn get_default_template(transaction: &Transaction, input_index: u32) -> std::io::Result<Sha256> {
    let mut sha256 = Sha256::engine();

    transaction.version.consensus_encode(&mut sha256)?;
    transaction.lock_time.consensus_encode(&mut sha256)?;

    let any_script_sigs = transaction.input.iter()
        .any(|input| !input.script_sig.is_empty());

    if any_script_sigs {
        for input in transaction.input.iter() {
            input.script_sig.consensus_encode(&mut sha256)?;
        }
    }

    let vin_count: u32 = transaction.input.len() as u32;
    sha256.write(&vin_count.to_le_bytes())?;
    for input in transaction.input.iter() {
        let sequence: u32 = input.sequence.to_consensus_u32();
        sha256.write(&sequence.to_le_bytes())?;
    }

    let vout_count: u32 = transaction.output.len() as u32;
    sha256.write(&vout_count.to_le_bytes())?;

    for output in transaction.output.iter() {
        output.consensus_encode(&mut sha256)?;
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

impl VaultParameters {
    fn amount_from_increment(&self, increment: u32) -> VaultAmount {
        VaultAmount {
            amount: increment,
            increment: self.increment,
        }
    }

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
        let mut builder = Builder::new();

        let withdrawal_key = self.withdrawal_key(secp, depth);

        builder
            .push_int(timelock as i64)
            .push_opcode(OP_CSV)
            .push_x_only_key(&withdrawal_key)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }

    fn withdrawal_timelock(&self, value: VaultAmount) -> u32 {
        u32::saturating_mul(value.amount, self.delay_per_increment)
    }

    fn withdrawal_output<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, value: VaultAmount) -> TxOut {
        let master_key = self.master_key(secp, depth);
        let recovery_tx = self.recovery_template(secp, depth + 1, value);

        let timelock = self.withdrawal_timelock(value);
        let withdrawal_script = self.withdrawal_script(secp, depth, timelock);

        let withdrawal = TapNodeHash::from_script(&withdrawal_script, LeafVersion::TapScript);
        // FIXME: let's make this 1 and the vault 0?
        let recovery_template = get_default_template(&recovery_tx, 1)
            .expect("recovery tx template");

        let mut builder = Builder::new();
        builder.push_slice(recovery_template.as_ref());
        builder.push_opcode(OP_CHECKTEMPLATEVERIFY);
        builder.push_x_only_key(&self.withdrawal_key(secp, depth));
        builder.push_opcode(OP_CHECKSIG);

        let recovery = TapNodeHash::from_script(&builder.as_script(), LeafVersion::TapScript);

        let root_node_hash = TapNodeHash::from_node_hashes(recovery, withdrawal);

        let script_pubkey = ScriptBuf::new_p2tr(secp, master_key, Some(root_node_hash));

        TxOut {
            value: value.into(),
            script_pubkey,
        }
    }

    fn recovery_template<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, value: VaultAmount) -> Transaction {
        let mut input: Vec<TxIn> = Vec::new();
        input.push(dummy_input(RelativeLockTime::ZERO));
        input.push(dummy_input(RelativeLockTime::ZERO));
        let mut output: Vec<TxOut> = Vec::new();

        let key = self.recovery_key(secp, depth);

        let script_pubkey = ScriptBuf::new_p2tr(secp, key, None);

        let recovery_output = TxOut {
            value: value.into(),
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

    // SHIT we have a 1 input and 2 input variation at every step
    // I think the 1 input version would have a lock time, and the 2 input version probably doesn't
    // need it (that'd be a deposit)
    fn terminal_tx_template<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, input_count: usize, lock_time: RelativeLockTime, value: VaultAmount, withdrawal_amount: VaultAmount) -> Transaction {
        let mut input: Vec<TxIn> = Vec::new();

        for _ in 0..input_count {
            input.push(dummy_input(lock_time));
            input.push(dummy_input(lock_time));
        }

        let mut output: Vec<TxOut> = Vec::new();

        let key = self.recovery_key(secp, depth + 1);

        let script_pubkey = ScriptBuf::new_p2tr(secp, key, None);

        let recovery_output = TxOut {
            value: value.into(),
            script_pubkey,
        };
        output.push(recovery_output);

        if withdrawal_amount.to_sats() > 0 {
            let withdrawal_output = self.withdrawal_output(secp, depth + 1, withdrawal_amount);
            output.push(withdrawal_output);
        }
        output.push(ephemeral_anchor());

        Transaction {
            version: Version::non_standard(3),
            lock_time: LockTime::ZERO,
            input,
            output,
        }
    }
}

fn main() {
    println!("Hello, world!");
}
