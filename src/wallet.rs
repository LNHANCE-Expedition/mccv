use bdk_wallet::{
    error::CreateTxError,
    Wallet,
    KeychainKind
};

use bitcoin::secp256k1::{
    Secp256k1,
    Verification,
};

use bitcoin::{
    Amount,
    FeeRate,
    OutPoint,
    Psbt,
    Weight,
};

use crate::vault::{
    DepositTransaction,
    WithdrawalTransaction,
};

/// When calculating the weight of transactions that have no witness data (yet), rust-bitcoin
/// assumes they are non-segwit transactions, and skips the segwit marker
const SEGWIT_MARKER_WEIGHT: Weight = Weight::from_wu(2);

/// When manually calculating the weight of an unsigned transaction, we need to include the weight
/// of the witness-item-count in addition to max_weight_to_satisfy(). We hardcode this to 1 because
/// we will never have a witness bigger than 0xFC items.
const WITNESS_ITEM_COUNT_WEIGHT: Weight = Weight::from_wu(1);

pub trait VaultDepositor {
    type Error;

    fn create_shape<C: Verification>(&mut self, secp: &Secp256k1<C>, deposit_transaction: &mut DepositTransaction, fee_rate: FeeRate) -> Result<Psbt, Self::Error>;
}

#[derive(Debug)]
pub enum ShapeTransactionCreationError {
    TransactionBuildError(CreateTxError),
    InsufficientFunds,
}

impl VaultDepositor for Wallet {
    type Error = ShapeTransactionCreationError;

    fn create_shape<C: Verification>(&mut self, secp: &Secp256k1<C>, deposit_transaction: &mut DepositTransaction, fee_rate: FeeRate) -> Result<Psbt, Self::Error> {
        let (script_pubkey, deposit_amount) = deposit_transaction.payment_info(secp);
        let mut shape_weight = Weight::ZERO;
        // This weight should be correct already
        let deposit_weight = deposit_transaction.weight(secp);
        let mut fee_amount = fee_rate * (shape_weight + deposit_weight);

        let shape_psbt = loop {
            let mut builder = self.build_tx();
            builder
                .version(3)
                .fee_absolute(Amount::ZERO)
                .add_recipient(script_pubkey.as_script(), deposit_amount + fee_amount);

            let shape_psbt = builder.finish()
                .map_err(|e| {
                    match e {
                        CreateTxError::CoinSelection(_cs) => ShapeTransactionCreationError::InsufficientFunds,
                        _ => ShapeTransactionCreationError::TransactionBuildError(e),
                    }
                })?;

            let shape_tx = &shape_psbt.unsigned_tx;

            let index = self.spk_index();
            shape_weight = shape_tx
                .input
                .iter()
                .flat_map(|txin| {
                    index
                        .txout(txin.previous_output)
                        .map(|((keychain, derivation_index), _txout)| {
                            let descriptor = self.public_descriptor(keychain);

                            let derived = descriptor.at_derivation_index(derivation_index)
                                .expect("this better work"); // TODO: Replace with error variant

                            // TODO: we can do better than this, but this should be fine for now
                            derived.max_weight_to_satisfy()
                                .expect("this better work") // TODO: replace with error variant
                        })
                })
                .fold(shape_tx.weight() + SEGWIT_MARKER_WEIGHT, |x, y| x + y);

            let total_weight = shape_weight + deposit_weight;
            let minimum_fee = fee_rate.checked_mul_by_weight(total_weight)
                .expect("fee shouldn't overflow"); // TODO: replace with error variant

            if fee_amount >= minimum_fee {
                break shape_psbt;
            }

            // Update the absolute fee we must supply
            fee_amount = if fee_amount >= minimum_fee {
                fee_amount
            } else {
                minimum_fee
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

        deposit_transaction.connect_input(
            secp,
            OutPoint {
                txid: shape_txid,
                vout: shape_output_index as u32,
            },
            shape_psbt.unsigned_tx.output[shape_output_index].clone(),
        );

        Ok(shape_psbt)
    }
}

#[derive(Debug)]
pub enum CpfpCreationError {
    FeeOverflow,
    InsufficientFunds,
    TransactionBuildError(CreateTxError),
}

pub trait VaultWithdrawer {
    type Error;

    /// Create a child-pays-for-parent transaction to bump a withdrawal transaciton
    fn create_cpfp<C: Verification>(&mut self, _secp: &Secp256k1<C>, withdrawal_transaction: &WithdrawalTransaction, fee_rate: FeeRate) -> Result<Psbt, Self::Error>;
}

impl VaultWithdrawer for Wallet {
    type Error = CpfpCreationError;

    fn create_cpfp<C: Verification>(&mut self, _secp: &Secp256k1<C>, withdrawal_transaction: &WithdrawalTransaction, fee_rate: FeeRate) -> Result<Psbt, CpfpCreationError> {
        let parent_weight = withdrawal_transaction.weight();
        let mut child_weight = Weight::ZERO;

        let anchor_outpoint = withdrawal_transaction.anchor_outpoint();
        let psbt_input = withdrawal_transaction.anchor_output_psbt_input();
        let change_address = self.reveal_next_address(KeychainKind::Internal);

        loop {
            let total_fee = fee_rate.checked_mul_by_weight(parent_weight + child_weight)
                .ok_or(CpfpCreationError::FeeOverflow)?;

            let mut builder = self.build_tx();
            builder
                .version(3)
                .fee_absolute(total_fee)
                .drain_to(change_address.script_pubkey())
                .add_foreign_utxo(anchor_outpoint, psbt_input.clone(), Weight::ZERO)
                .expect("we provide correct foreign utxo metadata");

            let cpfp_psbt = builder.finish()
                .map_err(|e| {
                    match e {
                        CreateTxError::CoinSelection(_cs) => CpfpCreationError::InsufficientFunds,
                        _ => CpfpCreationError::TransactionBuildError(e),
                    }
                })?;

            let index = self.spk_index();
            child_weight = cpfp_psbt
                .unsigned_tx
                .input
                .iter()
                .filter(|txin| txin.previous_output != anchor_outpoint)
                .flat_map(|txin| {
                    index
                        .txout(txin.previous_output)
                        .map(|((keychain, derivation_index), _txout)| {
                            let descriptor = self.public_descriptor(keychain);

                            let derived = descriptor.at_derivation_index(derivation_index)
                                .expect("this better work"); // TODO: replace with error variant

                            // TODO: we can do better than this, but this should be fine for now
                            derived.max_weight_to_satisfy()
                                .expect("this better work") // TODO: replace with error variant
                                + WITNESS_ITEM_COUNT_WEIGHT
                        })
                })
                .fold(cpfp_psbt.unsigned_tx.weight() + SEGWIT_MARKER_WEIGHT, |x, y| x + y);

            let total_weight = child_weight + parent_weight;

            let minimum_fee = fee_rate.checked_mul_by_weight(total_weight)
                .ok_or(CpfpCreationError::FeeOverflow)?;

            if total_fee >= minimum_fee {
                break Ok(cpfp_psbt)
            } else {
                //eprintln!("{total_fee} < {minimum_fee}");
            }
        }
    }
}
