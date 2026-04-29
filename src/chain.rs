use bitcoin::{
    Block,
    BlockHash,
    OutPoint,
    Txid,
};

#[cfg(test)]
use bitcoin::{
    locktime::absolute,
    Amount,
    block,
    CompactTarget,
    script::PushBytes,
    ScriptBuf,
    Sequence,
    transaction,
    Transaction,
    TxIn,
    TxOut,
    Witness,
};

#[cfg(test)]
use bitcoin::hashes::Hash;

#[cfg(test)]
use bitcoin::io::Write;

use bitcoin::secp256k1::{
    Secp256k1,
    Verification,
};

use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::{HashMap, BTreeSet, BTreeMap, btree_map};
use std::rc::{Rc, Weak};

fn utxos<T, O>(transaction: Rc<T>) -> impl Iterator<Item = (OutPoint, Rc<T>, O)>
where
    T: ContractTransaction + ContractOutputs<OutputMetadata = O>,
{
    let txid = transaction.txid();

    transaction
        .outputs()
        .into_iter()
        .map(move |(vout, metadata)|
            (
                OutPoint { vout, txid },
                transaction.clone(),
                metadata,
            )
        )
}

pub trait ContractInputs {
    // FIXME: This should be a map shouldn't it?
    fn inputs(&self) -> BTreeSet<(u32, OutPoint)>;
}

pub trait ContractOutputs {
    type OutputMetadata;

    fn outputs(&self) -> BTreeMap<u32, Self::OutputMetadata>;
}

pub trait ContractTransaction {
    fn txid(&self) -> Txid;
}

#[derive(Debug)]
pub enum ConnectTransactionSuccess<T, O>
{
    Connect {
        inputs: BTreeSet<OutPoint>,
        transaction: T,
        outputs: BTreeMap<u32, O>,
    },
    Ignore,
}

impl<T, O> From<T> for ConnectTransactionSuccess<T, O>
where
    T: ContractInputs + ContractOutputs<OutputMetadata = O>
{
    fn from(transaction: T) -> Self {
        let inputs = transaction
            .inputs()
            .into_iter()
            .map(|(_input_index, outpoint)| outpoint);
        let outputs = transaction.outputs();

        ConnectTransactionSuccess::Connect {
            inputs: inputs.collect(),
            transaction,
            outputs,
        }
    }
}

pub trait ContractTransactionConnector {
    type Transaction;
    type OutputMetadata;
    type Error;

    fn connect<C: Verification>(&self, secp: &Secp256k1<C>, utxos: &ChainTipState<Self::Transaction, Self::OutputMetadata>, transaction: &bitcoin::Transaction)
        -> Result<
            ConnectTransactionSuccess<Self::Transaction, Self::OutputMetadata>,
            Self::Error
        >;
}

#[derive(Clone, Debug)]
pub struct SeenBlock<T> {
    height: u32,
    block_hash: BlockHash,
    /// Direct parent block (may be pruned if no relevant transactions are in it)
    parent_hash: BlockHash,
    // XXX: Might be worth it to keep a flattened set of all important ancestors in the chain tip,
    // maybe keep a special data structure for the chain tip?
    /// Most recent important ancestor (will not be pruned)
    important_ancestor: Option<Rc<SeenBlock<T>>>,

    pub(crate) transactions: RefCell<BTreeSet<Rc<T>>>,
}

#[cfg(test)]
fn make_test_block_hash<T>(parent: Option<&SeenBlock<T>>, seed: u64) -> BlockHash {
    let mut engine = BlockHash::engine();

    let _ = engine.write("TEST_BLOCK_TAG".as_bytes())
        .expect("hash writes always succeed");

    if let Some(parent) = parent {
        let _ = engine.write(parent.block_hash.as_byte_array())
            .expect("hash writes always succeed");
    }

    let _ = engine.write(&seed.to_be_bytes())
        .expect("hash writes always succeed");

    BlockHash::from_engine(engine)
}

#[cfg(test)]
impl<T> SeenBlock<T>
where
    T: Ord,
{
    pub fn genesis<I>(transactions: I) -> Rc<Self>
    where
        I: IntoIterator<Item = T>
    {
        let transactions: BTreeSet<_> = transactions
                    .into_iter()
                    .map(|transaction| Rc::new(transaction))
                    .collect();

        Rc::new(
            Self {
                height: 0,
                block_hash: make_test_block_hash::<T>(None, transactions.len() as u64),
                parent_hash: BlockHash::from_byte_array([0; 32]),
                important_ancestor: None,
                transactions: RefCell::new(transactions),
            }
        )
    }
}

impl<T> Ord for SeenBlock<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.height, self.block_hash).cmp(&(other.height, other.block_hash))
    }
}

impl<T> PartialOrd for SeenBlock<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(<SeenBlock<T> as Ord>::cmp(self, other))
    }
}

impl<T> PartialEq for SeenBlock<T> {
    fn eq(&self, other: &Self) -> bool {
        (self.height, self.block_hash).eq(&(other.height, other.block_hash))
    }
}

impl<T> Eq for SeenBlock<T> { }

trait WeakMap<K, V> {
    fn get_rc<Q: ?Sized>(&self, k: &Q) -> Option<Rc<V>>
    where
        K: Borrow<Q>,
        Q: std::hash::Hash + Eq;

    #[allow(dead_code)]
    fn prune_invalid(&mut self);
}

impl<K, V> WeakMap<K, V> for HashMap<K, Weak<V>>
where
    K: std::hash::Hash + Eq,
{
    fn get_rc<Q: ?Sized>(&self, k: &Q) -> Option<Rc<V>>
    where
        K: Borrow<Q>,
        Q: std::hash::Hash + Eq,
    {
        self.get(k).and_then(Weak::upgrade)
    }

    fn prune_invalid(&mut self) {
        self.retain(|_, v| v.upgrade().is_some())
    }
}

#[derive(Clone)]
pub struct ChainTipState<T, O> {
    /// utxo => (tx, outpoint metadata, height)
    utxos: BTreeMap<OutPoint, (Rc<T>, O, u32)>,
    /// All (confirmed) vault transactions
    transactions: HashMap<Txid, (Rc<T>, u32)>,
}

// TODO: Maybe eliminate the newtype
struct ChainTips<T, O>(BTreeMap<Rc<SeenBlock<T>>, ChainTipState<T, O>>);

impl<T, O> ChainTips<T, O> {
    pub fn new() -> Self { Self(BTreeMap::new()) }

    fn longest(&self) -> Option<(Rc<SeenBlock<T>>, &ChainTipState<T, O>)> {
        self.0.last_key_value()
            .map(|(k, v)| (k.clone(), v))
    }

    fn drop(&mut self, minimum_height: u32) {
        let mut tips_iter = self.0.iter();
        
        let first_retained_block = loop {
            if let Some((tip, _)) = tips_iter.next() {
                if minimum_height <= tip.height {
                    break Some(tip.clone());
                }
            } else {
                break None;
            }
        };

        if let Some(first_retained_block) = first_retained_block {
            self.0 = self.0.split_off(&first_retained_block);
        }
    }

    fn iter(&self) -> impl Iterator<Item = (&SeenBlock<T>, &ChainTipState<T, O>)> {
        self.0.iter().rev().map(|(block, state)| (block.as_ref(), state))
    }

    fn iter_mut(&mut self) -> impl Iterator<Item = (Rc<SeenBlock<T>>, &mut ChainTipState<T, O>)> {
        self.0.iter_mut().map(|(block, state)| (block.clone(), state))
    }

    fn get_mut(&mut self, block: &Rc<SeenBlock<T>>) -> Option<&mut ChainTipState<T, O>> {
        self.0.get_mut(block)
    }
}

impl<T, O> ChainTips<T, O>
where
    ChainTipState<T, O>: Clone,
    O: Ord,
    T: Clone + Ord + ContractTransaction + ContractOutputs<OutputMetadata = O> + ContractInputs,
{
    fn add_block(&mut self, parent_block: Option<Rc<SeenBlock<T>>>, block: Rc<SeenBlock<T>>) -> &mut ChainTipState<T, O> {
        // Couldn't figure out how to satisfy the borrow checker to have a single search in the
        // vacant case, but it's fine
        let state =
            if let Some(parent_block) = parent_block {
                match self.0.entry(parent_block.clone()) {
                    btree_map::Entry::Vacant(_) => ChainTipState::new(),
                    btree_map::Entry::Occupied(entry) => entry.remove(),
                }
            } else {
                ChainTipState::new()
            };

        self.0.entry(block).or_insert(state)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum UtxoSelector {
    /// Only select UTXOs confirmed at or before a given height
    /// If height is None, UTXOs with any confirmation are accepted
    Confirmed(Option<u32>),
    /// Implies any height is valid
    /// bool defines whether it replaces unconfirmed spends or not
    #[allow(dead_code)]
    Unconfirmed(bool),
}

impl UtxoSelector {
    pub fn any_confirmed() -> Self {
        Self::Confirmed(None)
    }

    // FIXME: Struggling to decide what behavior we want generally
    fn select(&self, height: Option<u32>, unconfirmed_spend: bool) -> bool {
        match self {
            // Confirmed on or before max_height
            Self::Confirmed(Some(max_height)) => match height {
                Some(height) => height <= *max_height,
                None => false,
            }
            // As long as it's confirmed
            Self::Confirmed(None) => height.is_some(),
            // Replace unconfirmed spends
            Self::Unconfirmed(true) => true,
            // Don't replace existing unconfirmed spends
            Self::Unconfirmed(false) => !unconfirmed_spend,
        }
    }
}

#[derive(Debug)]
pub enum RevertConfirmedTransactionError {
    /// Trying to revert a transaction with spent outputs
    /// Indicates its being reverted before a child transaction
    UtxoSpent,
    Inconsistent,
    MissingTxid(Txid),
    MissingInput,
}

impl std::fmt::Display for RevertConfirmedTransactionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RevertConfirmedTransactionError::UtxoSpent => write!(f, "UTXO spent"),
            RevertConfirmedTransactionError::Inconsistent => write!(f, "Inconsistent"),
            RevertConfirmedTransactionError::MissingTxid(txid) => write!(f, "Missing TXID: {txid}"),
            RevertConfirmedTransactionError::MissingInput => write!(f, "Missing input"),
        }
    }
}

#[derive(Debug)]
pub enum AddBlockError {
    IrreconcilableHistory,
    MissingParent(BlockHash),
    RevertConfirmedTransactionError(RevertConfirmedTransactionError),
    AddTransactionError,
}

impl std::fmt::Display for AddBlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddBlockError::IrreconcilableHistory => write!(f, "Irreconcilable history"),
            AddBlockError::MissingParent(block_hash) => write!(f, "Missing parent block {block_hash}"),
            AddBlockError::RevertConfirmedTransactionError(e) => write!(f, "Revert confirmed transaction error {e}"),
            AddBlockError::AddTransactionError => write!(f, "Add transaction error"),
        }
    }
}

impl<T, O> ChainTipState<T, O> {
    pub fn new() -> Self {
        Self {
            utxos: BTreeMap::new(),
            transactions: HashMap::new(),
        }
    }

    pub fn transaction(&self, txid: Txid) -> Option<Rc<T>> {
        self.transactions.get(&txid).map(|(tx, _height)| tx.clone())
    }

    pub fn utxo(&self, outpoint: OutPoint) -> Option<(&Rc<T>, &O, u32)> {
        self.utxos.get(&outpoint)
            .map(|(tx, metadata, height)| (tx, metadata, *height))
    }
}

impl<T, O> ChainTipState<T, O>
where
    ChainTipState<T, O>: Clone,
    O: Ord,
    T: Clone + Ord + ContractTransaction + ContractInputs + ContractOutputs<OutputMetadata = O>,
{
    pub fn rewind_to(&self, current_tip: Rc<SeenBlock<T>>, new_tip: &SeenBlock<T>) -> Result<ChainTipState<T, O>, RevertConfirmedTransactionError> {
        let mut state = self.clone();

        let blocks = ChainWalker::new(current_tip);

        for block in blocks {
            if new_tip == block.as_ref() {
                return Ok(state);
            }

            for tx in block.transactions.borrow().iter().rev() {
                let _ = state.revert_confirmed(tx.txid())?;
            }
        }

        Err(RevertConfirmedTransactionError::Inconsistent)
    }
}

impl<T, O> ChainTipState<T, O>
where
    O: Ord,
    T: Clone + Ord + ContractTransaction + ContractInputs + ContractOutputs<OutputMetadata = O>,
{
    pub fn add<C: Verification, Cc>(&mut self, secp: &Secp256k1<C>, connector: &Cc, txid: Txid, transaction: &bitcoin::Transaction, height: u32) -> Result<AddTransactionSuccess<T>, AddTransactionError<Cc::Error>>
    where
        Cc: ContractTransactionConnector<Transaction = T, OutputMetadata = O>,
    {
        match connector.connect(secp, &self, transaction) {
            Ok(ConnectTransactionSuccess::Connect { inputs, transaction, outputs }) => {
                if !inputs.iter().all(|input| self.utxos.contains_key(input)) {
                    return Err(AddTransactionError::MissingInputs);
                }
                let transaction = Rc::new(transaction);

                match self.add_confirmed(txid, inputs, transaction, outputs, height) {
                    Some(tx) => Ok(AddTransactionSuccess::TransactionAdded(tx)),
                    None => Err(AddTransactionError::InternalError),
                }
            }
            Ok(ConnectTransactionSuccess::Ignore) =>
                Ok(AddTransactionSuccess::TransactionIgnored),
            Err(e) => Err(AddTransactionError::ConnectError(e)),
        }
    }

    fn revert_confirmed(&mut self, txid: Txid) -> Result<Rc<T>, RevertConfirmedTransactionError> {
        let transaction = if let Some((transaction, _height)) = self.transactions.get(&txid) {
            transaction.clone()
        } else {
            return Err(RevertConfirmedTransactionError::MissingTxid(txid));
        };

        let utxos: BTreeSet<_> = utxos(transaction.clone()).collect();

        let utxos_spent = utxos.iter().any(|(outpoint, ..)| !self.utxos.contains_key(outpoint));
        if utxos_spent {
            return Err(RevertConfirmedTransactionError::UtxoSpent);
        }

        let input_txes: BTreeMap<Txid, (Rc<T>, u32)> = transaction.inputs()
            .iter()
            .map(|(_input_index, outpoint)|
                self.transactions.get(&outpoint.txid)
                    .map(|(transaction, height)| (outpoint.txid, (transaction.clone(), *height)))
                    .ok_or(RevertConfirmedTransactionError::MissingInput)
             )
            .collect::<Result<_, _>>()?;
            
        let input_utxos = input_txes.iter()
            .flat_map(|(txid, (tx, height))| {
                tx.outputs()
                    .into_iter()
                    .map(|(vout, metadata)| (
                            OutPoint {
                                vout,
                                txid: txid.clone(),
                            },
                            (
                                tx.clone(),
                                metadata,
                                *height,
                            )
                        )
                    )
            });

        self.transactions.remove(&txid);
        self.utxos.retain(|outpoint, _| outpoint.txid != txid);
        self.utxos.extend(input_utxos);

        Ok(transaction)
    }

    pub fn utxos(&self, selector: UtxoSelector) -> BTreeSet<(&OutPoint, Rc<T>, &O, u32)> {
        self.utxos.iter()
            .filter(|(_outpoint, (_tx, _output_metadata, height))| selector.select(Some(*height), false))
            .map(|(outpoint, (tx, output_metadata, height))| (outpoint, tx.clone(), output_metadata, *height))
            .collect()
    }
}

impl<T, O> ChainTipState<T, O>
{
    pub fn add_confirmed(&mut self, txid: Txid, inputs: BTreeSet<OutPoint>, transaction: Rc<T>, outputs: BTreeMap<u32, O>, height: u32) -> Option<Rc<T>> {
        if self.transactions.contains_key(&txid) {
            return Some(transaction);
        }

        if inputs.iter().any(|outpoint| !self.utxos.contains_key(outpoint)) {
            return None;
        }

        for outpoint in inputs {
            self.utxos.remove(&outpoint);
        }

        let utxos = outputs
            .into_iter()
            .map(|(vout, output)| (
                    OutPoint {
                        txid,
                        vout,
                    },
                    (transaction.clone(), output, height)
                )
            );

        self.utxos.extend(utxos);
        self.transactions.insert(txid, (transaction.clone(), height));

        Some(transaction)
    }
}

/// The private add transaction types
#[derive(Debug, Eq, PartialEq)]
pub enum AddTransactionSuccess<T> {
    /// Provided transaction has been added to the vault state
    TransactionAdded(Rc<T>),
    /// The provided transaction is irrelevant to this vault
    TransactionIgnored,
}

#[derive(Debug, Eq, PartialEq)]
pub enum AddTransactionError<E> {
    InternalError,
    ConnectError(E),
    MissingInputs,
}

impl<E: std::fmt::Display> std::fmt::Display for AddTransactionError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddTransactionError::InternalError => write!(f, "Internal error"),
            AddTransactionError::ConnectError(e) => write!(f, "Connect error: {e}"),
            AddTransactionError::MissingInputs => write!(f, "Missing inputs"),
        }
    }
}

pub struct ContractState<T, O> {
    chain_tips: ChainTips<T, O>,
    blocks: HashMap<BlockHash, Weak<SeenBlock<T>>>,
    recent_block_cache: BTreeSet<(u32, Rc<SeenBlock<T>>)>,
}

impl<T, O> ContractState<T, O> {
    pub fn new() -> Self {
        Self {
            chain_tips: ChainTips::new(),
            blocks: HashMap::new(),
            recent_block_cache: BTreeSet::new(),
        }
    }

    pub fn normalize(&mut self) {
        const PRUNE_HEIGHT_DELTA: u32 = 144;

        let max_height = self.chain_tips.iter()
            .map(|(block, _)| block.height)
            .max()
            .unwrap_or(0);

        let minimum_height = max_height.checked_sub(PRUNE_HEIGHT_DELTA).unwrap_or(0);

        self.chain_tips.drop(minimum_height);
        self.blocks.retain(|_, block| block.upgrade().is_some());
    }

    pub fn longest_chain_tip(&self) -> Option<(Rc<SeenBlock<T>>, &ChainTipState<T, O>)> {
        self.chain_tips.longest()
    }

    pub fn get_tip_mut(&mut self, tip: &Rc<SeenBlock<T>>) -> Option<&mut ChainTipState<T, O>> {
        self.chain_tips.get_mut(tip)
    }
}

#[derive(Debug)]
pub enum ApplyBlockError<E> {
    AddBlockError(AddBlockError),
    AddTransactionError(AddTransactionError<E>),
    InternalError,
}

impl<T, O> ContractState<T, O>
where
    ChainTipState<T, O>: Clone,
    O: Ord,
    T: Clone + Ord + ContractTransaction + ContractOutputs<OutputMetadata = O> + ContractInputs,
    AddTransactionSuccess<T>: std::cmp::PartialEq,
{
    pub fn add<C: Verification, Cc>(&mut self, secp: &Secp256k1<C>, connector: &Cc, transaction: &bitcoin::Transaction, height: u32) -> Result<AddTransactionSuccess<T>, AddTransactionError<Cc::Error>>
    where
        Cc: ContractTransactionConnector<Transaction = T, OutputMetadata = O>,
        ChainTipState<T, O>: Clone,
        O: Ord,
        T: Ord + ContractOutputs<OutputMetadata = O> + ContractInputs,
    {
        let txid = transaction.compute_txid();

        let mut first_success: Option<AddTransactionSuccess<T>> = None;
        let mut last_error: Option<AddTransactionError<Cc::Error>> = None;
        for (_tip, state) in self.chain_tips.iter_mut() {
            match state.add(secp, connector, txid, transaction, height) {
                Ok(success) => {
                    if let Some(ref previous_success) = first_success {
                        if *previous_success != AddTransactionSuccess::TransactionIgnored {
                        } else {
                            first_success = Some(success);
                        }
                    } else {
                        first_success = Some(success);
                    }
                }
                Err(e) => { last_error = Some(e); }
            }
        }

        match (first_success, last_error) {
            (Some(AddTransactionSuccess::TransactionIgnored), Some(e)) => Err(e),
            (Some(success), _) => Ok(success),
            (_, Some(e)) => Err(e),
            (_, _) => Err(AddTransactionError::InternalError),
        }
    }

    fn rewind_to(&self, height: u32, block_hash: BlockHash) -> Result<(Rc<SeenBlock<T>>, ChainTipState<T, O>), AddBlockError> {
        'outer: for (tip_block, state) in self.chain_tips.iter()
            .filter(|(block, _tip)| block.height >= height)
        {
            let mut rollback_transactions: Vec<Rc<T>> = Vec::new();
            
            let mut tip_block = self.blocks.get_rc(&tip_block.block_hash)
                .expect("tip block must be in blocks store");

            let mut divergent_block = self.blocks.get_rc(&block_hash)
                .ok_or(AddBlockError::MissingParent(block_hash))?;

            // Rewind block to height of our diverging block
            while tip_block.height > divergent_block.height {
                rollback_transactions.extend(
                    tip_block.transactions.borrow().iter().rev().cloned()
                );

                if let Some(block) = self.blocks.get_rc(&tip_block.parent_hash) {
                    tip_block = block;
                } else {
                    continue 'outer;
                }
            }

            // rewind divergent block to height of chain tip, this is probably overly defensive
            // since that should never be necessary
            while divergent_block.height > tip_block.height {
                if let Some(block) = self.blocks.get_rc(&divergent_block.parent_hash) {
                    divergent_block = block;
                } else {
                    continue 'outer;
                }
            }

            while tip_block != divergent_block {
                rollback_transactions.extend(
                    tip_block.transactions.borrow().iter().rev().cloned()
                );

                if let Some(block) = self.blocks.get_rc(&tip_block.parent_hash) {
                    tip_block = block;
                } else {
                    continue 'outer;
                }

                if let Some(block) = self.blocks.get_rc(&divergent_block.parent_hash) {
                    divergent_block = block;
                } else {
                    continue 'outer;
                }
            }

            let mut new_state = state.clone();

            for transaction in rollback_transactions {
                new_state.revert_confirmed(transaction.txid())
                    .expect("rollback transactions should be structured to prevent panic");
            }

            return Ok((tip_block, new_state))
        }

        Err(AddBlockError::IrreconcilableHistory)
    }

    pub fn add_block(&mut self, new_height: u32, new_chain_tip: BlockHash, parent_hash: BlockHash) -> Result<Rc<SeenBlock<T>>, AddBlockError> {
        if let Some(block) = self.blocks.get_rc(&new_chain_tip) {
            return Ok(block);
        }

        let parent = self.blocks
            .get(&parent_hash)
            .and_then(|block_ref| block_ref.upgrade());

        let important_ancestor = if let Some(ref parent) = parent {
            if !parent.transactions.borrow().is_empty() {
                Some(parent.clone())
            } else {
                parent.important_ancestor.clone()
            }
        } else {
            None
        };

        let block = Rc::new(
            SeenBlock {
                height: new_height,
                block_hash: new_chain_tip,
                parent_hash,
                important_ancestor,
                transactions: RefCell::new(BTreeSet::new()),
            }
        );

        self.blocks.insert(block.block_hash, Rc::downgrade(&block));
        self.recent_block_cache.insert((new_height, block.clone()));

        // If the parent isn't a current chain tip we have to do more complicated processing
        let parent = parent.and_then(|parent| {
            if self.chain_tips.0.contains_key(&parent) {
                Some(parent)
            } else {
                None
            }
        });

        // First block is handled specially
        let tip_state = if block.height == 0 {
            self.chain_tips.add_block(None, block.clone())
        } else if let Some(parent) = parent {
            self.chain_tips.add_block(Some(parent), block.clone())
        } else {
            let parent_height = block.height.saturating_sub(1);

            let (parent, rewound_state) = self.rewind_to(parent_height, block.parent_hash)?;

            let state = self.chain_tips.add_block(Some(parent), block.clone());
            *state = rewound_state;
            state
        };

        for transaction in block.transactions.borrow().iter() {
            tip_state.add_confirmed(
                transaction.txid(),
                transaction.inputs().into_iter().map(|(_, outpoint)| outpoint).collect(),
                transaction.clone(),
                transaction.outputs(),
                block.height,
            )
            .ok_or(AddBlockError::AddTransactionError)?;
        }

        Ok(block)
    }

    pub fn apply_block<C: Verification, Cc, E>(&mut self, secp: &Secp256k1<C>, connector: &Cc, block: &Block, block_height: u32) -> Result<Vec<Rc<T>>, ApplyBlockError<E>>
    where
        Cc: ContractTransactionConnector<Transaction = T, OutputMetadata = O, Error=E>,
    {
        let block_hash = block.block_hash();
        let parent_block_hash = block.header.prev_blockhash;

        let seen_block = self.add_block(block_height, block_hash, parent_block_hash)
            .map_err(ApplyBlockError::AddBlockError)?;

        let state = self.get_tip_mut(&seen_block)
            .expect("block was just added");

        let mut added_txes = Vec::new();

        for transaction in &block.txdata {
            let txid = transaction.compute_txid();
            let add_result = state.add(secp, connector, txid, transaction, block_height);

            match add_result {
                Ok(AddTransactionSuccess::TransactionAdded(tx)) => {
                    seen_block.transactions.borrow_mut()
                        .insert(tx.clone());
                    added_txes.push(tx);
                },
                Ok(AddTransactionSuccess::TransactionIgnored) => { }

                // TODO: We should revert changes in case of error
                Err(AddTransactionError::InternalError) => { return Err(ApplyBlockError::InternalError); },
                Err(AddTransactionError::ConnectError(e)) => {
                    return Err(
                        ApplyBlockError::AddTransactionError(
                            AddTransactionError::ConnectError(e)
                        )
                    );
                }
                Err(AddTransactionError::MissingInputs) => { return Err(ApplyBlockError::InternalError); }
            }
        }

        self.normalize();

        Ok(added_txes)
    }

    pub fn drop(&mut self, minimum_height: u32) {
        while let Some((height, _)) = self.recent_block_cache.first() {
            if *height >= minimum_height {
                break;
            }

            self.recent_block_cache.pop_first()
                .expect("in the loop body recent_block_cache is not empty");
        }

        self.chain_tips.drop(minimum_height);
        self.normalize();
    }
}

/// Iterate over the important blocks in a chain, from newest to oldest
// TODO: I think we might be able to do wthis without taking an Rc?
struct ChainWalker<T> {
    current_block: Option<Rc<SeenBlock<T>>>,
}

impl<T> ChainWalker<T> {
    pub fn new(block: Rc<SeenBlock<T>>) -> Self {
        Self { current_block: Some(block) }
    }
}

impl<T> Iterator for ChainWalker<T> {
    type Item = Rc<SeenBlock<T>>;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.current_block.clone()?;

        self.current_block = current.important_ancestor.clone();

        Some(current)
    }
}

pub(crate) enum Either<A, B> {
    A(A),
    B(B),
}

impl<A, B, I> Iterator for Either<A, B>
where
    A: Iterator<Item = I>,
    B: Iterator<Item = I>,
{
    type Item = I;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::A(ref mut a) => a.next(),
            Self::B(ref mut b) => b.next(),
        }
    }
}

#[cfg(test)]
pub(crate) trait TestBlock {
    fn test_coinbase() -> Transaction {
        let anyonecanspend = ScriptBuf::from_hex("51")
            .expect("OP_TRUE is a valid script");

        let mut coinbase_scriptsig = ScriptBuf::new();
        coinbase_scriptsig
            .push_slice::<&PushBytes>(
                "test"
                    .as_bytes()
                    .try_into()
                    .expect("short string is valid pushdata")
            );

        Transaction {
            version: transaction::Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array([0; 32]),
                        vout: 0,
                    },
                    script_sig: coinbase_scriptsig,
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
            ],
            output: vec![
                TxOut {
                    value: Amount::from_btc(50.0)
                        .expect("50BTC is a valid amount"),
                    script_pubkey: anyonecanspend,
                }
            ],
        }
    }

    fn test_genesis() -> Self;

    fn test_block(prev_blockhash: BlockHash, time: u32, nonce: u32, txdata: Vec<Transaction>) -> Self;

    fn test_child<T: IntoIterator<Item = Transaction>>(&self, nonce: u32, transactions: T) -> Self;
}

#[cfg(test)]
impl TestBlock for Block {
    fn test_genesis() -> Self {
        bitcoin::blockdata::constants::genesis_block(&bitcoin::params::REGTEST)
    }

    fn test_block(prev_blockhash: BlockHash, time: u32, nonce: u32, txdata: Vec<Transaction>) -> Self {
        let mut initial_block = Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash,
                merkle_root: block::TxMerkleNode::from_byte_array([0; 32]),
                time,
                bits: CompactTarget::default(),
                nonce,
            },
            txdata,
        };

        if let Some(merkle_root) = initial_block.compute_merkle_root() {
            initial_block.header.merkle_root = merkle_root;
        }

        initial_block
    }

    fn test_child<T: IntoIterator<Item = Transaction>>(&self, nonce: u32, transactions: T) -> Self {
        let mut txdata = vec![
            Self::test_coinbase(),
        ];

        txdata.extend(transactions);

        Self::test_block(
            self.block_hash(),
            self.header.time + 1,
            nonce,
            txdata
        )
    }
}

#[cfg(test)]
mod test {
    // XXX: We abuse the fact there's very little/no validation of blocks and transactions in
    // rust-bitcoin to construct these pseudo-mocks.

    use super::*;

    use bitcoin::{
        block,
        locktime::absolute,
        Transaction,
        TxIn,
        TxOut,
        transaction,
        ScriptBuf,
        Witness,
    };

    use bitcoin::bip32::{
        Xpriv,
        Xpub,
        ChildNumber,
    };

    use bitcoin::hashes::Hash;

    use bitcoin::secp256k1::{
        Signing,
        XOnlyPublicKey,
    };

    use std::iter;
    use std::str::FromStr;

    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    enum TransactionType {
        Head,
        Body(u32),
        Tail(u32),
    }

    impl TransactionType {
        fn to_pk_index(&self) -> u32 {
            match self {
                TransactionType::Head => 0,
                TransactionType::Body(i) => *i,
                TransactionType::Tail(i) => *i,
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct ContractOutput;

    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct TestContractTransaction {
        txid: Txid,
        transaction: Transaction,
        txtype: TransactionType,
        pubkey: XOnlyPublicKey,
    }

    impl ContractInputs for TestContractTransaction {
        fn inputs(&self) -> BTreeSet<(u32, OutPoint)> {
            match self.txtype {
                TransactionType::Head => iter::empty().collect(),
                _ => self.transaction.input.iter()
                    .enumerate()
                    .map(|(i, input)| (
                        i as u32,
                        input.previous_output,
                    ))
                    .collect(),
            }
        }
    }

    impl ContractOutputs for TestContractTransaction {
        type OutputMetadata = ContractOutput;

        fn outputs(&self) -> BTreeMap<u32, Self::OutputMetadata> {
            match self.txtype {
                TransactionType::Tail(_) => iter::empty().collect(),
                _ => iter::once((0, ContractOutput)).collect(),
            }
        }
    }

    impl ContractTransaction for TestContractTransaction {
        fn txid(&self) -> Txid { self.txid }
    }

    struct TestContractContext(Xpub, u32);

    impl TestContractContext {
        fn pubkey<C: Verification>(&self, secp: &Secp256k1<C>, index: u32) -> XOnlyPublicKey {
            self.0.derive_pub(secp, &[
                    ChildNumber::from_normal_idx(index)
                        .expect("test indices will be constrained")
                ]
            )
            .expect("valid")
            .to_x_only_pub()
        }

        fn initial<C: Verification>(&self, secp: &Secp256k1<C>, outpoint: OutPoint) -> TestContractTransaction {
            let pubkey = self.pubkey(secp, 0);

            let transaction = Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![
                    TxIn {
                        previous_output: outpoint,
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::MAX,
                        witness: Witness::new(),
                    },
                ],
                output: vec![
                    TxOut {
                        value: Amount::ONE_BTC,
                        script_pubkey: ScriptBuf::new_p2tr(secp, pubkey, None),
                    },
                ],
            };

            TestContractTransaction {
                txid: transaction.compute_txid(),
                transaction,
                txtype: TransactionType::Head,
                pubkey,
            }
        }
    }

    struct TestContract {
        context: TestContractContext,
        state: ContractState<TestContractTransaction, ContractOutput>,
    }

    impl TestContract {
        fn initial<C: Verification>(&self, secp: &Secp256k1<C>, outpoint: OutPoint) -> TestContractTransaction {
            self.context.initial(secp, outpoint)
        }

        fn next<C: Verification>(&self, secp: &Secp256k1<C>, previous: &TestContractTransaction) -> Option<TestContractTransaction> {
            let txtype = match previous.txtype {
                TransactionType::Head => TransactionType::Body(1),
                TransactionType::Body(i) if (i + 1) < self.context.1 => TransactionType::Body(i + 1),
                TransactionType::Body(i) => TransactionType::Tail(i + 1),
                TransactionType::Tail(_) => { return None; }
            };

            let pk_index = txtype.to_pk_index();
            let pubkey = self.context.pubkey(secp, pk_index);

            let transaction = Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![
                    TxIn {
                        previous_output: OutPoint {
                            txid: previous.txid(),
                            vout: 0,
                        },
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::MAX,
                        witness: Witness::new(),
                    },
                ],
                output: vec![
                    TxOut {
                        value: Amount::ONE_BTC,
                        script_pubkey: ScriptBuf::new_p2tr(secp, pubkey, None),
                    },
                ],
            };

            Some(
                TestContractTransaction {
                    txid: transaction.compute_txid(),
                    transaction,
                    txtype,
                    pubkey,
                }
            )
        }
    }

    impl ContractTransactionConnector for TestContractContext {
        type Transaction = TestContractTransaction;

        type OutputMetadata = ContractOutput;

        type Error = ();

        fn connect<C: Verification>(&self, secp: &Secp256k1<C>, utxos: &ChainTipState<Self::Transaction, Self::OutputMetadata>, transaction: &bitcoin::Transaction)
            -> Result<
                ConnectTransactionSuccess<Self::Transaction, Self::OutputMetadata>,
                Self::Error
            >
        {
            if transaction.input.len() != 1 {
                return Ok(ConnectTransactionSuccess::Ignore);
            }

            let outpoint = transaction.input[0].previous_output;

            let prev_tx = match utxos.utxo(outpoint) {
                Some((prev_tx, _metadata, _height)) => prev_tx,
                None => {
                    if transaction.output.len() != 1 {
                        return Ok(ConnectTransactionSuccess::Ignore);
                    }

                    let first_pk = self.pubkey(secp, 0);
                    let first_spk = ScriptBuf::new_p2tr(secp, first_pk, None);

                    if transaction.output[0].script_pubkey == first_spk {
                        let transaction = TestContractTransaction {
                            txid: transaction.compute_txid(),
                            transaction: transaction.clone(),
                            txtype: TransactionType::Head,
                            pubkey: first_pk,
                        };

                        return Ok(transaction.into());
                    }

                    return Ok(ConnectTransactionSuccess::Ignore);
                }
            };

            let max_index = self.1;

            let txtype = match prev_tx.txtype {
                TransactionType::Head => TransactionType::Body(1),
                TransactionType::Body(i) if (i + 1) < max_index => TransactionType::Body(i + 1),
                TransactionType::Body(i) => TransactionType::Tail(i + 1),
                TransactionType::Tail(_) => {
                    return Ok(ConnectTransactionSuccess::Ignore);
                }
            };

            let pk_index = txtype.to_pk_index();

            let pubkey = self.pubkey(secp, pk_index);
            
            let transaction = TestContractTransaction {
                txid: transaction.compute_txid(),
                transaction: transaction.clone(),
                txtype,
                pubkey,
            };

            Ok(transaction.into())
        }
    }

    struct ContractId(u32);

    fn make_test_contract<C: Signing>(secp: &Secp256k1<C>, contract_id: ContractId) -> (Xpriv, TestContract) {
        let milk_sad_master = Xpriv::from_str("tprv8ZgxMBicQKsPd1EzCPZcQSPhsotX5HvRDCivA7ASNQFmjWuTsW3WWEwUNKFAZrnD9qpz55rtyLdphqkwRZUqNWYXwSEzd6P4pYvXGByRim3").unwrap();

        let master = milk_sad_master.derive_priv(secp, &[
            ChildNumber::from_hardened_idx(contract_id.0).expect("valid contract id")
        ])
        .expect("sane test values");

        let xpub = Xpub::from_priv(secp, &master);

        (
            master,
            TestContract {
                context: TestContractContext(xpub, 3),
                state: ContractState::new(),
            }
        )
    }

    fn make_test_genesis() -> Block {
        bitcoin::blockdata::constants::genesis_block(&bitcoin::params::REGTEST)
    }

    fn make_test_block_inner(previous: BlockHash, nonce: u32, txdata: Vec<Transaction>) -> Block {
        let mut initial_block = Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: previous,
                merkle_root: block::TxMerkleNode::from_byte_array([0; 32]),
                time: 0,
                bits: CompactTarget::default(),
                nonce,
            },
            txdata,
        };

        if let Some(merkle_root) = initial_block.compute_merkle_root() {
            initial_block.header.merkle_root = merkle_root;
        }

        initial_block
    }

    fn make_test_block(previous: &Block, nonce: u32, txdata: Vec<Transaction>) -> Block {
        make_test_block_inner(previous.block_hash(), nonce, txdata)
    }

    fn make_test_prevout(seed: u64) -> OutPoint {
        const MAX_VOUT: u64 = 252;
        let seed_bytes = seed.to_be_bytes();
        let mut txid = [0u8; 32];
        for i in 0..4 {
            txid[(i * 8)..((i + 1) * 8)].copy_from_slice(&seed_bytes);
        }

        OutPoint {
            txid: Txid::from_byte_array(txid),
            vout: (seed % (MAX_VOUT + 1)) as u32,
        }
    }

    fn make_test_seen_genesis() -> (Block, Rc<SeenBlock<TestContractTransaction>>) {
        let genesis = make_test_genesis();
        let block0 = Rc::new(SeenBlock {
            height: 0,
            block_hash: genesis.block_hash(),
            parent_hash: genesis.block_hash(), // Doesn't matter
            important_ancestor: None,
            transactions: RefCell::new(BTreeSet::new()),
        });

        (genesis, block0)
    }
    /// Helper that creates a child
    fn make_test_child_block(
        parent: &Rc<SeenBlock<TestContractTransaction>>,
        important_ancestor: Option<Rc<SeenBlock<TestContractTransaction>>>,
        transactions: Vec<TestContractTransaction>,
    ) -> Rc<SeenBlock<TestContractTransaction>> {
        let next = make_test_block_inner(parent.block_hash, 0, vec![]);

        Rc::new(
            SeenBlock {
                height: parent.height,
                block_hash: next.block_hash(),
                parent_hash: parent.block_hash,
                important_ancestor,
                transactions: RefCell::new(transactions.into_iter().map(Rc::new).collect()),
            }
        )
    }

    #[test]
    fn test_chain_single_tip() {
        let mut tips: ChainTips<TestContractTransaction, ContractOutput> = ChainTips::new();

        let (_genesis, block0) = make_test_seen_genesis();
        let block1 = make_test_child_block(&block0, None, vec![]);
        let block2 = make_test_child_block(&block1, None, vec![]);

        tips.add_block(None, block0.clone());
        assert_eq!(tips.0.len(), 1);
        tips.add_block(Some(block0.clone()), block1.clone());
        assert_eq!(tips.0.len(), 1);
        tips.add_block(Some(block1.clone()), block2.clone());
        assert_eq!(tips.0.len(), 1);
    }

    /// Test a chain split
    #[test]
    fn test_chain_tips_split() {
        fn tx_utxos(tx: &TestContractTransaction, height: u32) -> BTreeSet<(OutPoint, ContractOutput, u32)> {
            tx
                .outputs()
                .into_iter()
                .map(|(vout, metadata)|
                    (
                        OutPoint {
                            txid: tx.txid,
                            vout,
                        },
                        metadata,
                        height,
                    )
                )
                .collect()
        }

        fn massage_utxos(state: &ChainTipState<TestContractTransaction, ContractOutput>) -> BTreeSet<(OutPoint, ContractOutput, u32)> {
            state
            .utxos(
                UtxoSelector::any_confirmed()
            )
            .into_iter()
            .map(|(outpoint, _tx, metadata, height)| (outpoint.clone(), metadata.clone(), height))
            .collect()
        }

        fn get_utxos(state: &ContractState<TestContractTransaction, ContractOutput>) -> BTreeSet<(OutPoint, ContractOutput, u32)> {
            let state = state.longest_chain_tip().unwrap().1;
            massage_utxos(&state)
        }

        let secp = Secp256k1::new();

        let mut state: ContractState<TestContractTransaction, ContractOutput> = ContractState::new();

        let (_xpriv, contract) = make_test_contract(&secp, ContractId(0));

        let test_tx1 = contract.initial(&secp, make_test_prevout(0));
        let test_tx2 = contract.initial(&secp, make_test_prevout(1));
        let test_tx3 = contract.next(&secp, &test_tx1).unwrap();

        let tx1_utxos = tx_utxos(&test_tx1, 1);
        let tx2_utxos = tx_utxos(&test_tx2, 2);
        let tx3_utxos = tx_utxos(&test_tx3, 3);

        let genesis = make_test_genesis();
        let block1 = make_test_block(&genesis, 0, vec![test_tx1.transaction.clone()]);
        let block2 = make_test_block(&block1, 0, vec![test_tx2.transaction.clone()]);

        let block2b = make_test_block(&block1, 1, vec![]);

        let block3 = make_test_block(&block2b, 0, vec![test_tx3.transaction.clone()]);

        assert_eq!(state.chain_tips.0.len(), 0);

        state.apply_block(&secp, &contract.context, &genesis, 0).unwrap();
        state.apply_block(&secp, &contract.context, &block1, 1).unwrap();
        let seen_block1 = state.blocks.get_rc(&block1.block_hash()).unwrap();
        let utxos = get_utxos(&state);
        assert!(state.chain_tips.0.contains_key(&seen_block1));
        assert_eq!(utxos, tx1_utxos);
        assert_eq!(state.chain_tips.0.len(), 1);

        state.apply_block(&secp, &contract.context, &block2, 2).unwrap();
        let seen_block2 = state.blocks.get_rc(&block2.block_hash()).unwrap();
        assert!(!state.chain_tips.0.contains_key(&seen_block1));
        assert!(state.chain_tips.0.contains_key(&seen_block2));
        let block2_utxos = get_utxos(&state);
        let expected_block2_utxos: BTreeSet<_> = tx1_utxos.union(&tx2_utxos).cloned().collect();
        assert_eq!(block2_utxos, expected_block2_utxos);
        assert_eq!(state.chain_tips.0.len(), 1);

        state.apply_block(&secp, &contract.context, &block2b, 2).unwrap();
        let seen_block2b = state.blocks.get_rc(&block2b.block_hash()).unwrap();
        assert!(!state.chain_tips.0.contains_key(&seen_block1));
        assert!(state.chain_tips.0.contains_key(&seen_block2));
        assert!(state.chain_tips.0.contains_key(&seen_block2b));
        assert_eq!(state.chain_tips.0.len(), 2);

        let block2_utxos = massage_utxos(state.chain_tips.0.get(&seen_block2).unwrap());
        let block2b_utxos = massage_utxos(state.chain_tips.0.get(&seen_block2b).unwrap());
        let expected_block2b_utxos = tx1_utxos.clone();
        assert_eq!(block2_utxos, expected_block2_utxos);
        assert_eq!(block2b_utxos, expected_block2b_utxos);

        state.apply_block(&secp, &contract.context, &block3, 3).unwrap();
        let seen_block3 = state.blocks.get_rc(&block3.block_hash()).unwrap();
        assert!(!state.chain_tips.0.contains_key(&seen_block1));
        assert!(!state.chain_tips.0.contains_key(&seen_block2b));

        assert!(state.chain_tips.0.contains_key(&seen_block2));
        assert!(state.chain_tips.0.contains_key(&seen_block3));
        assert_eq!(state.chain_tips.0.len(), 2);

        let block3_utxos = get_utxos(&state);
        let expected_block3_utxos = tx3_utxos.clone();
        assert_eq!(block3_utxos, expected_block3_utxos);
    }

    fn as_refs<'a, T>(xs: &'a Vec<Rc<T>>) -> Vec<&'a T> {
        xs.iter().map(|x| x.as_ref()).collect()
    }

    #[test]
    fn test_ignore() {
        let secp = Secp256k1::new();
        let (_xpriv, mut contract) = make_test_contract(&secp, ContractId(0));
        let (_xpriv2, mut contract2) = make_test_contract(&secp, ContractId(1));

        let genesis = make_test_genesis();
        let block1 = make_test_block(&genesis, 0, vec![]);

        let _ = contract.state.apply_block(&secp, &contract.context, &genesis, 0)
            .unwrap();
        let _ = contract2.state.apply_block(&secp, &contract2.context, &genesis, 0)
            .unwrap();

        let txes = contract.state.apply_block(&secp, &contract.context, &block1, 1)
            .unwrap();
        assert_eq!(txes, vec![]);

        let txes = contract2.state.apply_block(&secp, &contract2.context, &block1, 1)
            .unwrap();
        assert_eq!(txes, vec![]);

        let contract2_tx1 = contract2.initial(&secp, make_test_prevout(0));
        let block2 = make_test_block(&block1, 0, vec![contract2_tx1.transaction.clone()]);

        let txes = contract.state.apply_block(&secp, &contract.context, &block2, 2)
            .unwrap();
        assert_eq!(txes, vec![]);

        let txes = contract2.state.apply_block(&secp, &contract2.context, &block2, 2)
            .unwrap();
        assert_eq!(as_refs(&txes), vec![&contract2_tx1]);
    }
}
