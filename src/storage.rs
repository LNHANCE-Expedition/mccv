use bitcoin::{
    BlockHash,
};

use bitcoin::secp256k1::{
    Secp256k1,
    Verification,
};

use std::rc::Rc;

#[derive(Clone,Debug)]
pub enum Change<T> {
    /// Informs the storage backend or VaultState about the existence of a transaction
    AddTransaction(BlockHash, Rc<T>),

    /// Informs the storage backend or VaultState about the existence of a block, presumably a relevant one
    AddBlock {
        height: u32,
        block_hash: BlockHash,
        parent_block_hash: BlockHash,
        sparse_parent_block_hash: BlockHash,
    },
}

pub struct ChangeLog<S: Storage> {
    id: S::Id,
    changes: Vec<Change<S::Transaction>>,
}

pub struct ChangeIterator<S: Storage>(std::vec::IntoIter<Change<S::Transaction>>);

impl<S: Storage> Iterator for ChangeIterator<S> {
    type Item = Change<S::Transaction>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

impl<S: Storage> ChangeLog<S> {
    /// Create a new, empty changelog
    /// Must be used with discipline, creating multiple changelogs with the same
    /// id may cause unpredictable results
    pub fn new(id: S::Id) -> Self { Self { id, changes: vec![] } }

    pub fn take(&mut self) -> Self {
        std::mem::replace(self, Self::new(self.id))
    }

    pub fn id(&self) -> S::Id { self.id }

    pub fn add(&mut self, change: Change<S::Transaction>) {
        self.changes.push(change);
    }

    pub fn to_iterator(self) -> (ChangeLog<S>, ChangeIterator<S>) {
        (
            Self::new(self.id),
            ChangeIterator(self.changes.into_iter()),
        )
    }
}

pub trait Storage: Sized {
    type StoreError;
    type LoadError;
    type PruneError;
    type Id: Clone + Copy;
    type StaticParameters;
    type State;
    type Transaction;

    fn create(&mut self, name: &str, parameters: Self::StaticParameters) -> Result<(Self::State, ChangeLog<Self>), Self::StoreError>;

    fn load<C: Verification>(&mut self, secp: &Secp256k1<C>, id: Self::Id) -> Result<(Self::State, ChangeLog<Self>), Self::LoadError>;

    fn list(&mut self) -> Result<Vec<(Self::Id, String)>, Self::LoadError>;

    // FIXME: Probably shouldn't be part of a public trait
    fn store(&mut self, changes: ChangeLog<Self>) -> Result<ChangeLog<Self>, Self::StoreError>;

    /// Prune chain tips and unused blocks below a certain height
    fn prune(&mut self, height: u32) -> Result<(), Self::PruneError>;
}
