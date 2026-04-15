use bitcoin::{
    BlockHash,
    Txid,
};

use rusqlite;

use crate::vault::{
    VaultStateTransaction,
};

use std::ops::{Deref, DerefMut};
use std::rc::Rc;

use crate::migrate::{
    MigrationError,
};

use crate::{
    Vault,
    VaultId,
    VaultParameters,
};

pub struct SqliteStorage {
    sqlite: rusqlite::Connection,
}

#[derive(Debug)]
pub enum SqliteInitializationError {
    MigrationError(MigrationError),
    ConnectionConfigurationError(rusqlite::Error),
}

#[allow(dead_code)]
impl SqliteStorage {
    pub fn from_connection(mut _sqlite: rusqlite::Connection) -> Result<Self, SqliteInitializationError> {
        todo!()
    }

    fn store_change(_transaction: &mut rusqlite::Transaction, _vault_id: VaultId, _change: &Change) -> Result<(), StoreError> {
        todo!()
    }
}

impl Deref for SqliteStorage {
    type Target = rusqlite::Connection;

    fn deref(&self) -> &Self::Target {
        &self.sqlite
    }
}

impl DerefMut for SqliteStorage {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.sqlite
    }
}

#[derive(Debug)]
pub enum StoreError {
    SqliteError(rusqlite::Error),
    InvalidState,
    InternalError,
}

#[derive(Debug)]
pub enum LoadError {
    SqliteError(rusqlite::Error),
    InvalidState,
    InternalError,
    NotFound,
    InvalidXpub,
    InvalidWithdrawal,
    InvalidDeposit,
}

impl From<rusqlite::Error> for LoadError {
    fn from(e: rusqlite::Error) -> Self {
        LoadError::SqliteError(e)
    }
}

impl From<rusqlite::types::FromSqlError> for LoadError {
    fn from(e: rusqlite::types::FromSqlError) -> Self {
        LoadError::SqliteError(e.into())
    }
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::SqliteError(e) => e.fmt(f),
            LoadError::InvalidState => write!(f, "Invalid state"),
            LoadError::InternalError => write!(f, "Internal error"),
            LoadError::NotFound => write!(f, "Not found"),
            LoadError::InvalidXpub => write!(f, "Invalid xpub"),
            LoadError::InvalidWithdrawal => write!(f, "Invalid withdrawal"),
            LoadError::InvalidDeposit => write!(f, "Invalid deposit"),

        }
    }
}

impl std::error::Error for LoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LoadError::SqliteError(e) => Some(e),
            _ => None,
        }
    }

    fn description(&self) -> &str {
        "Error loading vault data"
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::SqliteError(e)
    }
}

#[derive(Clone,Debug)]
#[allow(dead_code)]
pub(crate) enum Change {
    /// Informs the storage backend or VaultState about the existence of a transaction
    AddTransaction(Rc<VaultStateTransaction>),

    /// Informs the storage backend or VaultState about the existence of a block, presumably a relevant one
    AddBlock {
        height: u32,
        block_hash: BlockHash,
        parent_block_hash: BlockHash,
    },

    /// Informs the storage backend or VaultState of a transaction's inclusion in a given block
    /// Must be issued after AddTransaction and AddBlock for the provided blocks
    // FIXME: Lose the height from this? Backend and now VaultState can derive height 
    Confirm(Txid, BlockHash, u32),

    /// Instructs the storage backend to drop metadata related to the given block
    Unconfirm(BlockHash),
}

pub struct ChangeLog {
    id: VaultId,
    changes: Vec<Change>,
}

impl ChangeLog {
    pub(crate) fn new(id: VaultId) -> Self { Self { id, changes: vec![] } }

    pub fn id(&self) -> VaultId { self.id }

    pub(crate) fn add(&mut self, change: Change) {
        self.changes.push(change);
    }

    pub fn store<S: VaultStorage>(&mut self, storage: S) -> Result<(), S::StoreError> {
        let _ = storage.store_vault(&self)?;
        self.changes = Vec::new();
        Ok(())
    }
}

pub trait VaultStorage {
    type StoreError;
    type LoadError;

    fn create_vault(self, name: &str, parameters: VaultParameters) -> Result<(Vault, ChangeLog), Self::StoreError>;

    fn load_vault(self, id: VaultId) -> Result<(Vault, ChangeLog), Self::LoadError>;

    fn list_vaults(self) -> Result<Vec<(VaultId, String)>, Self::LoadError>;

    // FIXME: Probably shouldn't be part of a public trait
    fn store_vault(self, changes: &ChangeLog) -> Result<(), Self::StoreError>;
}

impl VaultStorage for &mut SqliteStorage {
    type StoreError = StoreError;
    type LoadError = LoadError;

    fn create_vault(self, _name: &str, _parameters: VaultParameters) -> Result<(Vault, ChangeLog), Self::StoreError> {
        todo!()
    }

    fn load_vault(self, _id: VaultId) -> Result<(Vault, ChangeLog), Self::LoadError> {
        todo!()
    }

    fn store_vault(self, _changes: &ChangeLog) -> Result<(), Self::StoreError> {
        todo!()
    }

    fn list_vaults(self) -> Result<Vec<(VaultId, String)>, Self::LoadError> {
        todo!()
    }
}
