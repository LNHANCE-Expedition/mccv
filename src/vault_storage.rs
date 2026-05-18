#[cfg(feature = "bitcoind")]
use bdk_bitcoind_rpc::bitcoincore_rpc;

use bitcoin::{BlockHash, Transaction, Txid};
use bitcoin::bip32::{Xpub, Fingerprint, Xpriv, DerivationPath};
use bitcoin::consensus::{Encodable, Decodable};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Secp256k1, Verification};

use rusqlite::{self, OptionalExtension};
use rusqlite::{
    params,
    types::FromSql,
    types::ToSql,
    types::ToSqlOutput,
};

use std::collections::{hash_map, HashMap, HashSet};
use std::ops::{Deref, DerefMut};
#[cfg(feature = "bitcoind")]
use std::path::PathBuf;

use crate::chain::{
    AddBlockError, AddTransactionSuccess, AddTransactionError,
};

use crate::migrate::{
    migrate,
    MigrationError,
};

use crate::storage::{
    Change,
    ChangeLog,
    Storage,
};

use crate::vault::{
    ConnectVaultTransactionError,
    Context,
    Vault,
    VaultAmount,
    VaultId,
    VaultParameters,
    VaultScale,
    VaultState,
    VaultStateTransaction,
};

use std::str::FromStr;

#[allow(dead_code)]
pub static VAULT_VERSION_ID: i64 = 1;

#[allow(dead_code)]
pub static VAULT_MIGRATIONS: [(u32, &str); 1] = [
    (1, include_str!("../data/migrations/0001-initial.sql")),
];

pub struct SqliteStorage {
    sqlite: rusqlite::Connection,
}

#[derive(Debug)]
pub enum SqliteInitializationError {
    MigrationError(MigrationError),
    ConnectionConfigurationError(rusqlite::Error),
    CommitError(rusqlite::Error),
}

pub struct StoredSecrets {
    pub master_fingerprint: Fingerprint,
    pub master_xpriv: Option<Xpriv>,
    pub hot_path: DerivationPath,
    pub hot_xpriv: Xpriv,
    pub descriptor: String,
    pub change_descriptor: String,
}

#[allow(dead_code)]
impl SqliteStorage {
    pub fn from_connection(mut sqlite: rusqlite::Connection) -> Result<Self, SqliteInitializationError> {
        {
            let mut transaction = sqlite.transaction().unwrap();

            migrate(&mut transaction, VAULT_VERSION_ID, &VAULT_MIGRATIONS)
                .map_err(SqliteInitializationError::MigrationError)?;

            transaction.commit()
                .map_err(SqliteInitializationError::CommitError)?;
        }

        Ok(SqliteStorage { sqlite })
    }

    pub fn store_secrets(&mut self, id: VaultId, secrets: &StoredSecrets) -> Result<(), StoreError> {
        let transaction = self.sqlite.transaction()?;

        transaction.execute(r#"
            insert
            into mccv_secret (
                id,
                master_fingerprint,
                master_xpriv,
                hot_path,
                hot_xpriv,
                descriptor,
                change_descriptor
            )
            values ( ?, ?, ?, ?, ?, ?, ? )
            "#,
            params![
                id,
                secrets.master_fingerprint.to_bytes(),
                secrets.master_xpriv
                    .map(|xpriv| xpriv.to_string()),
                secrets.hot_path.to_string(),
                secrets.hot_xpriv.to_string(),
                secrets.descriptor,
                secrets.change_descriptor,
            ],
        )?;

        transaction.commit()?;

        Ok(())
    }

    pub fn load_secrets(&mut self, id: VaultId) -> Result<Option<StoredSecrets>, StoreError> {
        let transaction = self.sqlite.transaction()?;

        let secrets = transaction.query_row(r#"
            select
                master_fingerprint,
                master_xpriv,
                hot_path,
                hot_xpriv,
                descriptor,
                change_descriptor
            from
                mccv_secret
            where
                id = ?
            "#,
            params![ id ],
            |row| {
                let master_fingerprint: [u8; 4] = row.get(0)?;
                let master_xpriv: Option<Xpriv> = row.get_ref(1)?
                        .as_str_or_null()?
                        .map(|s| s
                            .parse()
                            .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                                    1,
                                    rusqlite::types::Type::Text,
                                    Box::new(e),
                                )
                            )
                        )
                        .transpose()?;

                let hot_path: DerivationPath = row.get_ref(2)?
                    .as_str()?
                    .parse()
                    .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                            2,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    )?;

                let hot_xpriv: Xpriv = row.get_ref(3)?
                    .as_str()?
                    .parse()
                    .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                            3,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    )?;



                Ok(
                    StoredSecrets {
                        master_fingerprint: master_fingerprint.into(),
                        master_xpriv,
                        hot_path,
                        hot_xpriv,
                        descriptor: row
                            .get_ref(4)?
                            .as_str()?
                            .to_owned(),
                        change_descriptor: row
                            .get_ref(5)?
                            .as_str()?
                            .to_owned(),
                    }
                )
            }
        )
        .optional()?;

        Ok(secrets)
    }

    #[cfg(feature = "bitcoind")]
    pub fn store_rpc_conf(&mut self, id: VaultId, rpc_url: &str, auth: &bitcoincore_rpc::Auth) -> Result<(), StoreError> {
        let transaction = self.sqlite.transaction()?;

        let (rpc_username, rpc_password, rpc_cookie) = match auth {
            bitcoincore_rpc::Auth::None => (None, None, None),
            bitcoincore_rpc::Auth::UserPass(username, password) => (
                Some(username.as_str()),
                Some(password.as_str()),
                None,
            ),
            bitcoincore_rpc::Auth::CookieFile(cookie_path) => (
                None,
                None,
                Some(
                    cookie_path.to_str()
                        // FIXME: really abusing this error variant...
                        // TODO: Make a new error type for this method
                        .ok_or(StoreError::InvalidState)?
                ),
            ),
        };

        transaction.execute(r#"
            insert
            into mccv_rpc_config (
                id,
                rpc_url,
                rpc_username,
                rpc_password,
                rpc_cookie
            )
            values ( ?, ?, ?, ?, ? )
            on conflict ( id )
                do update
                    set
                        rpc_url = excluded.rpc_url,
                        rpc_username = excluded.rpc_username,
                        rpc_password = excluded.rpc_password,
                        rpc_cookie = excluded.rpc_cookie
            "#,
            params![
                id,

                rpc_url,
                rpc_username,
                rpc_password,
                rpc_cookie,
            ],
        )?;

        transaction.commit()?;

        Ok(())
    }

    #[cfg(feature = "bitcoind")]
    pub fn load_rpc_conf(&mut self, id: VaultId) -> Result<Option<(String, bitcoincore_rpc::Auth)>, LoadError> {
        let transaction = self.sqlite.transaction()?;

        let row =
            transaction.query_row(r#"
                    select
                        rpc_url,
                        rpc_username,
                        rpc_password,
                        rpc_cookie
                    from mccv_rpc_config
                    where
                        id = ?
                "#,
                params![ id ],
                |row| {
                    let rpc_url: String = row.get(0)?;
                    let rpc_username: Option<String> = row.get(1)?;
                    let rpc_password: Option<String> = row.get(2)?;
                    let cookie_path: Option<PathBuf> = row
                        .get_ref(3)?
                        .as_str_or_null()?
                        .map(|cookie_path| PathBuf::from_str(cookie_path))
                        .transpose()
                        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                                3,
                                rusqlite::types::Type::Text,
                                Box::new(e),
                            )
                        )?;

                    Ok((rpc_url, rpc_username, rpc_password, cookie_path))
                }
            )
            .optional()?;

        if let Some((rpc_url, rpc_username, rpc_password, cookie_path)) = row {
            let auth = match (rpc_username, rpc_password, cookie_path) {
                (None, None, None) => bitcoincore_rpc::Auth::None,
                (Some(rpc_username), Some(rpc_password), None) =>
                    bitcoincore_rpc::Auth::UserPass(
                        rpc_username,
                        rpc_password,
                    ),
                (None, None, Some(cookie_path)) =>
                    bitcoincore_rpc::Auth::CookieFile(cookie_path),
                _ => {
                    // FIXME: Abusing this error variant quite a bit too
                    return Err(LoadError::InvalidState);
                }
            };

            Ok(Some((rpc_url, auth)))
        } else {
            Ok(None)
        }
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
    ConnectError(ConnectVaultTransactionError),
    AddBlockError(AddBlockError),
    AddTransactionError(AddTransactionError<ConnectVaultTransactionError>),
    IgnoredContractTransaction(Txid),
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
            LoadError::ConnectError(e) => write!(f, "Error connecting transaction: {e}"),
            LoadError::AddBlockError(e) => write!(f, "Error adding block: {e}"),
            LoadError::AddTransactionError(e) => write!(f, "Error adding transaction {e}"),
            LoadError::IgnoredContractTransaction(txid) => write!(f, "Transaction {txid} was erroneously ignored"),
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

impl ToSql for VaultAmount {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(self.to_unscaled_amount().into())
    }
}

impl FromSql for VaultAmount {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        let amount: u32 = FromSql::column_result(value)?;

        Ok(VaultAmount::new(amount))
    }
}

struct ScopeExit<F: FnOnce()>(Option<F>);

impl<F: FnOnce()> Drop for ScopeExit<F> {
    fn drop(&mut self) {
        match self.0.take() {
            None => {}
            Some(f) => { f(); }
        }
    }
}

impl<F: FnOnce()> ScopeExit<F> {
    fn new(f: F) -> Self { Self(Some(f)) }
}

#[derive(Debug)]
pub enum PruneError {
    SqliteError(rusqlite::Error),
}

impl From<rusqlite::Error> for PruneError {
    fn from(e: rusqlite::Error) -> Self {
        PruneError::SqliteError(e)
    }
}

/// Topologically sort contract transactions
fn sorted_transactions(block_transactions: &HashMap<Txid, Transaction>) -> Vec<Txid> {
    let mut unsorted_parent_counts: HashMap<Txid, usize> = HashMap::new();
    let mut children: HashMap<Txid, HashSet<Txid>> = block_transactions
        .iter()
        .map(|(txid, _transaction)| (*txid, HashSet::new()))
        .collect();

    let mut current: Vec<Txid> = Vec::new();

    for (txid, transaction) in block_transactions {
        let mut parent_count = 0;
        for input in &transaction.input {
            let parent_txid = &input.previous_output.txid;
            if block_transactions.contains_key(parent_txid) {
                children
                    .get_mut(parent_txid)
                    .expect("all transactions in this block have an entry")
                    .insert(*txid);

                parent_count += 1;
            }
        }

        if parent_count < 1 {
            current.push(*txid);
        } else {
            unsorted_parent_counts.insert(*txid, parent_count);
        }
    }

    let mut ordered_txids: Vec<Txid> = Vec::with_capacity(block_transactions.len());

    while let Some(txid) = current.pop() {
        ordered_txids.push(txid);

        let children = children.get(&txid)
            .expect("all transactions accounted for");
        for child_txid in children {
            match unsorted_parent_counts.entry(*child_txid) {
                hash_map::Entry::Occupied(mut entry) => {
                    // When a transaction references another multiple times
                    // it must be handled correctly
                    let reference_count = block_transactions
                        .get(child_txid)
                        .expect("must be in input transaction set")
                        .input
                        .iter()
                        .filter(|input| input.previous_output.txid == txid)
                        .count();
                    let parent_count = entry.get().saturating_sub(reference_count);
                    if parent_count == 0 {
                        entry.remove();
                        current.push(*child_txid);
                    } else {
                        entry.insert(parent_count);
                    }
                }
                hash_map::Entry::Vacant(_) => { }
            }
        }
    }

    assert!(unsorted_parent_counts.is_empty());

    ordered_txids
}

fn hash_column<H: bitcoin::hashes::Hash>(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<H>
{
    let bytes = row
        .get_ref(index)?
        .as_bytes()?;

    H::from_slice(bytes)
        .map_err(|e|
            rusqlite::Error::FromSqlConversionFailure(
                index,
                rusqlite::types::Type::Text,
                Box::new(e)
            )
        )
}

fn optional_hash_column<H: bitcoin::hashes::Hash>(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Option<H>> {
    let bytes = row
        .get_ref(index)?
        .as_bytes_or_null()?;

    bytes
        .map(|bytes| H::from_slice(bytes))
        .transpose()
        .map_err(|e|
            rusqlite::Error::FromSqlConversionFailure(
                index,
                rusqlite::types::Type::Text,
                Box::new(e)
            )
        )
}

fn parse_column<T, E>(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<T>
where
    T: FromStr<Err = E>,
    E: std::error::Error + Send + Sync + 'static,
{
    row
        .get_ref(index)?
        .as_str()?
        .parse()
        .map_err(|e|
            rusqlite::Error::FromSqlConversionFailure(
                index,
                rusqlite::types::Type::Text,
                Box::new(e)
            )
        )
}

impl Storage for SqliteStorage {
    type StoreError = StoreError;
    type LoadError = LoadError;
    type PruneError = PruneError;

    type Id = VaultId;
    type StaticParameters = VaultParameters;
    type State = Vault;
    type Transaction = VaultStateTransaction;

    fn create(&mut self, name: &str, parameters: Self::StaticParameters) -> Result<(Self::State, ChangeLog<Self>), Self::StoreError> {
        let transaction = self.sqlite.transaction()?;

        let id = {
            let mut insert_vault = transaction.prepare(r#"
                insert or ignore
                into mccv_vault (
                    name,
                    scale,
                    "max",
                    cold_xpub,
                    hot_xpub,
                    delay_per_increment,
                    max_withdrawal_per_step,
                    max_deposit_per_step,
                    max_depth
                ) values ( ?, ?, ?, ?, ?, ?, ?, ?, ? )
            "#)?;

            insert_vault.execute(
                params![
                    name,
                    parameters.scale.to_sat(),
                    parameters.max,
                    parameters.cold_xpub.to_string(),
                    parameters.hot_xpub.to_string(),
                    parameters.delay_per_increment,
                    parameters.max_withdrawal_per_step,
                    parameters.max_deposit_per_step,
                    parameters.max_depth,
                ]
            )?;

            let id = transaction.last_insert_rowid();

            if id == 0 {
                return Err(StoreError::InternalError);
            }

            id
        };

        transaction.commit()?;

        Ok(
            (
                Vault::new(
                    parameters,
                    VaultState::new(),
                ),
                ChangeLog::new(id as VaultId),
            )
        )
    }

    fn load<C: Verification>(&mut self, secp: &Secp256k1<C>, id: Self::Id) -> Result<(Self::State, ChangeLog<Self>), Self::LoadError> {
        let transaction = self.sqlite.transaction()?;

        let mut parameters = transaction.prepare(r#"
            select
                scale,
                "max",
                cold_xpub,
                hot_xpub,
                delay_per_increment,
                max_withdrawal_per_step,
                max_deposit_per_step,
                max_depth
            from mccv_vault
            where id = ?
        "#)?;

        let parameters = parameters.query_map(
            params![ id ],
            |row| {
                let scale: VaultScale = row.get::<_, u32>(0)
                    .map(|scale| VaultScale::new(scale))?;
                let max: VaultAmount = row.get(1)?;
                let cold_xpub: Xpub = parse_column(row, 2)?;
                let hot_xpub: Xpub = parse_column(row, 3)?;
                let delay_per_increment: u32 = row.get(4)?;
                let max_withdrawal_per_step: VaultAmount = row.get(5)?;
                let max_deposit_per_step: VaultAmount = row.get(6)?;
                let max_depth: u32 = row.get(7)?;

                Ok(
                    VaultParameters {
                        scale,
                        max,
                        cold_xpub,
                        hot_xpub,
                        delay_per_increment,
                        max_withdrawal_per_step,
                        max_deposit_per_step,
                        max_depth,
                    }
                )
            },
        )?
        .next()
        .ok_or(LoadError::NotFound)?
        .map_err(LoadError::SqliteError)?;

        let mut query_blocks = transaction.prepare(r#"
            with
                longest_chain ( tip_hash )
                as (
                    select
                        block_hash as tip_hash
                    from chain_tip
                    order by height desc
                    limit 1
                )
            select
                block.block_hash,
                block.parent_block_hash,
                chain.sparse_parent_block_hash,
                block.height,
                conf.txid as txid,
                tx."transaction"
            from contract_chain chain
            join block
                on block.block_hash = chain.block_hash
            left join transaction_confirmation as conf
                on conf.block_hash = chain.block_hash
            left join "transaction" as tx
                on tx.txid = conf.txid
            left join mccv_transaction as vtx
                on vtx.txid = conf.txid
            where
                chain.chain_tip_hash in longest_chain and
                case
                    when vtx.vault = :0 then 1
                    when vtx.vault is null then 1
                    else 0
                end and
                chain.vault = :0
            order by block.height asc
        "#)?;

        let context = Context::from_parameters(secp, parameters);
        let mut state = VaultState::new();

        // (height, parent_block_hash, block_hash)
        let mut previous_block: Option<(u32, BlockHash, BlockHash, Option<BlockHash>)> = None;
        let mut block_transactions: HashMap<Txid, Transaction> = HashMap::new();

        let mut rows = query_blocks.query(params![ id ])?;

        while let Some(row) = rows.next()? {
            let block_hash: BlockHash = hash_column(&row, 0)?;
            let parent_block_hash: BlockHash = optional_hash_column(&row, 1)?
                .unwrap_or(BlockHash::from_byte_array([0; 32]));
            let sparse_parent_block_hash: Option<BlockHash> = optional_hash_column(&row, 2)?;
            let height: u32 = row.get(3)?;
            let txid: Option<Txid> = optional_hash_column(&row, 4)?;
            let transaction = {
                let blob = row
                    .get_ref(5)?
                    .as_bytes_or_null()?;
                blob.map(|mut blob| Transaction::consensus_decode(&mut blob))
                    .transpose()
                    .map_err(|_| LoadError::InvalidState)?
            };

            let this_block = (height, block_hash, parent_block_hash, sparse_parent_block_hash);

            if Some(this_block) != previous_block {
                if let Some((previous_height, previous_block_hash, previous_parent_block_hash, sparse_parent_block_hash)) = previous_block {
                    let seen_block = state
                        .state_mut()
                        .add_block(
                            previous_height,
                            previous_block_hash,
                            previous_parent_block_hash,
                            sparse_parent_block_hash,
                        )
                        .map_err(|e| LoadError::AddBlockError(e))?;

                    let tip = state
                        .state_mut()
                        .get_tip_mut(&seen_block)
                        .expect("block was just added");

                    for txid in sorted_transactions(&block_transactions) {
                        let transaction = block_transactions.get(&txid)
                            .expect("all txids should be in the block");
                        let add_result = tip.add(secp, &context, txid, transaction, previous_height);
                        match add_result {
                            Ok(AddTransactionSuccess::TransactionAdded(tx)) => {
                                seen_block.transactions.borrow_mut()
                                    .insert(tx.clone());
                            },
                            Ok(AddTransactionSuccess::TransactionIgnored) => {
                                return Err(
                                    LoadError::IgnoredContractTransaction(txid)
                                );
                            }

                            // TODO: We should revert changes in case of error
                            Err(AddTransactionError::InternalError) => { return Err(LoadError::InternalError); },
                            Err(AddTransactionError::ConnectError(e)) => {
                                return Err(
                                    LoadError::AddTransactionError(
                                        AddTransactionError::ConnectError(e)
                                    )
                                );
                            }
                            Err(AddTransactionError::MissingInputs) => { return Err(LoadError::InternalError); }
                        }
                    }
                }

                block_transactions = HashMap::new();
                previous_block = Some(this_block);
            }

            match (txid, transaction) {
                (Some(txid), Some(transaction)) => {
                    block_transactions.insert(txid, transaction);
                }
                (None, None) => { }
                _ => unreachable!(),
            }
        }

        if let Some((previous_height, previous_block_hash, previous_parent_block_hash, sparse_parent_block_hash)) = previous_block {
            let seen_block = state
                .state_mut()
                .add_block(
                    previous_height,
                    previous_block_hash,
                    previous_parent_block_hash,
                    sparse_parent_block_hash,
                )
                .map_err(|e| LoadError::AddBlockError(e))?;

            let tip = state
                .state_mut()
                .get_tip_mut(&seen_block)
                .expect("block was just added");

            for txid in sorted_transactions(&block_transactions) {
                let transaction = block_transactions.get(&txid)
                    .expect("all txids should be in the block");
                let add_result = tip.add(secp, &context, txid, transaction, previous_height);
                match add_result {
                    Ok(AddTransactionSuccess::TransactionAdded(tx)) => {
                        seen_block.transactions.borrow_mut()
                            .insert(tx.clone());
                    },
                    Ok(AddTransactionSuccess::TransactionIgnored) => {
                        return Err(
                            LoadError::IgnoredContractTransaction(txid)
                        );
                    }

                    // TODO: We should revert changes in case of error
                    Err(AddTransactionError::InternalError) => { return Err(LoadError::InternalError); },
                    Err(AddTransactionError::ConnectError(e)) => {
                        return Err(
                            LoadError::AddTransactionError(
                                AddTransactionError::ConnectError(e)
                            )
                        );
                    }
                    Err(AddTransactionError::MissingInputs) => { return Err(LoadError::InternalError); }
                }
            }
        }

        Ok(
            (
                Vault::new(parameters, state),
                ChangeLog::new(id),
            )
        )
    }

    fn list(&mut self) -> Result<Vec<(Self::Id, String)>, Self::LoadError> {
        let transaction = self.sqlite.transaction()?;

        let mut list_query = transaction.prepare(r#"
            select
                id,
                name
            from mccv_vault
        "#)?;

        let result = list_query.query_map(
            params![],
            |row| {
                Ok(
                    (
                        row.get::<_, Self::Id>(0)?,
                        row.get::<_, String>(1)?,
                    )
                )
            },
        )?
        .map(|row|
            row.map_err(LoadError::from)
        )
        .collect();

        result
    }

    fn store(&mut self, changes: ChangeLog<Self>) -> Result<ChangeLog<Self>, Self::StoreError> {
        let transaction = self.sqlite.transaction()?;

        let new_changelog = {
            let mut insert_transaction = transaction.prepare(r#"
                insert or ignore
                into "transaction" (
                    txid,
                    "transaction"
                ) values ( ?, ? )
            "#)?;

            let mut insert_transaction_confirmation = transaction.prepare(r#"
                insert or ignore
                into transaction_confirmation (
                    txid,
                    block_hash
                ) values ( ?, ? )
            "#)?;

            let vault_id = changes.id();
            let (new_changelog, changes) = changes.to_iterator();

            for change in changes {
                match change {
                    Change::AddTransaction(block_hash, tx) => {
                        let mut serialized_transaction: Vec<u8> = Vec::new();

                        let txid = tx.transaction.compute_txid();
                        let _ = tx.transaction.consensus_encode(&mut serialized_transaction)
                            .map_err(|_| StoreError::InternalError)?;

                        insert_transaction.execute(
                            params![ txid.as_byte_array(), serialized_transaction ]
                        )?;

                        insert_transaction_confirmation.execute(
                            params![
                                txid.as_byte_array(),
                                block_hash.as_byte_array(),
                            ],
                        )?;

                        transaction.execute(r#"
                                insert
                                into mccv_transaction (
                                    vault,
                                    txid
                                ) VALUES ( ?, ? )
                            "#,
                            params![
                                vault_id,
                                txid.as_byte_array(),
                            ]
                        )?;
                    }
                    Change::AddBlock { height, block_hash, parent_block_hash, sparse_parent_block_hash } => {
                        let parent_block_hash = if height > 0 {
                            Some(parent_block_hash.as_byte_array())
                        } else {
                            None
                        };

                        transaction.execute(r#"
                                    insert or ignore
                                    into block (
                                        block_hash, parent_block_hash, height
                                    ) values ( ?, ?, ? )
                                "#,
                                params![
                                    block_hash.as_byte_array(),
                                    parent_block_hash,
                                    height
                                ],
                            )?;

                        let sparse_parent_block_hash = if sparse_parent_block_hash != BlockHash::from_byte_array([0; 32]) {
                            Some(sparse_parent_block_hash.to_byte_array())
                        } else {
                            None
                        };

                        transaction.execute(r#"
                                    insert or ignore
                                    into sparse_chain (
                                        block_hash, sparse_parent_block_hash, vault
                                    ) values ( ?, ?, ? )
                                "#,
                                params![
                                    block_hash.as_byte_array(),
                                    sparse_parent_block_hash,
                                    vault_id,
                                ],
                            )?;
                    }
                }
            }

            new_changelog
        };

        transaction.commit()?;

        Ok(new_changelog)
    }

    fn prune(&mut self, height: u32) -> Result<(), Self::PruneError> {
        // FIXME: This is unaaware of multi-contract setups and is dangerous
        let transaction = self.sqlite.transaction()?;

        transaction.execute(
            r#"
                create temp table saved_block (
                    block_hash blob primary key
                )
            "#,
            [],
        )?;

        let mut cleanup_error: Option<rusqlite::Error> = None;

        {
            let _cleanup = ScopeExit::new(
                || {
                    let result = transaction.execute(
                        r#"
                            drop table if exists saved_block
                        "#,
                        [],
                    );

                    match result {
                        Ok(_) => {}
                        Err(e) => {
                            cleanup_error = Some(e);
                        }
                    }
                }
            );

            let _ = transaction.execute(
                r#"
                with retained_chain_tip ( chain_tip_hash ) as (
                    select
                        block_hash
                    from chain_tip
                    where height >= ?
                )
                insert or ignore into saved_block (
                    block_hash
                ) values (
                    select
                        chain.block_hash
                    from
                        sparse_chain chain
                    where
                        chain.chain_tip_hash in retained_chain_tip
                )
                "#,
                params![ height ],
            )?;

            transaction.execute(
                r#"
                    delete from block
                    where
                        block.block_hash not in
                            ( select block_hash from saved_block )
                "#,
                [],
            )?;
        }

        transaction.commit()?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use bitcoin::{Block, locktime::absolute, OutPoint, transaction, TxIn, TxOut, ScriptBuf, Sequence, Witness};
    use bitcoin::bip32::{
        Xpriv,
    };

    use bitcoin::secp256k1::{
        Signing,
    };

    use crate::chain::{TestBlock};
    use crate::vault::AccountId;

    #[test]
    fn test_migrate() {
        let mut connection = rusqlite::Connection::open_in_memory().unwrap();

        let mut transaction = connection.transaction().unwrap();

        migrate(&mut transaction, VAULT_VERSION_ID, &VAULT_MIGRATIONS).unwrap();
    }

    // master xpriv derived from milk sad key,
    // XXX: copied in three places
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
    fn test_create_list() {
        let secp = Secp256k1::new();

        let mut storage = SqliteStorage::from_connection(
                rusqlite::Connection::open_in_memory().unwrap()
            )
            .unwrap();

        let parameters = test_parameters(&secp);

        let (_vault, changelog) = storage.create("test", parameters).unwrap();
        let (_vault2, changelog2) = storage.create("test2", parameters).unwrap();
        let (_vault3, changelog3) = storage.create("test3", parameters).unwrap();

        let list = storage.list().unwrap();

        assert_eq!(
            list,
            vec![
                (changelog.id(), "test".to_string()),
                (changelog2.id(), "test2".to_string()),
                (changelog3.id(), "test3".to_string()),
            ],
        );
    }

    #[test]
    fn test_sorted_transactions() {
        fn txid(x: u8) -> Txid {
            Txid::from_byte_array([x; 32])
        }

        let a_txid = txid(0xAA);
        let b_txid = txid(0xBB);
        let c_txid = txid(0xCC);
        let d_txid = txid(0xDD);
        let e_txid = txid(0xEE);
        let f_txid = txid(0xFF);

        fn tx<I: IntoIterator<Item = Txid>>(inputs: I) -> Transaction {
            Transaction {
                version: transaction::Version::non_standard(3),
                lock_time: absolute::LockTime::ZERO,
                input: inputs
                    .into_iter()
                    .map(|txid| TxIn {
                        previous_output: OutPoint {
                            txid,
                            // XXX: vout doesn't matter because outputs
                            // are irrelevant to this function
                            vout: 0,
                        },
                        sequence: Sequence::ZERO,
                        script_sig: ScriptBuf::new(),
                        witness: Witness::new(),
                    })
                    .collect(),
                // XXX: Outputs don't matter at all here
                output: vec![],
            }
        }

        let a_tx = tx([ txid(01), txid(02) ]);
        let b_tx = tx([ a_txid, a_txid ]);
        let c_tx = tx([ b_txid ]);
        let d_tx = tx([ a_txid, c_txid ]);
        let e_tx = tx([ d_txid ]);
        let f_tx = tx([ txid(01), txid(03) ]);

        let block_transactions: HashMap<_, _> = [
                (a_txid, a_tx),
                (b_txid, b_tx),
                (c_txid, c_tx),
                (d_txid, d_tx),
                (e_txid, e_tx),
                (f_txid, f_tx),
            ]
            .into_iter()
            .collect();

        let sorted = sorted_transactions(&block_transactions);

        for (index, txid) in sorted.iter().enumerate() {
            let tx = block_transactions.get(txid).unwrap();
            for input in &tx.input {
                let parent_index = sorted
                    .iter()
                    .position(|parent_txid| *parent_txid == input.previous_output.txid);

                if let Some(parent_index) = parent_index {
                    assert!(parent_index < index);
                }
            }

        }
    }

    #[test]
    fn test_store_load() {
        let secp = Secp256k1::new();

        let mut storage = SqliteStorage::from_connection(
                rusqlite::Connection::open_in_memory().unwrap()
            )
            .unwrap();

        let parameters = test_parameters(&secp);

        let (mut vault, mut changelog) = storage.create("test", parameters).unwrap();


        let (vault2, _changelog2) = storage.load(&secp, changelog.id()).unwrap();

        assert_eq!(
            vault.parameters(),
            vault2.parameters(),
        );

        let mut deposit = vault.create_deposit(&secp, VaultAmount::new(1)).unwrap();

        let deposit_prevout = OutPoint {
            txid: Txid::from_byte_array([1; 32]),
            vout: 0,
        };

        let deposit_txout = TxOut {
            value: parameters.scale.scale_amount(VaultAmount::new(1)),
            script_pubkey: ScriptBuf::from_hex("51").unwrap(), // OP_1 (anyone can spend)
        };

        deposit.connect_input(&secp, deposit_prevout, deposit_txout);

        let genesis = Block::test_genesis();

        let signed_deposit = deposit.to_signed_transaction()
            .unwrap();

        let block1 = genesis.test_child(
            0,
            vec![signed_deposit],
        );

        let context = vault.context(&secp);

        vault.apply_block(&secp, &context, &genesis, 0, &mut changelog)
            .unwrap();

        vault.apply_block(&secp, &context, &block1, 1, &mut changelog)
            .unwrap();

        let mut changelog = storage.store(changelog).unwrap();

        let (vault2, _changelog2) = storage.load(&secp, changelog.id()).unwrap();

        assert_eq!(
            vault.confirmed_balance(None),
            vault2.confirmed_balance(None),
        );

        let block2 = block1.test_child(
            0,
            vec![],
        );

        vault.apply_block(&secp, &context, &block2, 2, &mut changelog)
            .unwrap();
    }
}
