use bdk_electrum::{
    BdkElectrumClient,
    electrum_client,
    electrum_client::ElectrumApi,
};

use bdk_wallet::{
    template::Bip86,
    KeychainKind,
    PersistedWallet,
    Wallet,
};

use bitcoin::bip32::{
    Xpub,
    Xpriv,
    ChildNumber,
    DerivationPath,
};

use bitcoin::consensus::Decodable;

use bitcoin::hashes::{
    Hash,
    sha256::Hash as Sha256,
};

use bitcoin::secp256k1::{
    Secp256k1,
    Signing,
};

use bitcoin::{
    hex::FromHex,
    Network,
    Transaction,
};

use electrsd::bitcoind::bitcoincore_rpc::{
    RpcApi,
};

use electrsd::{
    bitcoind,
    bitcoind::BitcoinD,
    ElectrsD,
};

use serde::{
    Deserialize,
    Deserializer,
    de::Visitor,
};

use crate::{
    Vault,
};

use std::collections::HashMap;
use std::io::Cursor;
use std::marker::PhantomData;
use std::str::FromStr;

use std::default::Default;

pub(crate) fn get_test_daemons() -> (BdkElectrumClient<electrum_client::Client>, ElectrsD, BitcoinD) {
    let bitcoind_path = bitcoind::exe_path().expect("Failed to get bitcoind path. See README.md \"Testing Error\" section.");
    let bitcoind_conf = {
        let mut conf: bitcoind::Conf = Default::default();
        conf.p2p = bitcoind::P2P::Yes;
        conf.network = "regtest";
        //conf.view_stdout = true;
        conf
    };
    let bitcoind = BitcoinD::with_conf(bitcoind_path, &bitcoind_conf).expect("Failed to start bitcoind");

    let electrs_path = electrsd::exe_path().expect("Failed to get electrsd path. See README.md \"Testing Error\" section.");
    let electrs_conf = {
        let mut conf: electrsd::Conf = Default::default();
        conf.network = bitcoind_conf.network;
        conf.http_enabled = true;
        conf.view_stderr = true;
        conf
    };
    let electrs = ElectrsD::with_conf(electrs_path, &bitcoind, &electrs_conf).expect("Failed to start electrs");

    let electrum_client = electrum_client::Client::new(electrs.electrum_url.as_str())
        .expect("electrum client create");

    (BdkElectrumClient::new(electrum_client), electrs, bitcoind)
}

struct TransactionHexVisitor(PhantomData<()>);

impl<'de> Visitor<'de> for TransactionHexVisitor {
    type Value = Transaction;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "transaction hex")
    }

    fn visit_borrowed_str<E>(self, s: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let bytes: Vec<u8> = FromHex::from_hex(s)
            .map_err(serde::de::Error::custom)?;

        Transaction::consensus_decode_from_finite_reader(&mut Cursor::new(bytes))
            .map_err(serde::de::Error::custom)
    }

}

fn deserialize_transaction_hex<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Transaction, D::Error> {
    if deserializer.is_human_readable() {
        deserializer.deserialize_str(TransactionHexVisitor(PhantomData::default()))
    } else {
        panic!()
    }
}

struct Sha256VecVisitor(PhantomData<()>);

impl<'de> Visitor<'de> for Sha256VecVisitor {
    type Value = Vec<Sha256>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "sequence of Sha256 hex")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut result: Vec<Sha256> = Vec::new();
        while let Some(element) = seq.next_element()? {
            let bytes: Vec<u8> = FromHex::from_hex(element)
                .map_err(serde::de::Error::custom)?;

            let sha256 = Sha256::from_slice(&bytes)
                .map_err(serde::de::Error::custom)?;

            result.push(sha256);
        }

        Ok(result)
    }
}

fn deserialize_sha256_vec<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Sha256>, D::Error> {
    if deserializer.is_human_readable() {
        deserializer.deserialize_seq(Sha256VecVisitor(PhantomData::default()))
    } else {
        panic!()
    }
}

#[derive(Debug,Deserialize)]
struct CtvTestVector {
    #[serde(rename = "hex_tx", deserialize_with = "deserialize_transaction_hex")]
    transaction: Transaction,

    spend_index: Vec<u32>,

    #[serde(deserialize_with = "deserialize_sha256_vec")]
    result: Vec<Sha256>,

    #[serde(flatten)]
    _remainder: HashMap<String, serde_json::Value>,
}

#[derive(Debug,Deserialize)]
#[serde(untagged)]
enum CtvTestVectorEntry {
    TestVector(CtvTestVector),
    Documentation(String),
}

pub(crate) fn get_ctv_test_vectors() -> impl Iterator<Item=(Transaction, u32, Sha256)> {
    let ctv_test_vectors = include_str!("../data/tests/ctvhash.json");
    let ctv_test_vectors: Vec<CtvTestVectorEntry> = serde_json::from_str(ctv_test_vectors).expect("failed to parse ctv test vectors");

    ctv_test_vectors.into_iter()
        .filter_map(|entry| {
            match entry {
                CtvTestVectorEntry::Documentation(_) => None,
                CtvTestVectorEntry::TestVector(entry) => Some(entry),
            }
        })
        .flat_map(|entry| {
            entry.spend_index.into_iter()
                .zip(entry.result.into_iter())
                .map(move |(spend_index, result)| (entry.transaction.clone(), spend_index, result))
        })
}

pub(crate) fn load_wallet() -> (PersistedWallet<rusqlite::Connection>, rusqlite::Connection) {
    let mut sqlite = rusqlite::Connection::open_in_memory()
        .expect("open wallet");

    let master_xpriv = Xpriv::from_str("tprv8ZgxMBicQKsPd1EzCPZcQSPhsotX5HvRDCivA7ASNQFmjWuTsW3WWEwUNKFAZrnD9qpz55rtyLdphqkwRZUqNWYXwSEzd6P4pYvXGByRim3")
        .expect("decode test xpriv");

    let descriptor = Bip86(master_xpriv, KeychainKind::External);
    let change_descriptor = Bip86(master_xpriv, KeychainKind::Internal);

    let _wallet = Wallet::create(descriptor, change_descriptor)
        .network(Network::Regtest)
        .create_wallet(&mut sqlite)
        .expect("wallet create");

    let wallet = Wallet::load()
        .descriptor(KeychainKind::External, Some(Bip86(master_xpriv, KeychainKind::External)))
        .descriptor(KeychainKind::Internal, Some(Bip86(master_xpriv, KeychainKind::Internal)))
        //.extract_keys()
        .load_wallet(&mut sqlite)
        .expect("wallet load")
        .expect("wallet construct");

    (wallet, sqlite)
}

/*
pub(crate) fn generate_to_wallet(bitcoind: &BitcoinD, electrum: &BdkElectrumClient<electrum_client::Client>, wallet: &mut PersistedWallet<rusqlite::Connection>, count: usize) {
    for _ in 0..count {
        let address = wallet.reveal_next_address(KeychainKind::External);
        bitcoind.client.generate_to_address(1, &address)
            .expect("generate failed");

        let MAX_TIME = std::time::Duration::from_millis(30000);
        let start = std::time::Instant::now();
        let end = start + MAX_TIME;

        let mut update = false;

        while std::time::Instant::now() < end {
            let history = electrum.inner
                .script_get_history(address.script_pubkey().as_script())
                .expect("get history");

            if history.len() > 0 {
                update = true;
                break;
            }
        }

        assert!(update);
    }
}
*/

pub(crate) fn generate_to_wallet(bitcoind: &BitcoinD, electrum: &BdkElectrumClient<electrum_client::Client>, wallet: &mut PersistedWallet<rusqlite::Connection>, count: usize) {
    let address = wallet.reveal_next_address(KeychainKind::External);
    bitcoind.client.generate_to_address(count as u64, &address)
        .expect("generate failed");

    let MAX_TIME = std::time::Duration::from_millis(30000);
    let start = std::time::Instant::now();
    let end = start + MAX_TIME;

    let mut update = false;

    while std::time::Instant::now() < end {
        let history = electrum.inner
            .script_get_history(address.script_pubkey().as_script())
            .expect("get history");

        if history.len() >= count {
            update = true;
            break;
        }
    }

    assert!(update);
}

pub(crate) fn full_scan(
    electrum: &BdkElectrumClient<electrum_client::Client>,
    wallet: &mut PersistedWallet<rusqlite::Connection>,
    sqlite: &mut rusqlite::Connection
) {
    let req = wallet.start_full_scan();

    let result = electrum.full_scan(req, 32, 4, true)
        .expect("full scan failed");

    wallet.apply_update(result)
        .expect("update failed");

    wallet.persist(sqlite)
        .expect("update sqlite");
}
