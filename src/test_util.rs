use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client, RpcApi};
use bdk_bitcoind_rpc::Emitter;

use bdk_wallet::{
    template::Bip86Public,
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

use bitcoin::secp256k1::rand::{RngCore, thread_rng};

use bitcoin::secp256k1::{
    Secp256k1,
    Signing,
};

use bitcoin::{
    hex::FromHex,
    Network,
    Transaction,
};

use corepc_node::{
    Node,
    exe_path,
};

use serde::{
    Deserialize,
    Deserializer,
    de::Visitor,
};

use std::collections::HashMap;
use std::io::Cursor;
use std::marker::PhantomData;
use std::str::FromStr;

use std::default::Default;

pub fn get_test_node() -> (Node, Client) {
    let path = corepc_node::exe_path().expect("Failed to get bitcoind path. See README.md \"Testing Error\" section.");
    let node = Node::new(path).unwrap();
    let url = node.rpc_url();
    let auth = Auth::CookieFile(node.params.cookie_file.clone());
    (node, Client::new(&url, auth).unwrap())
}

pub fn get_test_wallet() -> (Xpriv, Wallet) {
    let mut seed_bytes = [0u8; 128];
    thread_rng().fill_bytes(&mut seed_bytes);
    let master = Xpriv::new_master(Network::Regtest, &seed_bytes).unwrap();

    let secp = Secp256k1::new();
    //let public = Bip86Public(master.clone(), KeychainKind::External);
    let master_xpub = Xpub::from_priv(&secp, &master);
    let public = Bip86Public(master_xpub.clone(), master_xpub.fingerprint(), KeychainKind::External);

    let private = Bip86(master.clone(), KeychainKind::External);
    let wallet = Wallet::create_single(
        Bip86(master.clone(), KeychainKind::External)
    )
    .network(Network::Regtest)
    .create_wallet_no_persist()
    .unwrap();

    (master, wallet)
}

pub fn update_wallet(wallet: &mut Wallet, client: &Client) {
    let latest_checkpoint = wallet.latest_checkpoint();
    let height = latest_checkpoint.height();

    // we don't touch the mempool interface at all so this is ok
    let mut emitter = Emitter::new(client, latest_checkpoint, height, bdk_bitcoind_rpc::NO_EXPECTED_MEMPOOL_TXIDS);

    while let Some(block) = emitter.next_block().unwrap() {
        wallet.apply_block(&block.block, block.block_height()).unwrap();
    }
}

pub fn generate_to_wallet(wallet: &mut Wallet, client: &Client, num_blocks: u64) {
    let address = wallet.reveal_next_address(KeychainKind::External);

    client.generate_to_address(num_blocks, &address.address).unwrap();

    update_wallet(wallet, client);
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
