use bitcoin::consensus::Decodable;
use electrsd::{
    ElectrsD,
    bitcoind::BitcoinD,
};

use electrsd::bitcoind;

use bitcoin::hashes::{
    Hash,
    sha256::Hash as Sha256,
};

use bitcoin::{
    hex::FromHex,
    Transaction,
};

use serde::{
    Deserialize,
    Deserializer,
    de::Visitor,
};

use std::collections::HashMap;
use std::io::Cursor;
use std::marker::PhantomData;

pub(crate) fn get_test_daemons() -> (ElectrsD, BitcoinD) {
    let bitcoind_path = bitcoind::exe_path().expect("Failed to get bitcoind path. See README.md \"Testing Error\" section.");
    let bitcoind = BitcoinD::new(bitcoind_path).expect("Failed to start bitcoind");

    let electrs_path = electrsd::exe_path().expect("Failed to get electrsd path. See README.md \"Testing Error\" section.");
    let electrs = ElectrsD::new(electrs_path, &bitcoind).expect("Failed to start electrs");

    (electrs, bitcoind)
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
