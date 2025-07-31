use bitcoin::hashes::{
    Hash,
    sha256::Hash as Sha256,
};

use bitcoin::{
    consensus::Encodable,
    Transaction,
};

use std::io::Write;

// FIXME: confirmed a long time ago that sha256 writes never fail, so this function is actually
// infallible, rewrite per what you've done elsewhere
pub fn get_default_template(transaction: &Transaction, input_index: u32) -> std::io::Result<Sha256> {
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

#[cfg(test)]
mod test {
    use super::*;

    use bitcoin::{
        consensus::Decodable,
        hex::FromHex,
    };

    use serde::{
        Deserialize,
        Deserializer,
        de::Visitor,
    };

    use std::collections::HashMap;
    use std::default::Default;
    use std::io::Cursor;
    use std::marker::PhantomData;

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

    #[test]
    fn test_ctv() {
        for (tx, index, result) in get_ctv_test_vectors() {
            assert_eq!(get_default_template(&tx, index).unwrap(), result);
        }
    }
}
