use bdk_bitcoind_rpc::Emitter;
use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client, RpcApi};

use bdk_wallet::{
    template::Bip86Public,
    template::Bip86,
    KeychainKind,
    PersistedWallet,
    SignOptions,
    Wallet,
};

use bitcoin::{
    Amount,
    bip32::Xpriv,
    bip32::Xpub,
    consensus::encode::serialize_hex,
    FeeRate,
    hashes::Hash,
    hashes::sha256::Hash as Sha256,
    Network,
    secp256k1::Secp256k1,
    secp256k1::Signing,
    secp256k1::Verification,
    Transaction,
};

use bitcoin::secp256k1::rand::{RngCore, thread_rng};

use corepc_node::{
    Node,
    exe_path,
};

use serde::Serialize;

use std::time::Instant;

use std::str::FromStr;

use mccv::{
    AccountId,
    VaultAmount,
    VaultParameters,
    VaultScale,
    Vault,
    vault::SqliteVaultStorage,
};

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

// master xpriv derived from milk sad key (at least I'm pretty sure...)
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

#[test]
fn test_deposit() {
    let secp = Secp256k1::new();

    let (node, client) = get_test_node();

    let (cold_xpriv, hot_xpriv) = test_xprivs(&secp, 0);

    let test_parameters = VaultParameters::new(
        VaultScale::from_sat(100_000_000),   // scale
        VaultAmount::new(10),                // max amount
        Xpub::from_priv(&secp, &cold_xpriv), //
        Xpub::from_priv(&secp, &hot_xpriv),  //
        36,
        VaultAmount::new(3),                 // max withdrawal
        VaultAmount::new(3),                 // max deposit
        10,                                  // max depth
    );

    let (xpriv, mut wallet) = get_test_wallet();

    generate_to_wallet(&mut wallet, &client, 100);

    let balance = wallet.balance();

    assert_eq!(balance.confirmed.to_sat(), 50 * 100_000_000);

    let sqlite = rusqlite::Connection::open_in_memory()
        .expect("open memory wallet should succeed");
    let mut storage = SqliteVaultStorage::from_connection(sqlite)
        .expect("initialize vault storage");
    let vault = Vault::create_new(&mut storage, "Test Vault", test_parameters)
        .expect("create vault");

    let (deposit_amount, remainder) = vault.to_vault_amount(Amount::from_sat(100_000_000));
    assert_eq!(remainder, Amount::ZERO);

    let mut deposit_transactions = vault.create_deposit(&secp, &mut wallet, deposit_amount, FeeRate::BROADCAST_MIN).unwrap();

    eprintln!("{:?}", deposit_transactions);

    let sign_success = wallet.sign(&mut deposit_transactions.shape_transaction, SignOptions::default())
        .expect("sign success");

    let shape_transaction = deposit_transactions.shape_transaction.extract_tx()
        .expect("tx complete");

    assert!(sign_success);

    let args: Vec<serde_json::Value> = vec![
        vec![
            serialize_hex(&shape_transaction),
            serialize_hex(&deposit_transactions.deposit_transaction),
        ].into(),
    ];

    let result: serde_json::Value = client.call("submitpackage", args.as_ref()).unwrap();

    eprintln!("result = {result}");
}

#[test]
fn test_scratch_workspace() {
    use bdk_wallet::keys::GeneratableDefaultOptions;
    //use bdk_wallet::miniscript::ScriptContext;
    use corepc_node::{
        Node,
        exe_path,
    };

    use bdk_wallet::{
        Wallet,
        descriptor::template::Bip86,
        descriptor::template::DescriptorTemplate,
        KeychainKind,

    };

    use bitcoin::bip32::Xpriv;
    use bitcoin::Network;
    use bitcoin::secp256k1::rand::{RngCore, thread_rng};

    use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client, RpcApi};
    use bdk_bitcoind_rpc::Emitter;

    let (xpriv, mut wallet) = get_test_wallet();

    let template = Bip86(xpriv.clone(), KeychainKind::External);

    let (descriptor, key_map, networks) = template.build(Network::Regtest).unwrap();
}
