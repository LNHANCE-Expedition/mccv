use bdk_bitcoind_rpc::Emitter;
use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client, RpcApi};

use bdk_wallet::{
    template::Bip86,
    KeychainKind,
    SignOptions,
    Wallet,
};

use bitcoin::{
    Address,
    Amount,
    bip32::Xpriv,
    bip32::Xpub,
    FeeRate,
    Network,
    Txid,
};

use bitcoin::secp256k1::{
    Secp256k1,
    Signing,
    XOnlyPublicKey,
};

use bitcoin::secp256k1::rand::{RngCore, thread_rng};

use std::str::FromStr;

use mccv::{
    AccountId,
    VaultAmount,
    VaultParameters,
    VaultScale,
    Vault,
    VaultDepositor,
    VaultWithdrawer,
    vault::SqliteVaultStorage,
};

pub fn get_test_node() -> (corepc_node::Node, Client) {
    let path = corepc_node::exe_path().expect("Failed to get bitcoind path. See README.md \"Testing Error\" section.");
    let node = corepc_node::Node::new(path).unwrap();
    let url = node.rpc_url();
    let auth = Auth::CookieFile(node.params.cookie_file.clone());
    (node, Client::new(&url, auth).unwrap())
}

pub fn get_test_wallet() -> (Xpriv, Wallet) {
    let mut seed_bytes = [0u8; 128];
    thread_rng().fill_bytes(&mut seed_bytes);
    let master = Xpriv::new_master(Network::Regtest, &seed_bytes).unwrap();

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

pub fn update_vault(vault: &mut Vault, emitter: &mut Emitter<&Client>) {
    while let Some(block) = emitter.next_block().unwrap() {
        //eprintln!("applying block {}", block.block.block_hash());
        vault.apply_block(&block.block, block.block_height());
    }
}

pub fn generate_to_wallet(wallet: &mut Wallet, client: &Client, num_blocks: u64) {
    let address = wallet.reveal_next_address(KeychainKind::External);

    client.generate_to_address(num_blocks, &address.address).unwrap();

    update_wallet(wallet, client);
}

// master xpriv derived from milk sad key (at least I'm pretty sure... it's been a while...)
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

// Test cases to add:
// - deposit greater than max
// - clawback
//   - clawback vault UTXO only
//   - clawback withdrawal UTXO only
//   - clawback both UTXOs simultaneously
// - load and store
// - reorgs

#[test]
fn test_deposit_withdraw() {
    let secp = Secp256k1::new();

    let (_node, client) = get_test_node();

    let (cold_xpriv, hot_xpriv) = test_xprivs(&secp, 0);

    const VAULT_SCALE: Amount = Amount::from_sat(100_000_000);

    let test_parameters = VaultParameters::new(
        VaultScale::from_sat(VAULT_SCALE.to_sat() as u32),   // scale
        VaultAmount::new(10),                // max amount
        Xpub::from_priv(&secp, &cold_xpriv), //
        Xpub::from_priv(&secp, &hot_xpriv),  //
        36,
        VaultAmount::new(3),                 // max withdrawal
        VaultAmount::new(3),                 // max deposit
        10,                                  // max depth
    );

    let (_xpriv, mut wallet) = get_test_wallet();

    let genesis_checkpoint = wallet.local_chain().get(0).expect("chain has genesis block");

    generate_to_wallet(&mut wallet, &client, 100);

    let balance = wallet.balance();

    assert_eq!(balance.confirmed.to_sat(), 50 * 100_000_000);

    let sqlite = rusqlite::Connection::open_in_memory()
        .expect("open memory wallet should succeed");
    let mut storage = SqliteVaultStorage::from_connection(sqlite)
        .expect("initialize vault storage");
    let mut vault = Vault::create_new(&mut storage, "Test Vault", test_parameters)
        .expect("create vault");

    // ============ Deposit 1 ============ 
    let mut total_deposit = Amount::ZERO;
    let deposit_amount_raw = VAULT_SCALE * 3;
    total_deposit += deposit_amount_raw;
    let (deposit_amount, remainder) = vault.to_vault_amount(deposit_amount_raw).expect("valid vault amount");
    assert_eq!(remainder, Amount::ZERO);

    let mut deposit_transaction = vault.create_deposit(&secp, deposit_amount).unwrap();

    assert_eq!(vault.get_confirmed_balance(), Amount::ZERO);

    let mut shape_psbt = wallet.create_shape(&secp, &mut deposit_transaction, FeeRate::BROADCAST_MIN)
        .expect("create shape success");

    let transmittable_deposit_transaction = deposit_transaction.to_signed_transaction()
        .expect("initial deposit doesn't require signing");

    let sign_success = wallet.sign(&mut shape_psbt, SignOptions::default())
        .expect("sign success");

    let shape_transaction = shape_psbt.extract_tx()
        .expect("tx complete");

    assert!(sign_success);

    let args: Vec<serde_json::Value> = vec![
        mccv::vault::package_encodable(
            vec![
                &shape_transaction,
                &transmittable_deposit_transaction,
            ],
        ),
    ];

    let result: serde_json::Value = client.call("submitpackage", args.as_ref()).unwrap();
    assert_eq!(result.get("package_msg"), Some(&"success".into()), "{:?}", result);

    let _ = client.get_mempool_entry(&shape_transaction.compute_txid())
        .expect("shape tx in mempool");

    let _ = client.get_mempool_entry(&transmittable_deposit_transaction.compute_txid())
        .expect("deposit tx in mempool");

    generate_to_wallet(&mut wallet, &client, 6);

    let _ = client.get_mempool_entry(&shape_transaction.compute_txid())
        .expect_err("shape tx has been mined");

    let _ = client.get_mempool_entry(&transmittable_deposit_transaction.compute_txid())
        .expect_err("deposit tx has been mined");

    let mut vault_block_emitter = Emitter::new(&client, genesis_checkpoint, 0, Option::<Txid>::None);

    assert_eq!(vault.get_confirmed_balance(), Amount::ZERO);

    vault.add_transaction(deposit_transaction.into())
        .expect("deposit transaction should add cleanly");

    update_vault(&mut vault, &mut vault_block_emitter);

    assert_eq!(vault.get_confirmed_balance(), total_deposit);

    // ============ Deposit 2 ============ 
    let deposit_amount_raw = VAULT_SCALE * 2;
    total_deposit += deposit_amount_raw;
    let (deposit_amount, remainder) = vault.to_vault_amount(deposit_amount_raw).expect("valid vault amount");
    assert_eq!(remainder, Amount::ZERO);

    let mut deposit_transaction = vault.create_deposit(&secp, deposit_amount).unwrap();

    let mut shape_psbt = wallet.create_shape(&secp, &mut deposit_transaction, FeeRate::BROADCAST_MIN)
        .expect("create shape success");

    let sign_success = wallet.sign(&mut shape_psbt, SignOptions::default())
        .expect("sign success");

    assert!(sign_success);

    let shape_transaction = shape_psbt.extract_tx()
        .expect("tx complete");

    let hot_keypair = deposit_transaction.hot_keypair(&secp, &hot_xpriv)
        .expect("successful key derivation");

    let _ = deposit_transaction.sign_vault_input(&secp, &hot_keypair)
        .expect("sign success");

    let transmittable_deposit_transaction = deposit_transaction.to_signed_transaction().expect("deposit transaction signed");

    //eprintln!("tx {} = {shape_transaction:?}", shape_transaction.compute_txid());
    //eprintln!("tx {} = {:?}", transmittable_deposit_transaction.compute_txid(), &transmittable_deposit_transaction);

    let args: Vec<serde_json::Value> = vec![
        mccv::vault::package_encodable(
            vec![
                &shape_transaction,
                &transmittable_deposit_transaction,
            ],
        ),
    ];

    let result: serde_json::Value = client.call("submitpackage", args.as_ref()).unwrap();
    assert_eq!(result.get("package_msg"), Some(&"success".into()));

    vault.add_transaction(deposit_transaction.into())
        .expect("deposit transaction should add cleanly");

    generate_to_wallet(&mut wallet, &client, 6);

    update_vault(&mut vault, &mut vault_block_emitter);

    assert_eq!(vault.get_confirmed_balance(), total_deposit);

    // ============ Withdrawal 1 ============ 
    match vault.create_withdrawal(&secp, VaultAmount::new(6)) {
        Ok(_) => panic!("can't withdraw more than balance"),
        Err(_) => {}
    }

    // ============ Withdrawal 2 ============ 
    let withdrawal_amount_raw = VAULT_SCALE * 3;
    total_deposit -= withdrawal_amount_raw;
    let (withdrawal_amount, remainder) = vault.to_vault_amount(withdrawal_amount_raw).expect("valid vault amount");
    assert_eq!(remainder, Amount::ZERO);

    let mut withdrawal_transaction = vault.create_withdrawal(&secp, withdrawal_amount)
        .expect("can withdraw");

    let mut withdrawal_cpfp_psbt = wallet.create_cpfp(&secp, &withdrawal_transaction, FeeRate::BROADCAST_MIN)
        .expect("can cpfp");

    let sign_success = wallet.sign(&mut withdrawal_cpfp_psbt, SignOptions::default())
        .expect("sign success");
    assert!(sign_success);

    let withdrawal_cpfp = withdrawal_cpfp_psbt.extract_tx().unwrap();

    let hot_keypair = withdrawal_transaction.hot_keypair(&secp, &hot_xpriv)
        .expect("successful key derivation");

    withdrawal_transaction.sign_vault_input(&secp, &hot_keypair)
        .expect("can sign withdrawal");

    let transmittable_withdrawal_transaction = withdrawal_transaction.to_signed_transaction()
        .expect("signed tx");

    vault.add_transaction(withdrawal_transaction.into())
        .expect("can add withdrawal");

    client.send_raw_transaction(&transmittable_withdrawal_transaction)
        .expect_err("can't broadcast withdrawal without a cpfp");

    let args: Vec<serde_json::Value> = vec![
        mccv::vault::package_encodable(
            vec![
                &transmittable_withdrawal_transaction,
                &withdrawal_cpfp,
            ],
        ),
    ];

    let result: serde_json::Value = client.call("submitpackage", args.as_ref()).unwrap();
    assert_eq!(result.get("package_msg"), Some(&"success".into()), "{:?}", result);

    let unspendable_key = XOnlyPublicKey::from_slice(&[1; 32]).unwrap();
    let unspendable_address = Address::p2tr(&secp, unspendable_key, None, Network::Regtest);

    client.generate_to_address(1, &unspendable_address).unwrap();

    update_vault(&mut vault, &mut vault_block_emitter);
    assert_eq!(vault.get_confirmed_balance(), total_deposit);



    todo!("complete withdrawal by either spending it to the BDK wallet, or somehow informing BDK how to spend the timelocked withdrawal output")
}
