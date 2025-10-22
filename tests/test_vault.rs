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
    relative,
    Txid,
};

#[allow(unused_imports)]
use bitcoin::consensus::encode::serialize_hex;

use bitcoin::secp256k1::{
    Secp256k1,
    Signing,
    Verification,
    XOnlyPublicKey,
};

use bitcoin::secp256k1::rand::{RngCore, thread_rng};

use std::str::FromStr;
use std::time;
use std::thread;

use mccv::{
    AccountId,
    VaultAmount,
    VaultParameters,
    VaultScale,
    Vault,
    VaultDepositor,
    VaultWithdrawer,
    vault::SqliteVaultStorage,
    vault::SubmitPackage,
};

fn test_node_subver(node_index: usize) -> String {
    format!("mccv_testnode{node_index}")
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

pub fn update_vault<C: Verification>(secp: &Secp256k1<C>, vault: &mut Vault, emitter: &mut Emitter<&Client>) {
    while let Some(block) = emitter.next_block().unwrap() {
        vault.apply_block(secp, &block.block, block.block_height());
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

fn advance_chain<C: Verification>(secp: &Secp256k1<C>, wallet: &mut Wallet, client: &Client, num_blocks: u64) {
    let unspendable_address = {
        let unspendable_key = XOnlyPublicKey::from_slice(&[1; 32]).unwrap();
        Address::p2tr(secp, unspendable_key, None, Network::Regtest)
    };

    client.generate_to_address(num_blocks, &unspendable_address).unwrap();

    update_wallet(wallet, client);
}

struct TestNodes {
    nodes: Vec<(corepc_node::Node, Client)>,
}

impl TestNodes {
    fn new(node_count: usize) -> Self {
        let mut nodes = Vec::with_capacity(node_count);
        for i in 0..node_count {
            let node_ua = format!("-uacomment={}", test_node_subver(i + 1));

            let path = corepc_node::exe_path().expect("Failed to get bitcoind path. See README.md \"Testing Error\" section.");
            let mut conf = corepc_node::Conf::default();
            conf.args.push(&node_ua); // Append because we need to keep the -regtest arg
            conf.p2p = corepc_node::P2P::Yes;

            let node = corepc_node::Node::with_conf(path, &conf).unwrap();
            let url = node.rpc_url();
            let auth = Auth::CookieFile(node.params.cookie_file.clone());

            nodes.push((node, Client::new(&url, auth).unwrap()));
        }

        Self { nodes }
    }

    fn client(&self, index: usize) -> &Client { &self.nodes[index].1 }
    fn node(&self, index: usize) -> &corepc_node::Node { &self.nodes[index].0 }

    fn connect_nodes(&self, a: usize, b: usize) {
        let a_addr = self.node(a).params.p2p_socket.unwrap();
        let b_addr = self.node(b).params.p2p_socket.unwrap();

        self.client(a).add_node(&b_addr.to_string()).unwrap();
        self.client(b).add_node(&a_addr.to_string()).unwrap();
    }

    fn disconnect_nodes(&self, a: usize, b: usize) {
        let b_peers = self.client(b).get_peer_info().unwrap();

        let a_subver = test_node_subver(a);
        let all_a_peers: Vec<_> = b_peers.into_iter().filter(|peer| a_subver == peer.subver).collect();

        for peer in all_a_peers {
            // FIXME: disambiguate "node already disconnected" scenario like core
            // test_framework does
            match self.client(b).disconnect_node_by_id(peer.id as u32) {
                Ok(_) => {}
                Err(bdk_bitcoind_rpc::bitcoincore_rpc::Error::JsonRpc(e)) => {
                    let ok = match &e {
                        bdk_bitcoind_rpc::bitcoincore_rpc::jsonrpc::Error::Rpc(e) => {
                            // -29 means the client is already disconnected, which can happen
                            // for benign reasons
                            if e.code == -29 {
                                true
                            } else {
                                false
                            }
                        }
                        _ => false,
                    };

                    if !ok {
                        panic!("{e:?}");
                    }
                }
                Err(e) => panic!("{e:?}"),
            }
        }

        loop {
            let has_a_peer = self.client(b)
                .get_peer_info()
                .unwrap()
                .into_iter()
                .filter(|peer| a_subver == peer.subver)
                .next()
                .is_some();

            if !has_a_peer {
                break;
            } else {
                let sleep_time = time::Duration::from_secs_f32(0.1);
                thread::sleep(sleep_time);
            }
        }
    }

    fn sync_nodes(&self, clients: &[usize]) {
        loop {
            let best_blocks: Vec<_> = clients.iter()
                .map(|client| {
                    self.client(*client).get_best_block_hash()
                })
                .collect::<Result<Vec<_>, _>>()
                .unwrap();

            if best_blocks.iter().all(|block| *block == best_blocks[0]) {
                break;
            } else {
                let sleep_time = time::Duration::from_secs_f32(0.1);

                thread::sleep(sleep_time);
            }
        }
    }
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

    let nodes = TestNodes::new(2);

    nodes.connect_nodes(0, 1);

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

    generate_to_wallet(&mut wallet, nodes.client(0), 1);
    advance_chain(&secp, &mut wallet, nodes.client(0), 100);

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

    nodes.client(0)
        .submit_package(&[&shape_transaction, &transmittable_deposit_transaction])
        .expect("package submit success");

    let _ = nodes.client(0).get_mempool_entry(&shape_transaction.compute_txid())
        .expect("shape tx in mempool");

    let _ = nodes.client(0).get_mempool_entry(&transmittable_deposit_transaction.compute_txid())
        .expect("deposit tx in mempool");

    generate_to_wallet(&mut wallet, nodes.client(0), 6);

    let _ = nodes.client(0).get_mempool_entry(&shape_transaction.compute_txid())
        .expect_err("shape tx has been mined");

    let _ = nodes.client(0).get_mempool_entry(&transmittable_deposit_transaction.compute_txid())
        .expect_err("deposit tx has been mined");

    let mut vault_block_emitter = Emitter::new(nodes.client(0), genesis_checkpoint, 0, Option::<Txid>::None);

    assert_eq!(vault.get_confirmed_balance(), Amount::ZERO);

    vault.add_transaction(deposit_transaction.into())
        .expect("deposit transaction should add cleanly");

    update_vault(&secp, &mut vault, &mut vault_block_emitter);

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

    nodes.client(0)
        .submit_package(&[&shape_transaction, &transmittable_deposit_transaction])
        .expect("package submission success");

    vault.add_transaction(deposit_transaction.into())
        .expect("deposit transaction should add cleanly");

    generate_to_wallet(&mut wallet, nodes.client(0), 6);

    update_vault(&secp, &mut vault, &mut vault_block_emitter);

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

    vault.add_transaction(withdrawal_transaction.clone().into())
        .expect("can add withdrawal");

    nodes.client(0).send_raw_transaction(&transmittable_withdrawal_transaction)
        .expect_err("can't broadcast withdrawal without a cpfp");

    // Just make sure all wallet coins are spendable now
    advance_chain(&secp, &mut wallet, nodes.client(0), 100);

    nodes.client(0)
        .submit_package(&[&transmittable_withdrawal_transaction, &withdrawal_cpfp])
        .expect("package submission success");

    advance_chain(&secp, &mut wallet, nodes.client(0), 1);
    update_vault(&secp, &mut vault, &mut vault_block_emitter);
    assert_eq!(vault.get_confirmed_balance(), total_deposit);

    let withdrawal_spend = withdrawal_transaction.spend_withdrawal();

    let keypair = withdrawal_spend.hot_keypair(&secp, &hot_xpriv).expect("derive withdrawal hot keypair");

    let dest = wallet.reveal_next_address(KeychainKind::External);

    let withdrawal_spend_tx = withdrawal_spend.spend(&secp, &keypair, dest.script_pubkey(), Amount::ZERO, FeeRate::BROADCAST_MIN)
        .expect("generate spend tx success");

    nodes.client(0).send_raw_transaction(&withdrawal_spend_tx)
        .expect_err("can't broadcast yet");

    let wait_blocks = match withdrawal_spend.timelock() {
        relative::LockTime::Blocks(blocks) => blocks.value(),
        relative::LockTime::Time(_) => unreachable!("must be relative blocks"),
    };

    advance_chain(&secp, &mut wallet, nodes.client(0), wait_blocks.into());
    nodes.client(0).send_raw_transaction(&withdrawal_spend_tx)
        .expect("valid now");

    let balance_before_update = wallet.balance();
    let withdrawal_value = withdrawal_spend_tx.output[0].value;

    advance_chain(&secp, &mut wallet, nodes.client(0), 1);

    let balance_after_update = wallet.balance();

    assert_eq!(
        balance_before_update.confirmed + withdrawal_value,
        balance_after_update.confirmed,
    );

    let withdrawal_amount_raw = VAULT_SCALE * 1;
    total_deposit -= withdrawal_amount_raw;
    let (withdrawal_amount, remainder) = vault.to_vault_amount(withdrawal_amount_raw).expect("valid vault amount");
    assert_eq!(remainder, Amount::ZERO);

    nodes.sync_nodes(&[0, 1]);
    nodes.disconnect_nodes(0, 1);

    // ============ Unauthorized Withdrawal ============
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

    nodes.client(0)
        .submit_package(&[&transmittable_withdrawal_transaction, &withdrawal_cpfp])
        .expect("package submission success");

    advance_chain(&secp, &mut wallet, nodes.client(0), 1);

    // XXX: We do *not* add the transaction to the vault, to simulate someone else creating it

    let vault_amount = vault.get_confirmed_balance();
    update_vault(&secp, &mut vault, &mut vault_block_emitter);

    // If the vault is able to reconstruct the vault state from the blockchain the balance should
    // be updated
    assert_eq!(vault_amount - VAULT_SCALE, vault.get_confirmed_balance());

    let mut recovery = vault.create_recovery(&secp).expect("recovery create success");

    let recovery_keypair = recovery.hot_keypair(&secp, &hot_xpriv)
        .expect("successful key derivation");

    recovery.sign(&secp, &recovery_keypair)
        .expect("sign success");

    let mut recovery_cpfp_psbt = wallet.create_cpfp(&secp, &recovery, FeeRate::BROADCAST_MIN)
        .expect("can cpfp");

    let sign_success = wallet.sign(&mut recovery_cpfp_psbt, SignOptions::default())
        .expect("sign success");
    assert!(sign_success);

    let recovery_cpfp = recovery_cpfp_psbt.extract_tx().unwrap();

    let recovery_tx = recovery.into_signed_transaction().expect("valid transaction");

    nodes.client(0)
        .submit_package(&[&recovery_tx, &recovery_cpfp])
        .expect("package submission success");

    advance_chain(&secp, &mut wallet, nodes.client(0), 1);
    update_vault(&secp, &mut vault, &mut vault_block_emitter);

    assert_eq!(Amount::ZERO, vault.get_confirmed_balance());
}
