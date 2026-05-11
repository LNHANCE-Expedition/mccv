#[cfg(not(feature = "bitcoind"))]
compile_error!("Vault CLI requires a blockchain interface, enable the `bitcoind` feature.");

#[cfg(feature = "bitcoind")]
use bdk_bitcoind_rpc::Emitter;
#[cfg(feature = "bitcoind")]
use bdk_bitcoind_rpc::bitcoincore_rpc::{Client, RpcApi};
#[cfg(feature = "bitcoind")]
use bdk_bitcoind_rpc::bitcoincore_rpc::json::GetChainTipsResultStatus;

#[cfg(feature = "bitcoind")]
use bdk_core::{BlockId, CheckPoint};

use bdk_wallet::SignOptions;

use bdk_wallet::{
    KeychainKind,
    PersistedWallet,
    template::Bip86,
    template::DescriptorTemplate,
    Update,
    Wallet,
};

use bitcoin::address::NetworkUnchecked;
use bitcoin::amount::Display;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::{Address, Amount, FeeRate, Denomination};

use bitcoin::bip32::{
    Xpriv,
    Xpub,
};

use bitcoin::secp256k1::{
    Secp256k1,
    Signing,
    Verification,
};

use bitcoin::{
    Network,
};

use clap::{
    Args,
    Parser,
    Subcommand,
};

use rand::{
    RngCore,
    thread_rng,
};

#[allow(unused_imports)]
use rusqlite::{
    Connection,
    params,
};

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "bitcoind")]
use mccv::{
    vault::SubmitPackage,
};

use mccv::{
    AccountId,
    storage::ChangeLog,
    UtxoSelector,
    vault::Context,
    VaultAmount,
    VaultDepositor,
    VaultId,
    VaultParameters,
    VaultScale,
    VaultWithdrawer,
    Vault,
};

use mccv::storage::{
    Storage as _,
};

use mccv::vault_storage::{
    StoredSecrets,
    SqliteStorage,
};

#[derive(Clone, Args)]
struct RpcAuthArg {
    #[arg(short = 'u', long = "rpc-username")]
    username: Option<String>,
    #[arg(short = 'p', long = "rpc-password")]
    password: Option<String>,
    #[arg(short = 'c', long = "cookie-path")]
    cookie_path: Option<PathBuf>,
}

#[derive(Debug)]
enum AuthArgError {
    Invalid,
}

impl TryFrom<RpcAuthArg> for bdk_bitcoind_rpc::bitcoincore_rpc::Auth {
    type Error = AuthArgError;

    fn try_from(auth: RpcAuthArg) -> Result<Self, Self::Error> {
        match (auth.username, auth.password, auth.cookie_path) {
            (_, _, Some(cookie_path)) => Ok(Self::CookieFile(cookie_path)),
            (Some(username), Some(password), _) => Ok(Self::UserPass(username, password)),
            (None, None, None) => Ok(Self::None),
            _ => Err(AuthArgError::Invalid),
        }
    }
}

#[derive(Clone, Args)]
struct RpcConf {
    #[command(flatten)]
    rpc_auth: RpcAuthArg,
    #[arg(short = 'U', long = "rpc-url")]
    rpc_url: String,
}

impl RpcConf {
    fn open(&self) -> Client {
        Client::new(
            self.rpc_url.as_ref(),
            self.rpc_auth.clone()
                .try_into()
                .expect("valid auth settings")
        )
        .expect("valid RPC settings")
    }
}

#[derive(Clone, Args)]
struct GenerateArg {
    #[arg(short = 'n', long = "vault-name", help = "Human readable identifier string")]
    name: String,
    #[arg(short = 's', long = "scale", help = "The increment over which the vault will work")]
    scale: Amount,
    #[arg(short = 'm', long = "max", help = "The maximum capacity of the vault, expressed as an integer multiple. The effective maximum capacity will be scale * max BTC")]
    max: u32,
    #[arg(short = 'd', long = "delay", help = "The number of blocks to delay per withdrawn increment")]
    delay: u32, // blocks per increment
    #[arg(short = 'D', long = "max-deposit", help = "The maximum number of increments that can be deposited in a single transaction")]
    max_deposit: u32,
    #[arg(short = 'W', long = "max-withdrawal", help = "The maximum number of increments that can be withdrawn in a single transaction")]
    max_withdrawal: u32,
    #[arg(long = "max-depth", help = "The maximum number of vault operations that can be performed before moving it into a new vault")]
    max_depth: u32,

    #[command(flatten)]
    rpc_conf: RpcConf,
}

fn vault_parameters_from_args(args: &GenerateArg, cold_xpub: Xpub, hot_xpub: Xpub) -> VaultParameters {
    let scale = VaultScale::from_sat(
        args.scale.to_sat().try_into()
            .expect("vault scale within 1-4294967295 sats")
    );

    let max = VaultAmount::new(args.max);
    let max_deposit = VaultAmount::new(args.max_deposit);
    let max_withdrawal = VaultAmount::new(args.max_withdrawal);

    VaultParameters::new(
        scale,
        max,
        cold_xpub,
        hot_xpub,
        args.delay,
        max_deposit,
        max_withdrawal,
        args.max_depth,
    )
}

#[derive(Clone, Args)]
struct FeeRateArg {
    #[arg(short, long, help = "Fee rate override in sats/vbyte")]
    fee_rate: Option<u64>,

    #[arg(short, long, default_value_t = 6, help = "Target confirmation block for fee rate estimation")]
    block_confirmation_target: u16,
}

impl FeeRateArg {
    fn fee_rate(&self, rpc_client: &Client) -> FeeRate {
        if let Some(fee_rate) = self.fee_rate {
            FeeRate::from_sat_per_vb(fee_rate)
                .expect("valid fee rate")
        } else {
            let fee_rate_estimate = rpc_client.estimate_smart_fee(
                    self.block_confirmation_target,
                    None,
                )
                .expect("fee rate");

            // Checked RPC docs and this is indeed kvB not kB, which makes sense, docs are probably
            // just stale
            let amount_per_kvb = fee_rate_estimate.fee_rate.expect("fee rate");

            FeeRate::from_sat_per_kwu(amount_per_kvb.to_sat() / 4)
        }
    }
}

#[derive(Clone, Args)]
struct ModifyArg {
    #[arg(short, long = "vault-name", help = "Human readable identifier string")]
    name: Option<String>,

    #[command(flatten)]
    rpc_conf: RpcConf,

    #[command(flatten)]
    fee_rate: FeeRateArg,

    amount: Amount,
}

#[derive(Clone, Subcommand)]
enum Command {
    Generate(GenerateArg),
    List,
    Balance {
        #[arg(short, long = "vault-name", help = "Human readable identifier string")]
        name: Option<String>
    },
    Receive {
        #[arg(short, long = "vault-name", help = "Human readable identifier string")]
        name: Option<String>,
    },
    SweepToHot {
        #[command(flatten)]
        fee_rate: FeeRateArg,

        #[command(flatten)]
        rpc_conf: RpcConf,

        #[arg(short, long = "vault-name", help = "Human readable identifier string")]
        name: Option<String>,
    },
    Send {
        #[arg(short, long = "vault-name", help = "Human readable identifier string")]
        name: Option<String>,

        #[arg(short, long, help = "Sweep entire contents of the hot wallet (amount will be ignored)")]
        sweep: bool,

        #[command(flatten)]
        fee_rate: FeeRateArg,

        #[command(flatten)]
        rpc_conf: RpcConf,

        address: Address<NetworkUnchecked>,

        amount: Amount,
    },
    Sync {
        #[arg(short, long = "vault-name", help = "Human readable identifier string")]
        name: Option<String>,

        #[command(flatten)]
        rpc_conf: RpcConf,
    },
    Deposit(ModifyArg),
    Withdraw(ModifyArg),
}

#[derive(Parser)]
#[command(name = "mccv", version)]
struct CommandLine {
    #[arg(short = 'c', long = "config", default_value="./config.toml")]
    config: PathBuf,

    #[arg(short = 'd', long = "vault-database", default_value="./mccv-vault.sqlite")]
    vault_path: PathBuf,

    #[arg(short = 'w', long = "wallet-database", default_value="./mccv-wallet.sqlite")]
    wallet_path: PathBuf,

    #[command(subcommand)]
    command: Command,

    #[arg(short = 'n', long = "network", default_value="signet")]
    network: Network,
}

impl CommandLine {
    fn open_storage(&self) -> Storage {
        let vault_storage = SqliteStorage::from_connection(
                Connection::open(&self.vault_path)
                    .expect("open vault database")
            )
            .expect("open vault");

        let wallet_storage = Connection::open(&self.wallet_path)
            .expect("open wallet");

        Storage {
            wallet_storage,
            vault_storage,
        }
    }
}

#[cfg(feature = "bitcoind")]
fn latest_blockid(rpc_client: &Client) -> BlockId {
    rpc_client.get_chain_tips().expect("RPC success")
        .into_iter()
        .filter_map(|tip| -> Option<BlockId> {
            if tip.status == GetChainTipsResultStatus::Active {
                Some(
                    BlockId {
                        height: tip.height
                            .try_into().expect("block height fits in u32"),
                        hash: tip.hash,
                    }
                )
            } else {
                None
            }
        })
        .next()
        .expect("at least one active chain")
}

#[cfg(feature = "bitcoind")]
fn block_parent(rpc_client: &Client, mut block_id: BlockId, mut depth: u32) -> BlockId {
    while depth != 0 {
        depth -= 1;

        let header = rpc_client.get_block_header(&block_id.hash)
            .expect("rpc success");

        block_id = BlockId {
            hash: header.prev_blockhash,
            height: block_id.height - 1,
        };
    }

    block_id
}

fn select_vault(storage: &mut SqliteStorage, name: Option<&str>) -> VaultId {
    let vaults = storage.list().unwrap();

    let id = if vaults.len() == 1 {
        vaults.first()
            .map(|(id, _)| *id)
    } else {
        let name = name.clone().expect("name required if multiple vaults present");
        vaults.iter()
            .find_map(|(id, vault_name)| {
                if *vault_name == name {
                    Some(*id)
                } else {
                    None
                }
            })
    };

    if let Some(id) = id {
        id
    } else {
        if let Some(name) = name {
            eprintln!("Unknown vault \"{name}\"");
        } else {
            eprintln!("Must select a vault");
        }
        eprintln!("{} Known vaults:", vaults.len());
        for (_, vault_name) in vaults {
            eprintln!("\"{vault_name}\"");
        }
        panic!();
    }
}

struct Storage {
    wallet_storage: rusqlite::Connection,
    vault_storage: SqliteStorage,
}

struct VaultSystem {
    storage: Storage,

    secrets: StoredSecrets,

    wallet: PersistedWallet<rusqlite::Connection>,

    vault: Vault,

    vault_changelog: ChangeLog<SqliteStorage>,
}

impl VaultSystem {
    fn load<C: Verification>(secp: &Secp256k1<C>, mut storage: Storage, name: Option<&str>) -> Self {
        let vault_id = select_vault(&mut storage.vault_storage, name);

        let secrets = storage.vault_storage.load_secrets(vault_id)
            .expect("load secrets")
            .expect("vault has secrets");

        let wallet = Wallet::load()
            .descriptor(KeychainKind::External, Some(secrets.descriptor.clone()))
            .descriptor(KeychainKind::Internal, Some(secrets.change_descriptor.clone()))
            .extract_keys()
            .load_wallet(&mut storage.wallet_storage)
            .expect("load wallet")
            .expect("wallet should be non-empty");

        let (vault, vault_changelog) = storage.vault_storage
            .load(secp, vault_id)
            .expect("load vault");

        Self {
            storage,
            secrets,
            wallet,
            vault,
            vault_changelog,
        }
    }

    fn store(&mut self) {
        self.wallet.persist(&mut self.storage.wallet_storage)
            .expect("update sqlite");

        // XXX: A little janky
        let vault_changelog = self.vault_changelog.take();
        self.vault_changelog = self.storage.vault_storage.store(vault_changelog)
            .expect("store success");
    }

    fn create<C: Signing>(secp: &Secp256k1<C>, name: &str, master_xpriv: Xpriv, vault_parameters: VaultParameters, mut storage: Storage, network: Network) -> Self {
        let (descriptor, key_map, _) = Bip86(master_xpriv, KeychainKind::External)
            .build(network)
            .expect("Failed to build external descriptor");

        let descriptor_string = descriptor.to_string_with_secret(&key_map);

        let (change_descriptor, change_key_map, _) = Bip86(master_xpriv, KeychainKind::Internal)
            .build(network)
            .expect("Failed to build change descriptor");

        let change_descriptor_string = change_descriptor.to_string_with_secret(&change_key_map);

        let wallet = Wallet::create(descriptor, change_descriptor)
            .network(network)
            .create_wallet(&mut storage.wallet_storage)
            .expect("wallet create");

        println!("Creating Vault...");
        let (vault, vault_changelog) = storage.vault_storage.create(&name, vault_parameters)
            .expect("vault creation success");

        let account = AccountId::new(0)
            .expect("account id < 0x7FFFFFFF");

        let hot_xpriv = master_xpriv.derive_priv(&secp, &account.to_hot_derivation_path())
            .expect("xpriv derivation will not fail with a short derivation path");

        let secrets = StoredSecrets {
            master_fingerprint: master_xpriv.fingerprint(secp),
            master_xpriv: None,
            hot_path: account.to_hot_derivation_path(),
            hot_xpriv,
            descriptor: descriptor_string,
            change_descriptor: change_descriptor_string,
        };

        storage.vault_storage.store_secrets(vault_changelog.id(), &secrets)
            .expect("store secrets");

        Self {
            storage,
            secrets,
            wallet,
            vault,
            vault_changelog,
        }
    }

    #[cfg(feature = "bitcoind")]
    fn sync<C: Verification>(&mut self, secp: &Secp256k1<C>, context: &Context, rpc_client: &Client) {
        let vault_checkpoint = self.vault.checkpoint().unwrap();
        let wallet_checkpoint = self.wallet.latest_checkpoint();

        let vault_height = vault_checkpoint.height();
        let wallet_height = wallet_checkpoint.height();

        let highest = std::cmp::max(vault_height, wallet_height);

        self.sync_to(secp, context, rpc_client, highest);

        self.store();

        const BATCH_SIZE: u32 = 1000;

        fn next_height(height: u32) -> u32 {
            ( ( height  / BATCH_SIZE ) + 1 ) * BATCH_SIZE
        }

        let mut height = highest;
        loop {
            let next = next_height(height);
            if self.sync_to(secp, context, rpc_client, next) == 0 {
                break;
            }

            self.store_wallet();
            self.store_vault();
            height = next;
        }
    }

    #[cfg(feature = "bitcoind")]
    fn sync_to<C: Verification>(&mut self, secp: &Secp256k1<C>, context: &Context, rpc_client: &Client, max_height: u32) -> usize {
        let vault_checkpoint = self.vault.checkpoint().unwrap();
        let wallet_checkpoint = self.wallet.latest_checkpoint();

        let vault_height = vault_checkpoint.height();
        let wallet_height = wallet_checkpoint.height();

        let highest = std::cmp::max(vault_height, wallet_height);
        let highest = std::cmp::min(highest, max_height);

        self.sync_wallet_to(rpc_client, wallet_checkpoint, highest);
        self.sync_vault_to(secp, context, rpc_client, vault_checkpoint, highest);

        // TODO: Should assert we've synced both to the same tip just to be defensive

        // Pretty sure as long as we're synced to the same tip we ought to be safe to use the same
        // checkpoint
        let checkpoint = self.vault.checkpoint().unwrap();
        let height = checkpoint.height();

        let mut blocks_synced = 0;
        let mut emitter = Emitter::new(rpc_client, checkpoint, height, bdk_bitcoind_rpc::NO_EXPECTED_MEMPOOL_TXIDS);

        use std::io::Write;
        let mut out = std::io::stdout().lock();
        while let Some(block) = emitter.next_block().unwrap() {
            let _ = write!(out, "Syncing block {} @{} with wallet...", block.block.block_hash(), block.block_height());
            out.flush().unwrap();

            self.wallet.apply_block(&block.block, block.block_height()).unwrap();

            let _ = write!(out, "...and vault...");
            out.flush().unwrap();

            self.vault.apply_block(&secp, &context, &block.block, block.block_height(), &mut self.vault_changelog)
                .expect("apply block success");

            let _ = writeln!(out, "Done!");
            out.flush().unwrap();

            blocks_synced += 1;
        }

        blocks_synced
    }

    #[cfg(feature = "bitcoind")]
    fn sync_wallet_to(&mut self, rpc_client: &Client, checkpoint: CheckPoint, max_height: u32) {
        let mut height = checkpoint.height();
        let mut emitter = Emitter::new(rpc_client, checkpoint, height, bdk_bitcoind_rpc::NO_EXPECTED_MEMPOOL_TXIDS);
        use std::io::Write;
        let mut out = std::io::stdout().lock();
        while height < max_height {
            if let Some(block) = emitter.next_block()
                .expect("get next block")
            {
                height = block.checkpoint.height();

                let _ = write!(out, "Syncing block {} @{} with wallet...", block.block.block_hash(), block.block_height());
                out.flush().unwrap();

                self.wallet.apply_block(&block.block, block.block_height()).unwrap();
                let _ = writeln!(out, "Done!");
                out.flush().unwrap();
            } else {
                break;
            }
        }
    }

    #[cfg(feature = "bitcoind")]
    fn sync_vault_to<C: Verification>(&mut self, secp: &Secp256k1<C>, context: &Context, rpc_client: &Client, checkpoint: CheckPoint, max_height: u32) {
        let mut height = checkpoint.height();
        let mut emitter = Emitter::new(rpc_client, checkpoint, height, bdk_bitcoind_rpc::NO_EXPECTED_MEMPOOL_TXIDS);

        use std::io::Write;
        let mut out = std::io::stdout().lock();
        while height < max_height {
            if let Some(block) = emitter.next_block()
                .expect("get next block")
            {
                height = block.checkpoint.height();

                let _ = write!(out, "Syncing block {} @{} with vault...", block.block.block_hash(), block.block_height());
                out.flush().unwrap();

                self.vault.apply_block(&secp, context, &block.block, block.block_height(), &mut self.vault_changelog).unwrap();

                let _ = writeln!(out, "Done!");
                out.flush().unwrap();
            } else {
                break;
            }
        }
    }

    fn store_wallet(&mut self) {
        self.wallet
            .persist(&mut self.storage.wallet_storage)
            .expect("update sqlite");
    }

    fn store_vault(&mut self) {
        self.vault_changelog =
            self.storage.vault_storage.store(self.vault_changelog.take())
                .expect("store success");
    }
}

fn main() {
    let args = CommandLine::parse();

    let secp = Secp256k1::new();

    match args.command {
        Command::Generate(ref generate_arg) => {
            let mut rng = thread_rng();

            let mut seed = [0u8; 128];

            rng.fill_bytes(&mut seed);
            let master_xpriv = Xpriv::new_master(args.network, &seed)
                .expect("privkey generation");
            let master_xpub = Xpub::from_priv(&secp, &master_xpriv);

            println!("Xpub: {master_xpub}");
            println!("Xpriv: {master_xpriv}");

            let account = AccountId::new(0)
                .expect("account id < 0x7FFFFFFF");

            let hot_xpriv = master_xpriv.derive_priv(&secp, &account.to_hot_derivation_path())
                .expect("xpriv derivation will not fail with a short derivation path");

            let cold_xpriv = master_xpriv.derive_priv(&secp, &account.to_cold_derivation_path())
                .expect("xpriv derivation will not fail with a short derivation path derivation");

            let cold_xpub = Xpub::from_priv(&secp, &cold_xpriv);
            let hot_xpub = Xpub::from_priv(&secp, &hot_xpriv);

            let vault_parameters = vault_parameters_from_args(
                &generate_arg,
                cold_xpub,
                hot_xpub,
            );

            let storage = args.open_storage();

            let mut vault = VaultSystem::create(
                &secp,
                &generate_arg.name,
                master_xpriv,
                vault_parameters,
                storage,
                args.network,
            );

            println!("Generating Vault (this may take a while)...");

            // Sync vault
            let context = vault.vault.context(&secp);

            let genesis_block = bitcoin::blockdata::constants::genesis_block(args.network);

            vault.vault.apply_block(&secp, &context, &genesis_block, 0, &mut vault.vault_changelog)
                .expect("vault apply genesis");

            vault.vault_changelog = vault.storage.vault_storage.store(vault.vault_changelog.take()).expect("store vault");

            let rpc_client = generate_arg.rpc_conf.open();

            let latest_block = latest_blockid(&rpc_client);
            let checkpoint_start = block_parent(&rpc_client, latest_block, 6);
            let checkpoint_start_block_header = rpc_client.get_block_header(&checkpoint_start.hash)
                .expect("get block header");

            // Start from the latest block
            let latest_checkpoint = vault.wallet.latest_checkpoint().push(checkpoint_start).unwrap();

            let update_to_wallet_birthday = Update {
                chain: Some(latest_checkpoint.clone()),
                ..Default::default()
            };

            vault.wallet.apply_update(update_to_wallet_birthday).unwrap();

            vault.store_wallet();

            vault.vault.birthday(checkpoint_start.hash, checkpoint_start_block_header.prev_blockhash, checkpoint_start.height, &mut vault.vault_changelog);

            vault.store_vault();

            println!("Saved!");
        }
        Command::List => {
            let mut vault_storage = SqliteStorage::from_connection(
                    Connection::open(&args.vault_path)
                        .expect("open vault database")
                )
                .expect("open vault");

            let list = vault_storage.list().unwrap();

            println!("{} Vaults: ", list.len());
            for (_, name) in list {
                println!("\"{name}\"");
            }
        }
        Command::Balance { ref name } => {
            let storage = args.open_storage();

            let vault = VaultSystem::load(&secp, storage, name.as_deref());
            let balance = vault.wallet.balance();

            let current_height = vault.vault.height()
                .expect("must have synced at least one block");

            let mut withdrawal_utxos =
                vault
                    .vault
                    .spend_withdrawal_transactions(&secp, UtxoSelector::any_confirmed());

            withdrawal_utxos.sort_by_key(|(height, _)| *height);

            let vault_amount = vault.vault.confirmed_balance(None);
            let mut immature_withdrawal_amount = Amount::ZERO;
            fn format_amount(amount: Amount) -> Display {
                amount
                    .display_in(Denomination::Bitcoin)
            }
            immature_withdrawal_amount.display_in(Denomination::Bitcoin);

            println!("                vaulted: {:<14} BTC", format_amount(vault_amount));
            for (height, utxo) in withdrawal_utxos {
                immature_withdrawal_amount += utxo.value();

                let height = height.expect("valid withrawal maturity height");
                let delta = (height as i64) - (current_height as i64);
                let height_str = format!("@{height}");
                println!("+ {height_str:>21}: {:<14} BTC ( in {delta} blocks )",
                    format_amount(utxo.value())
                );
                if delta < 0 {
                    println!("(This withdrawal is mature but has not been swept yet)");
                }
            }
            println!("+ available immediately: {:<14} BTC", format_amount(balance.confirmed));
            println!("-------------------------------------------");
            println!("                  total: {:<14} BTC",
                format_amount(
                    balance.confirmed + vault_amount + immature_withdrawal_amount
                )
            );
        }

        Command::Sync { ref name, ref rpc_conf } => {
            let storage = args.open_storage();

            let mut vault = VaultSystem::load(&secp, storage, name.as_deref());

            let rpc_client = rpc_conf.open();

            let context = vault.vault.context(&secp);

            println!("Syncing...");
            vault.sync(&secp, &context, &rpc_client);
            vault.store();
            println!("Synced!");
        }
        Command::SweepToHot { ref name, ref fee_rate, ref rpc_conf } => {
            let storage = args.open_storage();
            let rpc_client = rpc_conf.open();

            let mut vault = VaultSystem::load(&secp, storage, name.as_deref());

            let current_height = vault.vault.height()
                .expect("must have synced at least one block");

            let mature_withdrawals: Vec<_> =
                vault
                    .vault
                    .spend_withdrawal_transactions(&secp, UtxoSelector::any_confirmed())
                    .into_iter()
                    .filter(|(maturity_height, _)|
                        maturity_height
                            .map(|maturity_height| maturity_height <= current_height)
                            .unwrap_or(false)
                    )
                    .map(|(_, withdrawal)| withdrawal)
                    .collect();


            let min_fee = Amount::ZERO;
            let min_fee_rate = fee_rate.fee_rate(&rpc_client);

            for withdrawal in mature_withdrawals {
                let keypair = withdrawal.hot_keypair(&secp, &vault.secrets.hot_xpriv)
                    .expect("valid keypair");
                let address = vault.wallet.reveal_next_address(KeychainKind::External);

                let transaction = withdrawal
                    .spend(&secp, &keypair, address.script_pubkey(), min_fee, min_fee_rate)
                    .expect("create sweep tx");

                println!("Sweep TX: {}", serialize_hex(&transaction));

                rpc_client.send_raw_transaction(&transaction)
                    .expect("send sweep tx");
            }

            vault.store();
        },
        Command::Send { ref name, ref address, ref amount, ref rpc_conf, ref fee_rate, sweep } => {
            let rpc_client = rpc_conf.open();

            let storage = args.open_storage();

            let fee_rate = fee_rate.fee_rate(&rpc_client);

            let mut vault = VaultSystem::load(&secp, storage, name.as_deref());

            let address = address.clone().require_network(args.network)
                .expect("address for expected network");

            let tx = if sweep {
                let mut builder = vault.wallet.build_tx();
                    builder
                        .fee_rate(fee_rate)
                        .drain_to(address.script_pubkey())
                        .drain_wallet();
                    builder.finish()
            } else {
                let mut builder = vault.wallet.build_tx();
                    builder
                        .fee_rate(fee_rate)
                        .add_recipient(address, *amount);
                    builder.finish()
            };

            let mut tx = tx.expect("build transaction");

            vault.store_wallet();

            let finalized = vault.wallet.sign(
                    &mut tx,
                    SignOptions::default(),
                )
                .expect("sign transaction");

            assert!(finalized);

            let tx = tx.extract_tx().expect("extract transaction");

            rpc_client.send_raw_transaction(&tx)
                .expect("broadcast transaction");

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time is never before unix epoch")
                .as_secs();

            vault.wallet.apply_unconfirmed_txs([(tx, now)]);

            vault.store_wallet();
        }
        Command::Receive { ref name } => {
            let storage = args.open_storage();

            let mut vault = VaultSystem::load(&secp, storage, name.as_deref());

            let address = vault.wallet.next_unused_address(KeychainKind::External);

            vault.store_wallet();

            println!("Address: {}", address.to_string());
        }
        Command::Deposit(ref deposit_args) => {
            let rpc_client = deposit_args.rpc_conf.open();

            let fee_rate = deposit_args.fee_rate.fee_rate(&rpc_client);

            let storage = args.open_storage();

            let mut vault = VaultSystem::load(&secp, storage, deposit_args.name.as_deref());

            let (deposit_amount, change) = vault.vault.to_vault_amount(deposit_args.amount)
                .expect("invalid deposit amount");

            assert_eq!(change, Amount::ZERO, "Invalid deposit amount");

            let wallet_balance = vault.wallet.balance();

            assert!(wallet_balance.confirmed >= deposit_args.amount);

            let mut deposit = vault.vault.create_deposit(&secp, deposit_amount)
                .expect("create deposit");

            let mut deposit_shape_psbt = vault
                .wallet
                .create_shape(&secp, &mut deposit, fee_rate)
                .expect("create shape");

            vault.store_wallet();

            // XXX: Right now the only time hot_keypair returns an error is for initial deposits,
            // which doesn't have a vault input to sign.
            if let Ok(vault_signing_keypair) = deposit.hot_keypair(&secp, &vault.secrets.hot_xpriv) {
                deposit.sign_vault_input(&secp, &vault_signing_keypair)
                    .expect("sign success");
            }

            let deposit = deposit.to_signed_transaction()
                .expect("success");

            let finalized = vault
                .wallet
                .sign(&mut deposit_shape_psbt, SignOptions::default())
                .expect("success");

            assert!(finalized);

            let deposit_shape = deposit_shape_psbt.extract_tx()
                .expect("tx finalized and complete");

            println!("Shape TX: {}", serialize_hex(&deposit_shape));
            println!("Deposit TX: {}", serialize_hex(&deposit));

            rpc_client.submit_package(&[
                    &deposit_shape,
                    &deposit,
                ])
                .expect("submit transaction package");

            // TODO: Persist unconfirmed transactions for rebroadcast
        }
        Command::Withdraw(ref withdrawal_args) => {
            let rpc_client = withdrawal_args.rpc_conf.open();

            let fee_rate = withdrawal_args.fee_rate.fee_rate(&rpc_client);

            let storage = args.open_storage();

            let mut vault = VaultSystem::load(&secp, storage, withdrawal_args.name.as_deref());

            let (withdrawal_amount, change) = vault.vault.to_vault_amount(withdrawal_args.amount)
                .expect("invalid withdrawal amount");

            assert_eq!(change, Amount::ZERO, "Invalid withdrawal amount");

            let wallet_balance = vault.wallet.balance();

            assert!(wallet_balance.confirmed >= withdrawal_args.amount);

            let mut withdrawal = vault.vault.create_withdrawal(&secp, withdrawal_amount)
                .expect("create withdrawal");

            let mut withdrawal_cpfp_psbt = vault.wallet.create_cpfp(&secp, &withdrawal, fee_rate)
                .expect("can cpfp");

            vault.store_wallet();

            let vault_signing_keypair = withdrawal.hot_keypair(&secp, &vault.secrets.hot_xpriv)
                .expect("keypair");

            withdrawal.sign_vault_input(&secp, &vault_signing_keypair)
                .expect("sign success");

            let withdrawal = withdrawal.to_signed_transaction()
                .expect("signed tx");

            let finalized = vault.wallet.sign(&mut withdrawal_cpfp_psbt, SignOptions::default())
                .expect("sign success");

            assert!(finalized);

            let withdrawal_cpfp = withdrawal_cpfp_psbt.extract_tx()
                .expect("cpfp transaction final");

            println!("Withdrawal TX: {}", serialize_hex(&withdrawal));
            println!("Withdrawal CPFP TX: {}", serialize_hex(&withdrawal_cpfp));

            rpc_client.submit_package(&[
                    &withdrawal,
                    &withdrawal_cpfp,
                ])
                .expect("submit transaction package");

            // TODO: Persist unconfirmed transactions for rebroadcast
            // TODO: Persist metadata for Withdrawal output spending
        }
    }
}
