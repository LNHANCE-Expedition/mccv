mod migrate;
mod vault;

#[cfg(test)]
mod test_util;

use bdk_esplora::{
    EsploraExt,
};

use bdk_wallet::KeychainKind;

use bdk_wallet::{
    template::Bip86,
    template::DescriptorTemplate,
    Wallet,
};

use bitcoin::NetworkKind;
use bitcoin::bip32::{
    Xpub,
    Xpriv,
    DerivationPath,
    ChildNumber,
};

use bitcoin::secp256k1::{
    Secp256k1,
    Signing,
    Verification,
    XOnlyPublicKey,
};

use bitcoin::{
    Amount,
    script::Builder,
    consensus::Encodable,
    absolute::LockTime,
    Network,
    opcodes::OP_TRUE,
    OutPoint,
    relative::LockTime as RelativeLockTime,
    ScriptBuf,
    TapNodeHash,
    Transaction,
    Txid, 
    transaction::TxIn,
    transaction::TxOut,
    blockdata::transaction::Version,
    taproot::{
        LeafVersion,
        TaprootBuilder,
    },
    Witness,
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

use rayon::iter::{
    IntoParallelIterator,
    ParallelIterator,
};

use rusqlite::{
    Connection,
    params,
};

use serde::{
    Deserialize,
    Serialize,
};

use std::io::Write;

use std::collections::HashMap;

use std::path::PathBuf;

use std::time::{Duration, Instant};

use crate::vault::{
    VaultParameters,
    Vault,
    VaultAmount,
};

fn new_xpriv(network: NetworkKind) -> Xpriv {
    let mut rng = thread_rng();

    let mut seed = [0u8; 128];

    rng.fill_bytes(&mut seed);
    Xpriv::new_master(network, &seed)
        .expect("privkey generation")
}

#[derive(Clone, Args)]
struct DepositArg {
    vault: u32,
    amount: u64,
}

#[derive(Clone, Args)]
struct WithdrawArg {
    vault: u32,
    amount: u64,
}

#[derive(Clone, Subcommand)]
enum Command {
    Generate,
    List,
    Receive,
    Sync,
    Deposit(DepositArg),
    Withdraw(WithdrawArg),
    Benchmark,
}

#[derive(Parser)]
#[command(name = "mccv")]
struct CommandLine {
    #[arg(short = 'c', long = "config", default_value="./config.toml")]
    config: PathBuf,

    #[arg(short = 'w', long = "wallet", default_value="./mccv-wallet.sqlite")]
    wallet_path: PathBuf,

    #[command(subcommand)]
    command: Command,

    #[arg(short = 'n', long = "network", default_value="signet")]
    network: Network,

    #[arg(short = 'e', long = "esplora", default_value="http://signet.bitcoindevkit.net")]
    esplora: String,
}

#[derive(Serialize,Deserialize)]
struct Configuration {
    vault_parameters: VaultParameters,
    master_xpriv: Xpriv,
    wallet_path: PathBuf,
    descriptor: String,
    change_descriptor: String,
}

fn read_config(path: &PathBuf) -> Configuration {
    let config = std::fs::read_to_string(path)
        .expect("Can't read config");
    toml::from_str::<Configuration>(&config)
        .expect("Can't parse config")
}

fn main() {
    let args = CommandLine::parse();

    let secp = Secp256k1::new();

    match args.command {
        Command::Generate => {
            let master_xpriv = new_xpriv(args.network.into());

            let vault_parameters = VaultParameters::from_xpriv(&secp, &master_xpriv, 0);

            let (descriptor, _, _) = Bip86(master_xpriv, KeychainKind::External)
                .build(args.network)
                .expect("Failed to build external descriptor");

            let descriptor_string = descriptor.to_string();

            let (change_descriptor, _, _) = Bip86(master_xpriv, KeychainKind::Internal)
                .build(args.network)
                .expect("Failed to build change descriptor");

            let change_descriptor_string = change_descriptor.to_string();

            let mut sqlite = Connection::open(&args.wallet_path)
                .expect("open wallet");

            Vault::init(&mut sqlite).expect("init vault");

            let mut wallet = Wallet::create(descriptor, change_descriptor)
                .network(args.network)
                .create_wallet(&mut sqlite)
                .expect("wallet create");

            let req = wallet.start_full_scan()
                .build();

            let blocking_esplora = bdk_esplora::esplora_client::Builder::new(&args.esplora)
                .build_blocking();

            let result = blocking_esplora.full_scan(req, 32, 4)
                .expect("full scan failed");

            wallet.apply_update(result)
                .expect("update failed");

            wallet.persist(&mut sqlite)
                .expect("update sqlite");

            let config = Configuration {
                vault_parameters,
                master_xpriv,
                wallet_path: args.wallet_path,
                descriptor: descriptor_string.clone(),
                change_descriptor: change_descriptor_string.clone(),
            };

            {
                let mut transaction = sqlite.transaction().expect("start transaction");
                transaction.execute(r#"
                    insert into
                        mccv_secret
                    (
                        master_xpriv,
                        descriptor,
                        change_descriptor
                    )
                    values
                    ( ?, ?, ? )
                "#, params![&master_xpriv.to_string(), descriptor_string, change_descriptor_string])
                    .expect("insert material");

                transaction.commit()
                    .expect("commit transaction");
            }

            let config = toml::to_string(&config).expect("serialize config");
            std::fs::write(args.config, config.as_bytes()).expect("write config");
        },
        Command::List => {
            let config = read_config(&args.config);
            let mut sqlite = Connection::open(&args.wallet_path)
                .expect("open wallet");

            Vault::init(&mut sqlite).expect("init vault");

            let mut wallet = Wallet::load()
                .load_wallet(&mut sqlite)
                .expect("load wallet")
                .expect("load wallet");

            let req = wallet.start_sync_with_revealed_spks()
                .build();

            let blocking_esplora = bdk_esplora::esplora_client::Builder::new(&args.esplora)
                .build_blocking();

            //let result = blocking_esplora.full_scan(req, 32, 4)
            let result = blocking_esplora.sync(req, 4)
                .expect("full scan failed");

            wallet.apply_update(result)
                .expect("update failed");

            wallet.persist(&mut sqlite)
                .expect("update sqlite");

            let balance = wallet.balance();

            println!("   immature: {}", balance.immature);
            println!("+ confirmed: {}", balance.confirmed);
            println!("----------------------------------");
            println!("total: {}", balance.total());

            todo!()
        }
        Command::Sync => {
            let config = read_config(&args.config);
            let mut sqlite = Connection::open(&args.wallet_path)
                .expect("open wallet");

            Vault::init(&mut sqlite).expect("init vault");

            let mut wallet = Wallet::load()
                .load_wallet(&mut sqlite)
                .expect("load wallet")
                .expect("load wallet");

            let req = wallet.start_sync_with_revealed_spks()
                .build();

            let blocking_esplora = bdk_esplora::esplora_client::Builder::new(&args.esplora)
                .build_blocking();

            //let result = blocking_esplora.full_scan(req, 32, 4)
            let result = blocking_esplora.sync(req, 4)
                .expect("full scan failed");

            wallet.apply_update(result)
                .expect("update failed");

            wallet.persist(&mut sqlite)
                .expect("update sqlite");

            println!("Sync'd");
        }
        Command::Receive => {
            let config = read_config(&args.config);
            let mut sqlite = Connection::open(&args.wallet_path)
                .expect("open wallet");

            Vault::init(&mut sqlite).expect("init vault");

            let mut wallet = Wallet::load()
                .load_wallet(&mut sqlite)
                .expect("load wallet")
                .expect("load wallet");

            let address = wallet.next_unused_address(KeychainKind::External);

            wallet.persist(&mut sqlite).expect("sqlite sync");

            println!("Address: {}", address.to_string());
        }
        Command::Deposit(amount) => {
            let config = read_config(&args.config);
            let mut sqlite = Connection::open(&args.wallet_path)
                .expect("open wallet");

            Vault::init(&mut sqlite).expect("init vault");

            // Actually I think you need the private descriptors via .descriptor() for
            // .extract_keys()
            //
            // That's a bit clunky imho.
            Wallet::load()
                // Seems like this is unnecessary, it's more of a "check" to see that descriptors
                // are correct according to the docs, which we don't care about
                // Let's see if it actually is...
                .descriptor(KeychainKind::External, Some(config.descriptor))
                .descriptor(KeychainKind::Internal, Some(config.change_descriptor))
                // This is what's necessary to load private keys
                // wtf? does that mean we have to derive private keys from an xpriv ourselves?
                // seems terribly unergonomic
                //.keymap(KeychainKind::External, &config.descriptor)
                //.keymap(KeychainKind::Internal, &config.change_descriptor)
                .extract_keys()
                .load_wallet(&mut sqlite)
                .expect("success");

            todo!()
        }
        Command::Withdraw(_amount) => {
            let config = read_config(&args.config);

            todo!()
        }
        Command::Benchmark => {
            let config = read_config(&args.config);

            let start = Instant::now();
            let first_level = config.vault_parameters.templates_at_depth(&secp, 0);
            let end = Instant::now();
            let duration = end - start;

            println!("done! {}s elapsed", duration.as_secs_f64());
        }
    }
}
