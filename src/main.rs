mod migrate;
mod vault;

#[cfg(test)]
mod test_util;

use bdk_electrum::{
    BdkElectrumClient,
    electrum_client,
};

use bdk_wallet::KeychainKind;

use bdk_wallet::{
    template::Bip86,
    template::DescriptorTemplate,
    Wallet,
};

use bitcoin::NetworkKind;
use bitcoin::bip32::{
    Xpriv,
};

use bitcoin::secp256k1::{
    Secp256k1,
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

use rusqlite::{
    Connection,
    params,
};

use serde::{
    Deserialize,
    Serialize,
};

use std::path::PathBuf;

use std::time::Instant;

use crate::vault::{
    VaultParameters,
    Vault,
    VaultId,
    SqliteVaultStorage,
};

const DEFAULT_VAULT: VaultId = 0;

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

    #[arg(short = 'e', long = "electrum")]
    electrum: String,
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

            let mut wallet = Wallet::create(descriptor, change_descriptor)
                .network(args.network)
                .create_wallet(&mut sqlite)
                .expect("wallet create");

            let req = wallet.start_full_scan()
                .build();

            let electrum = electrum_client::Client::new(args.electrum.as_str())
                .expect("create electrum client");

            let electrum = BdkElectrumClient::new(electrum);

            let result = electrum.full_scan(req, 32, 4, true)
                .expect("full scan failed");

            wallet.apply_update(result)
                .expect("update failed");

            wallet.persist(&mut sqlite)
                .expect("update sqlite");

            let mut storage = SqliteVaultStorage::from_connection(sqlite)
                .expect("initialize vault storage");

            let vault = Vault::create_new(&mut storage, "Default Vault", vault_parameters.clone()).expect("vault create");

            let config = Configuration {
                vault_parameters,
                master_xpriv,
                wallet_path: args.wallet_path,
                descriptor: descriptor_string.clone(),
                change_descriptor: change_descriptor_string.clone(),
            };

            {
                let mut transaction = storage.transaction().expect("start transaction");
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

            let mut wallet = Wallet::load()
                .load_wallet(&mut sqlite)
                .expect("load wallet")
                .expect("load wallet");

            let req = wallet.start_sync_with_revealed_spks()
                .build();

            let electrum = electrum_client::Client::new(args.electrum.as_str())
                .expect("create electrum client");

            let electrum = BdkElectrumClient::new(electrum);

            let result = electrum.sync(req, 4, true)
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

            let mut storage = SqliteVaultStorage::from_connection(sqlite)
                .expect("initialize vault storage");
            let vault = Vault::load(DEFAULT_VAULT, &mut storage).expect("load vault");
            todo!()
        }
        Command::Sync => {
            let config = read_config(&args.config);
            let mut sqlite = Connection::open(&args.wallet_path)
                .expect("open wallet");

            let mut wallet = Wallet::load()
                .load_wallet(&mut sqlite)
                .expect("load wallet")
                .expect("load wallet");

            let req = wallet.start_sync_with_revealed_spks()
                .build();

            let electrum = electrum_client::Client::new(args.electrum.as_str())
                .expect("create electrum client");

            let electrum = BdkElectrumClient::new(electrum);

            let result = electrum.sync(req, 4, true)
                .expect("full scan failed");

            wallet.apply_update(result)
                .expect("update failed");

            wallet.persist(&mut sqlite)
                .expect("update sqlite");

            let mut storage = SqliteVaultStorage::from_connection(sqlite)
                .expect("initialize vault storage");
            let vault = Vault::load(DEFAULT_VAULT, &mut storage).expect("load vault");

            println!("Sync'd");
        }
        Command::Receive => {
            let config = read_config(&args.config);
            let mut sqlite = Connection::open(&args.wallet_path)
                .expect("open wallet");

            let mut wallet = Wallet::load()
                .load_wallet(&mut sqlite)
                .expect("load wallet")
                .expect("load wallet");

            let address = wallet.next_unused_address(KeychainKind::External);

            wallet.persist(&mut sqlite).expect("sqlite sync");

            let mut storage = SqliteVaultStorage::from_connection(sqlite)
                .expect("initialize vault storage");
            let vault = Vault::load(DEFAULT_VAULT, &mut storage).expect("load vault");

            println!("Address: {}", address.to_string());
        }
        Command::Deposit(amount) => {
            let config = read_config(&args.config);
            let mut sqlite = Connection::open(&args.wallet_path)
                .expect("open wallet");
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

            let mut storage = SqliteVaultStorage::from_connection(sqlite)
                .expect("initialize vault storage");

            let vault = Vault::load(DEFAULT_VAULT, &mut storage).expect("load vault");

            todo!()
        }
        Command::Withdraw(_amount) => {
            let config = read_config(&args.config);

            todo!()
        }
    }
}
