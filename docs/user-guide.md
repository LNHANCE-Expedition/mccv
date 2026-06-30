# User Guide

> [!WARNING]
> This is experimental software!
> More importantly, it relies on the BIP-119 soft fork which is not active on mainnet!
> Attempting to use this on mainnet *will result in a loss of funds*!

This proof of concept builds a CLI tool which provides a usable wallet for users.

The wallet is divided into two parts: the hot wallet, and the vault.

The hot wallet is a normal BDK wallet, and can be used for sending and receiving funds.
When the user's hot wallet balance exceeds a certain amount, they may desire to increase the security of those funds.
They can then move those funds, in fixed sized chunks, into the vault.
Vaulted funds may not be spent immediately; they are first withdrawn and subject to a timelock, during the timelock period they can be swept to a recovery address if the withdrawal was unauthorized.

# Overview

This vault is designed around keeping a warmer operational wallet and a colder recovery key that can be kept highly secure.
The canonical form of this system consists of a hot wallet, a vault, and a deep cold recovery key.
The deep cold recovery key may be difficult to access, but it is offline and very secure.
In theory it could even be a MuSig2 composite key for additional security.
Coins in the vault are protected from unauthorized withdrawal by a relative timelock preventing an attacker from spending them immediately.
During the timelock period you (or in theory a delegated agent) can sweep the withdrawn funds into a deep cold recovery location.
Your improved security comes from your ability to detect unauthorized withdrawals on-chain before the attacker is able to spend them, and to sweep them to the recovery location.


# Getting Started

I invite you to experiment with the MCCV vault and report issues and user experience weaknesses.
I'm particularly interested in your level of tolerance for the vault precomputation work, which can take minutes for some parameters.
Once you've made your first deposit into the vault, MCCV can (but does not yet) cache some of the precomputation on disk safely and drastically speed this up.
Obviously, some kind of progress bar would go a long way to improving the UX there, but for now I am interested in gauging user tolerance for vault generation times.

## Build and Install MCCV

Building `mccv` requires a reasonably recent rust toolchain.

The first step to trying out the vault is to clone this repository and build it.

```
git clone https://github.com/LNHANCE-Expedition/mccv.git
cd mccv
cargo install --path . --features bitcoind
```

This will install the `mccv` command line tool.

## Build and Configure Bitcoin Inquisition

You will need a `bitcoind` that will relay transactions using `OP_CHECKTEMPLATEVERIFY` and supports 1P1C packages with ephemeral anchors (via TRUC).
I recommend just getting [Bitcoin Inquisition](https://github.com/bitcoin-inquisition/bitcoin) v29.
You should refer to the build documentation for your platform for dependencies and specific build instructions, but if you have the build dependencies installed, the process should be roughly like this:

```
git clone -b v29.2-inq https://github.com/bitcoin-inquisition/bitcoin.git bitcoin-inquisition-v29.2
mkdir bitcoin-inquisition-v29.2/build
cd bitcoin-inquisition-v29.2/build
cmake ..
cmake --build .
```

You will need an appropriate `bitcoin.conf` configured to allow `mccv` to interact with it over RPC or invoke `bitcoind` with the appropriate equivalent command line arguments.
This guide is written with a fairly technical user in mind, but over time I'd like to simplify it.
Here are the important settings to have set under the `[signet]` heading.

```
[signet]
server=1
rpcuser=test
rpcpassword=test
addnode=inquisition.bitcoin-signet.net
```

Note that you should use a different username and password than `test`, or even better, use cookie based authentication.
For simplicity, I'm just using `rpcuser` and `rpcpassword` for these examples since these are signet coins and it sidesteps other issues around accessing the cookie file.
Note also the `addnode` line, this is necessary to ensure transactions using CTV are mined, as not all of the signet network will relay them.

Once you have your configuration, you need to start your bitcoin node.

## Using MCCV

MCCV v0.1.0 doesn't yet support multi-vault setups, so it stores its data and configuration files in the current directory by default.
The two relevant files are `mccv-vault.sqlite` which contains vault specific data as well as secret descriptors for the BDK wallet, and `mccv-wallet.sqlite` which contains the BDK-based hot wallet data.
Running `mccv generate [args]` will generate these files.
Note that most vault operations require recalculating large parts of the vault, so most operations will take a while to complete.

### Generating your vault

In a directory of your choosing, run the following command

```
mccv generate \
    --vault-name test \
    --scale 10000sat \
    --max 10 \
    --delay 3 \
    --max-deposit 4 \
    --max-withdrawal 3 \
    --max-depth 10 \
    --rpc-username test \
    --rpc-password test \
    --rpc-url 'http://127.0.0.1:38332'
```

This generates a test vault, named "test" that processes deposits and withdrawals in chunks of 10,000 sats with a maximum deposit size of 40,000 sats, and a maximum withdrawal size of 30,000 sats.
Withdrawing 10,000 sats incurs a delay of 3 blocks, 20,000 sats incurs a delay of 6 blocks, and 30,000 sats incurs a delay of 9 blocks.
This vault permits up to 10 deposits and withdrawals before control reverts permanently to the cold recovery key.
The `--rpc-*` options define how to connect to `bitcoind`.
They will be persisted into the vault database in plain text and used for future `mccv` unless overridden on the command line.
The persisted configuration can be changed later using `mccv configure-rpc ...`.
For a detailed explanation of these parameters and how they affect security and performance, see the "`generate` Subcommand Arguments" section below.

#### Backup and Restore

Backing up `mccv-vault.sqlite`, `mccv-wallet.sqlite` and the master xpriv is sufficient to completely restore the vault.
The master xpriv was displayed on stdout during `mccv generate`.
Record this and store it carefully.
`mccv-wallet.sqlite` can be completely regenerated from information stored in `mccv-vault.sqlite` but this is not implemented at present.

### Receiving funds

Once a vault has been generated, it can receive funds.
Funds are received into the hot wallet, not the vault, so they do not have the full protection of the vault.

To create a receiving address, issue the command

```
mccv receive
```

The received balance can be checked with the command

```
mccv balance
```

An example balance after receiving a small amount of sBTC looks like this:

```
                vaulted: 0              BTC
+ available immediately: 0.00089104     BTC
-------------------------------------------
                  total: 0.00089104     BTC
```

Since vaulted funds are not available immediately, they are listed separately.
In this example, no funds have been vaulted *yet*.

### Vaulting funds

Once the hot wallet contains more than a vault increment, funds can (and probably should) be moved into the vault.

```
mccv deposit 10000sat
```

Now `mccv balance` should display an output like this:

```
                vaulted: 0.0001         BTC
+ available immediately: 0.00078838     BTC
-------------------------------------------
                  total: 0.00088838     BTC
```

Observe that 10,000 sats were moved into the vault, and the total is unchanged (minus 266 sats of on-chain fees).

### Withdrawing funds

Withdrawing funds into the hot wallet is presently a two step process.
The first step is to initiate the withdrawal using a command like the following:

```
mccv withdraw 10000sat
```

After the withdrawal has been included in a block, and the vault is synced, the balance should be updated accordingly.

```
                vaulted: 0              BTC
+               @304384: 0.0001         BTC ( in 1 blocks )
+ available immediately: 0.00078519     BTC
-------------------------------------------
                  total: 0.00088519     BTC
```

This indicates that the vault is empty, and the withdrawn amount has not yet matured.
It will mature at the height 304384, which is 1 block from when this balance was displayed.

After the withdrawal has matured, and is eligible to be moved by hot keys, the vault will show something like this:

```
                vaulted: 0              BTC
+               @304384: 0.0001         BTC ( in -8 blocks )
(This withdrawal is mature but has not been swept yet)
+ available immediately: 0.00078519     BTC
-------------------------------------------
                  total: 0.00088519     BTC
```

This indicates that the withdrawal matured 8 blocks ago and it can be moved to the hot wallet at any time.

> [!NOTE]
> Note that this is only a limitation of the current implementation.
> Without any changes to the protocol, in the future, mature withdrawal UTXOs will be directly spendable.
> When this is implemented, it no longer makes sense to list mature withdrawals separately from the "immediately available" balance, so they'll be merged.

At any point until it is spent, the withdrawal and the entire vault can be swept via the recovery path to a cold wallet.

The command to sweep to recovery is

```
mccv recover
```

This will sweep an open withdrawal UTXO as well as the vault UTXO to the recovery address.

To spend these funds instead, they must first be moved into the hot wallet (see note above; this is a transient UX wart)

```
mccv sweep-to-hot
```

After the sweep completes, the funds will be available in the hot wallet.

```
                vaulted: 0              BTC
+ available immediately: 0.00088382     BTC
-------------------------------------------
                  total: 0.00088382     BTC
```

At this point the funds can be spent from the hot wallet.

```
mccv send tb1p0dvncdux9r4wqdetetng0xe830r6wum06legmk29ek5l43497epse2u5vz 10000sat
```

### Monitoring the blockchain for unauthorized withdrawals

MCCV can be run to periodically poll a bitcoind instance for blockchain updates, and respond to vault withdrawals detected on-chain.

```
mccv watchtower --approval-timeout 300 --approval-executable ../examples/approve-prompt.sh
```

The watchtower subcommand takes a path to the approval executable.
The approval executable must return a status code of 0 before the timeout to approve the withdrawal.
The approval executable should return a non-zero status code immediately if the withdrawal should be rejected.
If the timeout elapses without the approval executable completing with a zero status code, it is considered to have rejected the withdrawal, and the watchtower will initiate a sweep to cold keys.
The configurable timeout is specified in seconds.

# MCCV Command Reference

| Subcommand | Purpose |
|------------|---------|
| generate | Generate a new vault |
| list | List available vaults |
| balance | List balance(s) for a given vault |
| receive | Get a new address to receive to the hot wallet |
| send | Send coins from the hot wallet |
| sync | Synchronize with the blockchain |
| deposit | Deposit from the hot wallet into the vault |
| withdraw | Initiate a timelock-delayed withdrawal from the vault to the hot wallet |
| sweep-to-hot | Sweep mature withdrawals into the hot wallet (finalize a withdrawal) |
| recover | Recover a withdrawal to the cold key (cancel a withdrawal) |

## `generate` Subcommand Arguments

Example command:

```
mccv generate \
    --vault-name test \
    --scale 10000sat \
    --max 10 \
    --delay 3 \
    --max-deposit 4 \
    --max-withdrawal 3 \
    --max-depth 10 \
    --rpc-username test \
    --rpc-password test \
    --rpc-url 'http://127.0.0.1:38332'
```

The command line options are as follows

* `--vault-name` - string name for this vault
* `--scale` - The increments that the vault operates on. In the above example, your vault accepts deposits and withdrawals in increments of 10,000 sats.
* `--max` - The maximum deposit value the vault can contain, expressed as an integer number of `--scale` increments. The total value in Satoshis is `scale * max`, in this example, the maximum capacity of this vault is 100,000 sats.
* `--delay` - The number of blocks it takes a withdrawal to mature.
  During this period, the withdrawal and the entire vault may be recovered to a deep cold key.
  This window is the most important aspect of your security, it gives you (or a trusted agent) a window to recover funds withdrawn without your permission.
  In this example withdrawing 10,000 sats would be delayed by 3 blocks, and delaying 20,000 sats would be delayed by 6 blocks.
  This value should be chosen to satisfy your risk tolerance for the amount of money represented by a single increment.
  For instance, the value of 3 blocks, with a scale of 10,000 sats means the vault can be drained at ~20,000 sats/hour by you or an attacker.
  For larger scales the delay should be increased.
* `--max-deposit` - The maximum amount that may be deposited at once in the vault.
The value of 4 means that you can deposit 40,000 sats at a time.
There is no delay associated with deposits, so the maximum deposit is more of an on-chain efficiency control than anything, because you can create an arbitrary number of deposits without delay.
* `--max-withdrawal` - The maximum that may be withdrawn in a single withdrawal.
The value of 3 means that you can withdraw a maximum of 30,000 sats at a time.
Unlike deposits, you will have to wait 9 blocks (3 * delay) before withdrawing another 30,000 sats.
This velocity control mechanism is one of the key safeguards for your vaulted bitcoin, but setting a higher `--max-withdrawal` will likely be desirable to avoid having to make many transactions over hours or days to withdraw the desired amount.
This should be set to the largest value you expect to want at once.
Note that `--max-withdrawal` and `--max-deposit` are two of the most powerful knobs in tuning performance.
Doubling `max-deposit + max-withdrawal` doubles the time it takes to generate your vault (every time you use it!).
Persistent caching will greatly help here but it's not yet implemented.
* `--max-depth` - This is the maximum number of vault operations (deposit or withdraw) you can perform.
After the operations are exhausted, the vault will only be spendable by the cold key.
* `--rpc-username` - Use this username to connect to `bitcoind`.
* `--rpc-password` - Use this password to connect to `bitcoind`.
  Note that this will be persisted in plain text in the `mccv-vault.sqlite`.
  All of the stored RPC configuration can be updated later using `mccv configure-rpc ...`.
  Using `--rpc-cookie` is generally preferable, and can be used instead of username and password, avoiding storing a password in the vault database.
* `--rpc-url` - Connect to `bitcoind` at this URL.
* `--rpc-cookie` - Use cookie-based authentication with `bitcoind` instead of username and password.
  This avoids storing an RPC password in the vault database and is generally the preferred authentication method.
  See `bitcoind` configuration for using cookie authentication.

# Known Issues

These are warts that should be removed but weren't deemed blockers to demonstrating the core concepts of this vault.

## Withdrawal Requires an Extra Sweep Step
As stated above, the CLI currently makes vault spends a three-step process: withdrawal, sweep, spend, instead of a 2 step process: withdraw, spend.
This is wasteful on-chain and bad UX.
The protocol already supports the two step process, but the code that spends the withdrawal UTXOs needs to be more flexible.

## Unconfirmed Transactions are Forgotten

Right now the CLI will generate transactions and submit packages to `bitcoind` but it won't make any attempts to rebroadcast, or fee bump.
As an incredibly crude workaround, the raw serialized transaction hex is provided on stdout for you to save and use to rebroadcast later if needed or desired.
