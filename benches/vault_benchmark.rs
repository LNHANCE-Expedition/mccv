use std::str::FromStr;
use bdk_electrum::{
    electrum_client::ElectrumApi,
};

use bdk_wallet::KeychainKind;
use bdk_wallet::Wallet;

use bitcoin::bip32::{
    Xpub,
    Xpriv,
    ChildNumber,
};

use std::time::Instant;

use bitcoin::secp256k1::{
    Secp256k1,
};

use criterion::{
    black_box,
    Bencher,
    criterion_group,
    criterion_main,
    Criterion
};

use mccv::vault::{
    VaultAmount,
    VaultParameters,
};

fn test_xpubs() -> (Xpub, Xpub, Xpub) {
    (
        Xpub::from_str("tpubDCjgmQsPz1xamjuPHqwFkdU2DfHe9oz4VSgzJD1JDWZWM1pYyk82WMN7zyQRN85F5Yx8Rs2xeGC4eZ5un27LqPu74BDQZcWkqkhnVmbWmMB").unwrap(), // Master Xpub
        Xpub::from_str("tpubDCjgmQsPz1xarEYG4eya8HegHuun3QU5VAJKo8oPwVgMoQb961aP7nv5J9PH9jjj74MzPp1U5YzzjdZF3gFANtMNuMKyrSYKmJt7jQMonM1").unwrap(), // Recovery Xpub
        Xpub::from_str("tpubDCjgmQsPz1xatYi9cSP3ov2CWMFcnh5FNzTtLykxpHYZXaGuYMRCgpThcmXFAHBKrR6Za69v7CcMqvEfT7wrQtWxZr4EW58NusmAGhUtj2F").unwrap(), // Withdrawal Xpub
    )
}

pub fn benchmark_state_generation(c: &mut Criterion) {
    let secp = Secp256k1::new();

    let (master_xpub, recovery_xpub, withdrawal_xpub) = test_xpubs();

    let test_parameters = VaultParameters::new(
        100_000_000,
        VaultAmount::new(16),
        master_xpub,
        recovery_xpub,
        withdrawal_xpub,
        36,
        VaultAmount::new(4),
        VaultAmount::new(4),
        4,
    );

    let mut group = c.benchmark_group("templates");

    group.sample_size(10);

    group.bench_function("iterate templates", |b| b.iter(|| {
        let mut iter = test_parameters.iter_templates(&secp);

        while let Some(state) = iter.next() {
            black_box(state);
        }
    }));
}

criterion_group!(benches, benchmark_state_generation);
criterion_main!(benches);
