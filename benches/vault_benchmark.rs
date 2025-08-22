use std::str::FromStr;

use bitcoin::bip32::{
    Xpub,
    Xpriv,
};

use bitcoin::secp256k1::{
    Secp256k1,
};

use criterion::{
    black_box,
    criterion_group,
    criterion_main,
    Criterion
};

use mccv::vault::{
    AccountId,
    VaultAmount,
    VaultParameters,
    VaultScale,
};

pub fn benchmark_state_generation(c: &mut Criterion) {
    let secp = Secp256k1::new();

    let milk_sad_master = Xpriv::from_str("tprv8ZgxMBicQKsPd1EzCPZcQSPhsotX5HvRDCivA7ASNQFmjWuTsW3WWEwUNKFAZrnD9qpz55rtyLdphqkwRZUqNWYXwSEzd6P4pYvXGByRim3").unwrap();

    let account = AccountId::new(0)
        .expect("Valid account");

    let cold_xpriv = milk_sad_master
            .derive_priv(&secp, &account.to_cold_derivation_path())
            .expect("success");

    let hot_xpriv = milk_sad_master
            .derive_priv(&secp, &account.to_hot_derivation_path())
            .expect("success");

    let test_parameters = VaultParameters::new(
        VaultScale::from_sat(100_000_000),
        VaultAmount::new(16),
        Xpub::from_priv(&secp, &cold_xpriv),
        Xpub::from_priv(&secp, &hot_xpriv),
        36,
        VaultAmount::new(4),
        VaultAmount::new(4),
        4,
    );

    let mut group = c.benchmark_group("templates");

    group.sample_size(40);

    group.bench_function("iterate templates", |b| b.iter(|| {
        let mut iter = test_parameters.iter_templates(&secp);

        while let Some(state) = iter.next() {
            black_box(state);
        }
    }));
}

criterion_group!(benches, benchmark_state_generation);
criterion_main!(benches);
