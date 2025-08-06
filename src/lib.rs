mod migrate;
pub mod vault;
pub mod bip119;

pub use vault::{
    AccountId,
    VaultAmount,
    VaultId,
    VaultKeyDerivationPathTemplate,
    VaultParameters,
    VaultScale,
    Vault,
    VaultDepositor,
};

#[cfg(test)]
pub mod test_util;
