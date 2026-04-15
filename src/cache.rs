use bitcoin::{
    TxOut,
};

use bitcoin::secp256k1::{
    Secp256k1,
    Verification,
};

use std::borrow::{Borrow, Cow};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::ops::Deref;
use std::rc::Rc;

use crate::vault::{Depth, GetVaultTemplateError, VaultAmount, VaultGeneration, VaultParameters, VaultStateParameters, VaultTemplates,};
use crate::transaction::{
    DepositTransactionTemplate,
    VaultTransactionTemplate,
};

pub(crate) struct VaultTemplateCache {
    parameters: VaultParameters,
    cache: RefCell<BTreeMap<Depth, CachedVaultGeneration>>,
}

impl VaultTemplateCache {
    pub fn new(parameters: VaultParameters) -> Self {
        Self {
            parameters,
            cache: RefCell::new(BTreeMap::new()),
        }
    }
}

#[derive(Clone)]
pub(crate) struct CachedVaultGeneration(Rc<VaultGeneration>);

impl Deref for CachedVaultGeneration {
    type Target = VaultGeneration;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl Borrow<VaultGeneration> for CachedVaultGeneration {
    fn borrow(&self) -> &VaultGeneration {
        self.0.as_ref()
    }
}

impl AsRef<VaultGeneration> for CachedVaultGeneration {
    fn as_ref(&self) -> &VaultGeneration {
        self.0.as_ref()
    }
}

impl CachedVaultGeneration {
    fn new(generation: VaultGeneration) -> Self {
        Self(Rc::new(generation))
    }
}

impl VaultTemplates for VaultTemplateCache {
    type Templates = CachedVaultGeneration;

    fn get<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth, parameters: &VaultStateParameters) -> Result<VaultTransactionTemplate, GetVaultTemplateError> {
        let generation = self.get_generation(secp, depth)
            .ok_or(GetVaultTemplateError::InvalidVaultDepth)?;

        generation.get(parameters).cloned().ok_or(GetVaultTemplateError::InvalidParameters)
    }

    fn get_generation<C: Verification>(&self, secp: &Secp256k1<C>, depth: Depth) -> Option<Self::Templates> {
        if depth > self.parameters.max_depth {
            return None;
        }

        let new_templates = {
            let cache = self.cache.borrow();
            let (cached_depth, templates) = if let Some((cached_depth, templates)) = cache.range(depth..).next() {
                (*cached_depth, Cow::Borrowed(templates))
            } else {
                (
                    self.parameters.max_depth,
                    Cow::Owned(
                        CachedVaultGeneration::new(
                            self.parameters.tx_templates(secp, self.parameters.max_depth, None)
                        )
                    )
                )
            };

            if cached_depth == depth {
                match templates {
                    Cow::Borrowed(templates) => return Some(templates.clone()),
                    Cow::Owned(templates) => templates,
                }
            } else {
                let mut current_depth = cached_depth;
                let mut current_templates = templates;

                while current_depth != depth {
                    current_depth -= 1;

                    assert!(current_depth >= depth);

                    current_templates = match current_templates {
                        Cow::Borrowed(templates) => Cow::Owned(
                            CachedVaultGeneration::new(
                                self.parameters.tx_templates(secp, current_depth, Some(templates.deref()))
                            )
                        ),
                        Cow::Owned(templates) => Cow::Owned(
                            CachedVaultGeneration::new(
                                self.parameters.tx_templates(secp, current_depth, Some(&templates))
                            )
                        ),
                    };
                }

                current_templates.into_owned()
            }
        };

        self.cache.borrow_mut().insert(depth, new_templates);

        self.cache.borrow().get(&depth).cloned()
    }
}

pub(crate) struct AddTransactionStateCache {
    first_generation_spks: HashMap<TxOut, VaultAmount>,
}

impl AddTransactionStateCache {
    pub(crate) fn get_initial_deposit_amount(&self, output: &TxOut) -> Option<VaultAmount> {
        self.first_generation_spks.get(output).cloned()
    }

    pub(crate) fn new<C: Verification, T: VaultTemplates>(secp: &Secp256k1<C>, templates: &T) -> Self {
        let first_generation = templates.get_generation(secp, 0)
            .expect("First generation must exist");

        let first_generation_spks: HashMap<_, _> = first_generation
            .iter()
            .filter_map(|(parameters, template)| {
                match template {
                    VaultTransactionTemplate::Deposit(DepositTransactionTemplate::InitialDeposit(deposit)) => Some(
                        (
                            deposit.vault_output().clone(),
                            parameters.result_value(),
                        )
                    ),
                    _ => { panic!("Invalid first generation"); }
                }
            })
            .collect();

        Self { first_generation_spks }
    }
}
