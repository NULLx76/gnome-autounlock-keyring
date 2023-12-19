use color_eyre::eyre::{bail, eyre, Context, Error};
use std::convert::TryFrom;

use super::utils::get_authorized_policy_step;
use color_eyre::Result;
use serde::{Deserialize, Serialize};
use tpm2_policy::TPMPolicyStep;
use tss_esapi::{
    attributes::object::ObjectAttributesBuilder,
    constants::tss as tss_constants,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
    },
    structures::{Digest, Public, SymmetricDefinitionObject},
};

#[derive(Serialize, Deserialize, Default, std::fmt::Debug)]
pub struct TPM2Config {
    pub hash: Option<String>,
    pub key: Option<String>,
    pub pcr_bank: Option<String>,
    // PCR IDs can be passed in as comma-separated string or json array
    pub pcr_ids: Option<serde_json::Value>,
    pub pcr_digest: Option<String>,
    // Whether to use a policy. If this is specified without pubkey path or policy path, they get set to defaults
    pub use_policy: Option<bool>,
    // Public key (in JSON format) for a wildcard policy that's possibly OR'd with the PCR one
    pub policy_pubkey_path: Option<String>,
    pub policy_ref: Option<String>,
    pub policy_path: Option<String>,
}

impl TryFrom<&TPM2Config> for TPMPolicyStep {
    type Error = Error;

    fn try_from(cfg: &TPM2Config) -> Result<Self> {
        if cfg.pcr_ids.is_some() && cfg.policy_pubkey_path.is_some() {
            Ok(TPMPolicyStep::Or([
                Box::new(TPMPolicyStep::PCRs(
                    cfg.get_pcr_hash_alg(),
                    cfg.get_pcr_ids().unwrap(),
                    Box::new(TPMPolicyStep::NoStep),
                )),
                Box::new(get_authorized_policy_step(
                    cfg.policy_pubkey_path.as_ref().unwrap(),
                    &None,
                    &cfg.policy_ref,
                )?),
                Box::new(TPMPolicyStep::NoStep),
                Box::new(TPMPolicyStep::NoStep),
                Box::new(TPMPolicyStep::NoStep),
                Box::new(TPMPolicyStep::NoStep),
                Box::new(TPMPolicyStep::NoStep),
                Box::new(TPMPolicyStep::NoStep),
            ]))
        } else if cfg.pcr_ids.is_some() {
            Ok(TPMPolicyStep::PCRs(
                cfg.get_pcr_hash_alg(),
                cfg.get_pcr_ids().unwrap(),
                Box::new(TPMPolicyStep::NoStep),
            ))
        } else if cfg.policy_pubkey_path.is_some() {
            get_authorized_policy_step(
                cfg.policy_pubkey_path.as_ref().unwrap(),
                &None,
                &cfg.policy_ref,
            )
        } else {
            Ok(TPMPolicyStep::NoStep)
        }
    }
}

const DEFAULT_POLICY_PATH: &str = "/boot/clevis_policy.json";
const DEFAULT_PUBKEY_PATH: &str = "/boot/clevis_pubkey.json";
const DEFAULT_POLICY_REF: &str = "";

impl TPM2Config {
    pub(super) fn get_pcr_hash_alg(
        &self,
    ) -> tss_esapi::interface_types::algorithm::HashingAlgorithm {
        super::utils::get_hash_alg_from_name(self.pcr_bank.as_ref())
    }

    pub(super) fn get_name_hash_alg(
        &self,
    ) -> tss_esapi::interface_types::algorithm::HashingAlgorithm {
        super::utils::get_hash_alg_from_name(self.hash.as_ref())
    }

    pub(super) fn get_pcr_ids(&self) -> Option<Vec<u64>> {
        match &self.pcr_ids {
            None => None,
            Some(serde_json::Value::Array(vals)) => {
                Some(vals.iter().map(|x| x.as_u64().unwrap()).collect())
            }
            _ => panic!("Unexpected type found for pcr_ids"),
        }
    }

    pub(super) fn get_pcr_ids_str(&self) -> Option<String> {
        match &self.pcr_ids {
            None => None,
            Some(serde_json::Value::Array(vals)) => Some(
                vals.iter()
                    .map(|x| x.as_u64().unwrap().to_string())
                    .collect::<Vec<String>>()
                    .join(","),
            ),
            _ => panic!("Unexpected type found for pcr_ids"),
        }
    }

    pub fn normalize(mut self) -> Result<TPM2Config> {
        self.normalize_pcr_ids()?;
        if self.pcr_ids.is_some() && self.pcr_bank.is_none() {
            self.pcr_bank = Some("sha256".to_string());
        }
        // Make use of the defaults if not specified
        if self.use_policy.is_some() && self.use_policy.unwrap() {
            if self.policy_path.is_none() {
                self.policy_path = Some(DEFAULT_POLICY_PATH.to_string());
            }
            if self.policy_pubkey_path.is_none() {
                self.policy_pubkey_path = Some(DEFAULT_PUBKEY_PATH.to_string());
            }
            if self.policy_ref.is_none() {
                self.policy_ref = Some(DEFAULT_POLICY_REF.to_string());
            }
        } else if self.policy_pubkey_path.is_some()
            || self.policy_path.is_some()
            || self.policy_ref.is_some()
        {
            eprintln!("To use a policy, please specifiy use_policy: true. Not specifying this will be a fatal error in a next release");
        }
        if (self.policy_pubkey_path.is_some()
            || self.policy_path.is_some()
            || self.policy_ref.is_some())
            && (self.policy_pubkey_path.is_none()
                || self.policy_path.is_none()
                || self.policy_ref.is_none())
        {
            bail!("Not all of policy pubkey, path and ref are specified",);
        }
        Ok(self)
    }

    fn normalize_pcr_ids(&mut self) -> Result<()> {
        // Normalize from array with one string to just string
        if let Some(serde_json::Value::Array(vals)) = &self.pcr_ids {
            if vals.len() == 1 {
                if let serde_json::Value::String(val) = &vals[0] {
                    self.pcr_ids = Some(serde_json::Value::String(val.to_string()));
                }
            }
        }
        // Normalize pcr_ids from comma-separated string to array
        if let Some(serde_json::Value::String(val)) = &self.pcr_ids {
            // Was a string, do a split
            let newval: Vec<serde_json::Value> = val
                .split(',')
                .map(|x| serde_json::Value::String(x.trim().to_string()))
                .collect();
            self.pcr_ids = Some(serde_json::Value::Array(newval));
        }
        // Normalize pcr_ids from array of Strings to array of Numbers
        if let Some(serde_json::Value::Array(vals)) = &self.pcr_ids {
            let newvals: Result<Vec<serde_json::Value>, _> = vals
                .iter()
                .map(|x| match x {
                    serde_json::Value::String(val) => {
                        match val.trim().parse::<serde_json::Number>() {
                            Ok(res) => {
                                let new = serde_json::Value::Number(res);
                                if !new.is_u64() {
                                    bail!("Non-positive string int");
                                }
                                Ok(new)
                            }
                            Err(_) => Err(eyre!("Unparseable string int")),
                        }
                    }
                    serde_json::Value::Number(n) => {
                        let new = serde_json::Value::Number(n.clone());
                        if !new.is_u64() {
                            return Err(eyre!("Non-positive int"));
                        }
                        Ok(new)
                    }
                    _ => Err(eyre!("Invalid value in pcr_ids")),
                })
                .collect();
            self.pcr_ids = Some(serde_json::Value::Array(newvals?));
        }

        match &self.pcr_ids {
            None => Ok(()),
            // The normalization above would've caught any non-ints
            Some(serde_json::Value::Array(_)) => Ok(()),
            _ => Err(eyre!("Invalid type")),
        }
    }
}

#[cfg(target_pointer_width = "64")]
type Sizedu = u64;
#[cfg(target_pointer_width = "32")]
type Sizedu = u32;

pub(super) fn get_key_public(
    key_type: &str,
    name_alg: HashingAlgorithm,
) -> color_eyre::Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .with_restricted(true)
        .build()?;

    let builder = tss_esapi::structures::PublicBuilder::new()
        .with_object_attributes(object_attributes)
        .with_name_hashing_algorithm(name_alg);

    match key_type {
        "ecc" => builder
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_ecc_parameters(
                tss_esapi::structures::PublicEccParametersBuilder::new_restricted_decryption_key(
                    SymmetricDefinitionObject::AES_128_CFB,
                    EccCurve::NistP256,
                )
                .build()?,
            )
            .with_ecc_unique_identifier(Default::default()),
        "rsa" => builder
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_rsa_parameters(
                tss_esapi::structures::PublicRsaParametersBuilder::new_restricted_decryption_key(
                    SymmetricDefinitionObject::AES_128_CFB,
                    tss_esapi::interface_types::key_bits::RsaKeyBits::Rsa2048,
                    tss_esapi::structures::RsaExponent::ZERO_EXPONENT,
                )
                .build()?,
            )
            .with_rsa_unique_identifier(Default::default()),
        _ => return Err(eyre!("Unsupported key type used")),
    }
    .build()
    .context("Error building public key")
}

pub(super) fn create_tpm2b_public_sealed_object(
    policy: Option<Digest>,
) -> Result<tss_esapi::tss2_esys::TPM2B_PUBLIC> {
    let mut object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_no_da(true)
        .with_admin_with_policy(true);

    if policy.is_none() {
        object_attributes = object_attributes.with_user_with_auth(true);
    }
    let policy = match policy {
        Some(p) => p,
        None => Digest::try_from(vec![])?,
    };

    let mut params: tss_esapi::tss2_esys::TPMU_PUBLIC_PARMS = Default::default();
    params.keyedHashDetail.scheme.scheme = tss_constants::TPM2_ALG_NULL;

    Ok(tss_esapi::tss2_esys::TPM2B_PUBLIC {
        size: std::mem::size_of::<tss_esapi::tss2_esys::TPMT_PUBLIC>() as u16,
        publicArea: tss_esapi::tss2_esys::TPMT_PUBLIC {
            type_: tss_constants::TPM2_ALG_KEYEDHASH,
            nameAlg: tss_constants::TPM2_ALG_SHA256,
            objectAttributes: object_attributes.build()?.0,
            authPolicy: tss_esapi::tss2_esys::TPM2B_DIGEST::from(policy),
            parameters: params,
            unique: Default::default(),
        },
    })
}

pub(super) fn get_tpm2b_public(val: tss_esapi::tss2_esys::TPM2B_PUBLIC) -> Result<Vec<u8>> {
    let mut offset = 0 as Sizedu;
    let mut resp = Vec::with_capacity((val.size + 4) as usize);

    unsafe {
        let res = tss_esapi::tss2_esys::Tss2_MU_TPM2B_PUBLIC_Marshal(
            &val,
            resp.as_mut_ptr(),
            resp.capacity() as Sizedu,
            &mut offset,
        );
        if res != 0 {
            bail!("Marshalling tpm2b_public failed");
        }
        resp.set_len(offset as usize);
    }

    Ok(resp)
}

pub(super) fn get_tpm2b_private(val: tss_esapi::tss2_esys::TPM2B_PRIVATE) -> Result<Vec<u8>> {
    let mut offset = 0 as Sizedu;
    let mut resp = Vec::with_capacity((val.size + 4) as usize);

    unsafe {
        let res = tss_esapi::tss2_esys::Tss2_MU_TPM2B_PRIVATE_Marshal(
            &val,
            resp.as_mut_ptr(),
            resp.capacity() as Sizedu,
            &mut offset,
        );
        if res != 0 {
            bail!("Marshalling tpm2b_private failed");
        }
        resp.set_len(offset as usize);
    }

    Ok(resp)
}

pub(super) fn build_tpm2b_private(val: &[u8]) -> Result<tss_esapi::tss2_esys::TPM2B_PRIVATE> {
    let mut resp = tss_esapi::tss2_esys::TPM2B_PRIVATE::default();
    let mut offset = 0 as Sizedu;

    unsafe {
        let res = tss_esapi::tss2_esys::Tss2_MU_TPM2B_PRIVATE_Unmarshal(
            val[..].as_ptr(),
            val.len() as Sizedu,
            &mut offset,
            &mut resp,
        );
        if res != 0 {
            bail!("Unmarshalling tpm2b_private failed");
        }
    }

    Ok(resp)
}

pub(super) fn build_tpm2b_public(val: &[u8]) -> Result<tss_esapi::tss2_esys::TPM2B_PUBLIC> {
    let mut resp = tss_esapi::tss2_esys::TPM2B_PUBLIC::default();
    let mut offset = 0 as Sizedu;

    unsafe {
        let res = tss_esapi::tss2_esys::Tss2_MU_TPM2B_PUBLIC_Unmarshal(
            val[..].as_ptr(),
            val.len() as Sizedu,
            &mut offset,
            &mut resp,
        );
        if res != 0 {
            bail!("Unmarshalling tpm2b_public failed");
        }
    }

    Ok(resp)
}
