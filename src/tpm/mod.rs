// Adapted from https://github.com/fedora-iot/clevis-pin-tpm2/
// by Patrick Uiterwijk under the MIT License

use std::convert::{TryFrom, TryInto};

use color_eyre::{
    eyre::{bail, Context, ContextCompat, Error},
    Result,
};
use josekit::jwe::{alg::direct::DirectJweAlgorithm::Dir, enc::A256GCM};
use serde::{Deserialize, Serialize};
use tpm2_policy::TPMPolicyStep;
use tpm_objects::TPM2Config;
use tss_esapi::structures::SensitiveData;

pub mod tpm_objects;
pub mod utils;

pub fn perform_encrypt(cfg: TPM2Config, input: &[u8]) -> Result<String> {
    let key_type = match &cfg.key {
        None => "ecc",
        Some(key_type) => key_type,
    };
    let key_public = tpm_objects::get_key_public(key_type, cfg.get_name_hash_alg())?;

    let mut ctx = utils::get_tpm2_ctx()?;
    let key_handle = utils::get_tpm2_primary_key(&mut ctx, key_public)?;

    let policy_runner: TPMPolicyStep = TPMPolicyStep::try_from(&cfg)?;

    let pin_type = match policy_runner {
        TPMPolicyStep::NoStep => "tpm2",
        TPMPolicyStep::PCRs(_, _, _) => "tpm2",
        _ => "tpm2plus",
    };

    let (_, policy_digest) = policy_runner.send_policy(&mut ctx, true)?;

    let mut jwk = josekit::jwk::Jwk::generate_oct_key(32).context("Error generating random JWK")?;
    jwk.set_key_operations(vec!["encrypt", "decrypt"]);
    let jwk_str = serde_json::to_string(&jwk.as_ref())?;

    let public = tpm_objects::create_tpm2b_public_sealed_object(policy_digest)?.try_into()?;
    let jwk_str = SensitiveData::try_from(jwk_str.as_bytes().to_vec())?;
    let jwk_result = ctx.execute_with_nullauth_session(|ctx| {
        ctx.create(key_handle, public, None, Some(jwk_str), None, None)
    })?;

    let jwk_priv = tpm_objects::get_tpm2b_private(jwk_result.out_private.into())?;

    let jwk_pub = tpm_objects::get_tpm2b_public(jwk_result.out_public.try_into()?)?;

    let private_hdr = ClevisInner {
        pin: pin_type.to_string(),
        tpm2: Tpm2Inner {
            hash: cfg.hash.as_ref().unwrap_or(&"sha256".to_string()).clone(),
            key: key_type.to_string(),
            jwk_pub,
            jwk_priv,
            pcr_bank: cfg.pcr_bank.clone(),
            pcr_ids: cfg.get_pcr_ids_str(),
            policy_pubkey_path: cfg.policy_pubkey_path,
            policy_ref: cfg.policy_ref,
            policy_path: cfg.policy_path,
        },
    };

    let mut hdr = josekit::jwe::JweHeader::new();
    hdr.set_algorithm(Dir.name());
    hdr.set_content_encryption(A256GCM.name());
    hdr.set_claim(
        "clevis",
        Some(serde_json::value::to_value(private_hdr).context("Error serializing private header")?),
    )
    .context("Error adding clevis claim")?;

    let encrypter = Dir
        .encrypter_from_jwk(&jwk)
        .context("Error creating direct encrypter")?;
    let jwe_token = josekit::jwe::serialize_compact(input, &hdr, &encrypter)
        .context("Error serializing JWE token")?;

    Ok(jwe_token)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Tpm2Inner {
    hash: String,
    #[serde(
        deserialize_with = "utils::deserialize_as_base64_url_no_pad",
        serialize_with = "utils::serialize_as_base64_url_no_pad"
    )]
    jwk_priv: Vec<u8>,
    #[serde(
        deserialize_with = "utils::deserialize_as_base64_url_no_pad",
        serialize_with = "utils::serialize_as_base64_url_no_pad"
    )]
    jwk_pub: Vec<u8>,
    key: String,

    // PCR Binding may be specified, may not
    #[serde(skip_serializing_if = "Option::is_none")]
    pcr_bank: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcr_ids: Option<String>,

    // Public key (in PEM format) for a wildcard policy that's OR'd with the PCR one
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_pubkey_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_path: Option<String>,
}

impl Tpm2Inner {
    fn get_pcr_ids(&self) -> Option<Vec<u64>> {
        Some(
            self.pcr_ids
                .as_ref()?
                .split(',')
                .map(|x| x.parse::<u64>().unwrap())
                .collect(),
        )
    }
}

impl TryFrom<&Tpm2Inner> for TPMPolicyStep {
    type Error = Error;

    fn try_from(cfg: &Tpm2Inner) -> Result<Self> {
        if cfg.pcr_ids.is_some() && cfg.policy_pubkey_path.is_some() {
            Ok(TPMPolicyStep::Or([
                Box::new(TPMPolicyStep::PCRs(
                    utils::get_hash_alg_from_name(cfg.pcr_bank.as_ref()),
                    cfg.get_pcr_ids().unwrap(),
                    Box::new(TPMPolicyStep::NoStep),
                )),
                Box::new(utils::get_authorized_policy_step(
                    cfg.policy_pubkey_path.as_ref().unwrap(),
                    &cfg.policy_path,
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
                utils::get_hash_alg_from_name(cfg.pcr_bank.as_ref()),
                cfg.get_pcr_ids().unwrap(),
                Box::new(TPMPolicyStep::NoStep),
            ))
        } else if cfg.policy_pubkey_path.is_some() {
            utils::get_authorized_policy_step(
                cfg.policy_pubkey_path.as_ref().unwrap(),
                &cfg.policy_path,
                &cfg.policy_ref,
            )
        } else {
            Ok(TPMPolicyStep::NoStep)
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ClevisInner {
    pin: String,
    tpm2: Tpm2Inner,
}

pub fn perform_decrypt(input: &[u8]) -> Result<Vec<u8>> {
    let input = String::from_utf8(input.to_vec()).context("Error reading input")?;
    let hdr = josekit::jwt::decode_header(&input).context("Error decoding header")?;
    let hdr_clevis = hdr.claim("clevis").context("Error getting clevis claim")?;
    let hdr_clevis: ClevisInner =
        serde_json::from_value(hdr_clevis.clone()).context("Error deserializing clevis header")?;

    if hdr_clevis.pin != "tpm2" && hdr_clevis.pin != "tpm2plus" {
        bail!("JWE pin mismatch");
    }

    let jwkpub = tpm_objects::build_tpm2b_public(&hdr_clevis.tpm2.jwk_pub)?.try_into()?;
    let jwkpriv = tpm_objects::build_tpm2b_private(&hdr_clevis.tpm2.jwk_priv)?;

    let policy = TPMPolicyStep::try_from(&hdr_clevis.tpm2)?;

    let name_alg = utils::get_hash_alg_from_name(Some(&hdr_clevis.tpm2.hash));
    let key_public = tpm_objects::get_key_public(hdr_clevis.tpm2.key.as_str(), name_alg)?;

    let mut ctx = utils::get_tpm2_ctx()?;
    let key_handle = utils::get_tpm2_primary_key(&mut ctx, key_public)?;

    let key =
        ctx.execute_with_nullauth_session(|ctx| ctx.load(key_handle, jwkpriv.try_into()?, jwkpub))?;

    let (policy_session, _) = policy.send_policy(&mut ctx, false)?;

    let unsealed = ctx.execute_with_session(policy_session, |ctx| ctx.unseal(key.into()))?;
    let unsealed = &unsealed.value();
    let mut jwk = josekit::jwk::Jwk::from_bytes(unsealed).context("Error unmarshaling JWK")?;
    jwk.set_parameter("alg", None)
        .context("Error removing the alg parameter")?;
    let decrypter = Dir
        .decrypter_from_jwk(&jwk)
        .context("Error creating decrypter")?;

    let (payload, _) =
        josekit::jwe::deserialize_compact(&input, &decrypter).context("Error decrypting JWE")?;

    Ok(payload)
}
