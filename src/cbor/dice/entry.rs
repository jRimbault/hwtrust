use super::field_value::FieldValue;
use crate::bcc::entry::{ConfigDesc, ConfigDescBuilder, DiceMode, Payload, PayloadBuilder};
use crate::cbor::{cose_error, value_from_bytes};
use crate::publickey::PublicKey;
use anyhow::{anyhow, bail, ensure, Context, Result};
use ciborium::value::Value;
use coset::{Algorithm, AsCborValue, CborSerializable, CoseKey, CoseSign1, Header};
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::HashMap;

const ISS: i64 = 1;
const SUB: i64 = 2;
const CODE_HASH: i64 = -4670545;
const CODE_DESC: i64 = -4670546;
const CONFIG_HASH: i64 = -4670547;
const CONFIG_DESC: i64 = -4670548;
const AUTHORITY_HASH: i64 = -4670549;
const AUTHORITY_DESC: i64 = -4670550;
const MODE: i64 = -4670551;
const SUBJECT_PUBLIC_KEY: i64 = -4670552;
const KEY_USAGE: i64 = -4670553;

const COMPONENT_NAME: i64 = -70002;
const COMPONENT_VERSION: i64 = -70003;
const RESETTABLE: i64 = -70004;

pub(super) struct Entry {
    payload: Vec<u8>,
}

impl Entry {
    pub(super) fn verify_cbor_value(cbor: Value, key: &PublicKey) -> Result<Self> {
        let sign1 = CoseSign1::from_cbor_value(cbor)
            .map_err(cose_error)
            .context("Given CBOR does not appear to be a COSE_sign1")?;
        let algorithm = Algorithm::Assigned(key.iana_algorithm());
        check_protected_header(&algorithm, &sign1.protected.header)
            .context("Validation of bcc entry protected header failed.")?;
        sign1
            .verify_signature(b"", |s, m| key.verify(s, m))
            .context("public key cannot verify cose_sign1 cert")?;
        match sign1.payload {
            None => bail!("Missing payload"),
            Some(payload) => Ok(Self { payload }),
        }
    }

    pub(super) fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Validate the protected header of a bcc entry with respect to the provided
/// alg (typically originating from the subject public key of the payload).
fn check_protected_header(alg: &Algorithm, header: &Header) -> Result<()> {
    ensure!(
        header.alg.as_ref() == Some(alg),
        "Protected 'alg' header doesn't have the expected algorithm"
    );
    ensure!(header.crit.is_empty(), "No critical header values may be defined in the BCC");
    Ok(())
}

impl Payload {
    pub(super) fn from_cbor(bytes: &[u8]) -> Result<Self> {
        let f = PayloadFields::from_cbor(bytes)?;
        PayloadBuilder::with_subject_public_key(f.subject_public_key)
            .issuer(f.issuer)
            .subject(f.subject)
            .mode(f.mode.ok_or_else(|| anyhow!("mode required"))?)
            .code_desc(f.code_desc)
            .code_hash(f.code_hash.ok_or_else(|| anyhow!("code hash required"))?)
            .config_desc(f.config_desc.ok_or_else(|| anyhow!("config desc required"))?)
            .config_hash(f.config_hash)
            .authority_desc(f.authority_desc)
            .authority_hash(f.authority_hash.ok_or_else(|| anyhow!("authority hash required"))?)
            .build()
            .context("building payload")
    }
}

pub(super) struct PayloadFields {
    pub(super) issuer: String,
    pub(super) subject: String,
    pub(super) subject_public_key: PublicKey,
    mode: Option<DiceMode>,
    code_desc: Option<Vec<u8>>,
    code_hash: Option<Vec<u8>>,
    config_desc: Option<ConfigDesc>,
    config_hash: Option<Vec<u8>>,
    authority_desc: Option<Vec<u8>>,
    authority_hash: Option<Vec<u8>>,
}

impl PayloadFields {
    pub(super) fn from_cbor(bytes: &[u8]) -> Result<Self> {
        let mut issuer = FieldValue::new("issuer");
        let mut subject = FieldValue::new("subject");
        let mut subject_public_key = FieldValue::new("subject public key");
        let mut mode = FieldValue::new("mode");
        let mut code_desc = FieldValue::new("code desc");
        let mut code_hash = FieldValue::new("code hash");
        let mut config_desc = FieldValue::new("config desc");
        let mut config_hash = FieldValue::new("config hash");
        let mut authority_desc = FieldValue::new("authority desc");
        let mut authority_hash = FieldValue::new("authority hash");
        let mut key_usage = FieldValue::new("key usage");

        let entries = cbor_map_from_slice(bytes)?;
        for (key, value) in entries.into_iter() {
            if let Some(Ok(key)) = key.as_integer().map(TryInto::try_into) {
                let field = match key {
                    ISS => &mut issuer,
                    SUB => &mut subject,
                    SUBJECT_PUBLIC_KEY => &mut subject_public_key,
                    MODE => &mut mode,
                    CODE_DESC => &mut code_desc,
                    CODE_HASH => &mut code_hash,
                    CONFIG_DESC => &mut config_desc,
                    CONFIG_HASH => &mut config_hash,
                    AUTHORITY_DESC => &mut authority_desc,
                    AUTHORITY_HASH => &mut authority_hash,
                    KEY_USAGE => &mut key_usage,
                    _ => bail!("Unknown key {}", key),
                };
                field.set(value)?;
            } else {
                bail!("Invalid key: {:?}", key);
            }
        }

        validate_key_usage(key_usage)?;

        Ok(Self {
            issuer: issuer.into_string().context("issuer")?,
            subject: subject.into_string().context("subject")?,
            subject_public_key: validate_subject_public_key(subject_public_key)?,
            mode: validate_mode(mode).context("mode")?,
            code_desc: code_desc.into_optional_bytes().context("code descriptor")?,
            code_hash: code_hash.into_optional_bytes().context("code hash")?,
            config_desc: validate_config_desc(config_desc).context("config descriptor")?,
            config_hash: config_hash.into_optional_bytes().context("config hash")?,
            authority_desc: authority_desc.into_optional_bytes().context("authority descriptor")?,
            authority_hash: authority_hash.into_optional_bytes().context("authority hash")?,
        })
    }
}

fn validate_key_usage(key_usage: FieldValue) -> Result<()> {
    let key_usage = key_usage.into_bytes().context("key usage")?;
    if key_usage.len() != 1 || key_usage[0] != 0x20 {
        bail!("key usage must be keyCertSign");
    };
    Ok(())
}

fn validate_subject_public_key(subject_public_key: FieldValue) -> Result<PublicKey> {
    let subject_public_key = subject_public_key.into_bytes().context("Subject public")?;
    let subject_public_key = CoseKey::from_slice(&subject_public_key)
        .map_err(cose_error)
        .context("parsing subject public key from bytes")?;
    PublicKey::from_cose_key(&subject_public_key)
        .context("parsing subject public key from COSE_key")
}

fn validate_mode(mode: FieldValue) -> Result<Option<DiceMode>> {
    let mode = mode.into_optional_bytes()?;
    mode.map(|mode| {
        if mode.len() != 1 {
            bail!("Expected mode to be a single byte, actual byte count: {}", mode.len())
        };
        Ok(match mode[0] {
            1 => DiceMode::Normal,
            2 => DiceMode::Debug,
            3 => DiceMode::Recovery,
            _ => DiceMode::NotConfigured,
        })
    })
    .transpose()
}

fn validate_config_desc(config_desc: FieldValue) -> Result<Option<ConfigDesc>> {
    let config_desc = config_desc.into_optional_bytes()?;
    config_desc
        .map(|config_desc| {
            config_desc_from_slice(&config_desc).context("parsing config descriptor")
        })
        .transpose()
}

fn cbor_map_from_slice(bytes: &[u8]) -> Result<Vec<(Value, Value)>> {
    let value = value_from_bytes(bytes).context("Error parsing CBOR into a map")?;
    let entries = match value {
        Value::Map(entries) => entries,
        _ => bail!("Not a map: {:?}", value),
    };
    Ok(entries)
}

fn config_desc_from_slice(bytes: &[u8]) -> Result<ConfigDesc> {
    let entries = cbor_map_from_slice(bytes)?;

    let mut component_name = FieldValue::new("component name");
    let mut component_version = FieldValue::new("component version");
    let mut resettable = FieldValue::new("resettable");
    let mut extensions = HashMap::new();

    for (key, value) in entries.into_iter() {
        if let Some(Ok(key)) = key.as_integer().map(TryInto::try_into) {
            match key {
                COMPONENT_NAME => {
                    component_name.set(value).context("Error setting component name")?
                }
                COMPONENT_VERSION => {
                    component_version.set(value).context("Error setting component version")?
                }
                RESETTABLE => resettable.set(value).context("Error setting resettable")?,
                _ => match extensions.entry(key) {
                    Vacant(entry) => {
                        entry.insert(value);
                    }
                    Occupied(entry) => {
                        bail!("Duplicate values for {}: {:?} and {:?}", key, entry.get(), value)
                    }
                },
            };
        } else {
            bail!("Invalid key: {:?}", key);
        }
    }

    Ok(ConfigDescBuilder::new()
        .component_name(component_name.into_optional_string().context("Component name")?)
        .component_version(component_version.into_optional_i64().context("Component version")?)
        .resettable(resettable.is_null().context("Resettable")?)
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use coset::{iana, Header, Label, RegisteredLabel};

    #[test]
    fn check_bcc_entry_protected_header() -> Result<()> {
        let eddsa = coset::Algorithm::Assigned(iana::Algorithm::EdDSA);
        let header = Header { alg: Some(eddsa.clone()), ..Default::default() };
        check_protected_header(&eddsa, &header).context("Only alg allowed")?;
        let header = Header { alg: Some(coset::Algorithm::PrivateUse(1000)), ..Default::default() };
        assert!(check_protected_header(&eddsa, &header).is_err());
        let mut header = Header { alg: Some(eddsa.clone()), ..Default::default() };
        header.rest.push((Label::Int(1000), Value::from(2000u16)));
        check_protected_header(&eddsa, &header).context("non-crit header allowed")?;
        let mut header = Header { alg: Some(eddsa.clone()), ..Default::default() };
        header.crit.push(RegisteredLabel::Assigned(iana::HeaderParameter::CounterSignature));
        assert!(check_protected_header(&eddsa, &header).is_err());
        Ok(())
    }
}
