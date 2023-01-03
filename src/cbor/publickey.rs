//! CBOR encoding and decoding of a [`PublicKey`].

use crate::publickey::{EcKind, Kind, PublicKey};
use anyhow::{anyhow, bail, ensure, Context, Result};
use coset::cbor::value::Value;
use coset::iana::{self, EnumI64};
use coset::{Algorithm, CoseKey, CoseKeyBuilder, KeyOperation, KeyType, Label};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Public};

impl PublicKey {
    pub(super) fn from_cose_key(cose_key: &CoseKey) -> Result<Self> {
        if !cose_key.key_ops.is_empty() {
            ensure!(cose_key.key_ops.contains(&KeyOperation::Assigned(iana::KeyOperation::Verify)));
        }
        let pkey = match cose_key.kty {
            KeyType::Assigned(iana::KeyType::OKP) => pkey_from_okp_key(cose_key)?,
            KeyType::Assigned(iana::KeyType::EC2) => pkey_from_ec2_key(cose_key)?,
            _ => bail!("Unexpected KeyType value: {:?}", cose_key.kty),
        };
        pkey.try_into().context("Making PublicKey from PKey")
    }

    pub(super) fn iana_algorithm(&self) -> iana::Algorithm {
        match self.kind() {
            Kind::Ed25519 => iana::Algorithm::EdDSA,
            Kind::Ec(EcKind::P256) => iana::Algorithm::ES256,
            Kind::Ec(EcKind::P384) => iana::Algorithm::ES384,
        }
    }

    /// Convert the public key into a [`CoseKey`].
    pub fn to_cose_key(&self) -> Result<CoseKey> {
        let builder = match self.kind() {
            Kind::Ed25519 => {
                let label_crv = iana::OkpKeyParameter::Crv.to_i64();
                let label_x = iana::OkpKeyParameter::X.to_i64();
                let x = self.pkey().raw_public_key().context("Get ed25519 raw public key")?;
                CoseKeyBuilder::new_okp_key()
                    .param(label_crv, Value::from(iana::EllipticCurve::Ed25519.to_i64()))
                    .param(label_x, Value::from(x))
            }
            Kind::Ec(ec) => {
                let key = self.pkey().ec_key().unwrap();
                let group = key.group();
                let mut ctx = BigNumContext::new().context("Failed to create bignum context")?;
                let mut x = BigNum::new().context("Failed to create x coord")?;
                let mut y = BigNum::new().context("Failed to create y coord")?;
                key.public_key()
                    .affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)
                    .context("Get EC coordinates")?;
                let crv = match ec {
                    EcKind::P256 => iana::EllipticCurve::P_256,
                    EcKind::P384 => iana::EllipticCurve::P_384,
                };
                CoseKeyBuilder::new_ec2_pub_key(crv, x.to_vec(), y.to_vec())
            }
        };
        Ok(builder.algorithm(self.iana_algorithm()).add_key_op(iana::KeyOperation::Verify).build())
    }
}

fn pkey_from_okp_key(cose_key: &CoseKey) -> Result<PKey<Public>> {
    ensure!(cose_key.kty == KeyType::Assigned(iana::KeyType::OKP));
    ensure!(cose_key.alg == Some(Algorithm::Assigned(iana::Algorithm::EdDSA)));
    let crv = get_label_value(cose_key, Label::Int(iana::OkpKeyParameter::Crv.to_i64()))?;
    let x = get_label_value_as_bytes(cose_key, Label::Int(iana::OkpKeyParameter::X.to_i64()))?;
    ensure!(crv == &Value::from(iana::EllipticCurve::Ed25519.to_i64()));
    PKey::public_key_from_raw_bytes(x, Id::ED25519).context("Failed to instantiate key")
}

fn pkey_from_ec2_key(cose_key: &CoseKey) -> Result<PKey<Public>> {
    ensure!(cose_key.kty == KeyType::Assigned(iana::KeyType::EC2));
    let crv = get_label_value(cose_key, Label::Int(iana::Ec2KeyParameter::Crv.to_i64()))?;
    let x = get_label_value_as_bytes(cose_key, Label::Int(iana::Ec2KeyParameter::X.to_i64()))?;
    let y = get_label_value_as_bytes(cose_key, Label::Int(iana::Ec2KeyParameter::Y.to_i64()))?;
    match cose_key.alg {
        Some(Algorithm::Assigned(iana::Algorithm::ES256)) => {
            ensure!(crv == &Value::from(iana::EllipticCurve::P_256.to_i64()));
            pkey_from_ec_coords(Nid::X9_62_PRIME256V1, x, y).context("Failed to instantiate key")
        }
        Some(Algorithm::Assigned(iana::Algorithm::ES384)) => {
            ensure!(crv == &Value::from(iana::EllipticCurve::P_384.to_i64()));
            pkey_from_ec_coords(Nid::SECP384R1, x, y).context("Failed to instantiate key")
        }
        _ => bail!("Need to specify ES256 or ES384 in the key. Got {:?}", cose_key.alg),
    }
}

fn pkey_from_ec_coords(nid: Nid, x: &[u8], y: &[u8]) -> Result<PKey<Public>> {
    let group = EcGroup::from_curve_name(nid).context("Failed to construct curve group")?;
    let x = BigNum::from_slice(x).context("Failed to create x coord")?;
    let y = BigNum::from_slice(y).context("Failed to create y coord")?;
    let key = EcKey::from_public_key_affine_coordinates(&group, &x, &y)
        .context("Failed to create EC public key")?;
    PKey::from_ec_key(key).context("Failed to create PKey")
}

/// Get the value corresponding to the provided label within the supplied CoseKey or error if it's
/// not present.
fn get_label_value(key: &CoseKey, label: Label) -> Result<&Value> {
    Ok(&key
        .params
        .iter()
        .find(|(k, _)| k == &label)
        .ok_or_else(|| anyhow!("Label {:?} not found", label))?
        .1)
}

/// Get the byte string for the corresponding label within the key if the label exists and the
/// value is actually a byte array.
fn get_label_value_as_bytes(key: &CoseKey, label: Label) -> Result<&[u8]> {
    get_label_value(key, label)?
        .as_bytes()
        .ok_or_else(|| anyhow!("Value not a bstr."))
        .map(Vec::as_slice)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::publickey::testkeys::{PrivateKey, ED25519_KEY_PEM, P256_KEY_PEM};

    #[test]
    fn to_and_from_okp_cose_key() {
        let key = PrivateKey::from_pem(ED25519_KEY_PEM[0]).public_key();
        let value = key.to_cose_key().unwrap();
        let new_key = PublicKey::from_cose_key(&value).unwrap();
        assert!(key.pkey().public_eq(new_key.pkey()));
    }

    #[test]
    fn to_and_from_ec2_cose_key() {
        let key = PrivateKey::from_pem(P256_KEY_PEM[0]).public_key();
        let value = key.to_cose_key().unwrap();
        let new_key = PublicKey::from_cose_key(&value).unwrap();
        assert!(key.pkey().public_eq(new_key.pkey()));
    }
}
