use crate::cbor::field_value::{FieldValue, FieldValueError};
use crate::cbor::value_from_bytes;
use crate::dice::ChainForm;
use crate::eek;
use crate::publickey::{KeyAgreementPublicKey, PublicKey};
use crate::rkp::{ProtectedData, UdsCerts, UdsCertsEntry};
use crate::session::Session;
use ciborium::value::Value;
use coset::{iana, Algorithm, AsCborValue, CoseEncrypt, CoseKey, CoseRecipient, CoseSign1, Label};
use openssl::cipher::Cipher;
use openssl::cipher_ctx::CipherCtx;
use openssl::pkey::{Id, PKey, Private};

const COSE_RECIPIENT_PUBKEY_LABEL: i64 = -1;

#[derive(Debug, thiserror::Error)]
enum ProtectedError {
    #[error("Unable to locate a COSE_recipient matching any known EEK")]
    CoseReciptientLocation,
    #[error("{0}")]
    Stack(#[from] openssl::error::ErrorStack),
    #[error("Unable to locate public key in COSE_encrypt recipients.")]
    KeyNotFound,
    #[error("{0:?}")]
    Coset(#[from] coset::CoseError),
    #[error("{0:?}")]
    CborDe(#[from] ciborium::de::Error<std::io::Error>),
    #[error("{0:?}")]
    CborSer(#[from] ciborium::ser::Error<std::io::Error>),
    #[error("Expected array for ProtectedDataPayload")]
    ArrayExpected,
    #[error("ProtectedDataPayload size must be 2 or 3, found {0}")]
    WrongLength(usize),
    #[error("{0:?}")]
    FieldValue(#[from] FieldValueError),
    #[error("SignedMac missing payload")]
    MissingPayload,
    #[error("Expected (string, value)")]
    UnexpectedValue,
    #[error("{0}")]
    UdsError(#[from] UdsError),
    #[error("Unsupported EEK: {0:?}")]
    UnsupportedEek(openssl::pkey::Id),
    #[error("Algorithm mismatch between EEK ({cose_alg:?}) and recipient ({alg:?})")]
    AlgMismatch {
        cose_alg: iana::Algorithm,
        alg: iana::Algorithm,
    },
    #[error("COSE_Encrypt recipient pubkey has unexpected algorithm: {0:?}")]
    UnexpectedAlg(Option<coset::RegisteredLabelWithPrivate<iana::Algorithm>>),
}

impl ProtectedData {
    pub(crate) fn from_cose_encrypt(
        session: &Session,
        protected_data: CoseEncrypt,
        challenge: &[u8],
        verified_device_info: &Value,
        tag: &[u8],
    ) -> Result<ProtectedData, ProtectedError> {
        let (recipient, eek) = Self::match_recipient(&protected_data.recipients)?;

        let mut headers = recipient.unprotected.rest;
        let pubkey_index = headers
            .iter()
            .position(|p| p.0 == Label::Int(COSE_RECIPIENT_PUBKEY_LABEL))
            .ok_or(ProtectedError::KeyNotFound)?;
        let mut pubkey_cose = CoseKey::from_cbor_value(headers.remove(pubkey_index).1)?;

        Self::work_around_recipient_key_missing_alg(&mut pubkey_cose, &eek)?;

        let pubkey = KeyAgreementPublicKey::from_cose_key(&pubkey_cose)?;
        let encryption_key = eek::derive_ephemeral_symmetric_key(&eek, pubkey.pkey())
            .with_context(|| format!("for pubkey {:?}", pubkey_cose))?;

        let protected_data_plaintext = protected_data.decrypt(&[], |ciphertext, aad| {
            let (ciphertext, tag) = ciphertext.split_at(ciphertext.len() - 16);
            let mut plaintext = Vec::new();
            let mut ctx = CipherCtx::new()?;
            // decrypt_init must be called twice because our IV is not 12 bytes, which is what
            // AES-GCM wants by default. The first init tells openssl the cipher+mode, then we
            // can tell openssl the IV len, and only after that can we set the non-standard IV.
            ctx.decrypt_init(Some(Cipher::aes_256_gcm()), Some(&encryption_key), None)?;
            ctx.set_iv_length(protected_data.unprotected.iv.len())?;
            ctx.decrypt_init(None, None, Some(&protected_data.unprotected.iv))?;
            ctx.set_tag(tag)?;
            ctx.cipher_update(aad, None)?;
            ctx.cipher_update_vec(ciphertext, &mut plaintext)?;
            ctx.cipher_final_vec(&mut plaintext)?;
            Ok::<Vec<u8>, ProtectedError>(plaintext)
        })?;

        Self::from_cbor_bytes(
            session,
            &protected_data_plaintext,
            challenge,
            verified_device_info,
            tag,
        )
    }

    fn from_cbor_bytes(
        session: &Session,
        plaintext_cbor: &[u8],
        challenge: &[u8],
        verified_device_info: &Value,
        tag: &[u8],
    ) -> Result<Self, ProtectedError> {
        let mut array = match value_from_bytes(plaintext_cbor)? {
            Value::Array(a) => a,
            _ => return Err(ProtectedError::ArrayExpected),
        };

        if array.len() != 2 && array.len() != 3 {
            return Err(ProtectedError::WrongLength(array.len()));
        }

        // pull items out in reverse order to avoid shifting the vector
        let uds_certs = if array.len() != 3 {
            None
        } else {
            let uds_certs_field = FieldValue::from_optional_value("UdsCerts", array.pop());
            Self::to_uds_certs(uds_certs_field.into_map()?)?
        };

        let dice_chain =
            Value::Array(FieldValue::from_optional_value("DiceChain", array.pop()).into_array()?);
        let dice_chain = ChainForm::from_value(session, dice_chain)?;

        let mac_key = Self::validate_mac_key(
            challenge,
            verified_device_info,
            tag,
            FieldValue::from_optional_value("SignedMac", array.pop()).into_cose_sign1()?,
            dice_chain.leaf_public_key(),
        )?;

        Ok(ProtectedData::new(mac_key, dice_chain, uds_certs))
    }

    fn validate_mac_key(
        challenge: &[u8],
        verified_device_info: &Value,
        tag: &[u8],
        signed_mac: CoseSign1,
        signer: &PublicKey,
    ) -> Result<Vec<u8>, ProtectedError> {
        let mut aad: Vec<u8> = vec![];
        ciborium::ser::into_writer(
            // This can be optimized if/when ciborium exposes lower-level serialization routines
            &Value::Array(vec![
                Value::Bytes(challenge.to_vec()),
                verified_device_info.clone(),
                Value::Bytes(tag.to_vec()),
            ]),
            &mut aad,
        )?;
        signer
            .verify_cose_sign1(&signed_mac, &aad)
            .context("verifying signed MAC")?;
        signed_mac.payload.ok_or(ProtectedError::MissingPayload)
    }

    fn to_uds_certs(kv_pairs: Vec<(Value, Value)>) -> Result<Option<UdsCerts>, ProtectedError> {
        if kv_pairs.is_empty() {
            return Ok(None);
        }

        let mut uds_certs = UdsCerts::new();
        for pair in kv_pairs {
            match pair {
                (Value::Text(signer), value) => uds_certs.add_signer(signer, value)?,
                _ => return Err(ProtectedError::UnexpectedValue),
            }
        }
        Ok(Some(uds_certs))
    }

    fn work_around_recipient_key_missing_alg(
        cose_key: &mut CoseKey,
        eek: &PKey<Private>,
    ) -> Result<(), ProtectedError> {
        let cose_alg = match eek.id() {
            Id::X25519 => iana::Algorithm::ECDH_ES_HKDF_256,
            Id::EC if eek.bits() == 256 => iana::Algorithm::ES256,
            other => return Err(ProtectedError::UnsupportedEek(other)),
        };

        match &cose_key.alg {
            None => cose_key.alg = Some(Algorithm::Assigned(cose_alg)),
            Some(Algorithm::Assigned(alg)) if *alg == cose_alg => (),
            Some(Algorithm::Assigned(alg)) => {
                return Err(ProtectedError::AlgMismatch {
                    cose_alg,
                    alg: *alg,
                });
            }
            other => return Err(ProtectedError::UnexpectedAlg(other.clone())),
        }
        Ok(())
    }

    /// Look through a set of COSE_recipients to see if any of them match a known EEK. If so,V
    /// return the matching recipieint and EEK to the caller so they can perform key agreement.
    fn match_recipient(
        recipients: &Vec<CoseRecipient>,
    ) -> Result<(CoseRecipient, PKey<Private>), ProtectedError> {
        for r in recipients {
            if r.unprotected.key_id == eek::X25519_EEK_ID {
                return Ok((r.clone(), eek::x25519_geek()));
            } else if r.unprotected.key_id == eek::P256_EEK_ID {
                return Ok((r.clone(), eek::p256_geek()));
            }
        }
        Err(ProtectedError::CoseReciptientLocation)
    }
}

impl UdsCerts {
    pub fn add_signer(&mut self, signer: String, data: Value) -> Result<(), UdsError> {
        // For now, assume all signers are using x.509 certs. This may change in the future for
        // platforms that need custom certification mechanisms for UDS_pub.
        match self.0.get_mut(&signer) {
            Some(_) => return Err(UdsError::SignerFoundTwice),
            None => self.0.insert(signer, UdsCertsEntry::from_cbor_value(data)?),
        };
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
enum UdsError {
    #[error("Expected UDS cert byte array found '{0:?}'")]
    ExpectedCertArray(ciborium::Value),
    #[error("Expected CBOR array of certificates, found {0:?}")]
    ExpectedCborCertArray(ciborium::Value),
    #[error(r#"Signer '{{signer}}' entry found twice in the UdsCerts"#)]
    SignerFoundTwice,
}

impl UdsCertsEntry {
    fn from_cbor_value(data: Value) -> Result<Self, UdsError> {
        match data {
            Value::Array(certs) => {
                let mut cert_buffers = vec![];
                for cert in certs {
                    match cert {
                        Value::Bytes(b) => cert_buffers.push(b),
                        other => return Err(UdsError::ExpectedCertArray(other)),
                    }
                }
                UdsCertsEntry::new_x509_chain(cert_buffers)
            }
            other => Err(UdsError::ExpectedCborCertArray(other)),
        }
    }
}
