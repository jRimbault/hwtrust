use crate::cbor::field_value::FieldValue;
use crate::rkp::{Csr, DeviceInfo};
use crate::session::Session;
use anyhow::{anyhow, bail, ensure, Context, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use ciborium::value::Value;

const VERSION_OR_DEVICE_INFO_INDEX: usize = 0;

impl Csr {
    /// Parse base64-encoded CBOR data as a Certificate Signing Request.
    pub fn from_base64_cbor<S: AsRef<[u8]>>(session: &Session, base64: &S) -> Result<Self> {
        let cbor: Vec<u8> = BASE64_STANDARD.decode(base64).context("invalid base64 CSR")?;
        Self::from_cbor(session, cbor.as_slice())
    }

    /// Read and parse CBOR data as a Certificate Signing Request.
    pub fn from_cbor<S: std::io::Read>(session: &Session, cbor: S) -> Result<Self> {
        let value: Value = ciborium::de::from_reader(cbor).context("invalid CBOR")?;
        let mut array = match value {
            Value::Array(a) if a.is_empty() => bail!("CSR CBOR is an empty array"),
            Value::Array(a) => a,
            other => bail!("expected array, found {other:?}"),
        };
        let version_or_device_info =
            std::mem::replace(&mut array[VERSION_OR_DEVICE_INFO_INDEX], Value::Null);
        match version_or_device_info {
            Value::Array(device_info) => Self::v2_from_cbor_values(session, array, device_info),
            Value::Integer(i) => Self::v3_from_authenticated_request(session, array, i.into()),
            other => Err(anyhow!(
                "Expected integer or array at index {VERSION_OR_DEVICE_INFO_INDEX}, \
                found {other:?}"
            )),
        }
    }

    fn v2_from_cbor_values(
        _session: &Session,
        _csr: Vec<Value>,
        mut device_info: Vec<Value>,
    ) -> Result<Self> {
        ensure!(device_info.len() == 2, "Device info should contain exactly 2 entries");
        device_info.pop(); // ignore unverified info
        let verified_device_info = match device_info.pop() {
            Some(Value::Map(d)) => d,
            other => bail!("Expected a map for verified device info, found '{:?}'", other),
        };

        Ok(Self::V2 { device_info: DeviceInfo::from_cbor_values(verified_device_info, None)? })
    }

    fn v3_from_authenticated_request(
        _session: &Session,
        mut csr: Vec<Value>,
        version: i128,
    ) -> Result<Self> {
        if version != 1 {
            bail!("Invalid CSR version. Only '1' is supported, found '{}", version);
        }

        let _unverified_info = FieldValue::from_optional_value("UnverifiedDeviceInfo", csr.pop());

        let signed_data =
            FieldValue::from_optional_value("SignedData", csr.pop()).into_cose_sign1()?;
        let signed_data_payload = signed_data.payload.context("missing payload in SignedData")?;
        let csr_payload_value =
            ciborium::de::from_reader::<Value, &[u8]>(signed_data_payload.as_slice())
                .context("SignedData payload is not valid CBOR")?
                .as_array_mut()
                .context("SignedData payload is not a CBOR array")?
                .pop()
                .context("Missing CsrPayload in SignedData")?;
        let csr_payload_bytes = csr_payload_value
            .as_bytes()
            .context("CsrPayload (in SignedData) is expected to be encoded CBOR")?
            .as_slice();
        let mut csr_payload = match ciborium::de::from_reader(csr_payload_bytes)? {
            Value::Array(a) => a,
            other => bail!("CsrPayload is expected to be an array, found {other:?}"),
        };

        let _keys_to_sign = FieldValue::from_optional_value("KeysToSign", csr_payload.pop());
        let device_info = FieldValue::from_optional_value("DeviceInfo", csr_payload.pop());
        let _certificate_type =
            FieldValue::from_optional_value("CertificateType", csr_payload.pop());

        let device_info = DeviceInfo::from_cbor_values(device_info.into_map()?, Some(3))?;
        Ok(Self::V3 { device_info })
    }
}

#[cfg(test)]
mod tests {
    // More complete testing happens in the factorycsr module, as the test data
    // generation spits out full JSON files, not just a CSR. Therefore, only a
    // minimal number of smoke tests are here.
    use super::*;
    use crate::rkp::DeviceInfoVersion;
    use std::fs;

    #[test]
    fn from_base64_valid_v2() {
        let input = fs::read_to_string("testdata/csr/v2_csr.base64").unwrap().trim().to_owned();
        let csr = Csr::from_base64_cbor(&Session::default(), &input).unwrap();
        assert_eq!(csr, Csr::V2 { device_info: testutil::test_device_info(DeviceInfoVersion::V2) });
    }

    #[test]
    fn from_base64_valid_v3() {
        let input = fs::read_to_string("testdata/csr/v3_csr.base64").unwrap().trim().to_owned();
        let csr = Csr::from_base64_cbor(&Session::default(), &input).unwrap();
        assert_eq!(csr, Csr::V3 { device_info: testutil::test_device_info(DeviceInfoVersion::V3) });
    }

    #[test]
    fn from_empty_string() {
        let err = Csr::from_base64_cbor(&Session::default(), &"").unwrap_err();
        assert!(err.to_string().contains("invalid CBOR"));
    }

    #[test]
    fn from_garbage() {
        let err = Csr::from_base64_cbor(&Session::default(), &"cnViYmlzaAo=").unwrap_err();
        assert!(err.to_string().contains("invalid CBOR"));
    }

    #[test]
    fn from_invalid_base64() {
        let err = Csr::from_base64_cbor(&Session::default(), &"not base64").unwrap_err();
        assert!(err.to_string().contains("invalid base64"));
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    use crate::rkp::{
        DeviceInfo, DeviceInfoBootloaderState, DeviceInfoSecurityLevel, DeviceInfoVbState,
        DeviceInfoVersion,
    };

    // The test data uses mostly common DeviceInfo fields
    pub fn test_device_info(version: DeviceInfoVersion) -> DeviceInfo {
        DeviceInfo {
            version,
            brand: "Google".to_string(),
            manufacturer: "Google".to_string(),
            product: "pixel".to_string(),
            model: "model".to_string(),
            device: "device".to_string(),
            vb_state: DeviceInfoVbState::Green,
            bootloader_state: DeviceInfoBootloaderState::Locked,
            vbmeta_digest: b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff".to_vec(),
            os_version: Some("12".to_string()),
            system_patch_level: 20221025,
            boot_patch_level: 20221026,
            vendor_patch_level: 20221027,
            security_level: Some(DeviceInfoSecurityLevel::Tee),
            fused: true,
        }
    }
}
