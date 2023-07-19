use crate::rkp::Csr;
use crate::session::Session;
use anyhow::{bail, Result};
use serde_json::{Map, Value};

/// Represents a "Factory CSR", which is a JSON value captured for each device on the factory
/// line. This JSON is uploaded to the RKP backend to register the device. We reuse the CSR
/// (Certificate Signing Request) format for this as an implementation convenience. The CSR
/// actually contains an empty set of keys for which certificates are needed.
#[non_exhaustive]
#[derive(Debug, Eq, PartialEq)]
pub struct FactoryCsr {
    /// The CSR, as created by an IRemotelyProvisionedComponent HAL.
    pub csr: Csr,
    /// The name of the HAL that generated the CSR.
    pub name: String,
}

fn get_string_from_map(fields: &Map<String, Value>, key: &str) -> Result<String> {
    match fields.get(key) {
        Some(Value::String(s)) => Ok(s.to_string()),
        Some(v) => bail!("Unexpected type for '{key}'. Expected String, found '{v:?}'"),
        None => bail!("Unable to locate '{key}' in input"),
    }
}

impl FactoryCsr {
    /// Parse the input JSON string into a CSR that was captured on the factory line. The
    /// format of the JSON data is defined by rkp_factory_extraction_tool.
    pub fn from_json(session: &Session, json: &str) -> Result<Self> {
        match serde_json::from_str(json) {
            Ok(Value::Object(map)) => Self::from_map(session, map),
            Ok(unexpected) => bail!("Expected a map, got some other type: {unexpected}"),
            Err(e) => bail!("Error parsing input json: {e}"),
        }
    }

    fn from_map(session: &Session, fields: Map<String, Value>) -> Result<Self> {
        let base64 = get_string_from_map(&fields, "csr")?;
        let name = get_string_from_map(&fields, "name")?;
        let csr = Csr::from_base64_cbor(session, &base64)?;
        Ok(Self { csr, name })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::rkp::csr::testutil::test_device_info;
    use crate::rkp::device_info::DeviceInfoVersion;
    use crate::rkp::factory_csr::FactoryCsr;
    use anyhow::anyhow;
    use std::fs;
    use std::fs::File;

    fn json_map_from_file(path: &str) -> Result<Map<String, Value>> {
        let input = File::open(path)?;
        match serde_json::from_reader(input)? {
            Value::Object(map) => Ok(map),
            other => Err(anyhow!("Unexpected JSON. Wanted a map, found {other:?}")),
        }
    }

    #[test]
    fn from_json_valid_v2_ed25519() {
        let json = fs::read_to_string("testdata/factory_csr/v2_ed25519_valid.json").unwrap();
        let csr = FactoryCsr::from_json(&Session::default(), &json).unwrap();
        assert_eq!(
            csr,
            FactoryCsr {
                csr: Csr::V2 { device_info: test_device_info(DeviceInfoVersion::V2) },
                name: "default".to_string(),
            }
        );
    }

    #[test]
    fn from_json_valid_v3_ed25519() {
        let json = fs::read_to_string("testdata/factory_csr/v3_ed25519_valid.json").unwrap();
        let csr = FactoryCsr::from_json(&Session::default(), &json).unwrap();
        assert_eq!(
            csr,
            FactoryCsr {
                csr: Csr::V3 { device_info: test_device_info(DeviceInfoVersion::V3) },
                name: "default".to_string(),
            }
        );
    }

    #[test]
    fn from_json_valid_v2_p256() {
        let json = fs::read_to_string("testdata/factory_csr/v2_p256_valid.json").unwrap();
        let csr = FactoryCsr::from_json(&Session::default(), &json).unwrap();
        assert_eq!(
            csr,
            FactoryCsr {
                csr: Csr::V2 { device_info: test_device_info(DeviceInfoVersion::V2) },
                name: "default".to_string(),
            }
        );
    }

    #[test]
    fn from_json_valid_v3_p256() {
        let json = fs::read_to_string("testdata/factory_csr/v3_p256_valid.json").unwrap();
        let csr = FactoryCsr::from_json(&Session::default(), &json).unwrap();
        assert_eq!(
            csr,
            FactoryCsr {
                csr: Csr::V3 { device_info: test_device_info(DeviceInfoVersion::V3) },
                name: "default".to_string(),
            }
        );
    }

    #[test]
    fn from_json_name_is_missing() {
        let mut value = json_map_from_file("testdata/factory_csr/v2_ed25519_valid.json").unwrap();
        value.remove_entry("name");
        let json = serde_json::to_string(&value).unwrap();
        let err = FactoryCsr::from_json(&Session::default(), &json).unwrap_err();
        assert!(err.to_string().contains("Unable to locate 'name'"));
    }

    #[test]
    fn from_json_name_is_wrong_type() {
        let mut value = json_map_from_file("testdata/factory_csr/v2_ed25519_valid.json").unwrap();
        value.insert("name".to_string(), Value::Object(Map::default()));
        let json = serde_json::to_string(&value).unwrap();
        let err = FactoryCsr::from_json(&Session::default(), &json).unwrap_err();
        assert!(err.to_string().contains("Unexpected type for 'name'"));
    }

    #[test]
    fn from_json_csr_is_missing() {
        let json = r#"{ "name": "default" }"#;
        let err = FactoryCsr::from_json(&Session::default(), json).unwrap_err();
        assert!(err.to_string().contains("Unable to locate 'csr'"));
    }

    #[test]
    fn from_json_csr_is_wrong_type() {
        let json = r#"{ "csr": 3.1415, "name": "default" }"#;
        let err = FactoryCsr::from_json(&Session::default(), json).unwrap_err();
        assert!(err.to_string().contains("Unexpected type for 'csr'"));
    }

    #[test]
    fn from_json_extra_tag_is_ignored() {
        let mut value = json_map_from_file("testdata/factory_csr/v2_ed25519_valid.json").unwrap();
        value.insert("extra".to_string(), Value::Bool(true));
        let json = serde_json::to_string(&value).unwrap();
        let csr = FactoryCsr::from_json(&Session::default(), &json).unwrap();
        assert_eq!(csr.name, "default");
    }
}
