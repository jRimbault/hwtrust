use crate::cbor::field_value::FieldValue;
use crate::rkp::{
    DeviceInfo, DeviceInfoBootloaderState, DeviceInfoSecurityLevel, DeviceInfoVbState,
};
use anyhow::{bail, ensure, Context, Result};
use ciborium::value::Value;

impl DeviceInfo {
    /// Create a new DeviceInfo struct from Values parsed by ciborium
    pub fn from_cbor_values(
        values: Vec<(Value, Value)>,
        explicit_version: Option<u32>,
    ) -> Result<Self> {
        let mut brand = FieldValue::new("brand");
        let mut manufacturer = FieldValue::new("manufacturer");
        let mut product = FieldValue::new("product");
        let mut model = FieldValue::new("model");
        let mut device = FieldValue::new("device");
        let mut vb_state = FieldValue::new("vb_state");
        let mut bootloader_state = FieldValue::new("bootloader_state");
        let mut vbmeta_digest = FieldValue::new("vbmeta_digest");
        let mut os_version = FieldValue::new("os_version");
        let mut system_patch_level = FieldValue::new("system_patch_level");
        let mut boot_patch_level = FieldValue::new("boot_patch_level");
        let mut vendor_patch_level = FieldValue::new("vendor_patch_level");
        let mut security_level = FieldValue::new("security_level");
        let mut version = FieldValue::new("version");
        let mut fused = FieldValue::new("fused");

        for (key, value) in values {
            let field_value = match key.as_text() {
                Some("brand") => &mut brand,
                Some("manufacturer") => &mut manufacturer,
                Some("product") => &mut product,
                Some("model") => &mut model,
                Some("device") => &mut device,
                Some("vb_state") => &mut vb_state,
                Some("bootloader_state") => &mut bootloader_state,
                Some("vbmeta_digest") => &mut vbmeta_digest,
                Some("os_version") => &mut os_version,
                Some("system_patch_level") => &mut system_patch_level,
                Some("boot_patch_level") => &mut boot_patch_level,
                Some("vendor_patch_level") => &mut vendor_patch_level,
                Some("security_level") => &mut security_level,
                Some("fused") => &mut fused,
                Some("version") => &mut version,
                _ => bail!("Unexpected DeviceInfo kv-pair: ({key:?},{value:?})"),
            };
            field_value.set_once(value)?;
        }

        let version = match version.into_optional_u32() {
            Ok(Some(v)) if v == explicit_version.unwrap_or(v) => v,
            Ok(Some(v)) => bail!(
                "Parsed DeviceInfo version '{v}' does not match expected version \
                '{explicit_version:?}'"
            ),
            Ok(None) => explicit_version.context("missing required version")?,
            Err(e) => return Err(e.into()),
        };

        let security_level = match security_level.into_optional_string()? {
            Some(s) => Some(s.as_str().try_into()?),
            None => None,
        };

        let info = DeviceInfo {
            brand: brand.into_string()?,
            manufacturer: manufacturer.into_string()?,
            product: product.into_string()?,
            model: model.into_string()?,
            device: device.into_string()?,
            vb_state: vb_state.into_string()?.as_str().try_into()?,
            bootloader_state: bootloader_state.into_string()?.as_str().try_into()?,
            vbmeta_digest: vbmeta_digest.into_bytes()?,
            os_version: os_version.into_optional_string()?,
            system_patch_level: system_patch_level.into_u32()?,
            boot_patch_level: boot_patch_level.into_u32()?,
            vendor_patch_level: vendor_patch_level.into_u32()?,
            security_level,
            fused: fused.into_bool()?,
            version: version.try_into()?,
        };
        info.validate()?;
        Ok(info)
    }

    fn validate(&self) -> Result<()> {
        ensure!(!self.vbmeta_digest.is_empty(), "vbmeta_digest must not be empty");
        ensure!(
            !self.vbmeta_digest.iter().all(|b| *b == 0u8),
            "vbmeta_digest must not be all zeros. Got {:?}",
            self.vbmeta_digest
        );

        if Some(DeviceInfoSecurityLevel::Avf) == self.security_level {
            ensure!(
                self.bootloader_state == DeviceInfoBootloaderState::Avf
                    && self.vb_state == DeviceInfoVbState::Avf
                    && self.brand == "aosp-avf"
                    && self.device == "avf"
                    && self.model == "avf"
                    && self.manufacturer == "aosp-avf"
                    && self.product == "avf",
                "AVF security level requires AVF fields. Got: {:?}",
                self
            );
        } else {
            ensure!(
                self.bootloader_state != DeviceInfoBootloaderState::Avf
                    && self.vb_state != DeviceInfoVbState::Avf
                    && self.brand != "aosp-avf"
                    && self.device != "avf"
                    && self.model != "avf"
                    && self.manufacturer != "aosp-avf"
                    && self.product != "avf",
                "Non-AVF security level requires non-AVF fields. Got: {:?}",
                self
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rkp::DeviceInfoVersion;

    #[test]
    fn device_info_from_cbor_values_optional_os_version() {
        let values: Vec<(Value, Value)> = get_valid_values_filtered(|x| x != "os_version");
        let info = DeviceInfo::from_cbor_values(values, None).unwrap();
        assert!(info.os_version.is_none());
    }

    #[test]
    fn device_info_from_cbor_values_missing_required_field() {
        let values: Vec<(Value, Value)> = get_valid_values_filtered(|x| x != "brand");
        let err = DeviceInfo::from_cbor_values(values, None).unwrap_err();
        println!("{err:?}");
        assert!(err.to_string().contains("brand"));
    }

    #[test]
    fn from_cbor_values_valid_v2() {
        let actual = DeviceInfo::from_cbor_values(get_valid_values(), None).unwrap();
        let expected = DeviceInfo {
            brand: "generic".to_string(),
            manufacturer: "acme".to_string(),
            product: "phone".to_string(),
            model: "the best one".to_string(),
            device: "really the best".to_string(),
            vb_state: DeviceInfoVbState::Green,
            bootloader_state: DeviceInfoBootloaderState::Locked,
            vbmeta_digest: b"abcdefg".to_vec(),
            os_version: Some("dessert".to_string()),
            system_patch_level: 303010,
            boot_patch_level: 30300102,
            vendor_patch_level: 30300304,
            security_level: Some(DeviceInfoSecurityLevel::Tee),
            fused: true,
            version: DeviceInfoVersion::V2,
        };
        assert_eq!(actual, expected);
    }

    #[test]
    fn device_info_from_cbor_values_valid_v3() {
        let values: Vec<(Value, Value)> = get_valid_values_filtered(|x| x != "version");
        let actual = DeviceInfo::from_cbor_values(values, Some(3)).unwrap();
        let expected = DeviceInfo {
            brand: "generic".to_string(),
            manufacturer: "acme".to_string(),
            product: "phone".to_string(),
            model: "the best one".to_string(),
            device: "really the best".to_string(),
            vb_state: DeviceInfoVbState::Green,
            bootloader_state: DeviceInfoBootloaderState::Locked,
            vbmeta_digest: b"abcdefg".to_vec(),
            os_version: Some("dessert".to_string()),
            system_patch_level: 303010,
            boot_patch_level: 30300102,
            vendor_patch_level: 30300304,
            security_level: Some(DeviceInfoSecurityLevel::Tee),
            fused: true,
            version: DeviceInfoVersion::V3,
        };
        assert_eq!(actual, expected);
    }

    #[test]
    fn device_info_from_cbor_values_mismatched_version() {
        let values: Vec<(Value, Value)> = get_valid_values();
        let err = DeviceInfo::from_cbor_values(values, Some(3)).unwrap_err();
        println!("{err:?}");
        assert!(err.to_string().contains("version"));
    }

    #[test]
    fn device_info_from_cbor_values_invalid_version_value() {
        let values: Vec<(Value, Value)> = get_valid_values_filtered(|x| x != "version");
        let err = DeviceInfo::from_cbor_values(values, None).unwrap_err();
        println!("{err:?}");
        assert!(err.to_string().contains("version"));
    }

    #[test]
    fn device_info_from_cbor_values_invalid_explicit_version() {
        let values: Vec<(Value, Value)> = get_valid_values_filtered(|x| x != "version");
        let err = DeviceInfo::from_cbor_values(values, Some(0)).unwrap_err();
        println!("{err:?}");
        assert!(err.to_string().contains("version"));
    }

    #[test]
    fn device_info_from_cbor_values_missing_version() {
        let values: Vec<(Value, Value)> = get_valid_values_filtered(|x| x != "version");
        let err = DeviceInfo::from_cbor_values(values, None).unwrap_err();
        println!("{err:?}");
        assert!(err.to_string().contains("version"));
    }

    #[test]
    fn device_info_from_cbor_duplicate_values() {
        let mut values: Vec<(Value, Value)> = get_valid_values();
        values.push(("brand".into(), "generic".into()));

        let err = DeviceInfo::from_cbor_values(values, None).unwrap_err();
        println!("{err:?}");
        assert!(err.to_string().contains("may be set only once"));
    }

    #[test]
    fn device_info_from_cbor_empty_vbmeta_digest() {
        let mut values: Vec<(Value, Value)> = get_valid_values_filtered(|v| v != "vbmeta_digest");
        values.push(("vbmeta_digest".into(), vec![0u8; 0].into()));

        let err = DeviceInfo::from_cbor_values(values, None).unwrap_err();
        println!("{err:?}");
        assert!(err.to_string().contains("vbmeta_digest must not be empty"), "{err:?}");
    }

    #[test]
    fn device_info_from_cbor_all_zero_vbmeta_digest() {
        let mut values: Vec<(Value, Value)> = get_valid_values_filtered(|v| v != "vbmeta_digest");
        values.push(("vbmeta_digest".into(), vec![0u8; 16].into()));

        let err = DeviceInfo::from_cbor_values(values, None).unwrap_err();
        println!("{err:?}");
        assert!(err.to_string().contains("vbmeta_digest must not be all zeros"), "{err:?}");
    }

    #[test]
    fn device_info_from_cbor_values_non_avf_security_level_has_avf_vb_state() {
        let mut values = get_valid_values_filtered(|x| x != "vb_state");
        values.push(("vb_state".into(), "avf".into()));

        let err = DeviceInfo::from_cbor_values(values, None).unwrap_err();
        assert!(err.to_string().contains("Non-AVF security level"), "{err:?}");
    }

    #[test]
    fn device_info_from_cbor_values_non_avf_security_level_has_avf_bootloader_state() {
        let mut values = get_valid_values_filtered(|x| x != "bootloader_state");
        values.push(("bootloader_state".into(), "avf".into()));

        let err = DeviceInfo::from_cbor_values(values, None).unwrap_err();
        assert!(err.to_string().contains("Non-AVF security level"), "{err:?}");
    }

    #[test]
    fn device_info_from_cbor_values_avf_security_level_has_non_avf_vb_state() {
        let values: Vec<(Value, Value)> = get_valid_avf_values()
            .into_iter()
            .filter(|(k, _v)| k.as_text().unwrap() != "vb_state")
            .chain(vec![("vb_state".into(), "green".into())])
            .collect();
        let err = DeviceInfo::from_cbor_values(values, Some(3)).unwrap_err();
        assert!(err.to_string().contains("AVF security level requires AVF fields"), "{err:?}");
    }

    #[test]
    fn device_info_from_cbor_values_avf_security_level_has_avf_fields() {
        let values = get_valid_avf_values();
        let actual = DeviceInfo::from_cbor_values(values, Some(3)).unwrap();
        let expected = DeviceInfo {
            brand: "aosp-avf".to_string(),
            manufacturer: "aosp-avf".to_string(),
            product: "avf".to_string(),
            model: "avf".to_string(),
            device: "avf".to_string(),
            vb_state: DeviceInfoVbState::Avf,
            bootloader_state: DeviceInfoBootloaderState::Avf,
            vbmeta_digest: b"abcdefg".to_vec(),
            os_version: Some("dessert".to_string()),
            system_patch_level: 303010,
            boot_patch_level: 30300102,
            vendor_patch_level: 30300304,
            security_level: Some(DeviceInfoSecurityLevel::Avf),
            fused: true,
            version: DeviceInfoVersion::V3,
        };
        assert_eq!(expected, actual);
    }

    fn get_valid_values() -> Vec<(Value, Value)> {
        vec![
            ("brand".into(), "generic".into()),
            ("manufacturer".into(), "acme".into()),
            ("product".into(), "phone".into()),
            ("model".into(), "the best one".into()),
            ("device".into(), "really the best".into()),
            ("vb_state".into(), "green".into()),
            ("bootloader_state".into(), "locked".into()),
            ("vbmeta_digest".into(), b"abcdefg".as_ref().into()),
            ("os_version".into(), "dessert".into()),
            ("system_patch_level".into(), 303010.into()),
            ("boot_patch_level".into(), 30300102.into()),
            ("vendor_patch_level".into(), 30300304.into()),
            ("security_level".into(), "tee".into()),
            ("fused".into(), 1.into()),
            ("version".into(), 2.into()),
        ]
    }

    fn get_valid_avf_values() -> Vec<(Value, Value)> {
        vec![
            ("brand".into(), "aosp-avf".into()),
            ("manufacturer".into(), "aosp-avf".into()),
            ("product".into(), "avf".into()),
            ("model".into(), "avf".into()),
            ("device".into(), "avf".into()),
            ("vb_state".into(), "avf".into()),
            ("bootloader_state".into(), "avf".into()),
            ("vbmeta_digest".into(), b"abcdefg".as_ref().into()),
            ("os_version".into(), "dessert".into()),
            ("system_patch_level".into(), 303010.into()),
            ("boot_patch_level".into(), 30300102.into()),
            ("vendor_patch_level".into(), 30300304.into()),
            ("security_level".into(), "avf".into()),
            ("fused".into(), 1.into()),
        ]
    }

    fn get_valid_values_filtered<F: Fn(&str) -> bool>(filter: F) -> Vec<(Value, Value)> {
        get_valid_values().into_iter().filter(|x| filter(x.0.as_text().unwrap())).collect()
    }
}
