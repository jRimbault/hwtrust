//! This module contains data types used in Remote Key Provisioning.

mod device_info;

pub use device_info::{
    DeviceInfo, DeviceInfoBootloaderState, DeviceInfoSecurityLevel, DeviceInfoVbState,
    DeviceInfoVersion,
};
