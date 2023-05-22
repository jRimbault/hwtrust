//! This module defines a helper for parsing fields in a CBOR map.

use coset::cbor::value::Value;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FieldValueError {
    #[error("expected a value for field {0}, but none was found")]
    Missing(&'static str),
    #[error("expected bytes for field {0}, but found `{1:?}`")]
    NotBytes(&'static str, Value),
    #[error("expected string for field {0}, but found `{1:?}`")]
    NotString(&'static str, Value),
    #[error("expected null for field {0}, but found `{1:?}`")]
    NotNull(&'static str, Value),
    #[error("expected i64 for field {0}, but found `{1:?}`")]
    NotI64(&'static str, Value),
    #[error("expected u64 for field {0}, but found `{1:?}`")]
    NotU64(&'static str, Value),
}

pub(super) struct FieldValue {
    name: &'static str,
    value: Option<Value>,
}

impl FieldValue {
    pub fn new(name: &'static str) -> Self {
        Self { name, value: None }
    }

    pub fn name(&self) -> &str {
        self.name
    }

    pub fn get(&self) -> &Option<Value> {
        &self.value
    }

    pub fn set(&mut self, value: Value) {
        self.value = Some(value)
    }

    pub fn is_bytes(&self) -> bool {
        self.value.as_ref().map_or(false, |v| v.is_bytes())
    }

    pub fn into_optional_bytes(self) -> Result<Option<Vec<u8>>, FieldValueError> {
        self.value
            .map(|v| match v {
                Value::Bytes(b) => Ok(b),
                _ => Err(FieldValueError::NotBytes(self.name, v)),
            })
            .transpose()
    }

    pub fn into_bytes(self) -> Result<Vec<u8>, FieldValueError> {
        require_present(self.name, self.into_optional_bytes())
    }

    pub fn into_optional_string(self) -> Result<Option<String>, FieldValueError> {
        self.value
            .map(|v| match v {
                Value::Text(s) => Ok(s),
                _ => Err(FieldValueError::NotString(self.name, v)),
            })
            .transpose()
    }

    pub fn into_string(self) -> Result<String, FieldValueError> {
        require_present(self.name, self.into_optional_string())
    }

    pub fn is_null(&self) -> Result<bool, FieldValueError> {
        // If there's no value, return false; if there is a null value, return true; anything else
        // is an error.
        self.value
            .as_ref()
            .map(|v| match *v {
                Value::Null => Ok(true),
                _ => Err(FieldValueError::NotNull(self.name, v.clone())),
            })
            .unwrap_or(Ok(false))
    }

    pub fn is_integer(&self) -> bool {
        self.value.as_ref().map_or(false, |v| v.is_integer())
    }

    pub fn into_optional_i64(self) -> Result<Option<i64>, FieldValueError> {
        self.value
            .map(|v| {
                let value =
                    if let Value::Integer(i) = v { i128::from(i).try_into().ok() } else { None };
                value.ok_or_else(|| FieldValueError::NotI64(self.name, v))
            })
            .transpose()
    }

    pub fn into_optional_u64(self) -> Result<Option<u64>, FieldValueError> {
        self.value
            .map(|v| {
                let value =
                    if let Value::Integer(i) = v { i128::from(i).try_into().ok() } else { None };
                value.ok_or_else(|| FieldValueError::NotU64(self.name, v))
            })
            .transpose()
    }
}

fn require_present<T>(
    name: &'static str,
    value: Result<Option<T>, FieldValueError>,
) -> Result<T, FieldValueError> {
    value.and_then(|opt| opt.ok_or(FieldValueError::Missing(name)))
}
