//! This module defines a helper for parsing fields in a CBOR map.

use coset::cbor::value::Value;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FieldValueError {
    #[error("expected a value but none was found")]
    Missing,
    #[error("expected bytes but found `{0:?}`")]
    NotBytes(Value),
    #[error("expected string but found `{0:?}`")]
    NotString(Value),
    #[error("expected null but found `{0:?}`")]
    NotNull(Value),
    #[error("expected i64 but found `{0:?}`")]
    NotI64(Value),
    #[error("expected u64 but found `{0:?}`")]
    NotU64(Value),
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
                _ => Err(FieldValueError::NotBytes(v)),
            })
            .transpose()
    }

    pub fn into_bytes(self) -> Result<Vec<u8>, FieldValueError> {
        require_present(self.into_optional_bytes())
    }

    pub fn into_optional_string(self) -> Result<Option<String>, FieldValueError> {
        self.value
            .map(|v| match v {
                Value::Text(s) => Ok(s),
                _ => Err(FieldValueError::NotString(v)),
            })
            .transpose()
    }

    pub fn into_string(self) -> Result<String, FieldValueError> {
        require_present(self.into_optional_string())
    }

    pub fn is_null(&self) -> Result<bool, FieldValueError> {
        // If there's no value, return false; if there is a null value, return true; anything else
        // is an error.
        self.value
            .as_ref()
            .map(|v| match *v {
                Value::Null => Ok(true),
                _ => Err(FieldValueError::NotNull(v.clone())),
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
                value.ok_or_else(|| FieldValueError::NotI64(v))
            })
            .transpose()
    }

    pub fn into_optional_u64(self) -> Result<Option<u64>, FieldValueError> {
        self.value
            .map(|v| {
                let value =
                    if let Value::Integer(i) = v { i128::from(i).try_into().ok() } else { None };
                value.ok_or_else(|| FieldValueError::NotU64(v))
            })
            .transpose()
    }
}

fn require_present<T>(value: Result<Option<T>, FieldValueError>) -> Result<T, FieldValueError> {
    value.and_then(|opt| opt.ok_or(FieldValueError::Missing))
}
