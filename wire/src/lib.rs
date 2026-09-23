// Copyright 2022, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use coset::TaggedCborSerializable;
use std::{
    format,
    string::{String, ToString},
    vec::Vec,
};

pub use ciborium as cbor;

pub use coset;

pub mod keymint;
pub mod legacy;
pub mod rpc;
pub mod secureclock;
pub mod sharedsecret;
pub mod types;
pub use types::*;

#[cfg(test)]
mod tests;

#[macro_export]
macro_rules! try_from_n {
    { $ename:ident } => {
        impl core::convert::TryFrom<i32> for $ename {
            type Error = $crate::ValueNotRecognized;
            fn try_from(value: i32) -> Result<Self, Self::Error> {
                Self::n(value).ok_or($crate::ValueNotRecognized::$ename)
            }
        }
    };
}

pub fn vec_try_fill_with_alloc_err<T: Clone, E>(
    elem: T,
    len: usize,
    alloc_err: fn() -> E,
) -> Result<Vec<T>, E> {
    let mut v = std::vec::Vec::new();
    v.try_reserve(len).map_err(|_e| alloc_err())?;
    v.resize(len, elem);
    Ok(v)
}

pub fn vec_try4_with_alloc_err<T: Clone, E>(
    x1: T,
    x2: T,
    x3: T,
    x4: T,
    alloc_err: fn() -> E,
) -> Result<Vec<T>, E> {
    let mut v = std::vec::Vec::new();
    match v.try_reserve(4) {
        Err(_e) => Err(alloc_err()),
        Ok(_) => {
            v.push(x1);
            v.push(x2);
            v.push(x3);
            v.push(x4);
            Ok(v)
        }
    }
}

pub fn vec_try3_with_alloc_err<T: Clone, E>(
    x1: T,
    x2: T,
    x3: T,
    alloc_err: fn() -> E,
) -> Result<Vec<T>, E> {
    let mut v = std::vec::Vec::new();
    match v.try_reserve(3) {
        Err(_e) => Err(alloc_err()),
        Ok(_) => {
            v.push(x1);
            v.push(x2);
            v.push(x3);
            Ok(v)
        }
    }
}

pub fn vec_try2_with_alloc_err<T: Clone, E>(
    x1: T,
    x2: T,
    alloc_err: fn() -> E,
) -> Result<Vec<T>, E> {
    let mut v = std::vec::Vec::new();
    match v.try_reserve(2) {
        Err(_e) => Err(alloc_err()),
        Ok(_) => {
            v.push(x1);
            v.push(x2);
            Ok(v)
        }
    }
}

pub fn vec_try1_with_alloc_err<T: Clone, E>(x1: T, alloc_err: fn() -> E) -> Result<Vec<T>, E> {
    let mut v = std::vec::Vec::new();
    match v.try_reserve(1) {
        Err(_e) => Err(alloc_err()),
        Ok(_) => {
            v.push(x1);
            Ok(v)
        }
    }
}

#[macro_export]
macro_rules! vec_try {
    { $elem:expr ; $len:expr } => {
        $crate::vec_try_fill_with_alloc_err($elem, $len, || $crate::CborError::AllocationFailed)
    };
    { $x1:expr, $x2:expr, $x3:expr, $x4:expr $(,)? } => {
        $crate::vec_try4_with_alloc_err($x1, $x2, $x3, $x4, || $crate::CborError::AllocationFailed)
    };
    { $x1:expr, $x2:expr, $x3:expr $(,)? } => {
        $crate::vec_try3_with_alloc_err($x1, $x2, $x3, || $crate::CborError::AllocationFailed)
    };
    { $x1:expr, $x2:expr $(,)? } => {
        $crate::vec_try2_with_alloc_err($x1, $x2, || $crate::CborError::AllocationFailed)
    };
    { $x1:expr $(,)? } => {
        $crate::vec_try1_with_alloc_err($x1, || $crate::CborError::AllocationFailed)
    };
}

#[derive(Debug)]
pub struct EndOfFile;

pub enum CborError {
    DecodeFailed(cbor::de::Error<EndOfFile>),

    EncodeFailed,

    ExtraneousData,

    OutOfRangeIntegerValue,

    NonEnumValue,

    UnexpectedItem(&'static str, &'static str),

    InvalidValue,

    AllocationFailed,
}

#[allow(clippy::from_over_into)]
impl Into<coset::CoseError> for CborError {
    fn into(self) -> coset::CoseError {
        match self {
            CborError::DecodeFailed(inner) => coset::CoseError::DecodeFailed(match inner {
                cbor::de::Error::Io(_io) => cbor::de::Error::Io(coset::EndOfFile),
                cbor::de::Error::Syntax(v) => cbor::de::Error::Syntax(v),
                cbor::de::Error::Semantic(sz, msg) => cbor::de::Error::Semantic(sz, msg),
                cbor::de::Error::RecursionLimitExceeded => cbor::de::Error::RecursionLimitExceeded,
            }),
            CborError::EncodeFailed => coset::CoseError::EncodeFailed,
            CborError::ExtraneousData => coset::CoseError::ExtraneousData,
            CborError::OutOfRangeIntegerValue => coset::CoseError::OutOfRangeIntegerValue,
            CborError::NonEnumValue => coset::CoseError::OutOfRangeIntegerValue,
            CborError::UnexpectedItem(got, want) => coset::CoseError::UnexpectedItem(got, want),
            CborError::InvalidValue => coset::CoseError::EncodeFailed,
            CborError::AllocationFailed => coset::CoseError::EncodeFailed,
        }
    }
}

impl<T> From<cbor::de::Error<T>> for CborError {
    fn from(e: cbor::de::Error<T>) -> Self {
        use cbor::de::Error::{Io, RecursionLimitExceeded, Semantic, Syntax};
        let e = match e {
            Io(_) => Io(EndOfFile),
            Syntax(x) => Syntax(x),
            Semantic(a, b) => Semantic(a, b),
            RecursionLimitExceeded => RecursionLimitExceeded,
        };
        CborError::DecodeFailed(e)
    }
}

impl<T> From<cbor::ser::Error<T>> for CborError {
    fn from(_e: cbor::ser::Error<T>) -> Self {
        CborError::EncodeFailed
    }
}

impl From<cbor::value::Error> for CborError {
    fn from(_e: cbor::value::Error) -> Self {
        CborError::InvalidValue
    }
}

impl From<core::num::TryFromIntError> for CborError {
    fn from(_: core::num::TryFromIntError) -> Self {
        CborError::OutOfRangeIntegerValue
    }
}

impl From<coset::CoseError> for CborError {
    fn from(e: coset::CoseError) -> Self {
        match e {
            coset::CoseError::DecodeFailed(inner) => CborError::DecodeFailed(match inner {
                cbor::de::Error::Io(_io) => cbor::de::Error::Io(EndOfFile),
                cbor::de::Error::Syntax(v) => cbor::de::Error::Syntax(v),
                cbor::de::Error::Semantic(sz, msg) => cbor::de::Error::Semantic(sz, msg),
                cbor::de::Error::RecursionLimitExceeded => cbor::de::Error::RecursionLimitExceeded,
            }),
            coset::CoseError::EncodeFailed => CborError::EncodeFailed,
            coset::CoseError::ExtraneousData => CborError::ExtraneousData,
            coset::CoseError::OutOfRangeIntegerValue => CborError::OutOfRangeIntegerValue,
            coset::CoseError::UnregisteredIanaValue => CborError::NonEnumValue,
            coset::CoseError::UnregisteredIanaNonPrivateValue => CborError::NonEnumValue,
            coset::CoseError::UnexpectedItem(got, want) => CborError::UnexpectedItem(got, want),
            coset::CoseError::DuplicateMapKey => {
                CborError::UnexpectedItem("dup map key", "unique keys")
            }
        }
    }
}

impl core::fmt::Debug for CborError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CborError::DecodeFailed(de) => write!(f, "decode CBOR failure: {de:?}"),
            CborError::EncodeFailed => write!(f, "encode CBOR failure"),
            CborError::ExtraneousData => write!(f, "extraneous data in CBOR input"),
            CborError::OutOfRangeIntegerValue => write!(f, "out of range integer value"),
            CborError::NonEnumValue => write!(f, "integer not a valid enum value"),
            CborError::UnexpectedItem(got, want) => write!(f, "got {got}, expected {want}"),
            CborError::InvalidValue => write!(f, "invalid CBOR value"),
            CborError::AllocationFailed => write!(f, "allocation failed"),
        }
    }
}

pub fn cbor_type_error<T>(value: &cbor::value::Value, want: &'static str) -> Result<T, CborError> {
    use cbor::value::Value;
    let got = match value {
        Value::Integer(_) => "int",
        Value::Bytes(_) => "bstr",
        Value::Text(_) => "tstr",
        Value::Array(_) => "array",
        Value::Map(_) => "map",
        Value::Tag(_, _) => "tag",
        Value::Float(_) => "float",
        Value::Bool(_) => "bool",
        Value::Null => "null",
        _ => "unknown",
    };
    Err(CborError::UnexpectedItem(got, want))
}

pub fn read_to_value(mut slice: &[u8]) -> Result<cbor::value::Value, CborError> {
    let value = cbor::de::from_reader_with_recursion_limit(&mut slice, 16)?;
    if slice.is_empty() {
        Ok(value)
    } else {
        Err(CborError::ExtraneousData)
    }
}

pub trait AsCborValue: Sized {
    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError>;

    fn to_cbor_value(self) -> Result<cbor::value::Value, CborError>;

    fn from_slice(slice: &[u8]) -> Result<Self, CborError> {
        Self::from_cbor_value(read_to_value(slice)?)
    }

    fn into_vec(self) -> Result<Vec<u8>, CborError> {
        let mut data = Vec::new();
        cbor::ser::into_writer(&self.to_cbor_value()?, &mut data)?;
        Ok(data)
    }

    fn cddl_typename() -> Option<String> {
        None
    }

    fn cddl_schema() -> Option<String> {
        None
    }

    fn cddl_ref() -> String {
        if let Some(item_name) = Self::cddl_typename() {
            item_name
        } else if let Some(item_schema) = Self::cddl_schema() {
            item_schema
        } else {
            panic!("type with unknown CDDL")
        }
    }
}

impl AsCborValue for coset::CoseEncrypt0 {
    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
        match value {
            cbor::value::Value::Tag(tag, inner_value) if tag == coset::CoseEncrypt0::TAG => {
                <coset::CoseEncrypt0 as coset::AsCborValue>::from_cbor_value(*inner_value)
                    .map_err(|e| e.into())
            }
            cbor::value::Value::Tag(_, _) => Err(CborError::UnexpectedItem("tag", "tag 16")),
            _ => cbor_type_error(&value, "tag 16"),
        }
    }
    fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
        Ok(cbor::value::Value::Tag(
            coset::CoseEncrypt0::TAG,
            std::boxed::Box::new(coset::AsCborValue::to_cbor_value(self)?),
        ))
    }
    fn cddl_schema() -> Option<String> {
        Some(format!("#6.{}(Cose_Encrypt0)", coset::CoseEncrypt0::TAG))
    }
}

impl<T: AsCborValue> AsCborValue for Option<T> {
    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
        let mut arr = match value {
            cbor::value::Value::Array(a) => a,
            _ => return Err(CborError::UnexpectedItem("non-arr", "arr")),
        };
        match arr.len() {
            0 => Ok(None),
            1 => Ok(Some(<T>::from_cbor_value(arr.remove(0))?)),
            _ => Err(CborError::UnexpectedItem("arr len >1", "arr len 0/1")),
        }
    }

    fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
        match self {
            Some(t) => Ok(cbor::value::Value::Array(vec_try![t.to_cbor_value()?]?)),
            None => Ok(cbor::value::Value::Array(Vec::new())),
        }
    }

    fn cddl_schema() -> Option<String> {
        Some(format!("[? {}]", <T>::cddl_ref()))
    }
}

impl<T: AsCborValue> AsCborValue for Vec<T> {
    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
        let arr = match value {
            cbor::value::Value::Array(a) => a,
            _ => return cbor_type_error(&value, "arr"),
        };
        let results: Result<Vec<_>, _> = arr.into_iter().map(<T>::from_cbor_value).collect();
        results
    }

    fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
        let values: Result<Vec<_>, _> = self.into_iter().map(|v| v.to_cbor_value()).collect();
        Ok(cbor::value::Value::Array(values?))
    }

    fn cddl_schema() -> Option<String> {
        Some(format!("[* {}]", <T>::cddl_ref()))
    }
}

impl AsCborValue for Vec<u8> {
    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
        match value {
            cbor::value::Value::Bytes(bstr) => Ok(bstr),
            _ => cbor_type_error(&value, "bstr"),
        }
    }

    fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
        Ok(cbor::value::Value::Bytes(self))
    }

    fn cddl_typename() -> Option<String> {
        Some("bstr".to_string())
    }
}

impl<const N: usize> AsCborValue for [u8; N] {
    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
        let data = match value {
            cbor::value::Value::Bytes(bstr) => bstr,
            _ => return cbor_type_error(&value, "bstr"),
        };
        data.try_into()
            .map_err(|_e| CborError::UnexpectedItem("bstr other size", "bstr specific size"))
    }

    fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
        let mut v = std::vec::Vec::new();
        if v.try_reserve(self.len()).is_err() {
            return Err(CborError::AllocationFailed);
        }
        v.extend_from_slice(&self);
        Ok(cbor::value::Value::Bytes(v))
    }

    fn cddl_typename() -> Option<String> {
        Some(format!("bstr .size {N}"))
    }
}

impl AsCborValue for String {
    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
        match value {
            cbor::value::Value::Text(s) => Ok(s),
            _ => cbor_type_error(&value, "tstr"),
        }
    }

    fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
        Ok(cbor::value::Value::Text(self))
    }

    fn cddl_typename() -> Option<String> {
        Some("tstr".to_string())
    }
}

impl AsCborValue for u64 {
    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
        match value {
            cbor::value::Value::Integer(i) => i
                .try_into()
                .map_err(|_| crate::CborError::OutOfRangeIntegerValue),
            v => crate::cbor_type_error(&v, "u64"),
        }
    }

    fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
        Ok(cbor::value::Value::Integer(self.into()))
    }

    fn cddl_typename() -> Option<String> {
        Some("int".to_string())
    }
}

impl AsCborValue for i64 {
    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
        match value {
            cbor::value::Value::Integer(i) => i
                .try_into()
                .map_err(|_| crate::CborError::OutOfRangeIntegerValue),
            v => crate::cbor_type_error(&v, "i64"),
        }
    }

    fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
        Ok(cbor::value::Value::Integer(self.into()))
    }

    fn cddl_typename() -> Option<String> {
        Some("int".to_string())
    }
}

impl AsCborValue for u32 {
    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
        match value {
            cbor::value::Value::Integer(i) => i
                .try_into()
                .map_err(|_| crate::CborError::OutOfRangeIntegerValue),
            v => crate::cbor_type_error(&v, "u32"),
        }
    }

    fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
        Ok(cbor::value::Value::Integer(self.into()))
    }

    fn cddl_typename() -> Option<String> {
        Some("int".to_string())
    }
}

impl AsCborValue for bool {
    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
        match value {
            cbor::value::Value::Bool(b) => Ok(b),
            v => crate::cbor_type_error(&v, "bool"),
        }
    }
    fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
        Ok(cbor::value::Value::Bool(self))
    }

    fn cddl_typename() -> Option<String> {
        Some("bool".to_string())
    }
}

impl AsCborValue for () {
    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
        match value {
            cbor::value::Value::Null => Ok(()),
            v => crate::cbor_type_error(&v, "null"),
        }
    }
    fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
        Ok(cbor::value::Value::Null)
    }

    fn cddl_typename() -> Option<String> {
        Some("null".to_string())
    }
}

impl AsCborValue for i32 {
    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
        match value {
            cbor::value::Value::Integer(i) => i
                .try_into()
                .map_err(|_| crate::CborError::OutOfRangeIntegerValue),
            v => crate::cbor_type_error(&v, "i64"),
        }
    }

    fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
        Ok(cbor::value::Value::Integer(self.into()))
    }

    fn cddl_typename() -> Option<String> {
        Some("int".to_string())
    }
}
