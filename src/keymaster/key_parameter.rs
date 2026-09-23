// Copyright 2020, The Android Open Source Project
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

use std::convert::TryInto;

use crate::android::system::keystore2::Authorization::Authorization;
use crate::keymaster::database::utils::SqlField;
use crate::keymaster::error::Error as KeystoreError;
use crate::keymaster::error::ResponseCode;

pub use crate::android::hardware::security::keymint::{
    Algorithm::Algorithm, BlockMode::BlockMode, Digest::Digest, EcCurve::EcCurve,
    HardwareAuthenticatorType::HardwareAuthenticatorType, KeyOrigin::KeyOrigin,
    KeyParameter::KeyParameter as KmKeyParameter,
    KeyParameterValue::KeyParameterValue as KmKeyParameterValue, KeyPurpose::KeyPurpose,
    MlDsaVariant::MlDsaVariant, PaddingMode::PaddingMode, SecurityLevel::SecurityLevel, Tag::Tag,
};
use anyhow::{Context, Result};
use rusqlite::types::{Null, ToSql, ToSqlOutput};
use rusqlite::Result as SqlResult;
use serde::de::Deserializer;
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod generated_key_parameter_tests;

#[cfg(test)]
mod basic_tests;

#[cfg(test)]
mod storage_tests;

#[cfg(test)]
mod wire_tests;

trait AssociatePrimitive {
    type Primitive: Into<Primitive> + TryFrom<Primitive>;

    fn from_primitive(v: Self::Primitive) -> Self;
    fn to_primitive(&self) -> Self::Primitive;
}

macro_rules! implement_associate_primitive_for_aidl_enum {
    ($t:ty) => {
        impl AssociatePrimitive for $t {
            type Primitive = i32;

            fn from_primitive(v: Self::Primitive) -> Self {
                Self(v)
            }
            fn to_primitive(&self) -> Self::Primitive {
                self.0
            }
        }
    };
}

macro_rules! implement_associate_primitive_identity {
    ($t:ty) => {
        impl AssociatePrimitive for $t {
            type Primitive = $t;

            fn from_primitive(v: Self::Primitive) -> Self {
                v
            }
            fn to_primitive(&self) -> Self::Primitive {
                self.clone()
            }
        }
    };
}

implement_associate_primitive_for_aidl_enum! {Algorithm}
implement_associate_primitive_for_aidl_enum! {BlockMode}
implement_associate_primitive_for_aidl_enum! {Digest}
implement_associate_primitive_for_aidl_enum! {EcCurve}
implement_associate_primitive_for_aidl_enum! {HardwareAuthenticatorType}
implement_associate_primitive_for_aidl_enum! {KeyOrigin}
implement_associate_primitive_for_aidl_enum! {KeyPurpose}
implement_associate_primitive_for_aidl_enum! {MlDsaVariant}
implement_associate_primitive_for_aidl_enum! {PaddingMode}
implement_associate_primitive_for_aidl_enum! {SecurityLevel}

implement_associate_primitive_identity! {Vec<u8>}
implement_associate_primitive_identity! {i64}
implement_associate_primitive_identity! {i32}

#[derive(Deserialize, Serialize)]
pub enum Primitive {
    I64(i64),

    I32(i32),

    Vec(Vec<u8>),
}

impl From<i64> for Primitive {
    fn from(v: i64) -> Self {
        Self::I64(v)
    }
}
impl From<i32> for Primitive {
    fn from(v: i32) -> Self {
        Self::I32(v)
    }
}
impl From<Vec<u8>> for Primitive {
    fn from(v: Vec<u8>) -> Self {
        Self::Vec(v)
    }
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PrimitiveError {
    #[error("Primitive does not match the expected tag type.")]
    TypeMismatch,

    #[error("Unknown tag.")]
    UnknownTag,
}

impl TryFrom<Primitive> for i64 {
    type Error = PrimitiveError;

    fn try_from(p: Primitive) -> Result<i64, Self::Error> {
        match p {
            Primitive::I64(v) => Ok(v),
            _ => Err(Self::Error::TypeMismatch),
        }
    }
}
impl TryFrom<Primitive> for i32 {
    type Error = PrimitiveError;

    fn try_from(p: Primitive) -> Result<i32, Self::Error> {
        match p {
            Primitive::I32(v) => Ok(v),
            _ => Err(Self::Error::TypeMismatch),
        }
    }
}
impl TryFrom<Primitive> for Vec<u8> {
    type Error = PrimitiveError;

    fn try_from(p: Primitive) -> Result<Vec<u8>, Self::Error> {
        match p {
            Primitive::Vec(v) => Ok(v),
            _ => Err(Self::Error::TypeMismatch),
        }
    }
}

fn serialize_primitive<S, P>(v: &P, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    P: AssociatePrimitive,
{
    let primitive: Primitive = v.to_primitive().into();
    primitive.serialize(serializer)
}

fn deserialize_primitive<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: AssociatePrimitive,
{
    let primitive: Primitive = serde::de::Deserialize::deserialize(deserializer)?;
    Ok(T::from_primitive(
        primitive
            .try_into()
            .map_err(|_| serde::de::Error::custom("Type Mismatch"))?,
    ))
}

macro_rules! implement_from_tag_primitive_pair {
    ($enum_name:ident; $($vname:ident$(($vtype:ty))? $tag_name:ident),*) => {


        pub fn new_from_tag_primitive_pair<T: Into<Primitive>>(
            tag: Tag,
            v: T
        ) -> Result<$enum_name, PrimitiveError> {
            let p: Primitive = v.into();
            Ok(match tag {
                $(Tag::$tag_name => $enum_name::$vname$((
                    <$vtype>::from_primitive(p.try_into()?)
                ))?,)*
                _ => return Err(PrimitiveError::UnknownTag),
            })
        }
    };
}

macro_rules! implement_enum {
    (
        $(#[$enum_meta:meta])*
        $enum_vis:vis enum $enum_name:ident {
             $($(#[$emeta:meta])* $vname:ident$(($vtype:ty))?),* $(,)?
        }
    ) => {
        $(#[$enum_meta])*
        $enum_vis enum $enum_name {
            $(
                $(#[$emeta])*
                $vname$(($vtype))?
            ),*
        }
    };
}

macro_rules! implement_get_tag {
    (
        @replace_type_spec
        $enum_name:ident,
        [$($out:tt)*],
        [$vname:ident($vtype:ty) $tag_name:ident, $($in:tt)*]
    ) => {
        implement_get_tag!{@replace_type_spec $enum_name, [$($out)*
            $enum_name::$vname(_) => Tag::$tag_name,
        ], [$($in)*]}
    };
    (
        @replace_type_spec
        $enum_name:ident,
        [$($out:tt)*],
        [$vname:ident $tag_name:ident, $($in:tt)*]
    ) => {
        implement_get_tag!{@replace_type_spec $enum_name, [$($out)*
            $enum_name::$vname => Tag::$tag_name,
        ], [$($in)*]}
    };
    (@replace_type_spec $enum_name:ident, [$($out:tt)*], []) => {

        pub fn get_tag(&self) -> Tag {
            match self {
                $($out)*
            }
        }
    };

    ($enum_name:ident; $($vname:ident$(($vtype:ty))? $tag_name:ident),*) => {
        implement_get_tag!{@replace_type_spec $enum_name, [], [$($vname$(($vtype))? $tag_name,)*]}
    };
}

macro_rules! implement_to_sql {
    (
        @replace_type_spec
        $enum_name:ident,
        [$($out:tt)*],
        [$vname:ident($vtype:ty), $($in:tt)*]
    ) => {
        implement_to_sql!{@replace_type_spec $enum_name, [ $($out)*
            $enum_name::$vname(v) => Ok(ToSqlOutput::from(v.to_primitive())),
        ], [$($in)*]}
    };
    (
        @replace_type_spec
        $enum_name:ident,
        [$($out:tt)*],
        [$vname:ident, $($in:tt)*]
    ) => {
        implement_to_sql!{@replace_type_spec $enum_name, [ $($out)*
            $enum_name::$vname => Ok(ToSqlOutput::from(Null)),
        ], [$($in)*]}
    };
    (@replace_type_spec $enum_name:ident, [$($out:tt)*], []) => {

        fn to_sql(&self) -> SqlResult<ToSqlOutput<'_>> {
            match self {
                $($out)*
            }
        }
    };


    ($enum_name:ident; $($vname:ident$(($vtype:ty))?),*) => {
        impl ToSql for $enum_name {
            implement_to_sql!{@replace_type_spec $enum_name, [], [$($vname$(($vtype))?,)*]}
        }

    }
}

macro_rules! implement_new_from_sql {
    ($enum_name:ident; $($vname:ident$(($vtype:ty))? $tag_name:ident),*) => {



        pub fn new_from_sql(
            tag: Tag,
            data: &SqlField,
        ) -> Result<Self> {
            Ok(match tag {
                $(
                    Tag::$tag_name => {
                        $enum_name::$vname$((<$vtype>::from_primitive(data
                            .get()
                            .map_err(|_| KeystoreError::Rc(ResponseCode::VALUE_CORRUPTED))
                            .context(concat!(
                                "Failed to read sql data for tag: ",
                                stringify!($tag_name),
                                "."
                            ))?
                        )))?
                    },
                )*
                _ => $enum_name::Invalid,
            })
        }
    };
}

trait KpDefault {
    fn default() -> Self;
}

impl KpDefault for i32 {
    fn default() -> Self {
        0
    }
}

impl KpDefault for bool {
    fn default() -> Self {
        true
    }
}

macro_rules! implement_try_from_to_km_parameter {

    (
        @from
        $enum_name:ident,
        [$($out:tt)*],
        [$vname:ident($vtype:ty) $tag_name:ident $field_name:ident, $($in:tt)*]
    ) => {
        implement_try_from_to_km_parameter!{@from $enum_name, [$($out)*
            KmKeyParameter {
                tag: Tag::$tag_name,
                value: KmKeyParameterValue::$field_name(v)
            } => $enum_name::$vname(v),
        ], [$($in)*]
    }};
    (
        @from
        $enum_name:ident,
        [$($out:tt)*],
        [$vname:ident $tag_name:ident $field_name:ident, $($in:tt)*]
    ) => {
        implement_try_from_to_km_parameter!{@from $enum_name, [$($out)*
            KmKeyParameter {
                tag: Tag::$tag_name,
                value: KmKeyParameterValue::$field_name(_)
            } => $enum_name::$vname,
        ], [$($in)*]
    }};
    (@from $enum_name:ident, [$($out:tt)*], []) => {
        impl From<KmKeyParameter> for $enum_name {
            fn from(kp: KmKeyParameter) -> Self {
                match kp {
                    $($out)*
                    _ => $enum_name::Invalid,
                }
            }
        }
    };


    (
        @into
        $enum_name:ident,
        [$($out:tt)*],
        [$vname:ident($vtype:ty) $tag_name:ident $field_name:ident, $($in:tt)*]
    ) => {
        implement_try_from_to_km_parameter!{@into $enum_name, [$($out)*
            $enum_name::$vname(v) => KmKeyParameter {
                tag: Tag::$tag_name,
                value: KmKeyParameterValue::$field_name(v)
            },
        ], [$($in)*]
    }};
    (
        @into
        $enum_name:ident,
        [$($out:tt)*],
        [$vname:ident $tag_name:ident $field_name:ident, $($in:tt)*]
    ) => {
        implement_try_from_to_km_parameter!{@into $enum_name, [$($out)*
            $enum_name::$vname => KmKeyParameter {
                tag: Tag::$tag_name,
                value: KmKeyParameterValue::$field_name(KpDefault::default())
            },
        ], [$($in)*]
    }};
    (@into $enum_name:ident, [$($out:tt)*], []) => {
        impl From<$enum_name> for KmKeyParameter {
            fn from(x: $enum_name) -> Self {
                match x {
                    $($out)*
                }
            }
        }
    };


    ($enum_name:ident; $($vname:ident$(($vtype:ty))? $tag_name:ident $field_name:ident),*) => {
        implement_try_from_to_km_parameter!(
            @from $enum_name,
            [],
            [$($vname$(($vtype))? $tag_name $field_name,)*]
        );
        implement_try_from_to_km_parameter!(
            @into $enum_name,
            [],
            [$($vname$(($vtype))? $tag_name $field_name,)*]
        );
    };
}

macro_rules! implement_key_parameter_value {
    (
        $(#[$enum_meta:meta])*
        $enum_vis:vis enum $enum_name:ident {
            $(
                $(#[$($emeta:tt)+])*
                $vname:ident$(($vtype:ty))?
            ),* $(,)?
        }
    ) => {
        implement_key_parameter_value!{
            @extract_attr
            $(#[$enum_meta])*
            $enum_vis enum $enum_name {
                []
                [$(
                    [] [$(#[$($emeta)+])*]
                    $vname$(($vtype))?,
                )*]
            }
        }
    };

    (
        @extract_attr
        $(#[$enum_meta:meta])*
        $enum_vis:vis enum $enum_name:ident {
            [$($out:tt)*]
            [
                [$(#[$mout:meta])*]
                [
                    #[key_param(tag = $tag_name:ident, field = $field_name:ident)]
                    $(#[$($mtail:tt)+])*
                ]
                $vname:ident$(($vtype:ty))?,
                $($tail:tt)*
            ]
        }
    ) => {
        implement_key_parameter_value!{
            @extract_attr
            $(#[$enum_meta])*
            $enum_vis enum $enum_name {
                [
                    $($out)*
                    $(#[$mout])*
                    $(#[$($mtail)+])*
                    $tag_name $field_name $vname$(($vtype))?,
                ]
                [$($tail)*]
            }
        }
    };

    (
        @extract_attr
        $(#[$enum_meta:meta])*
        $enum_vis:vis enum $enum_name:ident {
            [$($out:tt)*]
            [
                [$(#[$mout:meta])*]
                [
                    #[$front:meta]
                    $(#[$($mtail:tt)+])*
                ]
                $vname:ident$(($vtype:ty))?,
                $($tail:tt)*
            ]
        }
    ) => {
        implement_key_parameter_value!{
            @extract_attr
            $(#[$enum_meta])*
            $enum_vis enum $enum_name {
                [$($out)*]
                [
                    [
                        $(#[$mout])*
                        #[$front]
                    ]
                    [$(#[$($mtail)+])*]
                    $vname$(($vtype))?,
                    $($tail)*
                ]
            }
        }
    };

    (
        @extract_attr
        $(#[$enum_meta:meta])*
        $enum_vis:vis enum $enum_name:ident {
            [$($out:tt)*]
            []
        }
    ) => {
        implement_key_parameter_value!{
            @spill
            $(#[$enum_meta])*
            $enum_vis enum $enum_name {
                $($out)*
            }
        }
    };

    (
        @spill
        $(#[$enum_meta:meta])*
        $enum_vis:vis enum $enum_name:ident {
            $(
                $(#[$emeta:meta])*
                $tag_name:ident $field_name:ident $vname:ident$(($vtype:ty))?,
            )*
        }
    ) => {
        implement_enum!(
            $(#[$enum_meta])*
            $enum_vis enum $enum_name {
            $(
                $(#[$emeta])*
                $vname$(($vtype))?
            ),*
        });

        impl $enum_name {
            implement_new_from_sql!($enum_name; $($vname$(($vtype))? $tag_name),*);
            implement_get_tag!($enum_name; $($vname$(($vtype))? $tag_name),*);
            implement_from_tag_primitive_pair!($enum_name; $($vname$(($vtype))? $tag_name),*);

            #[cfg(test)]
            fn make_field_matches_tag_type_test_vector() -> Vec<KmKeyParameter> {
                vec![$(KmKeyParameter{
                    tag: Tag::$tag_name,
                    value: KmKeyParameterValue::$field_name(Default::default())}
                ),*]
            }

            #[cfg(test)]
            fn make_key_parameter_defaults_vector() -> Vec<KeyParameter> {
                vec![$(KeyParameter{
                    value: KeyParameterValue::$vname$((<$vtype as Default>::default()))?,
                    security_level: SecurityLevel(100),
                }),*]
            }
        }

        implement_try_from_to_km_parameter!(
            $enum_name;
            $($vname$(($vtype))? $tag_name $field_name),*
        );

        implement_to_sql!($enum_name; $($vname$(($vtype))?),*);
    };
}

implement_key_parameter_value! {


#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
pub enum KeyParameterValue {

    #[key_param(tag = INVALID, field = Invalid)]
    Invalid,

    #[serde(deserialize_with = "deserialize_primitive")]
    #[serde(serialize_with = "serialize_primitive")]
    #[key_param(tag = PURPOSE, field = KeyPurpose)]
    KeyPurpose(KeyPurpose),

    #[serde(deserialize_with = "deserialize_primitive")]
    #[serde(serialize_with = "serialize_primitive")]
    #[key_param(tag = ALGORITHM, field = Algorithm)]
    Algorithm(Algorithm),

    #[key_param(tag = KEY_SIZE, field = Integer)]
    KeySize(i32),

    #[serde(deserialize_with = "deserialize_primitive")]
    #[serde(serialize_with = "serialize_primitive")]
    #[key_param(tag = BLOCK_MODE, field = BlockMode)]
    BlockMode(BlockMode),

    #[serde(deserialize_with = "deserialize_primitive")]
    #[serde(serialize_with = "serialize_primitive")]
    #[key_param(tag = DIGEST, field = Digest)]
    Digest(Digest),

    #[serde(deserialize_with = "deserialize_primitive")]
    #[serde(serialize_with = "serialize_primitive")]
    #[key_param(tag = RSA_OAEP_MGF_DIGEST, field = Digest)]
    RsaOaepMgfDigest(Digest),

    #[serde(deserialize_with = "deserialize_primitive")]
    #[serde(serialize_with = "serialize_primitive")]
    #[key_param(tag = PADDING, field = PaddingMode)]
    PaddingMode(PaddingMode),

    #[key_param(tag = CALLER_NONCE, field = BoolValue)]
    CallerNonce,

    #[key_param(tag = MIN_MAC_LENGTH, field = Integer)]
    MinMacLength(i32),

    #[serde(deserialize_with = "deserialize_primitive")]
    #[serde(serialize_with = "serialize_primitive")]
    #[key_param(tag = EC_CURVE, field = EcCurve)]
    EcCurve(EcCurve),

    #[serde(deserialize_with = "deserialize_primitive")]
    #[serde(serialize_with = "serialize_primitive")]
    #[key_param(tag = ML_DSA_VARIANT, field = MlDsaVariant)]
    MlDsaVariant(MlDsaVariant),

    #[key_param(tag = RSA_PUBLIC_EXPONENT, field = LongInteger)]
    RSAPublicExponent(i64),


    #[key_param(tag = INCLUDE_UNIQUE_ID, field = BoolValue)]
    IncludeUniqueID,




    #[key_param(tag = BOOTLOADER_ONLY, field = BoolValue)]
    BootLoaderOnly,

    #[key_param(tag = ROLLBACK_RESISTANCE, field = BoolValue)]
    RollbackResistance,

    #[key_param(tag = EARLY_BOOT_ONLY, field = BoolValue)]
    EarlyBootOnly,

    #[key_param(tag = ACTIVE_DATETIME, field = DateTime)]
    ActiveDateTime(i64),

    #[key_param(tag = ORIGINATION_EXPIRE_DATETIME, field = DateTime)]
    OriginationExpireDateTime(i64),

    #[key_param(tag = USAGE_EXPIRE_DATETIME, field = DateTime)]
    UsageExpireDateTime(i64),

    #[key_param(tag = MIN_SECONDS_BETWEEN_OPS, field = Integer)]
    MinSecondsBetweenOps(i32),

    #[key_param(tag = MAX_USES_PER_BOOT, field = Integer)]
    MaxUsesPerBoot(i32),

    #[key_param(tag = USAGE_COUNT_LIMIT, field = Integer)]
    UsageCountLimit(i32),

    #[key_param(tag = USER_ID, field = Integer)]
    UserID(i32),

    #[key_param(tag = USER_SECURE_ID, field = LongInteger)]
    UserSecureID(i64),

    #[key_param(tag = NO_AUTH_REQUIRED, field = BoolValue)]
    NoAuthRequired,

    #[serde(deserialize_with = "deserialize_primitive")]
    #[serde(serialize_with = "serialize_primitive")]
    #[key_param(tag = USER_AUTH_TYPE, field = HardwareAuthenticatorType)]
    HardwareAuthenticatorType(HardwareAuthenticatorType),

    #[key_param(tag = AUTH_TIMEOUT, field = Integer)]
    AuthTimeout(i32),


    #[key_param(tag = ALLOW_WHILE_ON_BODY, field = BoolValue)]
    AllowWhileOnBody,

    #[key_param(tag = TRUSTED_USER_PRESENCE_REQUIRED, field = BoolValue)]
    TrustedUserPresenceRequired,


    #[key_param(tag = TRUSTED_CONFIRMATION_REQUIRED, field = BoolValue)]
    TrustedConfirmationRequired,

    #[key_param(tag = UNLOCKED_DEVICE_REQUIRED, field = BoolValue)]
    UnlockedDeviceRequired,


    #[key_param(tag = APPLICATION_ID, field = Blob)]
    ApplicationID(Vec<u8>),


    #[key_param(tag = APPLICATION_DATA, field = Blob)]
    ApplicationData(Vec<u8>),

    #[key_param(tag = CREATION_DATETIME, field = DateTime)]
    CreationDateTime(i64),

    #[serde(deserialize_with = "deserialize_primitive")]
    #[serde(serialize_with = "serialize_primitive")]
    #[key_param(tag = ORIGIN, field = Origin)]
    KeyOrigin(KeyOrigin),

    #[key_param(tag = ROOT_OF_TRUST, field = Blob)]
    RootOfTrust(Vec<u8>),

    #[key_param(tag = OS_VERSION, field = Integer)]
    OSVersion(i32),

    #[key_param(tag = OS_PATCHLEVEL, field = Integer)]
    OSPatchLevel(i32),

    #[key_param(tag = UNIQUE_ID, field = Blob)]
    UniqueID(Vec<u8>),

    #[key_param(tag = ATTESTATION_CHALLENGE, field = Blob)]
    AttestationChallenge(Vec<u8>),

    #[key_param(tag = ATTESTATION_APPLICATION_ID, field = Blob)]
    AttestationApplicationID(Vec<u8>),

    #[key_param(tag = ATTESTATION_ID_BRAND, field = Blob)]
    AttestationIdBrand(Vec<u8>),

    #[key_param(tag = ATTESTATION_ID_DEVICE, field = Blob)]
    AttestationIdDevice(Vec<u8>),

    #[key_param(tag = ATTESTATION_ID_PRODUCT, field = Blob)]
    AttestationIdProduct(Vec<u8>),

    #[key_param(tag = ATTESTATION_ID_SERIAL, field = Blob)]
    AttestationIdSerial(Vec<u8>),

    #[key_param(tag = ATTESTATION_ID_IMEI, field = Blob)]
    AttestationIdIMEI(Vec<u8>),

    #[key_param(tag = ATTESTATION_ID_SECOND_IMEI, field = Blob)]
    AttestationIdSecondIMEI(Vec<u8>),

    #[key_param(tag = ATTESTATION_ID_MEID, field = Blob)]
    AttestationIdMEID(Vec<u8>),

    #[key_param(tag = ATTESTATION_ID_MANUFACTURER, field = Blob)]
    AttestationIdManufacturer(Vec<u8>),

    #[key_param(tag = ATTESTATION_ID_MODEL, field = Blob)]
    AttestationIdModel(Vec<u8>),

    #[key_param(tag = VENDOR_PATCHLEVEL, field = Integer)]
    VendorPatchLevel(i32),

    #[key_param(tag = BOOT_PATCHLEVEL, field = Integer)]
    BootPatchLevel(i32),

    #[key_param(tag = ASSOCIATED_DATA, field = Blob)]
    AssociatedData(Vec<u8>),


    #[key_param(tag = NONCE, field = Blob)]
    Nonce(Vec<u8>),

    #[key_param(tag = MAC_LENGTH, field = Integer)]
    MacLength(i32),


    #[key_param(tag = RESET_SINCE_ID_ROTATION, field = BoolValue)]
    ResetSinceIdRotation,


    #[key_param(tag = CONFIRMATION_TOKEN, field = Blob)]
    ConfirmationToken(Vec<u8>),


    #[key_param(tag = CERTIFICATE_SERIAL, field = Blob)]
    CertificateSerial(Vec<u8>),


    #[key_param(tag = CERTIFICATE_SUBJECT, field = Blob)]
    CertificateSubject(Vec<u8>),

    #[key_param(tag = CERTIFICATE_NOT_BEFORE, field = DateTime)]
    CertificateNotBefore(i64),

    #[key_param(tag = CERTIFICATE_NOT_AFTER, field = DateTime)]
    CertificateNotAfter(i64),

    #[key_param(tag = MAX_BOOT_LEVEL, field = Integer)]
    MaxBootLevel(i32),
}
}

impl From<&KmKeyParameter> for KeyParameterValue {
    fn from(kp: &KmKeyParameter) -> Self {
        kp.clone().into()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct KeyParameter {
    value: KeyParameterValue,
    #[serde(deserialize_with = "deserialize_primitive")]
    #[serde(serialize_with = "serialize_primitive")]
    security_level: SecurityLevel,
}

impl KeyParameter {
    pub fn new(value: KeyParameterValue, security_level: SecurityLevel) -> Self {
        KeyParameter {
            value,
            security_level,
        }
    }

    pub fn new_from_sql(
        tag_val: Tag,
        data: &SqlField,
        security_level_val: SecurityLevel,
    ) -> Result<Self> {
        Ok(Self {
            value: KeyParameterValue::new_from_sql(tag_val, data)?,
            security_level: security_level_val,
        })
    }

    pub fn get_tag(&self) -> Tag {
        self.value.get_tag()
    }

    pub fn key_parameter_value(&self) -> &KeyParameterValue {
        &self.value
    }

    pub fn security_level(&self) -> &SecurityLevel {
        &self.security_level
    }

    pub fn into_key_parameter(self) -> KmKeyParameter {
        self.value.into()
    }

    pub fn into_authorization(self) -> Authorization {
        Authorization {
            securityLevel: self.security_level,
            keyParameter: self.value.into(),
        }
    }
}
