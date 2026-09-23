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

use crate::{km_err, Error};
use kmr_wire::keymint::{Tag, TagType};

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Characteristic {
    KeyMintEnforced,

    KeyMintHidden,

    KeystoreEnforced,

    BothEnforced,

    NotKeyCharacteristic,
}

pub const KEYSTORE_ENFORCED_CHARACTERISTICS: &[Tag] = &[
    Tag::ActiveDatetime,
    Tag::OriginationExpireDatetime,
    Tag::UsageExpireDatetime,
    Tag::UserId,
    Tag::AllowWhileOnBody,
    Tag::CreationDatetime,
    Tag::MaxBootLevel,
    Tag::UnlockedDeviceRequired,
];

pub const KEYMINT_ENFORCED_CHARACTERISTICS: &[Tag] = &[
    Tag::UserSecureId,
    Tag::Algorithm,
    Tag::EcCurve,
    Tag::MlDsaVariant,
    Tag::UserAuthType,
    Tag::Origin,
    Tag::Purpose,
    Tag::BlockMode,
    Tag::Digest,
    Tag::Padding,
    Tag::RsaOaepMgfDigest,
    Tag::KeySize,
    Tag::MinMacLength,
    Tag::MaxUsesPerBoot,
    Tag::AuthTimeout,
    Tag::OsVersion,
    Tag::OsPatchlevel,
    Tag::VendorPatchlevel,
    Tag::BootPatchlevel,
    Tag::RsaPublicExponent,
    Tag::CallerNonce,
    Tag::BootloaderOnly,
    Tag::RollbackResistance,
    Tag::EarlyBootOnly,
    Tag::NoAuthRequired,
    Tag::TrustedUserPresenceRequired,
    Tag::TrustedConfirmationRequired,
    Tag::StorageKey,
];

pub const AUTO_ADDED_CHARACTERISTICS: &[Tag] = &[
    Tag::Origin,
    Tag::OsVersion,
    Tag::OsPatchlevel,
    Tag::VendorPatchlevel,
    Tag::BootPatchlevel,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationParam {
    KeyGenImport,

    CipherExplicitArgOneOf,

    CipherParamOneOf,

    CipherParamExactMatch,

    CipherParam,

    NotOperationParam,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserSpecifiable(pub bool);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoAddedCharacteristic(pub bool);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueLifetime {
    FixedAtBoot,

    FixedAtStartup,

    Variable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertGenParam {
    NotRequired,

    Required,

    RequiredForAttestation,

    Optional,

    OptionalForAttestation,

    Special,
}

#[derive(Debug, Clone)]
pub struct Info {
    pub name: &'static str,

    pub tt: TagType,

    pub ext_asn1_type: Option<&'static str>,

    pub user_can_specify: UserSpecifiable,

    pub characteristic: Characteristic,

    pub op_param: OperationParam,

    pub keymint_auto_adds: AutoAddedCharacteristic,

    pub lifetime: ValueLifetime,

    pub cert_gen: CertGenParam,

    bit_index: usize,
}

const INFO: [(Tag, Info); 62] = [
    (
        Tag::Purpose,
        Info {
            name: "PURPOSE",
            tt: TagType::EnumRep,
            ext_asn1_type: Some("SET OF INTEGER"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::CipherExplicitArgOneOf,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 0,
        },
    ),
    (
        Tag::Algorithm,
        Info {
            name: "ALGORITHM",
            tt: TagType::Enum,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 1,
        },
    ),
    (
        Tag::KeySize,
        Info {
            name: "KEY_SIZE",
            tt: TagType::Uint,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 2,
        },
    ),
    (
        Tag::BlockMode,
        Info {
            name: "BLOCK_MODE",
            tt: TagType::EnumRep,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::CipherParamOneOf,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 3,
        },
    ),
    (
        Tag::Digest,
        Info {
            name: "DIGEST",
            tt: TagType::EnumRep,
            ext_asn1_type: Some("SET OF INTEGER"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::CipherParamOneOf,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 4,
        },
    ),
    (
        Tag::Padding,
        Info {
            name: "PADDING",
            tt: TagType::EnumRep,
            ext_asn1_type: Some("SET OF INTEGER"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::CipherParamOneOf,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 5,
        },
    ),
    (
        Tag::CallerNonce,
        Info {
            name: "CALLER_NONCE",
            tt: TagType::Bool,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 6,
        },
    ),
    (
        Tag::MinMacLength,
        Info {
            name: "MIN_MAC_LENGTH",
            tt: TagType::Uint,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 7,
        },
    ),
    (
        Tag::EcCurve,
        Info {
            name: "EC_CURVE",
            tt: TagType::Enum,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 8,
        },
    ),
    (
        Tag::RsaPublicExponent,
        Info {
            name: "RSA_PUBLIC_EXPONENT",
            tt: TagType::Ulong,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 9,
        },
    ),
    (
        Tag::IncludeUniqueId,
        Info {
            name: "INCLUDE_UNIQUE_ID",
            tt: TagType::Bool,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::OptionalForAttestation,
            bit_index: 10,
        },
    ),
    (
        Tag::RsaOaepMgfDigest,
        Info {
            name: "RSA_OAEP_MGF_DIGEST",
            tt: TagType::EnumRep,
            ext_asn1_type: Some("SET OF INTEGER"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::CipherParamOneOf,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 11,
        },
    ),
    (
        Tag::BootloaderOnly,
        Info {
            name: "BOOTLOADER_ONLY",
            tt: TagType::Bool,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(false),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 12,
        },
    ),
    (
        Tag::RollbackResistance,
        Info {
            name: "ROLLBACK_RESISTANCE",
            tt: TagType::Bool,
            ext_asn1_type: Some("NULL"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 13,
        },
    ),
    (
        Tag::EarlyBootOnly,
        Info {
            name: "EARLY_BOOT_ONLY",
            tt: TagType::Bool,
            ext_asn1_type: Some("NULL"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 14,
        },
    ),
    (
        Tag::ActiveDatetime,
        Info {
            name: "ACTIVE_DATETIME",
            tt: TagType::Date,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeystoreEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 15,
        },
    ),
    (
        Tag::OriginationExpireDatetime,
        Info {
            name: "ORIGINATION_EXPIRE_DATETIME",
            tt: TagType::Date,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeystoreEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 16,
        },
    ),
    (
        Tag::UsageExpireDatetime,
        Info {
            name: "USAGE_EXPIRE_DATETIME",
            tt: TagType::Date,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeystoreEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 17,
        },
    ),
    (
        Tag::MaxUsesPerBoot,
        Info {
            name: "MAX_USES_PER_BOOT",
            tt: TagType::Uint,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 18,
        },
    ),
    (
        Tag::UsageCountLimit,
        Info {
            name: "USAGE_COUNT_LIMIT",
            tt: TagType::Uint,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::BothEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 19,
        },
    ),
    (
        Tag::UserId,
        Info {
            name: "USER_ID",
            tt: TagType::Uint,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeystoreEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 20,
        },
    ),
    (
        Tag::UserSecureId,
        Info {
            name: "USER_SECURE_ID",
            tt: TagType::UlongRep,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::CipherExplicitArgOneOf,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 21,
        },
    ),
    (
        Tag::NoAuthRequired,
        Info {
            name: "NO_AUTH_REQUIRED",
            tt: TagType::Bool,
            ext_asn1_type: Some("NULL"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 22,
        },
    ),
    (
        Tag::UserAuthType,
        Info {
            name: "USER_AUTH_TYPE",
            tt: TagType::Enum,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::CipherParamOneOf,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 23,
        },
    ),
    (
        Tag::AuthTimeout,
        Info {
            name: "AUTH_TIMEOUT",
            tt: TagType::Uint,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 24,
        },
    ),
    (
        Tag::AllowWhileOnBody,
        Info {
            name: "ALLOW_WHILE_ON_BODY",
            tt: TagType::Bool,
            ext_asn1_type: Some("NULL"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeystoreEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 25,
        },
    ),
    (
        Tag::TrustedUserPresenceRequired,
        Info {
            name: "TRUSTED_USER_PRESENCE_REQUIRED",
            tt: TagType::Bool,
            ext_asn1_type: Some("NULL"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 26,
        },
    ),
    (
        Tag::TrustedConfirmationRequired,
        Info {
            name: "TRUSTED_CONFIRMATION_REQUIRED",
            tt: TagType::Bool,
            ext_asn1_type: Some("NULL"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 27,
        },
    ),
    (
        Tag::UnlockedDeviceRequired,
        Info {
            name: "UNLOCKED_DEVICE_REQUIRED",
            tt: TagType::Bool,
            ext_asn1_type: Some("NULL"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeystoreEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 28,
        },
    ),
    (
        Tag::ApplicationId,
        Info {
            name: "APPLICATION_ID",
            tt: TagType::Bytes,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintHidden,
            op_param: OperationParam::CipherParamExactMatch,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 29,
        },
    ),
    (
        Tag::ApplicationData,
        Info {
            name: "APPLICATION_DATA",
            tt: TagType::Bytes,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintHidden,
            op_param: OperationParam::CipherParamExactMatch,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 30,
        },
    ),
    (
        Tag::CreationDatetime,
        Info {
            name: "CREATION_DATETIME",
            tt: TagType::Date,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeystoreEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,

            cert_gen: CertGenParam::Special,
            bit_index: 31,
        },
    ),
    (
        Tag::Origin,
        Info {
            name: "ORIGIN",
            tt: TagType::Enum,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(false),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(true),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 32,
        },
    ),
    (
        Tag::RootOfTrust,
        Info {
            name: "ROOT_OF_TRUST",
            tt: TagType::Bytes,
            ext_asn1_type: Some("RootOfTrust SEQUENCE"),
            user_can_specify: UserSpecifiable(false),

            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::FixedAtBoot,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 33,
        },
    ),
    (
        Tag::OsVersion,
        Info {
            name: "OS_VERSION",
            tt: TagType::Uint,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(false),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(true),
            lifetime: ValueLifetime::FixedAtBoot,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 34,
        },
    ),
    (
        Tag::OsPatchlevel,
        Info {
            name: "OS_PATCHLEVEL",
            tt: TagType::Uint,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(false),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(true),
            lifetime: ValueLifetime::FixedAtBoot,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 35,
        },
    ),
    (
        Tag::UniqueId,
        Info {
            name: "UNIQUE_ID",
            tt: TagType::Bytes,
            ext_asn1_type: Some("OCTET STRING"),
            user_can_specify: UserSpecifiable(false),

            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::Special,
            bit_index: 36,
        },
    ),
    (
        Tag::AttestationChallenge,
        Info {
            name: "ATTESTATION_CHALLENGE",
            tt: TagType::Bytes,
            ext_asn1_type: Some("OCTET STRING"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::RequiredForAttestation,
            bit_index: 37,
        },
    ),
    (
        Tag::AttestationApplicationId,
        Info {
            name: "ATTESTATION_APPLICATION_ID",
            tt: TagType::Bytes,
            ext_asn1_type: Some("OCTET STRING"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::RequiredForAttestation,
            bit_index: 38,
        },
    ),
    (
        Tag::AttestationIdBrand,
        Info {
            name: "ATTESTATION_ID_BRAND",
            tt: TagType::Bytes,
            ext_asn1_type: Some("OCTET STRING"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::FixedAtBoot,
            cert_gen: CertGenParam::OptionalForAttestation,
            bit_index: 39,
        },
    ),
    (
        Tag::AttestationIdDevice,
        Info {
            name: "ATTESTATION_ID_DEVICE",
            tt: TagType::Bytes,
            ext_asn1_type: Some("OCTET STRING"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::FixedAtBoot,
            cert_gen: CertGenParam::OptionalForAttestation,
            bit_index: 40,
        },
    ),
    (
        Tag::AttestationIdProduct,
        Info {
            name: "ATTESTATION_ID_PRODUCT",
            tt: TagType::Bytes,
            ext_asn1_type: Some("OCTET STRING"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::FixedAtBoot,
            cert_gen: CertGenParam::OptionalForAttestation,
            bit_index: 41,
        },
    ),
    (
        Tag::AttestationIdSerial,
        Info {
            name: "ATTESTATION_ID_SERIAL",
            tt: TagType::Bytes,
            ext_asn1_type: Some("OCTET STRING"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::FixedAtBoot,
            cert_gen: CertGenParam::OptionalForAttestation,
            bit_index: 42,
        },
    ),
    (
        Tag::AttestationIdImei,
        Info {
            name: "ATTESTATION_ID_IMEI",
            tt: TagType::Bytes,
            ext_asn1_type: Some("OCTET STRING"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::FixedAtBoot,
            cert_gen: CertGenParam::OptionalForAttestation,
            bit_index: 43,
        },
    ),
    (
        Tag::AttestationIdSecondImei,
        Info {
            name: "ATTESTATION_ID_SECOND_IMEI",
            tt: TagType::Bytes,
            ext_asn1_type: Some("OCTET STRING"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::FixedAtBoot,
            cert_gen: CertGenParam::OptionalForAttestation,
            bit_index: 44,
        },
    ),
    (
        Tag::AttestationIdMeid,
        Info {
            name: "ATTESTATION_ID_MEID",
            tt: TagType::Bytes,
            ext_asn1_type: Some("OCTET STRING"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::FixedAtBoot,
            cert_gen: CertGenParam::OptionalForAttestation,
            bit_index: 45,
        },
    ),
    (
        Tag::AttestationIdManufacturer,
        Info {
            name: "ATTESTATION_ID_MANUFACTURER",
            tt: TagType::Bytes,
            ext_asn1_type: Some("OCTET STRING"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::FixedAtBoot,
            cert_gen: CertGenParam::OptionalForAttestation,
            bit_index: 46,
        },
    ),
    (
        Tag::AttestationIdModel,
        Info {
            name: "ATTESTATION_ID_MODEL",
            tt: TagType::Bytes,
            ext_asn1_type: Some("OCTET STRING"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::FixedAtBoot,
            cert_gen: CertGenParam::OptionalForAttestation,
            bit_index: 47,
        },
    ),
    (
        Tag::VendorPatchlevel,
        Info {
            name: "VENDOR_PATCHLEVEL",
            tt: TagType::Uint,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(false),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(true),
            lifetime: ValueLifetime::FixedAtStartup,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 48,
        },
    ),
    (
        Tag::BootPatchlevel,
        Info {
            name: "BOOT_PATCHLEVEL",
            tt: TagType::Uint,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(false),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(true),
            lifetime: ValueLifetime::FixedAtBoot,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 49,
        },
    ),
    (
        Tag::DeviceUniqueAttestation,
        Info {
            name: "DEVICE_UNIQUE_ATTESTATION",
            tt: TagType::Bool,
            ext_asn1_type: Some("NULL"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,

            cert_gen: CertGenParam::Special,
            bit_index: 50,
        },
    ),
    (
        Tag::StorageKey,
        Info {
            name: "STORAGE_KEY",
            tt: TagType::Bool,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 51,
        },
    ),
    (
        Tag::Nonce,
        Info {
            name: "NONCE",
            tt: TagType::Bytes,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::CipherParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 52,
        },
    ),
    (
        Tag::MacLength,
        Info {
            name: "MAC_LENGTH",
            tt: TagType::Uint,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::CipherParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 53,
        },
    ),
    (
        Tag::ResetSinceIdRotation,
        Info {
            name: "RESET_SINCE_ID_ROTATION",
            tt: TagType::Bool,
            ext_asn1_type: Some("part of UniqueID"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::OptionalForAttestation,
            bit_index: 54,
        },
    ),
    (
        Tag::CertificateSerial,
        Info {
            name: "CERTIFICATE_SERIAL",
            tt: TagType::Bignum,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::Optional,
            bit_index: 55,
        },
    ),
    (
        Tag::CertificateSubject,
        Info {
            name: "CERTIFICATE_SUBJECT",
            tt: TagType::Bytes,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::Optional,
            bit_index: 56,
        },
    ),
    (
        Tag::CertificateNotBefore,
        Info {
            name: "CERTIFICATE_NOT_BEFORE",
            tt: TagType::Date,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::Required,
            bit_index: 57,
        },
    ),
    (
        Tag::CertificateNotAfter,
        Info {
            name: "CERTIFICATE_NOT_AFTER",
            tt: TagType::Date,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::Required,
            bit_index: 58,
        },
    ),
    (
        Tag::MaxBootLevel,
        Info {
            name: "MAX_BOOT_LEVEL",
            tt: TagType::Uint,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeystoreEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 59,
        },
    ),
    (
        Tag::ModuleHash,
        Info {
            name: "MODULE_HASH",
            tt: TagType::Bytes,
            ext_asn1_type: Some("OCTET STRING"),
            user_can_specify: UserSpecifiable(false),

            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::FixedAtStartup,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 60,
        },
    ),
    (
        Tag::MlDsaVariant,
        Info {
            name: "ML_DSA_VARIANT",
            tt: TagType::Enum,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 61,
        },
    ),
];

pub fn info(tag: Tag) -> Result<&'static Info, Error> {
    for (t, info) in &INFO {
        if tag == *t {
            return Ok(info);
        }
    }
    Err(km_err!(InvalidTag, "unknown tag {:?}", tag))
}

#[inline]
pub fn multivalued(tag: Tag) -> bool {
    matches!(
        kmr_wire::keymint::tag_type(tag),
        TagType::EnumRep | TagType::UintRep | TagType::UlongRep
    )
}

#[derive(Default)]
pub struct DuplicateTagChecker(u64);

impl DuplicateTagChecker {
    pub fn add(&mut self, tag: Tag) -> Result<(), Error> {
        let bit_idx = info(tag)?.bit_index;
        let bit_mask = 0x01u64 << bit_idx;
        if !multivalued(tag) && (self.0 & bit_mask) != 0 {
            return Err(km_err!(InvalidKeyBlob, "duplicate value for {:?}", tag));
        }
        self.0 |= bit_mask;
        Ok(())
    }
}
