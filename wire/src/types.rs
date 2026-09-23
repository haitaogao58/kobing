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

use crate::keymint::{
    AttestationKey, HardwareAuthToken, KeyCharacteristics, KeyCreationResult, KeyFormat,
    KeyMintHardwareInfo, KeyParam, KeyPurpose,
};
use crate::rpc;
use crate::secureclock::TimeStampToken;
use crate::sharedsecret::SharedSecretParameters;
use crate::{cbor, cbor_type_error, vec_try, AsCborValue, CborError};
use enumn::N;
use kmr_derive::AsCborValue;
use std::{
    format,
    string::{String, ToString},
    vec::Vec,
};

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, AsCborValue)]
pub struct KeySizeInBits(pub u32);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, AsCborValue)]
pub struct RsaExponent(pub u64);

pub const DEFAULT_MAX_SIZE: usize = 4096;

#[derive(Debug)]
pub enum ValueNotRecognized {
    KeyPurpose,
    Algorithm,
    BlockMode,
    Digest,
    PaddingMode,
    EcCurve,
    ErrorCode,
    HardwareAuthenticatorType,
    KeyFormat,
    KeyOrigin,
    MlDsaVariant,
    SecurityLevel,
    Tag,
    TagType,
    KmVersion,
    EekCurve,
    Origin,

    Bool,
    Blob,
    DateTime,
    Integer,
    LongInteger,
}

pub trait Code<T> {
    const CODE: T;

    fn code(&self) -> T {
        Self::CODE
    }
}

#[derive(Debug, Default, AsCborValue)]
pub struct InternalBeginResult {
    pub challenge: i64,
    pub params: Vec<KeyParam>,

    pub op_handle: i64,
}

#[derive(Debug, AsCborValue)]
pub struct GetHardwareInfoRequest {}
#[derive(Debug, AsCborValue)]
pub struct GetHardwareInfoResponse {
    pub ret: KeyMintHardwareInfo,
}
#[derive(Debug, AsCborValue)]
pub struct AddRngEntropyRequest {
    pub data: Vec<u8>,
}
#[derive(Debug, AsCborValue)]
pub struct AddRngEntropyResponse {}
#[derive(Debug, AsCborValue)]
pub struct GenerateKeyRequest {
    pub key_params: Vec<KeyParam>,
    pub attestation_key: Option<AttestationKey>,
}
#[derive(Debug, AsCborValue)]
pub struct GenerateKeyResponse {
    pub ret: KeyCreationResult,
}
#[derive(Debug, AsCborValue)]
pub struct ImportKeyRequest {
    pub key_params: Vec<KeyParam>,
    pub key_format: KeyFormat,
    pub key_data: Vec<u8>,
    pub attestation_key: Option<AttestationKey>,
}
#[derive(Debug, AsCborValue)]
pub struct ImportKeyResponse {
    pub ret: KeyCreationResult,
}
#[derive(Debug, AsCborValue)]
pub struct ImportWrappedKeyRequest {
    pub wrapped_key_data: Vec<u8>,
    pub wrapping_key_blob: Vec<u8>,
    pub masking_key: Vec<u8>,
    pub unwrapping_params: Vec<KeyParam>,
    pub password_sid: i64,
    pub biometric_sid: i64,
}
#[derive(Debug, AsCborValue)]
pub struct ImportWrappedKeyResponse {
    pub ret: KeyCreationResult,
}
#[derive(Debug, AsCborValue)]
pub struct UpgradeKeyRequest {
    pub key_blob_to_upgrade: Vec<u8>,
    pub upgrade_params: Vec<KeyParam>,
}
#[derive(Debug, AsCborValue)]
pub struct UpgradeKeyResponse {
    pub ret: Vec<u8>,
}
#[derive(Debug, AsCborValue)]
pub struct DeleteKeyRequest {
    pub key_blob: Vec<u8>,
}
#[derive(Debug, AsCborValue)]
pub struct DeleteKeyResponse {}
#[derive(Debug, AsCborValue)]
pub struct DeleteAllKeysRequest {}
#[derive(Debug, AsCborValue)]
pub struct DeleteAllKeysResponse {}
#[derive(Debug, AsCborValue)]
pub struct DestroyAttestationIdsRequest {}
#[derive(Debug, AsCborValue)]
pub struct DestroyAttestationIdsResponse {}
#[derive(Debug, AsCborValue)]
pub struct BeginRequest {
    pub purpose: KeyPurpose,
    pub key_blob: Vec<u8>,
    pub params: Vec<KeyParam>,
    pub auth_token: Option<HardwareAuthToken>,
}
#[derive(Debug, AsCborValue)]
pub struct BeginResponse {
    pub ret: InternalBeginResult,
}
#[derive(Debug, AsCborValue)]
pub struct EarlyBootEndedRequest {}
#[derive(Debug, AsCborValue)]
pub struct EarlyBootEndedResponse {}
#[derive(Debug, AsCborValue)]
pub struct ConvertStorageKeyToEphemeralRequest {
    pub storage_key_blob: Vec<u8>,
}
#[derive(Debug, AsCborValue)]
pub struct ConvertStorageKeyToEphemeralResponse {
    pub ret: Vec<u8>,
}
#[derive(Debug, AsCborValue)]
pub struct GetKeyCharacteristicsRequest {
    pub key_blob: Vec<u8>,
    pub app_id: Vec<u8>,
    pub app_data: Vec<u8>,
}
#[derive(Debug, AsCborValue)]
pub struct GetKeyCharacteristicsResponse {
    pub ret: Vec<KeyCharacteristics>,
}

#[derive(Debug, AsCborValue)]
pub struct GetRootOfTrustChallengeRequest {}

#[derive(Debug, AsCborValue)]
pub struct GetRootOfTrustChallengeResponse {
    pub ret: [u8; 16],
}

#[derive(Debug, AsCborValue)]
pub struct GetRootOfTrustRequest {
    pub challenge: [u8; 16],
}
#[derive(Debug, AsCborValue)]
pub struct GetRootOfTrustResponse {
    pub ret: Vec<u8>,
}

#[derive(Debug, AsCborValue)]
pub struct SendRootOfTrustRequest {
    pub root_of_trust: Vec<u8>,
}

#[derive(Debug, AsCborValue)]
pub struct SendRootOfTrustResponse {}

#[derive(Debug, AsCborValue)]
pub struct SetAdditionalAttestationInfoRequest {
    pub info: Vec<KeyParam>,
}

#[derive(Debug, AsCborValue)]
pub struct SetAdditionalAttestationInfoResponse {}

#[derive(Debug, Clone, AsCborValue)]
pub struct UpdateAadRequest {
    pub op_handle: i64,
    pub input: Vec<u8>,
    pub auth_token: Option<HardwareAuthToken>,
    pub timestamp_token: Option<TimeStampToken>,
}
#[derive(Debug, AsCborValue)]
pub struct UpdateAadResponse {}
#[derive(Debug, Clone, AsCborValue)]
pub struct UpdateRequest {
    pub op_handle: i64,
    pub input: Vec<u8>,
    pub auth_token: Option<HardwareAuthToken>,
    pub timestamp_token: Option<TimeStampToken>,
}
#[derive(Debug, AsCborValue)]
pub struct UpdateResponse {
    pub ret: Vec<u8>,
}
#[derive(Debug, AsCborValue)]
pub struct FinishRequest {
    pub op_handle: i64,
    pub input: Option<Vec<u8>>,
    pub signature: Option<Vec<u8>>,
    pub auth_token: Option<HardwareAuthToken>,
    pub timestamp_token: Option<TimeStampToken>,
    pub confirmation_token: Option<Vec<u8>>,
}
#[derive(Debug, AsCborValue)]
pub struct FinishResponse {
    pub ret: Vec<u8>,
}
#[derive(Debug, AsCborValue)]
pub struct AbortRequest {
    pub op_handle: i64,
}
#[derive(Debug, AsCborValue)]
pub struct AbortResponse {}

#[derive(Debug, AsCborValue)]
pub struct GetRpcHardwareInfoRequest {}
#[derive(Debug, AsCborValue)]
pub struct GetRpcHardwareInfoResponse {
    pub ret: rpc::HardwareInfo,
}
#[derive(Debug, AsCborValue)]
pub struct GenerateEcdsaP256KeyPairRequest {
    pub test_mode: bool,
}
#[derive(Debug, AsCborValue)]
pub struct GenerateEcdsaP256KeyPairResponse {
    pub maced_public_key: rpc::MacedPublicKey,
    pub ret: Vec<u8>,
}
#[derive(Debug, AsCborValue)]
pub struct GenerateCertificateRequestRequest {
    pub test_mode: bool,
    pub keys_to_sign: Vec<rpc::MacedPublicKey>,
    pub endpoint_encryption_cert_chain: Vec<u8>,
    pub challenge: Vec<u8>,
}
#[derive(Debug, AsCborValue)]
pub struct GenerateCertificateRequestResponse {
    pub device_info: rpc::DeviceInfo,
    pub protected_data: rpc::ProtectedData,
    pub ret: Vec<u8>,
}
#[derive(Debug, AsCborValue)]
pub struct GenerateCertificateRequestV2Request {
    pub keys_to_sign: Vec<rpc::MacedPublicKey>,
    pub challenge: Vec<u8>,
}
#[derive(Debug, AsCborValue)]
pub struct GenerateCertificateRequestV2Response {
    pub ret: Vec<u8>,
}

#[derive(Debug, AsCborValue)]
pub struct GetSharedSecretParametersRequest {}
#[derive(Debug, AsCborValue)]
pub struct GetSharedSecretParametersResponse {
    pub ret: SharedSecretParameters,
}
#[derive(Debug, AsCborValue)]
pub struct ComputeSharedSecretRequest {
    pub params: Vec<SharedSecretParameters>,
}
#[derive(Debug, AsCborValue)]
pub struct ComputeSharedSecretResponse {
    pub ret: Vec<u8>,
}

#[derive(Debug, AsCborValue)]
pub struct GenerateTimeStampRequest {
    pub challenge: i64,
}
#[derive(Debug, AsCborValue)]
pub struct GenerateTimeStampResponse {
    pub ret: TimeStampToken,
}

#[derive(Debug, PartialEq, Eq, AsCborValue)]
pub struct SetHalInfoRequest {
    pub os_version: u32,
    pub os_patchlevel: u32,
    pub vendor_patchlevel: u32,
}
#[derive(Debug, AsCborValue)]
pub struct SetHalInfoResponse {}

#[derive(Debug, PartialEq, Eq, AsCborValue)]
pub struct SetHalVersionRequest {
    pub aidl_version: u32,
}
#[derive(Debug, AsCborValue)]
pub struct SetHalVersionResponse {}

#[derive(Debug, AsCborValue)]
pub struct SetBootInfoRequest {
    pub verified_boot_key: Vec<u8>,
    pub device_boot_locked: bool,
    pub verified_boot_state: i32,
    pub verified_boot_hash: Vec<u8>,
    pub boot_patchlevel: u32,
}
#[derive(Debug, AsCborValue)]
pub struct SetBootInfoResponse {}

#[derive(Clone, Debug, AsCborValue, PartialEq, Eq, Default)]
pub struct AttestationIdInfo {
    pub brand: Vec<u8>,
    pub device: Vec<u8>,
    pub product: Vec<u8>,
    pub serial: Vec<u8>,
    pub imei: Vec<u8>,
    pub imei2: Vec<u8>,
    pub meid: Vec<u8>,
    pub manufacturer: Vec<u8>,
    pub model: Vec<u8>,
}

#[derive(Debug, AsCborValue)]
pub struct SetAttestationIdsRequest {
    pub ids: AttestationIdInfo,
}
#[derive(Debug, AsCborValue)]
pub struct SetAttestationIdsResponse {}

#[derive(AsCborValue, Debug)]
pub struct PerformOpResponse {
    pub error_code: i32,
    pub rsp: Option<PerformOpRsp>,
}

macro_rules! declare_req_rsp_enums {
    {
        $cenum:ident => ($reqenum:ident, $rspenum:ident)
        {
            $( $cname:ident = $cvalue:expr => ($reqtyp:ty, $rsptyp:ty) , )*
        }
    } => {
        declare_req_rsp_enums! { $cenum => ($reqenum, $rspenum)
                                 ( concat!("&(\n",
                                           $( "    [", stringify!($cname), ", {}],\n", )*
                                           ")") )
          {
            $( $cname = $cvalue => ($reqtyp, $rsptyp), )*
        } }
    };
    {
        $cenum:ident => ($reqenum:ident, $rspenum:ident) ( $cddlfmt:expr )
        {
            $( $cname:ident = $cvalue:expr => ($reqtyp:ty, $rsptyp:ty) , )*
        }
    } => {

        #[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, N)]
        pub enum $cenum {
            $( $cname = $cvalue, )*
        }

        impl AsCborValue for $cenum {


            fn from_cbor_value(value: $crate::cbor::value::Value) ->
                Result<Self, crate::CborError> {
                use core::convert::TryInto;

                let v: i32 = match value {
                    $crate::cbor::value::Value::Integer(i) => i.try_into().map_err(|_| {
                        crate::CborError::OutOfRangeIntegerValue
                    })?,
                    v => return crate::cbor_type_error(&v, &"int"),
                };

                Self::n(v).ok_or(crate::CborError::NonEnumValue)
            }


            fn to_cbor_value(self) -> Result<$crate::cbor::value::Value, crate::CborError> {
                Ok($crate::cbor::value::Value::Integer((self as i64).into()))
            }
            fn cddl_typename() -> Option<std::string::String> {
                use std::string::ToString;
                Some(stringify!($cenum).to_string())
            }
            fn cddl_schema() -> Option<std::string::String> {
                use std::string::ToString;
                Some( concat!("&(\n",
                              $( "    ", stringify!($cname), ": ", stringify!($cvalue), ",\n", )*
                              ")").to_string() )
            }
        }

        #[derive(Debug)]
        pub enum $reqenum {
            $( $cname($reqtyp), )*
        }

        impl $reqenum {
            pub fn code(&self) -> $cenum {
                match self {
                    $( Self::$cname(_) => $cenum::$cname, )*
                }
            }
        }

        #[derive(Debug)]
        pub enum $rspenum {
            $( $cname($rsptyp), )*
        }

        impl AsCborValue for $reqenum {
            fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
                let mut a = match value {
                    cbor::value::Value::Array(a) => a,
                    _ => return crate::cbor_type_error(&value, "arr"),
                };
                if a.len() != 2 {
                    return Err(CborError::UnexpectedItem("arr", "arr len 2"));
                }
                let ret_val = a.remove(1);
                let ret_type = <$cenum>::from_cbor_value(a.remove(0))?;
                match ret_type {
                    $( $cenum::$cname => Ok(Self::$cname(<$reqtyp>::from_cbor_value(ret_val)?)), )*
                }
            }
            fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
                Ok(cbor::value::Value::Array(match self {
                    $( Self::$cname(val) => {
                        vec_try![
                            $cenum::$cname.to_cbor_value()?,
                            val.to_cbor_value()?
                        ]?
                    }, )*
                }))
            }

            fn cddl_typename() -> Option<String> {
                use std::string::ToString;
                Some(stringify!($reqenum).to_string())
            }

            fn cddl_schema() -> Option<String> {
                Some(format!($cddlfmt,
                             $( <$reqtyp>::cddl_ref(), )*
                ))
            }
        }

        impl AsCborValue for $rspenum {
            fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
                let mut a = match value {
                    cbor::value::Value::Array(a) => a,
                    _ => return crate::cbor_type_error(&value, "arr"),
                };
                if a.len() != 2 {
                    return Err(CborError::UnexpectedItem("arr", "arr len 2"));
                }
                let ret_val = a.remove(1);
                let ret_type = <$cenum>::from_cbor_value(a.remove(0))?;
                match ret_type {
                    $( $cenum::$cname => Ok(Self::$cname(<$rsptyp>::from_cbor_value(ret_val)?)), )*
                }
            }
            fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
                Ok(cbor::value::Value::Array(match self {
                    $( Self::$cname(val) => {
                        vec_try![
                            $cenum::$cname.to_cbor_value()?,
                            val.to_cbor_value()?
                        ]?
                    }, )*
                }))
            }

            fn cddl_typename() -> Option<String> {
                use std::string::ToString;
                Some(stringify!($rspenum).to_string())
            }

            fn cddl_schema() -> Option<String> {
                Some(format!($cddlfmt,
                             $( <$rsptyp>::cddl_ref(), )*
                ))
            }
        }

        $(
            impl Code<$cenum> for $reqtyp {
                const CODE: $cenum = $cenum::$cname;
            }
        )*

        $(
            impl Code<$cenum> for $rsptyp {
                const CODE: $cenum = $cenum::$cname;
            }
        )*
    };
}

declare_req_rsp_enums! { KeyMintOperation  =>    (PerformOpReq, PerformOpRsp) {
    DeviceGetHardwareInfo = 0x11 =>                    (GetHardwareInfoRequest, GetHardwareInfoResponse),
    DeviceAddRngEntropy = 0x12 =>                      (AddRngEntropyRequest, AddRngEntropyResponse),
    DeviceGenerateKey = 0x13 =>                        (GenerateKeyRequest, GenerateKeyResponse),
    DeviceImportKey = 0x14 =>                          (ImportKeyRequest, ImportKeyResponse),
    DeviceImportWrappedKey = 0x15 =>                   (ImportWrappedKeyRequest, ImportWrappedKeyResponse),
    DeviceUpgradeKey = 0x16 =>                         (UpgradeKeyRequest, UpgradeKeyResponse),
    DeviceDeleteKey = 0x17 =>                          (DeleteKeyRequest, DeleteKeyResponse),
    DeviceDeleteAllKeys = 0x18 =>                      (DeleteAllKeysRequest, DeleteAllKeysResponse),
    DeviceDestroyAttestationIds = 0x19 =>              (DestroyAttestationIdsRequest, DestroyAttestationIdsResponse),
    DeviceBegin = 0x1a =>                              (BeginRequest, BeginResponse),

    DeviceEarlyBootEnded = 0x1c =>                     (EarlyBootEndedRequest, EarlyBootEndedResponse),
    DeviceConvertStorageKeyToEphemeral = 0x1d =>       (ConvertStorageKeyToEphemeralRequest, ConvertStorageKeyToEphemeralResponse),
    DeviceGetKeyCharacteristics = 0x1e =>              (GetKeyCharacteristicsRequest, GetKeyCharacteristicsResponse),
    OperationUpdateAad = 0x31 =>                       (UpdateAadRequest, UpdateAadResponse),
    OperationUpdate = 0x32 =>                          (UpdateRequest, UpdateResponse),
    OperationFinish = 0x33 =>                          (FinishRequest, FinishResponse),
    OperationAbort = 0x34 =>                           (AbortRequest, AbortResponse),
    RpcGetHardwareInfo = 0x41 =>                       (GetRpcHardwareInfoRequest, GetRpcHardwareInfoResponse),
    RpcGenerateEcdsaP256KeyPair = 0x42 =>              (GenerateEcdsaP256KeyPairRequest, GenerateEcdsaP256KeyPairResponse),
    RpcGenerateCertificateRequest = 0x43 =>            (GenerateCertificateRequestRequest, GenerateCertificateRequestResponse),
    RpcGenerateCertificateV2Request = 0x44 =>          (GenerateCertificateRequestV2Request, GenerateCertificateRequestV2Response),
    SharedSecretGetSharedSecretParameters = 0x51 =>    (GetSharedSecretParametersRequest, GetSharedSecretParametersResponse),
    SharedSecretComputeSharedSecret = 0x52 =>          (ComputeSharedSecretRequest, ComputeSharedSecretResponse),
    SecureClockGenerateTimeStamp = 0x61 =>             (GenerateTimeStampRequest, GenerateTimeStampResponse),
    GetRootOfTrustChallenge = 0x71 =>                  (GetRootOfTrustChallengeRequest, GetRootOfTrustChallengeResponse),
    GetRootOfTrust = 0x72 =>                           (GetRootOfTrustRequest, GetRootOfTrustResponse),
    SendRootOfTrust = 0x73 =>                          (SendRootOfTrustRequest, SendRootOfTrustResponse),
    SetHalInfo = 0x81 =>                               (SetHalInfoRequest, SetHalInfoResponse),
    SetBootInfo = 0x82 =>                              (SetBootInfoRequest, SetBootInfoResponse),
    SetAttestationIds = 0x83 =>                        (SetAttestationIdsRequest, SetAttestationIdsResponse),
    SetHalVersion = 0x84 =>                            (SetHalVersionRequest, SetHalVersionResponse),
    SetAdditionalAttestationInfo = 0x91 =>             (SetAdditionalAttestationInfoRequest, SetAdditionalAttestationInfoResponse),
} }

pub fn is_rpc_operation(code: KeyMintOperation) -> bool {
    matches!(
        code,
        KeyMintOperation::RpcGetHardwareInfo
            | KeyMintOperation::RpcGenerateEcdsaP256KeyPair
            | KeyMintOperation::RpcGenerateCertificateRequest
            | KeyMintOperation::RpcGenerateCertificateV2Request
    )
}
