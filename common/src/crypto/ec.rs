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

use super::{CurveType, KeyMaterial, OpaqueOr};
use crate::{der_err, km_err, try_to_vec, vec_try, Error, FallibleAllocExt};
use der::{asn1::BitStringRef, AnyRef, Decode, Encode, Sequence};
use kmr_wire::{coset, keymint::EcCurve, rpc, KeySizeInBits};
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo, SubjectPublicKeyInfoRef};
use std::vec::Vec;
use zeroize::ZeroizeOnDrop;

pub const CURVE25519_PRIV_KEY_LEN: usize = 32;

pub const MAX_ED25519_MSG_SIZE: usize = 16 * 1024;

pub const RKP_TEST_KEY_CBOR_MARKER: i64 = -70000;

pub const SEC1_UNCOMPRESSED_PREFIX: u8 = 0x04;

pub const X509_NIST_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

pub const X509_ED25519_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.3.101.112");

pub const X509_X25519_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.3.101.110");

pub const ECDSA_SHA256_SIGNATURE_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

pub const ALGO_PARAM_P224_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.3.132.0.33");

pub const ALGO_PARAM_P256_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

pub const ALGO_PARAM_P384_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.3.132.0.34");

pub const ALGO_PARAM_P521_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.3.132.0.35");

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(i32)]
pub enum NistCurve {
    P224 = 0,

    P256 = 1,

    P384 = 2,

    P521 = 3,
}

impl NistCurve {
    pub fn coord_len(&self) -> usize {
        match self {
            NistCurve::P224 => 28,
            NistCurve::P256 => 32,
            NistCurve::P384 => 48,
            NistCurve::P521 => 66,
        }
    }
}

impl From<NistCurve> for EcCurve {
    fn from(nist: NistCurve) -> EcCurve {
        match nist {
            NistCurve::P224 => EcCurve::P224,
            NistCurve::P256 => EcCurve::P256,
            NistCurve::P384 => EcCurve::P384,
            NistCurve::P521 => EcCurve::P521,
        }
    }
}

impl TryFrom<EcCurve> for NistCurve {
    type Error = Error;
    fn try_from(curve: EcCurve) -> Result<NistCurve, Error> {
        match curve {
            EcCurve::P224 => Ok(NistCurve::P224),
            EcCurve::P256 => Ok(NistCurve::P256),
            EcCurve::P384 => Ok(NistCurve::P384),
            EcCurve::P521 => Ok(NistCurve::P521),
            EcCurve::Curve25519 => Err(km_err!(InvalidArgument, "curve 25519 is not a NIST curve")),
        }
    }
}

impl OpaqueOr<Key> {
    pub fn subject_public_key_info<'a>(
        &'a self,
        buf: &'a mut Vec<u8>,
        ec: &dyn super::Ec,
        curve: &EcCurve,
        curve_type: &CurveType,
    ) -> Result<SubjectPublicKeyInfoRef<'a>, Error> {
        buf.try_extend_from_slice(&ec.subject_public_key(self)?)?;
        let (oid, parameters) = match curve_type {
            CurveType::Nist => {
                let nist_curve: NistCurve = (*curve).try_into()?;
                let params_oid = match nist_curve {
                    NistCurve::P224 => &ALGO_PARAM_P224_OID,
                    NistCurve::P256 => &ALGO_PARAM_P256_OID,
                    NistCurve::P384 => &ALGO_PARAM_P384_OID,
                    NistCurve::P521 => &ALGO_PARAM_P521_OID,
                };
                (X509_NIST_OID, Some(AnyRef::from(params_oid)))
            }
            CurveType::EdDsa => (X509_ED25519_OID, None),
            CurveType::Xdh => (X509_X25519_OID, None),
        };
        Ok(SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier { oid, parameters },
            subject_public_key: BitStringRef::from_bytes(buf).unwrap(),
        })
    }

    pub fn public_cose_key(
        &self,
        ec: &dyn super::Ec,
        curve: EcCurve,
        curve_type: CurveType,
        purpose: CoseKeyPurpose,
        key_id: Option<Vec<u8>>,
        test_mode: rpc::TestMode,
    ) -> Result<coset::CoseKey, Error> {
        let nist_algo = match purpose {
            CoseKeyPurpose::Agree => coset::iana::Algorithm::ECDH_ES_HKDF_256,
            CoseKeyPurpose::Sign => coset::iana::Algorithm::ES256,
        };

        let pub_key = ec.subject_public_key(self)?;
        let mut builder = match curve_type {
            CurveType::Nist => {
                let nist_curve: NistCurve = curve.try_into()?;
                let (x, y) = coordinates_from_pub_key(pub_key, nist_curve)?;
                let cose_nist_curve = match nist_curve {
                    NistCurve::P224 => {
                        return Err(km_err!(Unimplemented, "no COSE support for P-224"));
                    }
                    NistCurve::P256 => coset::iana::EllipticCurve::P_256,
                    NistCurve::P384 => coset::iana::EllipticCurve::P_384,
                    NistCurve::P521 => coset::iana::EllipticCurve::P_521,
                };
                coset::CoseKeyBuilder::new_ec2_pub_key(cose_nist_curve, x, y).algorithm(nist_algo)
            }
            CurveType::EdDsa => coset::CoseKeyBuilder::new_okp_key()
                .param(
                    coset::iana::OkpKeyParameter::Crv as i64,
                    coset::cbor::value::Value::from(coset::iana::EllipticCurve::Ed25519 as u64),
                )
                .param(
                    coset::iana::OkpKeyParameter::X as i64,
                    coset::cbor::value::Value::from(pub_key),
                )
                .algorithm(coset::iana::Algorithm::EdDSA),
            CurveType::Xdh => coset::CoseKeyBuilder::new_okp_key()
                .param(
                    coset::iana::OkpKeyParameter::Crv as i64,
                    coset::cbor::value::Value::from(coset::iana::EllipticCurve::X25519 as u64),
                )
                .param(
                    coset::iana::OkpKeyParameter::X as i64,
                    coset::cbor::value::Value::from(pub_key),
                )
                .algorithm(coset::iana::Algorithm::ECDH_ES_HKDF_256),
        };

        if let Some(key_id) = key_id {
            builder = builder.key_id(key_id);
        }
        if test_mode == rpc::TestMode(true) {
            builder = builder.param(RKP_TEST_KEY_CBOR_MARKER, coset::cbor::value::Value::Null);
        }
        Ok(builder.build())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum Key {
    P224(NistKey),

    P256(NistKey),

    P384(NistKey),

    P521(NistKey),

    Ed25519(Ed25519Key),

    X25519(X25519Key),
}

pub enum CoseKeyPurpose {
    Agree,

    Sign,
}

impl Key {
    pub fn private_key_bytes(&self) -> &[u8] {
        match self {
            Key::P224(key) => &key.0,
            Key::P256(key) => &key.0,
            Key::P384(key) => &key.0,
            Key::P521(key) => &key.0,
            Key::Ed25519(key) => &key.0,
            Key::X25519(key) => &key.0,
        }
    }

    pub fn curve_type(&self) -> CurveType {
        match self {
            Key::P224(_) | Key::P256(_) | Key::P384(_) | Key::P521(_) => CurveType::Nist,
            Key::Ed25519(_) => CurveType::EdDsa,
            Key::X25519(_) => CurveType::Xdh,
        }
    }

    pub fn curve(&self) -> EcCurve {
        match self {
            Key::P224(_) => EcCurve::P224,
            Key::P256(_) => EcCurve::P256,
            Key::P384(_) => EcCurve::P384,
            Key::P521(_) => EcCurve::P521,
            Key::Ed25519(_) => EcCurve::Curve25519,
            Key::X25519(_) => EcCurve::Curve25519,
        }
    }
}

#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct NistKey(pub Vec<u8>);

pub fn coordinates_from_pub_key(
    pub_key: Vec<u8>,
    curve: NistCurve,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let coord_len = curve.coord_len();
    if pub_key.len() != (1 + 2 * coord_len) {
        return Err(km_err!(
            UnsupportedKeySize,
            "unexpected SEC1 pubkey len of {} for {:?}",
            pub_key.len(),
            curve
        ));
    }
    if pub_key[0] != SEC1_UNCOMPRESSED_PREFIX {
        return Err(km_err!(
            UnsupportedKeySize,
            "unexpected SEC1 pubkey initial byte {} for {:?}",
            pub_key[0],
            curve
        ));
    }
    Ok((
        try_to_vec(&pub_key[1..1 + coord_len])?,
        try_to_vec(&pub_key[1 + coord_len..])?,
    ))
}

#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct Ed25519Key(pub [u8; CURVE25519_PRIV_KEY_LEN]);

#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct X25519Key(pub [u8; CURVE25519_PRIV_KEY_LEN]);

pub fn curve_to_signing_oid(curve: EcCurve) -> pkcs8::ObjectIdentifier {
    match curve {
        EcCurve::P224 | EcCurve::P256 | EcCurve::P384 | EcCurve::P521 => ECDSA_SHA256_SIGNATURE_OID,
        EcCurve::Curve25519 => X509_ED25519_OID,
    }
}

pub fn curve_to_key_size(curve: EcCurve) -> KeySizeInBits {
    KeySizeInBits(match curve {
        EcCurve::P224 => 224,
        EcCurve::P256 => 256,
        EcCurve::P384 => 384,
        EcCurve::P521 => 521,
        EcCurve::Curve25519 => 256,
    })
}

pub fn import_sec1_private_key(data: &[u8]) -> Result<KeyMaterial, Error> {
    let ec_key = sec1::EcPrivateKey::from_der(data)
        .map_err(|e| der_err!(e, "failed to parse ECPrivateKey"))?;
    let ec_parameters = ec_key.parameters.ok_or_else(|| {
        km_err!(
            InvalidArgument,
            "sec1 formatted EC private key didn't have a parameters field"
        )
    })?;
    let parameters_oid = ec_parameters.named_curve().ok_or_else(|| {
        km_err!(
            InvalidArgument,
            "couldn't retrieve parameters oid from sec1 ECPrivateKey formatted ec key parameters"
        )
    })?;
    let algorithm = AlgorithmIdentifier {
        oid: X509_NIST_OID,
        parameters: Some(AnyRef::from(&parameters_oid)),
    };
    import_pkcs8_key_impl(&algorithm, data)
}

pub fn import_pkcs8_key(data: &[u8]) -> Result<KeyMaterial, Error> {
    let key_info = pkcs8::PrivateKeyInfoRef::try_from(data)
        .map_err(|_| km_err!(InvalidArgument, "failed to parse PKCS#8 EC key"))?;
    import_pkcs8_key_impl(&key_info.algorithm, key_info.private_key.as_bytes())
}

fn import_pkcs8_key_impl(
    algorithm: &AlgorithmIdentifier<AnyRef<'_>>,
    private_key: &[u8],
) -> Result<KeyMaterial, Error> {
    let algo_params = algorithm.parameters;
    match algorithm.oid {
        X509_NIST_OID => {
            let algo_params = algo_params.ok_or_else(|| {
                km_err!(
                    InvalidArgument,
                    "missing PKCS#8 parameters for NIST curve import under OID {:?}",
                    algorithm.oid
                )
            })?;
            let curve_oid = algo_params
                .decode_as()
                .map_err(|_e| km_err!(InvalidArgument, "imported key has no OID parameter"))?;
            let curve = match curve_oid {
                ALGO_PARAM_P224_OID => EcCurve::P224,
                ALGO_PARAM_P256_OID => EcCurve::P256,
                ALGO_PARAM_P384_OID => EcCurve::P384,
                ALGO_PARAM_P521_OID => EcCurve::P521,
                oid => {
                    return Err(km_err!(
                        ImportParameterMismatch,
                        "imported key has unknown OID {:?}",
                        oid,
                    ))
                }
            };
            let private_key = normalize_nist_private_key(curve_oid, private_key)?;
            let key = match curve {
                EcCurve::P224 => Key::P224(NistKey(private_key)),
                EcCurve::P256 => Key::P256(NistKey(private_key)),
                EcCurve::P384 => Key::P384(NistKey(private_key)),
                EcCurve::P521 => Key::P521(NistKey(private_key)),
                EcCurve::Curve25519 => unreachable!("NIST import cannot produce Curve25519"),
            };
            Ok(KeyMaterial::Ec(curve, CurveType::Nist, key.into()))
        }
        X509_ED25519_OID => {
            if algo_params.is_some() {
                Err(km_err!(
                    InvalidArgument,
                    "unexpected PKCS#8 parameters for Ed25519 import"
                ))
            } else {
                if private_key.len() != 2 + CURVE25519_PRIV_KEY_LEN
                    || private_key[0] != 0x04
                    || private_key[1] != 0x20
                {
                    return Err(km_err!(
                        InvalidArgument,
                        "unexpected CurvePrivateKey contents"
                    ));
                }
                import_raw_ed25519_key(&private_key[2..])
            }
        }
        X509_X25519_OID => {
            if algo_params.is_some() {
                Err(km_err!(
                    InvalidArgument,
                    "unexpected PKCS#8 parameters for X25519 import",
                ))
            } else {
                if private_key.len() != 2 + CURVE25519_PRIV_KEY_LEN
                    || private_key[0] != 0x04
                    || private_key[1] != 0x20
                {
                    return Err(km_err!(
                        InvalidArgument,
                        "unexpected CurvePrivateKey contents"
                    ));
                }
                import_raw_x25519_key(&private_key[2..])
            }
        }
        _ => Err(km_err!(
            InvalidArgument,
            "unexpected OID {:?} for PKCS#8 EC key import",
            algorithm.oid,
        )),
    }
}

fn normalize_nist_private_key(
    curve_oid: pkcs8::ObjectIdentifier,
    private_key: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut ec_key = sec1::EcPrivateKey::from_der(private_key)
        .map_err(|e| der_err!(e, "failed to parse ECPrivateKey"))?;
    match ec_key.parameters {
        Some(parameters) => {
            let parameters_oid = parameters.named_curve().ok_or_else(|| {
                km_err!(
                    InvalidArgument,
                    "couldn't retrieve parameters oid from sec1 ECPrivateKey formatted ec key parameters"
                )
            })?;
            if parameters_oid != curve_oid {
                return Err(km_err!(
                    ImportParameterMismatch,
                    "imported key has mismatched OID {:?}, expected {:?}",
                    parameters_oid,
                    curve_oid,
                ));
            }
            try_to_vec(private_key)
        }
        None => {
            ec_key.parameters = Some(curve_oid.into());
            ec_key
                .to_der()
                .map_err(|e| km_err!(EncodingError, "failed to encode ECPrivateKey: {:?}", e))
        }
    }
}

pub fn import_raw_ed25519_key(data: &[u8]) -> Result<KeyMaterial, Error> {
    let key = data.try_into().map_err(|_e| {
        km_err!(
            InvalidInputLength,
            "import Ed25519 key of incorrect len {}",
            data.len()
        )
    })?;
    Ok(KeyMaterial::Ec(
        EcCurve::Curve25519,
        CurveType::EdDsa,
        Key::Ed25519(Ed25519Key(key)).into(),
    ))
}

pub fn import_raw_x25519_key(data: &[u8]) -> Result<KeyMaterial, Error> {
    let key = data.try_into().map_err(|_e| {
        km_err!(
            InvalidInputLength,
            "import X25519 key of incorrect len {}",
            data.len()
        )
    })?;
    Ok(KeyMaterial::Ec(
        EcCurve::Curve25519,
        CurveType::Xdh,
        Key::X25519(X25519Key(key)).into(),
    ))
}

pub fn to_cose_signature(curve: EcCurve, sig: Vec<u8>) -> Result<Vec<u8>, Error> {
    match curve {
        EcCurve::P224 | EcCurve::P256 | EcCurve::P384 | EcCurve::P521 => {
            let der_sig = NistSignature::from_der(&sig)
                .map_err(|e| km_err!(EncodingError, "failed to parse DER signature: {:?}", e))?;

            let nist_curve = NistCurve::try_from(curve)?;
            let l = nist_curve.coord_len();
            let mut sig = vec_try![0; 2 * l]?;
            let r = der_sig.r.as_bytes();
            let s = der_sig.s.as_bytes();
            let r_offset = l - r.len();
            let s_offset = l + l - s.len();
            sig[r_offset..r_offset + r.len()].copy_from_slice(r);
            sig[s_offset..s_offset + s.len()].copy_from_slice(s);
            Ok(sig)
        }
        EcCurve::Curve25519 => Ok(sig),
    }
}

pub fn from_cose_signature(curve: EcCurve, sig: &[u8]) -> Result<Vec<u8>, Error> {
    match curve {
        EcCurve::P224 | EcCurve::P256 | EcCurve::P384 | EcCurve::P521 => {
            let nist_curve = NistCurve::try_from(curve)?;
            let l = nist_curve.coord_len();
            if sig.len() != 2 * l {
                return Err(km_err!(
                    EncodingError,
                    "unexpected len {} for {:?} COSE signature value",
                    sig.len(),
                    nist_curve
                ));
            }

            let der_sig = NistSignature {
                r: der::asn1::UintRef::new(&sig[..l])
                    .map_err(|e| km_err!(EncodingError, "failed to build INTEGER: {:?}", e))?,
                s: der::asn1::UintRef::new(&sig[l..])
                    .map_err(|e| km_err!(EncodingError, "failed to build INTEGER: {:?}", e))?,
            };
            der_sig.to_der().map_err(|e| {
                km_err!(
                    EncodingError,
                    "failed to encode signature SEQUENCE: {:?}",
                    e
                )
            })
        }
        EcCurve::Curve25519 => try_to_vec(sig),
    }
}

#[derive(Sequence)]
struct NistSignature<'a> {
    r: der::asn1::UintRef<'a>,
    s: der::asn1::UintRef<'a>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_sig_decode() {
        let sig_data = hex::decode("3045022001b309d5eeffa5d550bde27630f9fc7f08492e4617bc158da08b913414cf675b022100fcdca2e77d036c33fa78f4a892b98569358d83c047a7d8a74ce6fe12fbf919c6").unwrap();
        let sig = NistSignature::from_der(&sig_data).expect("sequence should decode");
        assert_eq!(
            hex::encode(sig.r.as_bytes()),
            "01b309d5eeffa5d550bde27630f9fc7f08492e4617bc158da08b913414cf675b"
        );
        assert_eq!(
            hex::encode(sig.s.as_bytes()),
            "fcdca2e77d036c33fa78f4a892b98569358d83c047a7d8a74ce6fe12fbf919c6"
        );
    }

    #[test]
    fn test_longer_sig_transmute() {
        let nist_sig_data = hex::decode(concat!(
            "30",
            "45",
            "02",
            "20",
            "01b309d5eeffa5d550bde27630f9fc7f08492e4617bc158da08b913414cf675b",
            "02",
            "21",
            "00fcdca2e77d036c33fa78f4a892b98569358d83c047a7d8a74ce6fe12fbf919c6"
        ))
        .unwrap();
        let cose_sig_data = to_cose_signature(EcCurve::P256, nist_sig_data.clone()).unwrap();
        assert_eq!(
            concat!(
                "01b309d5eeffa5d550bde27630f9fc7f08492e4617bc158da08b913414cf675b",
                "fcdca2e77d036c33fa78f4a892b98569358d83c047a7d8a74ce6fe12fbf919c6"
            ),
            hex::encode(&cose_sig_data),
        );
        let got_nist_sig = from_cose_signature(EcCurve::P256, &cose_sig_data).unwrap();
        assert_eq!(got_nist_sig, nist_sig_data);
    }

    #[test]
    fn test_short_sig_transmute() {
        let nist_sig_data = hex::decode(concat!(
            "30",
            "43",
            "02",
            "1e",
            "09d5eeffa5d550bde27630f9fc7f08492e4617bc158da08b913414cf675b",
            "02",
            "21",
            "00fcdca2e77d036c33fa78f4a892b98569358d83c047a7d8a74ce6fe12fbf919c6"
        ))
        .unwrap();
        let cose_sig_data = to_cose_signature(EcCurve::P256, nist_sig_data.clone()).unwrap();
        assert_eq!(
            concat!(
                "000009d5eeffa5d550bde27630f9fc7f08492e4617bc158da08b913414cf675b",
                "fcdca2e77d036c33fa78f4a892b98569358d83c047a7d8a74ce6fe12fbf919c6"
            ),
            hex::encode(&cose_sig_data),
        );
        let got_nist_sig = from_cose_signature(EcCurve::P256, &cose_sig_data).unwrap();
        assert_eq!(got_nist_sig, nist_sig_data);
    }

    #[test]
    fn test_sec1_ec_import() {
        let key_data = hex::decode(concat!(
            "3077",
            "020101",
            "0420",
            "a6a30ca3dc87b58763736400e7e86260",
            "9e8311f41e6b89888c33753218168517",
            "a00a",
            "0608",
            "2a8648ce3d030107",
            "a144",
            "0342",
            "00",
            "0481e4ce20d8be3dd40b940b3a3ba3e8",
            "cf5a3f2156eceb4debb8fce83cbe4a48",
            "bd576a03eebf77d329a438fcdc509f37",
            "1f092cad41e2ecf9f25cd82f31500f33",
            "8e"
        ))
        .unwrap();
        let key = import_sec1_private_key(&key_data).expect("SEC1 parse failed");
        if let KeyMaterial::Ec(curve, curve_type, _key) = key {
            assert_eq!(curve, EcCurve::P256);
            assert_eq!(curve_type, CurveType::Nist);
        } else {
            panic!("unexpected key type");
        }
    }

    #[test]
    fn test_pkcs8_ec_import_adds_missing_sec1_parameters() {
        let key_data = hex::decode(concat!(
            "308187020100301306072a8648ce3d020106082a8648ce3d030107",
            "046d306b0201010420fa370fbd35e8de457faad315371b9cbf8",
            "a05c373d2441f4cfad013a5ac0d1df0a14403420004dbb7",
            "c89f916a64c8828ebcc955bf9c6eb95d6234179d10c3bbef",
            "b0f050bbbe43acf3e897bc6604414eba233d7cfcec50af0",
            "fc3b5709621a695f6ca0f7cc4e2c8"
        ))
        .unwrap();

        let key = import_pkcs8_key(&key_data).expect("PKCS#8 parse failed");
        let KeyMaterial::Ec(curve, curve_type, OpaqueOr::Explicit(Key::P256(key))) = key else {
            panic!("unexpected key type");
        };
        assert_eq!(curve, EcCurve::P256);
        assert_eq!(curve_type, CurveType::Nist);

        let ec_key = sec1::EcPrivateKey::from_der(&key.0).expect("SEC1 parse failed");
        assert_eq!(
            ec_key.parameters.and_then(|params| params.named_curve()),
            Some(ALGO_PARAM_P256_OID)
        );
        assert!(ec_key.public_key.is_some());
    }
}
