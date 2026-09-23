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

use super::{KeyMaterial, KeySizeInBits, OpaqueOr, RsaExponent};
use crate::{km_err, tag, try_to_vec, Error, FallibleAllocExt};
use der::asn1::BitStringRef;
use kmr_wire::keymint::{Digest, KeyParam, PaddingMode};
use pkcs1::der::{Decode as Pkcs1Decode, Encode as Pkcs1Encode};
use pkcs1::RsaPrivateKey;
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo, SubjectPublicKeyInfoRef};
use std::vec::Vec;
use zeroize::ZeroizeOnDrop;

pub const PKCS1_UNDIGESTED_SIGNATURE_PADDING_OVERHEAD: usize = 11;

pub const X509_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

pub const SHA256_PKCS1_SIGNATURE_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

fn pkcs1_der_error(err: pkcs1::der::Error, context: core::fmt::Arguments<'_>) -> Error {
    log::warn!("{}: {:?} at {:?}", context, err, err.position());
    Error::from(crate::ErrorKind::Der(der::ErrorKind::Failed))
}

#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct Key(pub Vec<u8>);

impl Key {
    pub fn subject_public_key(&self) -> Result<Vec<u8>, Error> {
        let rsa_pvt_key = RsaPrivateKey::from_der(self.0.as_slice())
            .map_err(|e| pkcs1_der_error(e, format_args!("failed to parse RsaPrivateKey")))?;

        let rsa_pub_key = rsa_pvt_key.public_key();
        let mut encoded_data = Vec::<u8>::new();
        rsa_pub_key
            .encode_to_vec(&mut encoded_data)
            .map_err(|e| pkcs1_der_error(e, format_args!("failed to encode RSA PublicKey")))?;
        Ok(encoded_data)
    }

    pub fn size(&self) -> usize {
        let rsa_pvt_key = match RsaPrivateKey::from_der(self.0.as_slice()) {
            Ok(k) => k,
            Err(e) => {
                log::error!("failed to determine RSA key length: {:?}", e);
                return 0;
            }
        };
        let len = u32::from(rsa_pvt_key.modulus.len());
        len as usize
    }
}

impl OpaqueOr<Key> {
    pub fn subject_public_key_info<'a>(
        &'a self,
        buf: &'a mut Vec<u8>,
        rsa: &dyn super::Rsa,
    ) -> Result<SubjectPublicKeyInfoRef<'a>, Error> {
        let pub_key = rsa.subject_public_key(self)?;
        buf.try_extend_from_slice(&pub_key)?;
        Ok(SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                oid: X509_OID,
                parameters: Some(der::AnyRef::NULL),
            },
            subject_public_key: BitStringRef::from_bytes(buf)
                .map_err(|e| km_err!(UnknownError, "invalid bitstring: {e:?}"))?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptionMode {
    NoPadding,

    OaepPadding {
        msg_digest: Digest,

        mgf_digest: Digest,
    },

    Pkcs1_1_5Padding,
}

impl DecryptionMode {
    pub fn new(params: &[KeyParam]) -> Result<Self, Error> {
        let padding = tag::get_padding_mode(params)?;
        match padding {
            PaddingMode::None => Ok(DecryptionMode::NoPadding),
            PaddingMode::RsaOaep => {
                let msg_digest = tag::get_digest(params)?;
                let mgf_digest = tag::get_mgf_digest(params)?;
                Ok(DecryptionMode::OaepPadding {
                    msg_digest,
                    mgf_digest,
                })
            }
            PaddingMode::RsaPkcs115Encrypt => Ok(DecryptionMode::Pkcs1_1_5Padding),
            _ => Err(km_err!(
                UnsupportedPaddingMode,
                "padding mode {:?} not supported for RSA decryption",
                padding
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignMode {
    NoPadding,

    PssPadding(Digest),

    Pkcs1_1_5Padding(Digest),
}

impl SignMode {
    pub fn new(params: &[KeyParam]) -> Result<Self, Error> {
        let padding = tag::get_padding_mode(params)?;
        match padding {
            PaddingMode::None => Ok(SignMode::NoPadding),
            PaddingMode::RsaPss => {
                let digest = tag::get_digest(params)?;
                Ok(SignMode::PssPadding(digest))
            }
            PaddingMode::RsaPkcs115Sign => {
                let digest = tag::get_digest(params)?;
                Ok(SignMode::Pkcs1_1_5Padding(digest))
            }
            _ => Err(km_err!(
                UnsupportedPaddingMode,
                "padding mode {:?} not supported for RSA signing",
                padding
            )),
        }
    }
}

pub fn import_pkcs8_key(data: &[u8]) -> Result<(KeyMaterial, KeySizeInBits, RsaExponent), Error> {
    let key_info = pkcs8::PrivateKeyInfoRef::try_from(data)
        .map_err(|_| km_err!(InvalidArgument, "failed to parse PKCS#8 RSA key"))?;
    if key_info.algorithm.oid != X509_OID {
        return Err(km_err!(
            InvalidArgument,
            "unexpected OID {:?} for PKCS#1 RSA key import",
            key_info.algorithm.oid
        ));
    }

    import_pkcs1_key(key_info.private_key.as_bytes())
}

pub fn import_pkcs1_key(
    private_key: &[u8],
) -> Result<(KeyMaterial, KeySizeInBits, RsaExponent), Error> {
    let key = Key(try_to_vec(private_key)?);

    let parsed_key = pkcs1::RsaPrivateKey::try_from(private_key)
        .map_err(|_| km_err!(InvalidArgument, "failed to parse inner PKCS#1 key"))?;
    let key_size = parsed_key.modulus.as_bytes().len() as u32 * 8;

    let pub_exponent_bytes = parsed_key.public_exponent.as_bytes();
    if pub_exponent_bytes.len() > 8 {
        return Err(km_err!(
            InvalidArgument,
            "public exponent of length {} too big",
            pub_exponent_bytes.len()
        ));
    }
    let offset = 8 - pub_exponent_bytes.len();
    let mut pub_exponent_arr = [0u8; 8];
    pub_exponent_arr[offset..].copy_from_slice(pub_exponent_bytes);
    let pub_exponent = u64::from_be_bytes(pub_exponent_arr);

    Ok((
        KeyMaterial::Rsa(key.into()),
        KeySizeInBits(key_size),
        RsaExponent(pub_exponent),
    ))
}
