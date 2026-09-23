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

use crate::coset::{iana, AsCborValue, CoseSign1Builder, HeaderBuilder};
use kmr_common::{
    crypto, crypto::aes, crypto::hmac, crypto::KeyMaterial, crypto::OpaqueOr, keyblob, log_unimpl,
    unimpl, Error,
};
use kmr_wire::{keymint, rpc, secureclock::TimeStampToken, CborError};
use log::error;
use std::{boxed::Box, vec::Vec};

use crate::rkp::serialize_cbor;

pub const RPC_HMAC_KEY_CONTEXT: &[u8] = b"Key to MAC public keys";

pub const RPC_HMAC_KEY_LEN: usize = 32;

pub struct Implementation {
    pub keys: Box<dyn RetrieveKeyMaterial>,

    pub sign_info: Option<Box<dyn RetrieveCertSigningInfo>>,

    pub attest_ids: Option<Box<dyn RetrieveAttestationIds>>,

    pub sdd_mgr: Option<Box<dyn keyblob::SecureDeletionSecretManager>>,

    pub bootloader: Box<dyn BootloaderStatus>,

    pub sk_wrapper: Option<Box<dyn StorageKeyWrapper>>,

    pub tup: Box<dyn TrustedUserPresence>,

    pub legacy_key: Option<Box<dyn keyblob::LegacyKeyHandler>>,

    pub rpc: Box<dyn RetrieveRpcArtifacts>,
}

pub trait RetrieveKeyMaterial: Send {
    fn root_kek(&self, context: &[u8]) -> Result<OpaqueOr<hmac::Key>, Error>;

    fn kek_context(&self) -> Result<Vec<u8>, Error> {
        Ok(Vec::new())
    }

    fn kak(&self) -> Result<OpaqueOr<aes::Key>, Error>;

    fn hmac_key_agreed(&self, _key: &crypto::hmac::Key) -> Option<Box<dyn DeviceHmac>> {
        None
    }

    fn unique_id_hbk(&self, ckdf: &dyn crypto::Ckdf) -> Result<crypto::hmac::Key, Error> {
        let unique_id_label = b"UniqueID HBK 32B";
        ckdf.ckdf(&self.kak()?, unique_id_label, &[], 32)
            .map(crypto::hmac::Key::new)
    }

    fn timestamp_token_mac_input(&self, token: &TimeStampToken) -> Result<Vec<u8>, Error> {
        crate::clock::timestamp_token_mac_input(token)
    }

    fn kek_context_is_outdated(&self, _kek_context: &[u8]) -> Result<bool, Error> {
        Ok(false)
    }
}

pub trait DeviceHmac: Send {
    fn hmac(&self, imp: &dyn crypto::Hmac, data: &[u8]) -> Result<Vec<u8>, Error>;

    fn get_hmac_key(&self) -> Option<crypto::hmac::Key> {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SigningKey {
    Batch,

    DeviceUnique,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SigningAlgorithm {
    Ec,

    Rsa,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SigningKeyType {
    pub which: SigningKey,

    pub algo_hint: SigningAlgorithm,
}

#[derive(Clone)]
pub struct SigningInfoSnapshot {
    pub signing_key: KeyMaterial,

    pub cert_chain: Vec<keymint::Certificate>,

    pub identity_digest: [u8; 32],
}

pub trait RetrieveCertSigningInfo: Send {
    fn signing_info(&self, key_type: SigningKeyType) -> Result<SigningInfoSnapshot, Error>;
}

pub trait RetrieveAttestationIds: Send {
    fn get(&self) -> Result<crate::AttestationIdInfo, Error>;

    fn get_ids(&self) -> Result<Option<crate::AttestationIdInfo>, Error> {
        self.get().map(Some)
    }

    fn destroy_all(&mut self) -> Result<(), Error>;
}

pub trait BootloaderStatus: Send {
    fn done(&self) -> bool {
        true
    }
}

pub trait RetrieveRpcArtifacts: Send {
    fn derive_bytes_from_hbk(
        &self,
        hkdf: &dyn crypto::Hkdf,
        context: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, Error>;

    fn compute_hmac_sha256(
        &self,
        hmac: &dyn crypto::Hmac,
        hkdf: &dyn crypto::Hkdf,
        input: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let secret = self.derive_bytes_from_hbk(hkdf, RPC_HMAC_KEY_CONTEXT, RPC_HMAC_KEY_LEN)?;
        crypto::hmac_sha256(hmac, &secret, input)
    }

    fn get_dice_info(&self, test_mode: rpc::TestMode) -> Result<DiceInfo, Error>;

    fn sign_data(
        &self,
        ec: &dyn crypto::Ec,
        data: &[u8],
        rpc_v2: Option<RpcV2Req>,
    ) -> Result<Vec<u8>, Error>;

    fn sign_data_in_cose_sign1(
        &self,
        ec: &dyn crypto::Ec,
        signing_algorithm: &CsrSigningAlgorithm,
        payload: &[u8],
        _aad: &[u8],
        _rpc_v2: Option<RpcV2Req>,
    ) -> Result<Vec<u8>, Error> {
        let cose_sign_algorithm = match signing_algorithm {
            CsrSigningAlgorithm::ES256 => iana::Algorithm::ES256,
            CsrSigningAlgorithm::ES384 => iana::Algorithm::ES384,
            CsrSigningAlgorithm::EdDSA => iana::Algorithm::EdDSA,
        };

        let protected = HeaderBuilder::new().algorithm(cose_sign_algorithm).build();
        let signed_data = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload.to_vec())
            .try_create_signature(&[], |input| self.sign_data(ec, input, None))?
            .build();
        let signed_data_cbor = signed_data.to_cbor_value().map_err(CborError::from)?;
        serialize_cbor(&signed_data_cbor)
    }
}

#[derive(Clone)]
pub struct DiceInfo {
    pub pub_dice_artifacts: PubDiceArtifacts,

    pub signing_algorithm: CsrSigningAlgorithm,

    pub rpc_v2_test_cdi_priv: Option<RpcV2TestCDIPriv>,
}

#[derive(Clone, Copy, Debug)]
pub enum CsrSigningAlgorithm {
    ES256,

    ES384,

    EdDSA,
}

#[derive(Clone, Debug)]
pub struct PubDiceArtifacts {
    pub uds_certs: Vec<u8>,

    pub dice_cert_chain: Vec<u8>,
}

pub enum RpcV2Req<'a> {
    Production,

    Test(&'a [u8]),
}

#[derive(Clone)]
pub struct RpcV2TestCDIPriv {
    pub test_cdi_priv: Option<OpaqueOr<crypto::ec::Key>>,

    pub context: Vec<u8>,
}

pub struct BootloaderDone;
impl BootloaderStatus for BootloaderDone {}

pub trait TrustedUserPresence: Send {
    fn available(&self) -> bool {
        false
    }
}

pub struct TrustedPresenceUnsupported;
impl TrustedUserPresence for TrustedPresenceUnsupported {}

pub trait StorageKeyWrapper: Send {
    fn ephemeral_wrap(&self, key_material: &KeyMaterial) -> Result<Vec<u8>, Error>;
}

pub struct NoOpRetrieveKeyMaterial;
impl RetrieveKeyMaterial for NoOpRetrieveKeyMaterial {
    fn root_kek(&self, _context: &[u8]) -> Result<OpaqueOr<hmac::Key>, Error> {
        unimpl!();
    }

    fn kak(&self) -> Result<OpaqueOr<aes::Key>, Error> {
        unimpl!();
    }
}

pub struct NoOpRetrieveCertSigningInfo;
impl RetrieveCertSigningInfo for NoOpRetrieveCertSigningInfo {
    fn signing_info(&self, _key_type: SigningKeyType) -> Result<SigningInfoSnapshot, Error> {
        unimpl!();
    }
}

pub struct NoOpRetrieveRpcArtifacts;
impl RetrieveRpcArtifacts for NoOpRetrieveRpcArtifacts {
    fn derive_bytes_from_hbk(
        &self,
        _hkdf: &dyn crypto::Hkdf,
        _context: &[u8],
        _output_len: usize,
    ) -> Result<Vec<u8>, Error> {
        unimpl!();
    }

    fn get_dice_info<'a>(&self, _test_mode: rpc::TestMode) -> Result<DiceInfo, Error> {
        unimpl!();
    }

    fn sign_data(
        &self,
        _ec: &dyn crypto::Ec,
        _data: &[u8],
        _rpc_v2: Option<RpcV2Req>,
    ) -> Result<Vec<u8>, Error> {
        unimpl!();
    }
}
