// Copyright 2021, The Android Open Source Project
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

use crate::android::hardware::security::keymint::{
    HardwareAuthToken::HardwareAuthToken, HardwareAuthenticatorType::HardwareAuthenticatorType,
};
use crate::keymaster::db::AuthTokenEntry;
use crate::keymaster::utils::SecureUserId;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::RwLock;

#[derive(PartialEq, PartialOrd, Ord, Eq, Hash)]
struct AuthTokenId {
    user_id: SecureUserId,
    auth_id: SecureUserId,
    authenticator_type: HardwareAuthenticatorType,
}

impl AuthTokenId {
    fn from_auth_token(tok: &HardwareAuthToken) -> Self {
        AuthTokenId {
            user_id: SecureUserId(tok.userId),
            auth_id: SecureUserId(tok.authenticatorId),
            authenticator_type: tok.authenticatorType,
        }
    }
}

#[derive(Clone)]
struct AuthTokenEntryWrap(AuthTokenEntry);

impl std::hash::Hash for AuthTokenEntryWrap {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        AuthTokenId::from_auth_token(self.0.auth_token()).hash(state)
    }
}

impl PartialEq<AuthTokenEntryWrap> for AuthTokenEntryWrap {
    fn eq(&self, other: &AuthTokenEntryWrap) -> bool {
        AuthTokenId::from_auth_token(self.0.auth_token())
            == AuthTokenId::from_auth_token(other.0.auth_token())
    }
}

impl Eq for AuthTokenEntryWrap {}

#[derive(Default)]
pub struct PerbootDB {
    auth_tokens: RwLock<HashSet<AuthTokenEntryWrap>>,
}

pub static PERBOOT_DB: LazyLock<Arc<PerbootDB>> = LazyLock::new(|| Arc::new(PerbootDB::new()));

impl PerbootDB {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn insert_auth_token_entry(&self, entry: AuthTokenEntry) {
        self.auth_tokens
            .write()
            .unwrap()
            .replace(AuthTokenEntryWrap(entry));
    }

    pub fn find_auth_token_entry<P: Fn(&AuthTokenEntry) -> bool>(
        &self,
        p: P,
    ) -> Option<AuthTokenEntry> {
        let reader = self.auth_tokens.read().unwrap();
        let mut matches: Vec<_> = reader.iter().filter(|x| p(&x.0)).collect();
        matches.sort_by_key(|x| x.0.time_received());
        matches.last().map(|x| x.0.clone())
    }

    pub fn auth_tokens_len(&self) -> usize {
        self.auth_tokens.read().unwrap().len()
    }
    #[cfg(test)]
    pub fn get_all_auth_token_entries(&self) -> Vec<AuthTokenEntry> {
        self.auth_tokens
            .read()
            .unwrap()
            .iter()
            .cloned()
            .map(|x| x.0)
            .collect()
    }
}
