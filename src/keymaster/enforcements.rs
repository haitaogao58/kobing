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

use crate::android::hardware::security::keymint::{
    Algorithm::Algorithm, ErrorCode::ErrorCode as Ec, HardwareAuthToken::HardwareAuthToken,
    HardwareAuthenticatorType::HardwareAuthenticatorType,
    KeyParameter::KeyParameter as KmKeyParameter, KeyPurpose::KeyPurpose, Tag::Tag,
};
use crate::android::hardware::security::secureclock::TimeStampToken::TimeStampToken;
use crate::android::security::authorization::ResponseCode::ResponseCode as AuthzResponseCode;
use crate::android::system::keystore2::{
    Domain::Domain, IKeystoreSecurityLevel::KEY_FLAG_AUTH_BOUND_WITHOUT_CRYPTOGRAPHIC_LSKF_BINDING,
    OperationChallenge::OperationChallenge,
};
use crate::err as ks_err;
use crate::global::{get_timestamp_service, ASYNC_TASK, DB, ENFORCEMENTS, SUPER_KEY};
use crate::keymaster::async_task::AsyncTask;
use crate::keymaster::authorization::Error as AuthzError;
use crate::keymaster::boot_key::BootLevel;
use crate::keymaster::db::{AuthTokenEntry, BootTime};
use crate::keymaster::error::{map_binder_status, Error, ErrorCode};
use crate::keymaster::key_parameter::{KeyParameter, KeyParameterValue};
use crate::keymaster::super_key::SuperEncryptionType;
use crate::keymaster::utils::{watchdog as wd, AndroidUserId, Challenge, SecureUserId};
use anyhow::{Context, Result};
use log::{error, info, warn};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        mpsc::{channel, Receiver, Sender, TryRecvError},
        Arc, Mutex, RwLock, Weak,
    },
    time::SystemTime,
};

type ConfirmationTokenReceiver = Arc<Mutex<Option<Receiver<Vec<u8>>>>>;
type FinishAuthTokens = (
    Option<HardwareAuthToken>,
    Option<TimeStampToken>,
    Option<Vec<u8>>,
);

#[derive(Debug)]
enum AuthRequestState {
    OpAuth,

    TimeStamp(Mutex<Receiver<Result<TimeStampToken, Error>>>),
}

#[derive(Debug)]
struct AuthRequest {
    state: AuthRequestState,

    hat: Mutex<Option<HardwareAuthToken>>,
}

impl AuthRequest {
    fn op_auth() -> Arc<Self> {
        Arc::new(Self {
            state: AuthRequestState::OpAuth,
            hat: Mutex::new(None),
        })
    }

    fn timestamp(
        hat: HardwareAuthToken,
        receiver: Receiver<Result<TimeStampToken, Error>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            state: AuthRequestState::TimeStamp(Mutex::new(receiver)),
            hat: Mutex::new(Some(hat)),
        })
    }

    fn add_auth_token(&self, hat: HardwareAuthToken) {
        *self.hat.lock().unwrap() = Some(hat)
    }

    fn get_auth_tokens(&self) -> Result<(HardwareAuthToken, Option<TimeStampToken>)> {
        let hat = self
            .hat
            .lock()
            .unwrap()
            .take()
            .ok_or(Error::Km(ErrorCode::KEY_USER_NOT_AUTHENTICATED))
            .context(ks_err!("No operation auth token received."))?;

        let tst = match &self.state {
            AuthRequestState::TimeStamp(recv) => {
                let result = recv
                    .lock()
                    .unwrap()
                    .recv()
                    .context("In get_auth_tokens: Sender disconnected.")?;
                Some(result.context(ks_err!(
                    "Worker responded with error \
                    from generating timestamp token.",
                ))?)
            }
            AuthRequestState::OpAuth => None,
        };
        Ok((hat, tst))
    }
}

#[derive(Debug)]
enum DeferredAuthState {
    NoAuthRequired,

    OpAuthRequired(Vec<SecureUserId>, HardwareAuthenticatorType),

    TimeStampRequired(HardwareAuthToken),

    Waiting(Arc<AuthRequest>),

    Token(HardwareAuthToken, Option<TimeStampToken>),
}

#[derive(Debug)]
pub struct AuthInfo {
    state: DeferredAuthState,

    key_usage_limited: Option<i64>,
    confirmation_token_receiver: Option<ConfirmationTokenReceiver>,
}

struct TokenReceiverMap {
    map_and_cleanup_counter: Mutex<(HashMap<Challenge, TokenReceiver>, u8)>,
}

impl Default for TokenReceiverMap {
    fn default() -> Self {
        Self {
            map_and_cleanup_counter: Mutex::new((HashMap::new(), Self::CLEANUP_PERIOD + 1)),
        }
    }
}

impl TokenReceiverMap {
    const CLEANUP_PERIOD: u8 = 25;

    pub fn add_auth_token(&self, hat: HardwareAuthToken) {
        let recv = {
            let mut map = self.map_and_cleanup_counter.lock().unwrap();
            let (ref mut map, _) = *map;
            map.remove_entry(&Challenge(hat.challenge))
        };

        if let Some((_, recv)) = recv {
            recv.add_auth_token(hat);
        }
    }

    pub fn add_receiver(&self, challenge: Challenge, recv: TokenReceiver) {
        let mut map = self.map_and_cleanup_counter.lock().unwrap();
        let (ref mut map, ref mut cleanup_counter) = *map;
        map.insert(challenge, recv);

        *cleanup_counter -= 1;
        if *cleanup_counter == 0 {
            map.retain(|_, v| !v.is_obsolete());
            map.shrink_to_fit();
            *cleanup_counter = Self::CLEANUP_PERIOD + 1;
        }
    }
}

#[derive(Debug)]
struct TokenReceiver {
    req: Weak<AuthRequest>,

    sids: Vec<SecureUserId>,
    auth_type: HardwareAuthenticatorType,
}

impl TokenReceiver {
    fn is_obsolete(&self) -> bool {
        self.req.upgrade().is_none()
    }

    fn add_auth_token(&self, hat: HardwareAuthToken) {
        if let Some(state_arc) = self.req.upgrade() {
            if (self.auth_type.0 & hat.authenticatorType.0) == 0 {
                error!(
                    "Per-op {hat:?} doesn't match auth type {:?} required for key!",
                    self.auth_type
                );
            }
            if !self
                .sids
                .iter()
                .any(|&sid| hat.userId == sid.0 || hat.authenticatorId == sid.0)
            {
                error!(
                    "Per-op {hat:?} doesn't have a SID required for key: {:?}",
                    self.sids
                );
            }

            state_arc.add_auth_token(hat);
        }
    }
}

fn get_timestamp_token(challenge: Challenge) -> Result<TimeStampToken, Error> {
    let dev = get_timestamp_service().expect(concat!(
        "Secure Clock service must be present ",
        "if TimeStampTokens are required."
    ));
    map_binder_status(dev.generateTimeStamp(challenge.0))
}

fn timestamp_token_request(challenge: Challenge, sender: Sender<Result<TimeStampToken, Error>>) {
    if let Err(e) = sender.send(get_timestamp_token(challenge)) {
        info!("Receiver hung up before timestamp token could be delivered. {e:?}");
    }
}

impl AuthInfo {
    pub fn finalize_create_authorization(
        &mut self,
        challenge: Challenge,
    ) -> Option<OperationChallenge> {
        match &self.state {
            DeferredAuthState::OpAuthRequired(sids, auth_type) => {
                let auth_request = AuthRequest::op_auth();
                let token_receiver = TokenReceiver {
                    req: Arc::downgrade(&auth_request),
                    sids: sids.to_vec(),
                    auth_type: *auth_type,
                };
                ENFORCEMENTS.register_op_auth_receiver(challenge, token_receiver);

                self.state = DeferredAuthState::Waiting(auth_request);
                Some(OperationChallenge {
                    challenge: challenge.0,
                })
            }
            DeferredAuthState::TimeStampRequired(hat) => {
                let hat = (*hat).clone();
                let (sender, receiver) = channel::<Result<TimeStampToken, Error>>();
                let auth_request = AuthRequest::timestamp(hat, receiver);
                ASYNC_TASK.queue_hi(move |_| timestamp_token_request(challenge, sender));
                self.state = DeferredAuthState::Waiting(auth_request);
                None
            }
            _ => None,
        }
    }

    pub fn before_update(&mut self) -> Result<(Option<HardwareAuthToken>, Option<TimeStampToken>)> {
        self.get_auth_tokens()
    }

    pub fn before_finish(&mut self) -> Result<FinishAuthTokens> {
        let mut confirmation_token: Option<Vec<u8>> = None;
        if let Some(ref confirmation_token_receiver) = self.confirmation_token_receiver {
            let locked_receiver = confirmation_token_receiver.lock().unwrap();
            if let Some(ref receiver) = *locked_receiver {
                loop {
                    match receiver.try_recv() {
                        Ok(t) => confirmation_token = Some(t),
                        Err(TryRecvError::Empty) => break,
                        Err(TryRecvError::Disconnected) => {
                            error!("confirmation token receiver disconnected unexpectedly");
                            break;
                        }
                    }
                }
            }
        }
        self.get_auth_tokens()
            .map(|(hat, tst)| (hat, tst, confirmation_token))
    }

    pub fn after_finish(&self) -> Result<()> {
        if let Some(key_id) = self.key_usage_limited {
            DB.with(|db| {
                db.borrow_mut()
                    .check_and_update_key_usage_count(key_id)
                    .context("Trying to update key usage count.")
            })
            .context(ks_err!())?;
        }
        Ok(())
    }

    fn get_auth_tokens(&mut self) -> Result<(Option<HardwareAuthToken>, Option<TimeStampToken>)> {
        let deferred_tokens = if let DeferredAuthState::Waiting(ref auth_request) = self.state {
            Some(
                auth_request
                    .get_auth_tokens()
                    .context("In AuthInfo::get_auth_tokens.")?,
            )
        } else {
            None
        };

        if let Some((hat, tst)) = deferred_tokens {
            self.state = DeferredAuthState::Token(hat, tst);
        }

        match &self.state {
            DeferredAuthState::NoAuthRequired => Ok((None, None)),
            DeferredAuthState::Token(hat, tst) => Ok((Some((*hat).clone()), (*tst).clone())),
            DeferredAuthState::OpAuthRequired(_, _) | DeferredAuthState::TimeStampRequired(_) => {
                Err(Error::Km(ErrorCode::KEY_USER_NOT_AUTHENTICATED)).context(ks_err!(
                    "No operation auth token requested??? \
                    This should not happen."
                ))
            }

            DeferredAuthState::Waiting(_) => {
                Err(Error::sys()).context(ks_err!("AuthInfo::get_auth_tokens: Cannot be reached.",))
            }
        }
    }
}

#[derive(Default)]
pub struct Enforcements {
    device_unlocked_set: Mutex<HashSet<AndroidUserId>>,

    lock_state_task: RwLock<Option<Arc<AsyncTask>>>,

    op_auth_map: TokenReceiverMap,

    confirmation_token_receiver: ConfirmationTokenReceiver,
}

impl Enforcements {
    pub fn install_confirmation_token_receiver(
        &self,
        confirmation_token_receiver: Receiver<Vec<u8>>,
    ) {
        *self.confirmation_token_receiver.lock().unwrap() = Some(confirmation_token_receiver);
    }

    pub fn authorize_create(
        &self,
        purpose: KeyPurpose,
        key_properties: Option<&(i64, Vec<KeyParameter>)>,
        op_params: &[KmKeyParameter],
        requires_timestamp: bool,
    ) -> Result<(Option<HardwareAuthToken>, AuthInfo)> {
        let (key_id, key_params) = match key_properties {
            Some((key_id, key_params)) => (*key_id, key_params),
            None => {
                return Ok((
                    None,
                    AuthInfo {
                        state: DeferredAuthState::NoAuthRequired,
                        key_usage_limited: None,
                        confirmation_token_receiver: None,
                    },
                ));
            }
        };

        match purpose {
            KeyPurpose::SIGN | KeyPurpose::DECRYPT => {}

            KeyPurpose::WRAP_KEY => {
                return Err(Error::Km(Ec::INCOMPATIBLE_PURPOSE))
                    .context(ks_err!("WRAP_KEY purpose is not allowed here.",));
            }

            KeyPurpose::AGREE_KEY => {
                for kp in key_params.iter() {
                    if kp.get_tag() == Tag::ALGORITHM
                        && *kp.key_parameter_value() != KeyParameterValue::Algorithm(Algorithm::EC)
                    {
                        return Err(Error::Km(Ec::UNSUPPORTED_PURPOSE))
                            .context(ks_err!("key agreement is only supported for EC keys.",));
                    }
                }
            }
            KeyPurpose::VERIFY | KeyPurpose::ENCRYPT => {
                for kp in key_params.iter() {
                    match *kp.key_parameter_value() {
                        KeyParameterValue::Algorithm(Algorithm::RSA)
                        | KeyParameterValue::Algorithm(Algorithm::EC) => {
                            return Err(Error::Km(Ec::UNSUPPORTED_PURPOSE)).context(ks_err!(
                                "public operations on asymmetric keys are \
                                 not supported."
                            ));
                        }
                        _ => {}
                    }
                }
            }
            _ => {
                return Err(Error::Km(Ec::UNSUPPORTED_PURPOSE)).context(ks_err!(
                    "authorize_create: specified purpose is not supported."
                ));
            }
        }

        let mut key_purpose_authorized: bool = false;
        let mut user_auth_type: Option<HardwareAuthenticatorType> = None;
        let mut no_auth_required: bool = false;
        let mut caller_nonce_allowed = false;
        let mut user = AndroidUserId(-1);
        let mut user_sids = Vec::<SecureUserId>::new();
        let mut key_time_out: Option<i64> = None;
        let mut unlocked_device_required = false;
        let mut key_usage_limited: Option<i64> = None;
        let mut confirmation_token_receiver: Option<ConfirmationTokenReceiver> = None;
        let mut max_boot_level: Option<BootLevel> = None;

        for key_param in key_params.iter() {
            match key_param.key_parameter_value() {
                KeyParameterValue::NoAuthRequired => {
                    no_auth_required = true;
                }
                KeyParameterValue::AuthTimeout(t) => {
                    key_time_out = Some(*t as i64);
                }
                KeyParameterValue::HardwareAuthenticatorType(a) => {
                    user_auth_type = Some(*a);
                }
                KeyParameterValue::KeyPurpose(p) => {
                    key_purpose_authorized = key_purpose_authorized || *p == purpose;
                }
                KeyParameterValue::CallerNonce => {
                    caller_nonce_allowed = true;
                }
                KeyParameterValue::ActiveDateTime(a) => {
                    if !Enforcements::is_given_time_passed(*a, true) {
                        return Err(Error::Km(Ec::KEY_NOT_YET_VALID))
                            .context(ks_err!("key is not yet active."));
                    }
                }
                KeyParameterValue::OriginationExpireDateTime(o) => {
                    if (purpose == KeyPurpose::ENCRYPT || purpose == KeyPurpose::SIGN)
                        && Enforcements::is_given_time_passed(*o, false)
                    {
                        return Err(Error::Km(Ec::KEY_EXPIRED)).context(ks_err!("key is expired."));
                    }
                }
                KeyParameterValue::UsageExpireDateTime(u) => {
                    if (purpose == KeyPurpose::DECRYPT || purpose == KeyPurpose::VERIFY)
                        && Enforcements::is_given_time_passed(*u, false)
                    {
                        return Err(Error::Km(Ec::KEY_EXPIRED)).context(ks_err!("key is expired."));
                    }
                }
                KeyParameterValue::UserSecureID(s) => {
                    user_sids.push(SecureUserId(*s));
                }
                KeyParameterValue::UserID(u) => {
                    user = AndroidUserId(*u);
                }
                KeyParameterValue::UnlockedDeviceRequired => {
                    unlocked_device_required = true;
                }
                KeyParameterValue::UsageCountLimit(_) => {
                    key_usage_limited = Some(key_id);
                }
                KeyParameterValue::TrustedConfirmationRequired => {
                    confirmation_token_receiver = Some(self.confirmation_token_receiver.clone());
                }
                KeyParameterValue::MaxBootLevel(level) => {
                    max_boot_level = Some(BootLevel(*level as usize));
                }

                _ => {}
            }
        }

        if !key_purpose_authorized {
            return Err(Error::Km(Ec::INCOMPATIBLE_PURPOSE))
                .context(ks_err!("the purpose is not authorized."));
        }

        if !user_sids.is_empty() && no_auth_required {
            return Err(Error::Km(Ec::INVALID_KEY_BLOB)).context(ks_err!(
                "key has both NO_AUTH_REQUIRED and USER_SECURE_ID tags."
            ));
        }

        if (user_auth_type.is_some() && user_sids.is_empty())
            || (user_auth_type.is_none() && !user_sids.is_empty())
        {
            return Err(Error::Km(Ec::KEY_USER_NOT_AUTHENTICATED)).context(ks_err!(
                "Auth required, but auth type {user_auth_type:?} + {user_sids:?} inconsistently specified",
            ));
        }

        if (purpose == KeyPurpose::ENCRYPT || purpose == KeyPurpose::SIGN)
            && !caller_nonce_allowed
            && op_params.iter().any(|kp| kp.tag == Tag::NONCE)
        {
            return Err(Error::Km(Ec::CALLER_NONCE_PROHIBITED)).context(ks_err!(
                "NONCE is present, although CALLER_NONCE is not present"
            ));
        }

        if unlocked_device_required && self.is_device_locked(user) {
            return Err(Error::Km(Ec::DEVICE_LOCKED)).context(ks_err!("device is locked."));
        }

        if let Some(level) = max_boot_level {
            if !SUPER_KEY.read().unwrap().level_accessible(level) {
                return Err(Error::Km(Ec::BOOT_LEVEL_EXCEEDED))
                    .context(ks_err!("boot level is too late."));
            }
        }

        let (hat, state) = if user_sids.is_empty() {
            (None, DeferredAuthState::NoAuthRequired)
        } else if let Some(key_time_out) = key_time_out {
            let hat = Self::find_auth_token(|hat: &AuthTokenEntry| match user_auth_type {
                Some(auth_type) => hat.satisfies(&user_sids, auth_type),
                None => false,
            })
            .ok_or(Error::Km(Ec::KEY_USER_NOT_AUTHENTICATED))
            .context(ks_err!(
                "No suitable auth token for {user_sids:?} type {user_auth_type:?} received in last {key_time_out}s found",
            ))?;
            let now = BootTime::now();
            let token_age = now
                .checked_sub(&hat.time_received())
                .ok_or_else(Error::sys)
                .context(ks_err!(
                    "Overflow while computing Auth token validity. Validity cannot be established."
                ))?;

            if token_age.seconds() > key_time_out {
                return Err(Error::Km(Ec::KEY_USER_NOT_AUTHENTICATED)).context(ks_err!(
                    concat!(
                        "matching auth token (challenge={}, userId={}, authId={}, ",
                        "authType={:#x}, timestamp={}ms) rcved={:?} ",
                        "for sids {:?} type {:?} is expired ({}s old > timeout={}s)"
                    ),
                    hat.auth_token().challenge,
                    hat.auth_token().userId,
                    hat.auth_token().authenticatorId,
                    hat.auth_token().authenticatorType.0,
                    hat.auth_token().timestamp.milliSeconds,
                    hat.time_received(),
                    user_sids,
                    user_auth_type,
                    token_age.seconds(),
                    key_time_out
                ));
            }
            let state = if requires_timestamp {
                DeferredAuthState::TimeStampRequired(hat.auth_token().clone())
            } else {
                DeferredAuthState::NoAuthRequired
            };
            (Some(hat.take_auth_token()), state)
        } else {
            (
                None,
                DeferredAuthState::OpAuthRequired(
                    user_sids,
                    user_auth_type.unwrap_or(HardwareAuthenticatorType(0)),
                ),
            )
        };
        Ok((
            hat,
            AuthInfo {
                state,
                key_usage_limited,
                confirmation_token_receiver,
            },
        ))
    }

    fn find_auth_token<F>(p: F) -> Option<AuthTokenEntry>
    where
        F: Fn(&AuthTokenEntry) -> bool,
    {
        DB.with(|db| db.borrow().find_auth_token_entry(p))
    }

    fn is_given_time_passed(given_time: i64, is_given_time_inclusive: bool) -> bool {
        let duration_since_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH);

        let time_since_epoch = match duration_since_epoch {
            Ok(duration) => duration.as_millis(),
            Err(_) => return false,
        };

        if is_given_time_inclusive {
            time_since_epoch >= (given_time as u128)
        } else {
            time_since_epoch > (given_time as u128)
        }
    }

    pub fn install_lock_state_task(&self, task: Arc<AsyncTask>) {
        info!("Setting lock state task");
        *self.lock_state_task.write().unwrap() = Some(task);
    }

    fn is_device_locked(&self, user: AndroidUserId) -> bool {
        if let Some(task) = &*self.lock_state_task.read().unwrap() {
            let _wp = wd::watch("Enforcements::is_device_locked sync with task");
            let (send, rcv) = channel::<()>();

            let queued = task.queue_hi_if_running(move |_shelf| {
                if let Err(e) = send.send(()) {
                    warn!("failed to send queue sync notification: {e:?}");
                }
            });
            if queued {
                let _wp = wd::watch("Enforcements::is_device_locked sync with non-empty queue");
                info!("added sync closure to notification queue");

                let _result = rcv.recv();
                info!("sync closure in notification queue completed");
            }
        }

        let set = self.device_unlocked_set.lock().unwrap();
        !set.contains(&user)
    }

    pub fn set_device_locked(&self, user: AndroidUserId, device_locked_status: bool) {
        let mut set = self.device_unlocked_set.lock().unwrap();
        if device_locked_status {
            set.remove(&user);
        } else {
            set.insert(user);
        }
    }

    pub fn add_auth_token(&self, hat: HardwareAuthToken) {
        DB.with(|db| db.borrow_mut().insert_auth_token(&hat));
        self.op_auth_map.add_auth_token(hat);
    }

    fn register_op_auth_receiver(&self, challenge: Challenge, recv: TokenReceiver) {
        self.op_auth_map.add_receiver(challenge, recv);
    }

    pub fn super_encryption_required(
        domain: &Domain,
        key_parameters: &[KeyParameter],
        flags: Option<i32>,
    ) -> SuperEncryptionType {
        if let Some(flags) = flags {
            if (flags & KEY_FLAG_AUTH_BOUND_WITHOUT_CRYPTOGRAPHIC_LSKF_BINDING) != 0 {
                return SuperEncryptionType::None;
            }
        }

        struct Candidate {
            priority: u32,
            enc_type: SuperEncryptionType,
        }
        let mut result = Candidate {
            priority: 0,
            enc_type: SuperEncryptionType::None,
        };
        for kp in key_parameters {
            let t = match kp.key_parameter_value() {
                KeyParameterValue::MaxBootLevel(level) => Candidate {
                    priority: 3,
                    enc_type: SuperEncryptionType::BootLevel(BootLevel(*level as usize)),
                },
                KeyParameterValue::UnlockedDeviceRequired if *domain == Domain::APP => Candidate {
                    priority: 2,
                    enc_type: SuperEncryptionType::UnlockedDeviceRequired,
                },
                KeyParameterValue::UserSecureID(_) if *domain == Domain::APP => Candidate {
                    priority: 1,
                    enc_type: SuperEncryptionType::CredentialEncrypted,
                },
                _ => Candidate {
                    priority: 0,
                    enc_type: SuperEncryptionType::None,
                },
            };
            if t.priority > result.priority {
                result = t;
            }
        }
        result.enc_type
    }

    pub fn get_auth_tokens(
        &self,
        challenge: Challenge,
        sid: SecureUserId,
        auth_token_max_age_millis: i64,
    ) -> Result<(HardwareAuthToken, TimeStampToken)> {
        let auth_type = HardwareAuthenticatorType::ANY;
        let sids: Vec<SecureUserId> = vec![sid];

        let result = Self::find_auth_token(|hat: &AuthTokenEntry| {
            (challenge == hat.challenge()) && hat.satisfies(&sids, auth_type)
        });

        let auth_token = if let Some(auth_token_entry) = result {
            auth_token_entry.take_auth_token()
        } else {
            if auth_token_max_age_millis != 0 {
                let now_in_millis = BootTime::now();
                let result = Self::find_auth_token(|auth_token_entry: &AuthTokenEntry| {
                    let token_valid = now_in_millis
                        .checked_sub(&auth_token_entry.time_received())
                        .is_some_and(|token_age_in_millis| {
                            auth_token_max_age_millis > token_age_in_millis.milliseconds()
                        });
                    token_valid && auth_token_entry.satisfies(&sids, auth_type)
                });

                if let Some(auth_token_entry) = result {
                    auth_token_entry.take_auth_token()
                } else {
                    return Err(AuthzError::Rc(AuthzResponseCode::NO_AUTH_TOKEN_FOUND))
                        .context(ks_err!("No auth token found."));
                }
            } else {
                return Err(AuthzError::Rc(AuthzResponseCode::NO_AUTH_TOKEN_FOUND)).context(
                    ks_err!(
                        "No auth token found for \
                    the given challenge and passed-in auth token max age is zero."
                    ),
                );
            }
        };

        let tst =
            get_timestamp_token(challenge).context(ks_err!("Error in getting timestamp token."))?;
        Ok((auth_token, tst))
    }

    pub fn get_last_auth_time(
        &self,
        sid: SecureUserId,
        auth_type: HardwareAuthenticatorType,
    ) -> Option<BootTime> {
        let result =
            Self::find_auth_token(|entry: &AuthTokenEntry| entry.satisfies(&[sid], auth_type));

        result.map(|auth_token_entry| auth_token_entry.time_received())
    }
}
