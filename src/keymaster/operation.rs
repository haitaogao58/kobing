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
    IKeyMintOperation::IKeyMintOperation, KeyParameter::KeyParameter, KeyPurpose::KeyPurpose,
    SecurityLevel::SecurityLevel,
};
use crate::android::security::metrics::{
    Algorithm::Algorithm as MetricsAlgorithm, OperationType::OperationType,
};
use crate::android::system::keystore2::{
    IKeystoreOperation::BnKeystoreOperation, IKeystoreOperation::IKeystoreOperation,
};
use crate::err as ks_err;
use crate::keymaster::enforcements::AuthInfo;
use crate::keymaster::error::{
    error_to_serialized_error, into_binder, into_logged_binder, map_km_error, Error, ErrorCode,
    ResponseCode, SerializedError,
};
use crate::keymaster::metrics_store::{
    log_key_operation_event_stats, log_key_operation_streaming_stats, log_operation_latency,
};
use crate::keymaster::utils::AppUid;
use crate::log_client_err;
use crate::watchdog as wd;
use anyhow::{anyhow, Context, Result};
use log::{error, warn};
use rsbinder as binder;
use rsbinder::{Status, Strong};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard, Weak},
    time::{Duration, Instant},
};

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum Outcome {
    Unknown,

    Success,

    Abort,

    Dropped,

    Pruned,

    ErrorCode(SerializedError),
}

#[derive(Debug)]
pub struct Operation {
    index: usize,
    km_op: Strong<dyn IKeyMintOperation>,
    last_usage: Mutex<Instant>,
    outcome: Mutex<Outcome>,
    owner: AppUid,
    auth_info: Mutex<AuthInfo>,
    forced: bool,
    logging_info: LoggingInfo,
    operation_metrics: Mutex<OperationMetrics>,
}

#[derive(Debug, Default, Clone, Copy)]
struct OperationMetrics {
    total_duration: Duration,
    call_count: i32,
    total_input_bytes: u64,
}

#[derive(Debug)]
pub struct LoggingInfo {
    sec_level: SecurityLevel,
    purpose: KeyPurpose,
    algorithm: MetricsAlgorithm,
    op_params: Vec<KeyParameter>,
    key_upgraded: bool,
    is_attested: bool,
}

impl LoggingInfo {
    pub fn new(
        sec_level: SecurityLevel,
        purpose: KeyPurpose,
        algorithm: MetricsAlgorithm,
        op_params: Vec<KeyParameter>,
        key_upgraded: bool,
        is_attested: bool,
    ) -> LoggingInfo {
        Self {
            sec_level,
            purpose,
            algorithm,
            op_params,
            key_upgraded,
            is_attested,
        }
    }
}

struct PruningInfo {
    last_usage: Instant,
    owner: AppUid,
    index: usize,
    forced: bool,
}

const MAX_RECEIVE_DATA: usize = 0x8000;

impl Operation {
    pub fn new(
        index: usize,
        km_op: binder::Strong<dyn IKeyMintOperation>,
        owner: AppUid,
        auth_info: AuthInfo,
        forced: bool,
        logging_info: LoggingInfo,
    ) -> Self {
        Self {
            index,
            km_op,
            last_usage: Mutex::new(Instant::now()),
            outcome: Mutex::new(Outcome::Unknown),
            owner,
            auth_info: Mutex::new(auth_info),
            forced,
            logging_info,
            operation_metrics: Mutex::new(OperationMetrics::default()),
        }
    }

    fn watch(&self, id: &'static str) -> Option<wd::WatchPoint> {
        let sec_level = self.logging_info.sec_level;
        wd::watch_millis_with(id, wd::DEFAULT_TIMEOUT_MS, sec_level)
    }

    fn get_pruning_info(&self) -> Option<PruningInfo> {
        if let Ok(guard) = self.outcome.try_lock() {
            match *guard {
                Outcome::Unknown => {}

                _ => return None,
            }
        }

        Some(PruningInfo {
            last_usage: *self.last_usage.lock().expect("In get_pruning_info."),
            owner: self.owner,
            index: self.index,
            forced: self.forced,
        })
    }

    fn prune(&self, last_usage: Instant) -> Result<(), Error> {
        let mut locked_outcome = match self.outcome.try_lock() {
            Ok(guard) => match *guard {
                Outcome::Unknown => guard,
                _ => return Err(Error::Km(ErrorCode::INVALID_OPERATION_HANDLE)),
            },
            Err(_) => return Err(Error::Rc(ResponseCode::OPERATION_BUSY)),
        };

        if *self.last_usage.lock().expect("In Operation::prune()") != last_usage {
            return Err(Error::Rc(ResponseCode::OPERATION_BUSY));
        }
        *locked_outcome = Outcome::Pruned;

        let _wp = self.watch("Operation::prune: calling IKeyMintOperation::abort()");

        if let Err(e) = map_km_error(self.km_op.abort()) {
            warn!("In prune: KeyMint::abort failed: {e:?}.");
        }

        Ok(())
    }

    fn update_outcome<T>(
        &self,
        locked_outcome: &mut Outcome,
        err: Result<T, Error>,
    ) -> Result<T, Error> {
        if let Err(e) = &err {
            *locked_outcome = Outcome::ErrorCode(error_to_serialized_error(e))
        }
        err
    }

    fn check_active(&self) -> Result<MutexGuard<'_, Outcome>> {
        let guard = self.outcome.lock().expect("In check_active.");
        match *guard {
            Outcome::Unknown => Ok(guard),
            _ => Err(Error::Km(ErrorCode::INVALID_OPERATION_HANDLE)).context(ks_err!(
                "Call on finalized operation with outcome: {:?}.",
                *guard
            )),
        }
    }

    fn check_input_length(data: &[u8]) -> Result<()> {
        if data.len() > MAX_RECEIVE_DATA {
            return Err(anyhow!(Error::Rc(ResponseCode::TOO_MUCH_DATA)));
        }
        Ok(())
    }

    fn touch(&self) {
        *self.last_usage.lock().expect("In touch.") = Instant::now();
    }

    fn update_aad(&self, aad_input: &[u8]) -> Result<()> {
        let mut outcome = self.check_active().context("In update_aad")?;
        Self::check_input_length(aad_input).context("In update_aad")?;
        self.touch();

        let (hat, tst) = self
            .auth_info
            .lock()
            .unwrap()
            .before_update()
            .context(ks_err!("Trying to get auth tokens for {:?}", self.owner))?;

        self.update_outcome(&mut outcome, {
            let _wp = self.watch("Operation::update_aad: calling IKeyMintOperation::updateAad");
            map_km_error(self.km_op.updateAad(aad_input, hat.as_ref(), tst.as_ref()))
        })
        .context(ks_err!("Update failed for {:?}", self.owner))?;

        Ok(())
    }

    fn update(&self, input: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut outcome = self.check_active().context("In update")?;
        Self::check_input_length(input).context("In update")?;
        self.touch();

        let (hat, tst) = self
            .auth_info
            .lock()
            .unwrap()
            .before_update()
            .context(ks_err!("Trying to get auth tokens for {:?}", self.owner))?;

        let output = self
            .update_outcome(&mut outcome, {
                let _wp = self.watch("Operation::update: calling IKeyMintOperation::update");
                map_km_error(self.km_op.update(input, hat.as_ref(), tst.as_ref()))
            })
            .context(ks_err!("Update failed for {:?}", self.owner))?;

        if output.is_empty() {
            Ok(None)
        } else {
            Ok(Some(output))
        }
    }

    fn finish(&self, input: Option<&[u8]>, signature: Option<&[u8]>) -> Result<Option<Vec<u8>>> {
        let mut outcome = self.check_active().context("In finish")?;
        if let Some(input) = input {
            Self::check_input_length(input).context("In finish")?;
        }
        self.touch();

        let (hat, tst, confirmation_token) = self
            .auth_info
            .lock()
            .unwrap()
            .before_finish()
            .context(ks_err!("Trying to get auth tokens for {:?}", self.owner))?;

        let output = self
            .update_outcome(&mut outcome, {
                let _wp = self.watch("Operation::finish: calling IKeyMintOperation::finish");
                map_km_error(self.km_op.finish(
                    input,
                    signature,
                    hat.as_ref(),
                    tst.as_ref(),
                    confirmation_token.as_deref(),
                ))
            })
            .context(ks_err!("Finish failed for {:?}", self.owner))?;

        self.auth_info
            .lock()
            .unwrap()
            .after_finish()
            .context("In finish.")?;

        *outcome = Outcome::Success;

        if output.is_empty() {
            Ok(None)
        } else {
            Ok(Some(output))
        }
    }

    fn abort(&self, outcome: Outcome) -> Result<()> {
        let mut locked_outcome = self.check_active().context("In abort")?;
        *locked_outcome = outcome;

        {
            let _wp = self.watch("Operation::abort: calling IKeyMintOperation::abort");
            map_km_error(self.km_op.abort()).context(ks_err!("KeyMint::abort failed."))
        }
    }

    fn update_metrics(&self, latency: Duration, input_bytes: usize) {
        let mut metrics = self.operation_metrics.lock().unwrap();
        metrics.total_duration += latency;
        metrics.call_count += 1;
        metrics.total_input_bytes = metrics.total_input_bytes.saturating_add(input_bytes as u64);
    }

    fn log_metrics(&self, is_success: bool) {
        let metrics = self.operation_metrics.lock().unwrap();
        if metrics.call_count > 0 {
            log_operation_latency(
                OperationType::ENTIRE_OPERATION,
                self.logging_info.sec_level,
                &self.logging_info.op_params,
                is_success,
                metrics.total_duration,
            );
            log_key_operation_streaming_stats(
                self.logging_info.algorithm,
                is_success,
                metrics.call_count,
                metrics.total_input_bytes,
            );
        }
    }
}

impl Drop for Operation {
    fn drop(&mut self) {
        let guard = self.outcome.lock().expect("In drop.");
        log_key_operation_event_stats(
            self.owner.0 as i32,
            self.logging_info.sec_level,
            self.logging_info.purpose,
            &(self.logging_info.op_params),
            &guard,
            self.logging_info.key_upgraded,
            self.logging_info.is_attested,
        );
        self.log_metrics(matches!(*guard, Outcome::Success));

        if let Outcome::Unknown = *guard {
            drop(guard);

            if let Err(e) = self.abort(Outcome::Dropped) {
                error!("While dropping Operation: abort failed: {e:?}");
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct OperationDb {
    operations: Mutex<Vec<Weak<Operation>>>,
}

impl OperationDb {
    pub fn new() -> Self {
        Self {
            operations: Mutex::new(Vec::new()),
        }
    }

    pub fn create_operation(
        &self,
        km_op: binder::Strong<dyn IKeyMintOperation>,
        owner: AppUid,
        auth_info: AuthInfo,
        forced: bool,
        logging_info: LoggingInfo,
    ) -> Arc<Operation> {
        let mut operations = self.operations.lock().expect("In create_operation.");

        let mut index: usize = 0;

        match (*operations).iter_mut().find(|s| {
            index += 1;
            s.upgrade().is_none()
        }) {
            Some(free_slot) => {
                let new_op = Arc::new(Operation::new(
                    index - 1,
                    km_op,
                    owner,
                    auth_info,
                    forced,
                    logging_info,
                ));
                *free_slot = Arc::downgrade(&new_op);
                new_op
            }
            None => {
                let new_op = Arc::new(Operation::new(
                    operations.len(),
                    km_op,
                    owner,
                    auth_info,
                    forced,
                    logging_info,
                ));
                operations.push(Arc::downgrade(&new_op));
                new_op
            }
        }
    }

    fn get(&self, index: usize) -> Option<Arc<Operation>> {
        self.operations
            .lock()
            .expect("In OperationDb::get.")
            .get(index)
            .and_then(|op| op.upgrade())
    }

    pub fn prune(&self, caller: AppUid, forced: bool) -> Result<(), Error> {
        loop {
            let mut owners: HashMap<AppUid, u64> = HashMap::new();
            let mut pruning_info: Vec<PruningInfo> = Vec::new();

            let now = Instant::now();
            self.operations
                .lock()
                .expect("In OperationDb::prune: Trying to lock self.operations.")
                .iter()
                .for_each(|op| {
                    if let Some(op) = op.upgrade() {
                        if let Some(p_info) = op.get_pruning_info() {
                            let owner = p_info.owner;
                            pruning_info.push(p_info);

                            *owners.entry(owner).or_insert(0) += 1;
                        }
                    }
                });

            let caller_malus = if forced {
                0
            } else {
                1u64 + *owners.entry(caller).or_default()
            };

            struct CandidateInfo {
                index: usize,
                malus: u64,
                last_usage: Instant,
                age: Duration,
            }
            let mut oldest_caller_op: Option<CandidateInfo> = None;
            let candidate = pruning_info.iter().fold(
                None,
                |acc: Option<CandidateInfo>,
                 &PruningInfo {
                     last_usage,
                     owner,
                     index,
                     forced,
                 }| {
                    let age = now
                        .checked_duration_since(last_usage)
                        .unwrap_or_else(|| Duration::new(0, 0));

                    if owner == caller {
                        if let Some(CandidateInfo { age: a, .. }) = oldest_caller_op {
                            if age > a {
                                oldest_caller_op = Some(CandidateInfo {
                                    index,
                                    malus: 0,
                                    last_usage,
                                    age,
                                });
                            }
                        } else {
                            oldest_caller_op = Some(CandidateInfo {
                                index,
                                malus: 0,
                                last_usage,
                                age,
                            });
                        }
                    }

                    let malus = if forced {
                        0
                    } else {
                        *owners.get(&owner).expect(
                            "This is odd. We should have counted every owner in pruning_info.",
                        ) + ((age.as_secs() + 1) as f64).log(6.0).floor() as u64
                    };

                    match acc {
                        None => {
                            if caller_malus < malus {
                                Some(CandidateInfo {
                                    index,
                                    malus,
                                    last_usage,
                                    age,
                                })
                            } else {
                                None
                            }
                        }

                        Some(CandidateInfo {
                            index: i,
                            malus: m,
                            last_usage: l,
                            age: a,
                        }) => {
                            if malus > m || (malus == m && age > a) {
                                Some(CandidateInfo {
                                    index,
                                    malus,
                                    last_usage,
                                    age,
                                })
                            } else {
                                Some(CandidateInfo {
                                    index: i,
                                    malus: m,
                                    last_usage: l,
                                    age: a,
                                })
                            }
                        }
                    }
                },
            );

            let candidate = candidate.or(oldest_caller_op);

            match candidate {
                Some(CandidateInfo {
                    index,
                    malus: _,
                    last_usage,
                    age: _,
                }) => match self.get(index) {
                    Some(op) => match op.prune(last_usage) {
                        Ok(()) => break Ok(()),

                        Err(Error::Km(ErrorCode::INVALID_OPERATION_HANDLE)) => break Ok(()),

                        Err(Error::Rc(ResponseCode::OPERATION_BUSY)) => {
                            break Ok(());
                        }

                        _ => continue,
                    },

                    None => break Ok(()),
                },

                None => break Err(Error::Rc(ResponseCode::BACKEND_BUSY)),
            }
        }
    }
}

pub struct KeystoreOperation {
    operation: Mutex<Option<Arc<Operation>>>,
}

impl KeystoreOperation {
    pub fn new_native_binder(operation: Arc<Operation>) -> binder::Strong<dyn IKeystoreOperation> {
        BnKeystoreOperation::new_binder_with_features(
            Self {
                operation: Mutex::new(Some(operation)),
            },
            crate::consts::sid_features(),
        )
    }

    fn with_locked_operation<T, F>(&self, f: F, delete_op: bool, input_len: usize) -> Result<T>
    where
        for<'a> F: FnOnce(&'a Operation) -> Result<T>,
    {
        let mut delete_op: bool = delete_op;
        match self.operation.try_lock() {
            Ok(mut mutex_guard) => {
                let result = match &*mutex_guard {
                    Some(op) => {
                        let (latency, result) = crate::timed_call!(f(op));
                        op.update_metrics(latency, input_len);

                        if result.is_err() {
                            delete_op = true;
                        }
                        result
                    }
                    None => Err(Error::Km(ErrorCode::INVALID_OPERATION_HANDLE))
                        .context(ks_err!("KeystoreOperation::with_locked_operation")),
                };

                if delete_op {
                    *mutex_guard = None;
                }
                result
            }
            Err(_) => Err(Error::Rc(ResponseCode::OPERATION_BUSY))
                .context(ks_err!("KeystoreOperation::with_locked_operation")),
        }
    }
}

impl binder::Interface for KeystoreOperation {}

impl IKeystoreOperation for KeystoreOperation {
    fn updateAad(&self, aad_input: &[u8]) -> Result<(), Status> {
        let _wp = wd::watch("IKeystoreOperation::updateAad");
        self.with_locked_operation(
            |op| {
                op.update_aad(aad_input)
                    .context(ks_err!("KeystoreOperation::updateAad"))
            },
            false,
            aad_input.len(),
        )
        .map_err(into_logged_binder)
    }

    fn update(&self, input: &[u8]) -> Result<Option<Vec<u8>>, Status> {
        let _wp = wd::watch("IKeystoreOperation::update");
        self.with_locked_operation(
            |op| {
                op.update(input)
                    .context(ks_err!("KeystoreOperation::update"))
            },
            false,
            input.len(),
        )
        .map_err(into_logged_binder)
    }
    fn finish(
        &self,
        input: Option<&[u8]>,
        signature: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>, Status> {
        let _wp = wd::watch("IKeystoreOperation::finish");
        self.with_locked_operation(
            |op| {
                op.finish(input, signature)
                    .context(ks_err!("KeystoreOperation::finish"))
            },
            true,
            input.map_or(0, |v| v.len()),
        )
        .map_err(into_logged_binder)
    }

    fn abort(&self) -> Result<(), Status> {
        let _wp = wd::watch("IKeystoreOperation::abort");
        let result = self.with_locked_operation(
            |op| {
                op.abort(Outcome::Abort)
                    .context(ks_err!("KeystoreOperation::abort"))
            },
            true,
            0,
        );
        result.map_err(|e| {
            match e.root_cause().downcast_ref::<Error>() {
                Some(Error::Km(ErrorCode::INVALID_OPERATION_HANDLE)) => {}
                _ => log_client_err!(e),
            };
            into_binder(e)
        })
    }
}
