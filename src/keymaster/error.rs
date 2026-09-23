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

pub use crate::android::hardware::security::keymint::ErrorCode::ErrorCode;
pub use crate::android::system::keystore2::ResponseCode::ResponseCode;
use crate::keymaster::utils::AppUid;
use crate::selinux;
use log::{log, warn, Level};
use rsbinder::status::Result as BinderResult;
use rsbinder::{ExceptionCode, Status as BinderStatus, StatusCode};
use std::cmp::PartialEq;

#[cfg(test)]
pub mod tests;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("Error::Rc({0:?})")]
    Rc(ResponseCode),

    #[error("Error::Km({0:?})")]
    Km(ErrorCode),

    #[error("Binder exception code {0:?}, {1:?}")]
    Binder(ExceptionCode, i32),

    #[error("Binder transaction error {0:?}")]
    BinderTransaction(StatusCode),
}

pub type KsError = Error;

pub fn log_client_error(level: Option<Level>, e: &anyhow::Error) {
    if let Some(level) = level {
        let uid = AppUid::calling();
        log!(level, "{e:?} for {uid:?}");
    }
}

#[macro_export]
macro_rules! log_client_err {
    ($e:expr) => {
        $crate::keymaster::error::log_client_error(
            $crate::keymaster::error::get_log_level(&$e),
            &$e,
        )
    };
    ($e:expr, $level:expr) => {
        $crate::keymaster::error::log_client_error(Some($level), &$e)
    };
}

impl Error {
    pub fn sys() -> Self {
        Error::Rc(ResponseCode::SYSTEM_ERROR)
    }

    pub fn perm() -> Self {
        Error::Rc(ResponseCode::PERMISSION_DENIED)
    }

    pub fn log_level(&self) -> Option<Level> {
        match self {
            Error::Rc(ResponseCode::KEY_NOT_FOUND) => None,

            Error::Km(ErrorCode::KEY_USER_NOT_AUTHENTICATED) => Some(Level::Info),

            Error::Km(ErrorCode::ROLLBACK_RESISTANCE_UNAVAILABLE) => Some(Level::Info),
            _ => Some(Level::Error),
        }
    }
}

pub fn get_log_level(e: &anyhow::Error) -> Option<Level> {
    match e.root_cause().downcast_ref::<Error>() {
        Some(e) => e.log_level(),
        _ => Some(Level::Error),
    }
}

pub fn map_km_error<T>(r: BinderResult<T>) -> Result<T, Error> {
    r.map_err(|s| match s.exception_code() {
        ExceptionCode::ServiceSpecific => {
            let se = s.service_specific_error();
            if se < 0 {
                Error::Km(ErrorCode(s.service_specific_error()))
            } else {
                Error::Binder(ExceptionCode::ServiceSpecific, se)
            }
        }
        ExceptionCode::TransactionFailed => {
            let e = s.transaction_error();
            Error::BinderTransaction(e)
        }

        e_code => Error::Binder(e_code, 0),
    })
}

pub fn map_binder_status<T>(r: BinderResult<T>) -> Result<T, Error> {
    r.map_err(|s| match s.exception_code() {
        ExceptionCode::ServiceSpecific => {
            let se = s.service_specific_error();
            Error::Binder(ExceptionCode::ServiceSpecific, se)
        }
        ExceptionCode::TransactionFailed => {
            let e = s.transaction_error();
            Error::BinderTransaction(e)
        }
        e_code => Error::Binder(e_code, 0),
    })
}

pub fn map_binder_status_code<T>(r: Result<T, StatusCode>) -> Result<T, Error> {
    r.map_err(Error::BinderTransaction)
}

pub fn map_ks_error(e: Error) -> BinderStatus {
    match e {
        Error::Rc(rc) => BinderStatus::new_service_specific_error(rc.0, Some(format!("{rc:?}"))),
        Error::Km(ec) => BinderStatus::new_service_specific_error(ec.0, Some(format!("{ec:?}"))),
        Error::Binder(ExceptionCode::ServiceSpecific, se) => {
            BinderStatus::new_service_specific_error(se, None)
        }
        Error::Binder(ec, _se) => BinderStatus::from(ec),
        Error::BinderTransaction(sc) => BinderStatus::from(sc),
    }
}

pub fn map_ks_result<T>(r: Result<T, Error>) -> Result<T, BinderStatus> {
    r.map_err(map_ks_error)
}

pub fn into_logged_binder(e: anyhow::Error) -> BinderStatus {
    log_client_err!(e);
    into_binder(e)
}

pub fn anyhow_error_to_cstring(e: &anyhow::Error) -> Option<String> {
    let formatted = format!("{e:?}");
    if formatted.contains('\0') {
        warn!("Cannot convert error message to String. It contained a nul byte.");
        None
    } else {
        Some(formatted)
    }
}

pub fn into_binder(e: anyhow::Error) -> BinderStatus {
    let rc = anyhow_error_to_serialized_error(&e);
    BinderStatus::new_service_specific_error(rc.0, anyhow_error_to_cstring(&e))
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct SerializedError(pub i32);

pub fn error_to_serialized_error(e: &Error) -> SerializedError {
    match e {
        Error::Rc(rcode) => SerializedError(rcode.0),
        Error::Km(ec) => SerializedError(ec.0),

        Error::Binder(_, _) | Error::BinderTransaction(_) => {
            SerializedError(ResponseCode::SYSTEM_ERROR.0)
        }
    }
}

pub fn anyhow_error_to_serialized_error(e: &anyhow::Error) -> SerializedError {
    let root_cause = e.root_cause();
    match root_cause.downcast_ref::<Error>() {
        Some(e) => error_to_serialized_error(e),
        None => match root_cause.downcast_ref::<selinux::Error>() {
            Some(selinux::Error::PermissionDenied) => {
                SerializedError(ResponseCode::PERMISSION_DENIED.0)
            }
            _ => SerializedError(ResponseCode::SYSTEM_ERROR.0),
        },
    }
}
