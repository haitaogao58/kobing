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

#![allow(clippy::undocumented_unsafe_blocks)]

use anyhow::Context as AnyhowContext;
use anyhow::{anyhow, Result};
use std::ffi::{CStr, CString};
use std::fmt;
use std::io;
use std::marker::{Send, Sync};
pub use std::ops::Deref;
use std::os::raw::c_char;
use std::ptr;
use std::sync;

mod sys;

use self::sys as selinux;
pub use selinux::pid_t;
use selinux::SELABEL_CTX_ANDROID_KEYSTORE2_KEY;
use selinux::SELINUX_CB_LOG;

static SELINUX_LOG_INIT: sync::Once = sync::Once::new();

static LIB_SELINUX_LOCK: sync::Mutex<()> = sync::Mutex::new(());

fn redirect_selinux_logs_to_logcat() {
    let cb = selinux::selinux_callback {
        func_log: Some(selinux::selinux_log_callback),
    };
    unsafe {
        selinux::selinux_set_callback(SELINUX_CB_LOG as i32, cb);
    }
}

fn init_logger_once() {
    SELINUX_LOG_INIT.call_once(redirect_selinux_logs_to_logcat)
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum Error {
    #[error("Permission Denied")]
    PermissionDenied,

    #[error("Selinux SystemError: {0}")]
    SystemError(String),
}

impl Error {
    pub fn perm() -> Self {
        Error::PermissionDenied
    }
    fn sys<T: Into<String>>(s: T) -> Self {
        Error::SystemError(s.into())
    }
}

#[derive(Debug)]
pub enum Context {
    Raw(*mut ::std::os::raw::c_char),

    CString(CString),
}

impl PartialEq for Context {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}

impl Eq for Context {}

impl fmt::Display for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", (**self).to_str().unwrap_or("Invalid context"))
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        if let Self::Raw(p) = self {
            unsafe { selinux::freecon(*p) };
        }
    }
}

impl Deref for Context {
    type Target = CStr;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Raw(p) => unsafe { CStr::from_ptr(*p) },
            Self::CString(cstr) => cstr,
        }
    }
}

impl Context {
    pub fn new(con: &str) -> Result<Self> {
        Ok(Self::CString(CString::new(con).with_context(|| {
            format!("Failed to create Context with \"{con}\"")
        })?))
    }
}

pub trait Backend {
    fn lookup(&self, key: &str) -> Result<Context>;
}

pub struct KeystoreKeyBackend {
    handle: *mut selinux::selabel_handle,
}

unsafe impl Sync for KeystoreKeyBackend {}

unsafe impl Send for KeystoreKeyBackend {}

impl KeystoreKeyBackend {
    const BACKEND_TYPE: i32 = SELABEL_CTX_ANDROID_KEYSTORE2_KEY as i32;

    pub fn new() -> Result<Self> {
        init_logger_once();
        let _lock = LIB_SELINUX_LOCK.lock().unwrap();

        let handle = unsafe { selinux::selinux_android_keystore2_key_context_handle() };
        if handle.is_null() {
            return Err(anyhow!(Error::sys("Failed to open KeystoreKeyBackend")));
        }
        Ok(KeystoreKeyBackend { handle })
    }
}

impl Drop for KeystoreKeyBackend {
    fn drop(&mut self) {
        unsafe { selinux::selabel_close(self.handle) };
    }
}

impl Backend for KeystoreKeyBackend {
    fn lookup(&self, key: &str) -> Result<Context> {
        let mut con: *mut c_char = ptr::null_mut();
        let c_key = CString::new(key).with_context(|| {
            format!("selabel_lookup: Failed to convert key \"{key}\" to CString.")
        })?;
        match unsafe {
            let _lock = LIB_SELINUX_LOCK.lock().unwrap();

            selinux::selabel_lookup(self.handle, &mut con, c_key.as_ptr(), Self::BACKEND_TYPE)
        } {
            0 => {
                if !con.is_null() {
                    Ok(Context::Raw(con))
                } else {
                    Err(anyhow!(Error::sys(format!(
                        "selabel_lookup returned a NULL context for key \"{key}\""
                    ))))
                }
            }
            _ => Err(anyhow!(io::Error::last_os_error()))
                .with_context(|| format!("selabel_lookup failed for key \"{key}\"")),
        }
    }
}

pub fn getcon() -> Result<Context> {
    init_logger_once();
    let _lock = LIB_SELINUX_LOCK.lock().unwrap();

    let mut con: *mut c_char = ptr::null_mut();
    match unsafe { selinux::getcon(&mut con) } {
        0 => {
            if !con.is_null() {
                Ok(Context::Raw(con))
            } else {
                Err(anyhow!(Error::sys("getcon returned a NULL context")))
            }
        }
        _ => Err(anyhow!(io::Error::last_os_error())).context("getcon failed"),
    }
}

pub fn check_access(source: &CStr, target: &CStr, tclass: &str, perm: &str) -> Result<()> {
    init_logger_once();

    let c_tclass = CString::new(tclass).with_context(|| {
        format!("check_access: Failed to convert tclass \"{tclass}\" to CString.")
    })?;
    let c_perm = CString::new(perm)
        .with_context(|| format!("check_access: Failed to convert perm \"{perm}\" to CString."))?;

    match unsafe {
        let _lock = LIB_SELINUX_LOCK.lock().unwrap();

        selinux::selinux_check_access(
            source.as_ptr(),
            target.as_ptr(),
            c_tclass.as_ptr(),
            c_perm.as_ptr(),
            ptr::null_mut(),
        )
    } {
        0 => Ok(()),
        _ => {
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::PermissionDenied => Err(anyhow!(Error::perm())),
                _ => Err(anyhow!(e)),
            }
            .with_context(|| {
                format!(
                    concat!(
                        "check_access: Failed with sctx: {:?} tctx: {:?}",
                        " with target class: \"{}\" perm: \"{}\""
                    ),
                    source, target, tclass, perm
                )
            })
        }
    }
}

pub fn setcon(target: &CStr) -> std::io::Result<()> {
    if unsafe { selinux::setcon(target.as_ptr()) } != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub trait ClassPermission {
    fn name(&self) -> &'static str;

    fn class_name(&self) -> &'static str;
}

macro_rules! implement_class {

    (
        $(#[$($enum_meta:tt)+])*
        $enum_vis:vis enum $enum_name:ident $body:tt
    ) => {
        implement_class! {
            @extract_class
            []
            [$(#[$($enum_meta)+])*]
            $enum_vis enum $enum_name $body
        }
    };




    (
        @extract_class
        [$(#[$mout:meta])*]
        [
            #[selinux(class_name = $class_name:ident)]
            $(#[$($mtail:tt)+])*
        ]
        $enum_vis:vis enum $enum_name:ident {
            $(
                $(#[$($emeta:tt)+])*
                $vname:ident$( = $vval:expr)?
            ),* $(,)?
        }
    ) => {
        implement_class!{
            @extract_perm_name
            $class_name
            $(#[$mout])*
            $(#[$($mtail)+])*
            $enum_vis enum $enum_name {
                1;
                []
                [$(
                    [] [$(#[$($emeta)+])*]
                    $vname$( = $vval)?,
                )*]
            }
        }
    };


    (
        @extract_class
        [$(#[$mout:meta])*]
        [
            #[$front:meta]
            $(#[$($mtail:tt)+])*
        ]
        $enum_vis:vis enum $enum_name:ident $body:tt
    ) => {
        implement_class!{
            @extract_class
            [
                $(#[$mout])*
                #[$front]
            ]
            [$(#[$($mtail)+])*]
            $enum_vis enum $enum_name $body
        }
    };







    (
        @extract_perm_name
        $class_name:ident
        $(#[$enum_meta:meta])*
        $enum_vis:vis enum $enum_name:ident {
            $next_val:expr;
            [$($out:tt)*]
            [
                [$(#[$mout:meta])*]
                [
                    #[selinux(name = $selinux_name:ident)]
                    $(#[$($mtail:tt)+])*
                ]
                $vname:ident = $vval:expr,
                $($tail:tt)*
            ]
        }
    ) => {
        implement_class!{
            @extract_perm_name
            $class_name
            $(#[$enum_meta])*
            $enum_vis enum $enum_name {
                ($vval << 1);
                [
                    $($out)*
                    $(#[$mout])*
                    $(#[$($mtail)+])*
                    $selinux_name $vname = $vval,
                ]
                [$($tail)*]
            }
        }
    };



    (
        @extract_perm_name
        $class_name:ident
        $(#[$enum_meta:meta])*
        $enum_vis:vis enum $enum_name:ident {
            $next_val:expr;
            [$($out:tt)*]
            [
                [$(#[$mout:meta])*]
                [
                    #[selinux(name = $selinux_name:ident)]
                    $(#[$($mtail:tt)+])*
                ]
                $vname:ident,
                $($tail:tt)*
            ]
        }
    ) => {
        implement_class!{
            @extract_perm_name
            $class_name
            $(#[$enum_meta])*
            $enum_vis enum $enum_name {
                ($next_val << 1);
                [
                    $($out)*
                    $(#[$mout])*
                    $(#[$($mtail)+])*
                    $selinux_name $vname = $next_val,
                ]
                [$($tail)*]
            }
        }
    };


    (
        @extract_perm_name
        $class_name:ident
        $(#[$enum_meta:meta])*
        $enum_vis:vis enum $enum_name:ident {
            $next_val:expr;
            [$($out:tt)*]
            [
                [$(#[$mout:meta])*]
                [
                    #[$front:meta]
                    $(#[$($mtail:tt)+])*
                ]
                $vname:ident$( = $vval:expr)?,
                $($tail:tt)*
            ]
        }
    ) => {
        implement_class!{
            @extract_perm_name
            $class_name
            $(#[$enum_meta])*
            $enum_vis enum $enum_name {
                $next_val;
                [$($out)*]
                [
                    [
                        $(#[$mout])*
                        #[$front]
                    ]
                    [$(#[$($mtail)+])*]
                    $vname$( = $vval)?,
                    $($tail)*
                ]
            }
        }
    };



    (
        @extract_perm_name
        $class_name:ident
        $(#[$enum_meta:meta])*
        $enum_vis:vis enum $enum_name:ident {
            $next_val:expr;
            [$($out:tt)*]
            []
        }
    ) => {
        implement_class!{
            @spill
            $class_name
            $(#[$enum_meta])*
            $enum_vis enum $enum_name {
                $($out)*
            }
        }
    };

    (
        @spill
        $class_name:ident
        $(#[$enum_meta:meta])*
        $enum_vis:vis enum $enum_name:ident {
            $(
                $(#[$emeta:meta])*
                $selinux_name:ident $vname:ident = $vval:expr,
            )*
        }
    ) => {
        $(#[$enum_meta])*
        $enum_vis enum $enum_name {

            None = 0,
            $(
                $(#[$emeta])*
                $vname = $vval,
            )*
        }

        impl From<i32> for $enum_name {
            #[allow(non_upper_case_globals)]
            fn from (p: i32) -> Self {


                $(const $vname: i32 = $vval;)*
                match p {
                    0 => Self::None,
                    $($vname => Self::$vname,)*
                    _ => Self::None,
                }
            }
        }

        impl From<$enum_name> for i32 {
            fn from(p: $enum_name) -> i32 {
                p as i32
            }
        }

        impl ClassPermission for $enum_name {
            fn name(&self) -> &'static str {
                match self {
                    Self::None => &"none",
                    $(Self::$vname => stringify!($selinux_name),)*
                }
            }
            fn class_name(&self) -> &'static str {
                stringify!($class_name)
            }
        }
    };
}

pub(crate) use implement_class;

pub fn check_permission<T: ClassPermission>(source: &CStr, target: &CStr, perm: T) -> Result<()> {
    check_access(source, target, perm.class_name(), perm.name())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    static SU_KEY_NAMESPACE: &str = "0";

    static SHELL_KEY_NAMESPACE: &str = "1";

    fn check_context() -> Result<(Context, &'static str, bool)> {
        let context = getcon()?;
        match context.to_str().unwrap() {
            "u:r:magisk:s0" | "u:r:ksu:s0" | "u:r:su:s0" => {
                Ok((context, SU_KEY_NAMESPACE, true))
            }
            "u:r:shell:s0" => Ok((context, SHELL_KEY_NAMESPACE, false)),
            c => Err(anyhow!(format!(
                "This test must be run as \"magisk\", \"ksu\", \"su\" or \"shell\". Current context: \"{}\"",
                c
            ))),
        }
    }

    #[test]
    fn test_getcon() -> Result<()> {
        check_context()?;
        Ok(())
    }

    #[test]
    fn test_label_lookup() -> Result<()> {
        let (_context, namespace, is_su) = check_context()?;
        let backend = KeystoreKeyBackend::new()?;
        let context = backend.lookup(namespace)?;
        if is_su {
            assert_eq!(context.to_str(), Ok("u:object_r:su_key:s0"));
        } else {
            assert_eq!(context.to_str(), Ok("u:object_r:shell_key:s0"));
        }
        Ok(())
    }

    #[test]
    fn context_from_string() -> Result<()> {
        let tctx = Context::new("u:object_r:keystore:s0").unwrap();
        let sctx = Context::new("u:r:system_server:s0").unwrap();
        check_access(&sctx, &tctx, "keystore2_key", "use")?;
        Ok(())
    }

    mod perm {
        use super::*;
        use anyhow::Result;

        macro_rules! check_key_perm {




            (use, $privileged:expr) => {
                check_key_perm!(use_, $privileged, "use");
            };
            ($perm:ident, $privileged:expr) => {
                check_key_perm!($perm, $privileged, stringify!($perm));
            };
            ($perm:ident, $privileged:expr, $p_str:expr) => {
                #[test]
                fn $perm() -> Result<()> {
                    let scontext = Context::new("u:r:shell:s0")?;
                    let backend = KeystoreKeyBackend::new()?;
                    let tcontext = backend.lookup(SHELL_KEY_NAMESPACE)?;

                    if $privileged {
                        assert_eq!(
                            Some(&Error::perm()),
                            check_access(
                                &scontext,
                                &tcontext,
                                "keystore2_key",
                                $p_str
                            )
                            .err()
                            .unwrap()
                            .root_cause()
                            .downcast_ref::<Error>()
                        );
                    } else {
                        assert!(check_access(
                            &scontext,
                            &tcontext,
                            "keystore2_key",
                            $p_str
                        )
                        .is_ok());
                    }
                    Ok(())
                }
            };
        }

        check_key_perm!(manage_blob, true);
        check_key_perm!(delete, false);
        check_key_perm!(use_dev_id, true);
        check_key_perm!(req_forced_op, true);
        check_key_perm!(gen_unique_id, true);
        check_key_perm!(grant, true);
        check_key_perm!(get_info, false);
        check_key_perm!(rebind, false);
        check_key_perm!(update, false);
        check_key_perm!(use, false);

        macro_rules! check_keystore_perm {
            ($perm:ident) => {
                #[test]
                fn $perm() -> Result<()> {
                    let ks_context = Context::new("u:object_r:keystore:s0")?;
                    let priv_context = Context::new("u:r:system_server:s0")?;
                    let unpriv_context = Context::new("u:r:shell:s0")?;
                    assert!(check_access(
                        &priv_context,
                        &ks_context,
                        "keystore2",
                        stringify!($perm)
                    )
                    .is_ok());
                    assert_eq!(
                        Some(&Error::perm()),
                        check_access(&unpriv_context, &ks_context, "keystore2", stringify!($perm))
                            .err()
                            .unwrap()
                            .root_cause()
                            .downcast_ref::<Error>()
                    );
                    Ok(())
                }
            };
        }

        check_keystore_perm!(add_auth);
        check_keystore_perm!(clear_ns);
        check_keystore_perm!(lock);
        check_keystore_perm!(reset);
        check_keystore_perm!(unlock);
    }
}
