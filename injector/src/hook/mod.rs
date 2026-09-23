use std::ffi::c_void;
use std::os::raw::c_int;
use std::sync::atomic::AtomicPtr;
use std::sync::OnceLock;

pub(crate) mod binder;
mod install;
mod intercept;
pub(crate) mod rewrite;

static OLD_IOCTL: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static OLD_CLOSE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static OLD_FDSAN_CLOSE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static OLD_DUP: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static OLD_DUP2: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static OLD_DUP3: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static OLD_FCNTL: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static HOOK_INIT: OnceLock<Result<(), String>> = OnceLock::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct BinderFdToken {
    pub fd: c_int,
    pub generation: u64,
    pub connection: BinderStateKey,
}

pub(super) type BinderStateKey = u64;

pub unsafe extern "C" fn new_ioctl(fd: c_int, request: c_int, arg: *mut c_void) -> c_int {
    intercept::new_ioctl(fd, request, arg)
}

pub unsafe extern "C" fn new_close(fd: c_int) -> c_int {
    intercept::new_close(fd)
}

pub unsafe extern "C" fn new_fdsan_close(fd: c_int, tag: u64) -> c_int {
    intercept::new_fdsan_close(fd, tag)
}

pub unsafe extern "C" fn new_dup(fd: c_int) -> c_int {
    intercept::new_dup(fd)
}

pub unsafe extern "C" fn new_dup2(old_fd: c_int, new_fd: c_int) -> c_int {
    intercept::new_dup2(old_fd, new_fd)
}

pub unsafe extern "C" fn new_dup3(old_fd: c_int, new_fd: c_int, flags: c_int) -> c_int {
    intercept::new_dup3(old_fd, new_fd, flags)
}

pub unsafe extern "C" fn new_fcntl(fd: c_int, command: c_int, arg: libc::c_ulong) -> c_int {
    intercept::new_fcntl(fd, command, arg)
}

pub fn init_hook() -> anyhow::Result<()> {
    install::init_hook()
}
