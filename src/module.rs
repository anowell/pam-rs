//! Functions for use in pam modules.

use libc::{c_char};
use std::{mem, ptr};
use std::ffi::{CStr, CString};

use constants;
use constants::*;

/// Opaque type, used as a pointer when making pam API calls.
///
/// A module is invoked via an external function such as `pam_sm_authenticate`.
/// Such a call provides a pam handle pointer.  The same pointer should be given
/// as an argument when making API calls.
#[allow(missing_copy_implementations)]
pub enum PamHandleT {}

#[allow(missing_copy_implementations)]
enum PamItemT {}

#[allow(missing_copy_implementations)]
pub enum PamDataT {}

#[link(name = "pam")]
extern {
    fn pam_get_data(pamh: *const PamHandleT,
                    module_data_name: *const c_char,
                    data: &mut *const PamDataT,
                    ) -> PamResultCode;

    fn pam_set_data(pamh: *const PamHandleT,
                    module_data_name: *const c_char,
                    data: Box<PamDataT>,
                    cleanup: extern fn (pamh: *const PamHandleT,
                                        data: Box<PamDataT>,
                                        error_status: PamResultCode
                                        ),
                    ) -> PamResultCode;

    fn pam_get_item(pamh: *const PamHandleT,
                    item_type: PamItemType,
                    item: &mut *const PamItemT,
                    ) -> PamResultCode;

    fn pam_set_item(pamh: *mut PamHandleT,
                    item_type: PamItemType,
                    item: &PamItemT,
                    ) -> PamResultCode;

    fn pam_get_user(pamh: *const PamHandleT,
                    user: & *mut c_char,
                    prompt: *const c_char,
                    ) -> PamResultCode;
}

pub type PamResult<T> = Result<T, PamResultCode>;

/// Type-level mapping for safely retrieving values with `get_item`.
///
/// See `pam_get_item` in
/// http://www.linux-pam.org/Linux-PAM-html/mwg-expected-by-module-item.html
pub trait PamItem {
    /// Maps a Rust type to a pam constant.
    ///
    /// For example, the type PamConv maps to the constant PAM_CONV.  The pam
    /// API contract specifies that when the API function `pam_get_item` is
    /// called with the constant PAM_CONV, it will return a value of type
    /// `PamConv`.
    ///
    /// The argument will always be `None`.  Its purpose is to provide a type
    /// label - the value is not important.
    fn item_type(_: Option<Self>) -> PamItemType;
}

/// Gets some value, identified by `key`, that has been set by the module
/// previously.
///
/// See `pam_get_data` in
/// http://www.linux-pam.org/Linux-PAM-html/mwg-expected-by-module-item.html
pub unsafe fn get_data<'a, T>(pamh: &'a PamHandleT, key: &str) -> PamResult<&'a T> {
    let c_key = CString::new(key).unwrap().as_ptr();
    let mut ptr: *const PamDataT = ptr::null();
    let res = pam_get_data(pamh, c_key, &mut ptr);
    if constants::PAM_SUCCESS == res && !ptr.is_null() {
        let typed_ptr: *const T = mem::transmute(ptr);
        let data: &T = &*typed_ptr;
        Ok(data)
    }
    else {
        Err(res)
    }
}

/// Stores a value that can be retrieved later with `get_data`.  The value lives
/// as long as the current pam cycle.
///
/// See `pam_set_data` in
/// http://www.linux-pam.org/Linux-PAM-html/mwg-expected-by-module-item.html
pub fn set_data<T>(pamh: &PamHandleT, key: &str, data: Box<T>) -> PamResult<()> {
    let c_key = CString::new(key).unwrap().as_ptr();
    let res = unsafe {
        let c_data: Box<PamDataT> = mem::transmute(data);
        pam_set_data(pamh, c_key, c_data, cleanup::<T>)
    };
    if constants::PAM_SUCCESS == res { Ok(()) } else { Err(res) }
}

#[no_mangle]
pub extern fn cleanup<T>(_: *const PamHandleT, c_data: Box<PamDataT>, _: PamResultCode) {
    unsafe {
        let data: Box<T> = mem::transmute(c_data);
        mem::drop(data);
    }
}

/// Retrieves a value that has been set, possibly by the pam client.  This is
/// particularly useful for getting a `PamConv` reference.
///
/// See `pam_get_item` in
/// http://www.linux-pam.org/Linux-PAM-html/mwg-expected-by-module-item.html
pub fn get_item<'a, T: PamItem>(pamh: &'a PamHandleT) -> PamResult<&'a T> {
    let mut ptr: *const PamItemT = ptr::null();
    let (res, item) = unsafe {
        let r = pam_get_item(pamh, PamItem::item_type(None::<T>), &mut ptr);
        let typed_ptr: *const T = mem::transmute(ptr);
        let t: &T = &*typed_ptr;
        (r, t)
    };
    if constants::PAM_SUCCESS == res { Ok(item) } else { Err(res) }
}

/// Retrieves the name of the user who is authenticating or logging in.
///
/// This is really a specialization of `get_item`.
///
/// See `pam_get_user` in
/// http://www.linux-pam.org/Linux-PAM-html/mwg-expected-by-module-item.html
pub fn get_user<'a>(pamh: &'a PamHandleT, prompt: Option<&str>) -> PamResult<String> {
    let ptr: *mut c_char = ptr::null_mut();
    let c_prompt = match prompt {
        Some(p) => CString::new(p).unwrap().as_ptr(),
        None    => ptr::null(),
    };
    let res = unsafe { pam_get_user(pamh, &ptr, c_prompt) };
    if constants::PAM_SUCCESS == res && !ptr.is_null() {
        let const_ptr = ptr as *const c_char;
        let bytes = unsafe { CStr::from_ptr(const_ptr).to_bytes() };
        String::from_utf8(bytes.to_vec())
            .map_err(|_| PAM_CONV_ERR)
    }
    else {
        Err(res)
    }
}
