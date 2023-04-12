use alloc::ffi::CString;
use core::{ffi::CStr, ptr};

use libc::{c_char, c_int};

use crate::{
    constants::{PamMessageStyle, PamResultCode},
    items::Item,
    module::PamResult,
};

#[repr(C)]
struct PamMessage {
    msg_style: PamMessageStyle,
    msg:       *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp:         *const c_char,
    resp_retcode: libc::c_int, // Unused - always zero
}

/// `PamConv` acts as a channel for communicating with user.
///
/// Communication is mediated by the pam client (the application that invoked
/// pam).  Messages sent will be relayed to the user by the client, and response
/// will be relayed back.
#[repr(C)]
pub struct Inner {
    conv: extern "C" fn(
        num_msg: c_int,
        pam_message: &&PamMessage,
        pam_response: &mut *const PamResponse,
        appdata_ptr: *const libc::c_void,
    ) -> PamResultCode,
    appdata_ptr: *const libc::c_void,
}

pub struct Conv<'a>(&'a Inner);

impl<'a> Conv<'a> {
    /// Sends a message to the pam client.
    ///
    /// This will typically result in the user seeing a message or a prompt.
    /// There are several message styles available:
    ///
    /// - PAM_PROMPT_ECHO_OFF
    /// - PAM_PROMPT_ECHO_ON
    /// - PAM_ERROR_MSG
    /// - PAM_TEXT_INFO
    /// - PAM_RADIO_TYPE
    /// - PAM_BINARY_PROMPT
    ///
    /// Note that the user experience will depend on how the client implements
    /// these message styles - and not all applications implement all message
    /// styles.
    pub fn send(&self, style: PamMessageStyle, msg: &str) -> PamResult<Option<&CStr>> {
        let mut resp_ptr: *const PamResponse = ptr::null();
        let msg_cstr = CString::new(msg).unwrap();

        let ret = (self.0.conv)(
            1,
            &&PamMessage {
                msg_style: style,
                msg:       msg_cstr.as_ptr(),
            },
            &mut resp_ptr,
            self.0.appdata_ptr,
        );

        if PamResultCode::PAM_SUCCESS == ret {
            // PamResponse.resp is null for styles that don't return user input like
            // PAM_TEXT_INFO
            let response = unsafe { (*resp_ptr).resp };
            if response.is_null() {
                Ok(None)
            } else {
                Ok(Some(unsafe { CStr::from_ptr(response) }))
            }
        } else {
            Err(ret)
        }
    }
}

impl<'a> Item for Conv<'a> {
    type Raw = Inner;

    fn type_id() -> crate::items::ItemType {
        crate::items::ItemType::Conv
    }

    unsafe fn from_raw(raw: *const Self::Raw) -> Self {
        Self(&*raw)
    }

    fn into_raw(self) -> *const Self::Raw {
        self.0 as _
    }
}
