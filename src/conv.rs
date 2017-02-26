use libc::{c_char, c_int};
use std::ptr;
use std::ffi::{CStr, CString};

use constants;
use constants::*;
use module::{PamItem, PamResult};

#[allow(missing_copy_implementations)]
pub enum AppDataPtr {}

#[repr(C)]
struct PamMessage {
    msg_style: PamMessageStyle,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *const c_char,
    resp_retcode: AlwaysZero,
}

/// `PamConv` acts as a channel for communicating with user.
///
/// Communication is mediated by the pam client (the application that invoked
/// pam).  Messages sent will be relayed to the user by the client, and response
/// will be relayed back.
#[repr(C)]
pub struct PamConv {
    conv: extern "C" fn(num_msg: c_int,
                        pam_message: &&PamMessage,
                        pam_response: &mut *const PamResponse,
                        appdata_ptr: *const AppDataPtr)
                        -> PamResultCode,
    appdata_ptr: *const AppDataPtr,
}

impl PamConv {
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
    pub fn send(&self, style: PamMessageStyle, msg: &str) -> PamResult<Option<String>> {
        let mut resp_ptr: *const PamResponse = ptr::null();
        let msg = PamMessage {
            msg_style: style,
            msg: CString::new(msg).unwrap().as_ptr(),
        };

        let ret = (self.conv)(1, &&msg, &mut resp_ptr, self.appdata_ptr);

        if constants::PAM_SUCCESS == ret {
            if resp_ptr.is_null() {
                Ok(None)
            } else {
                let bytes = unsafe { CStr::from_ptr((*resp_ptr).resp).to_bytes() };
                Ok(String::from_utf8(bytes.to_vec()).ok())
            }
        } else {
            Err(ret)
        }
    }
}

impl PamItem for PamConv {
    fn item_type() -> PamItemType {
        PAM_CONV
    }
}
