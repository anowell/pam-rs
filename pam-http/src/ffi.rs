use pam::module::{PamHandleT};
use pam::constants::{PamFlag, PamResultCode, PAM_SILENT};
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};



fn extract_argv(argc: c_int, argv: *const *const c_char) -> Vec<String> {
    (0..argc)
        .map(|o| unsafe {
            CStr::from_ptr(*argv.offset(o as isize) as *const c_char)
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

#[no_mangle]
pub extern "C" fn pam_sm_acct_mgmt(
	pamh: &PamHandleT,
	flags: PamFlag,
	argc: c_int,
	argv: *const *const c_char,
) -> PamResultCode {
	let args = extract_argv(argc, argv);
	let silent = (flags & PAM_SILENT) != 0;
	super::acct_mgmt(pamh, args, silent)
}

#[no_mangle]
pub extern "C" fn pam_sm_authenticate(
	pamh: &PamHandleT,
	flags: PamFlag,
	argc: c_int,
	argv: *const *const c_char,
) -> PamResultCode {
	let args = extract_argv(argc, argv);
	let silent = (flags & PAM_SILENT) != 0;
	super::sm_authenticate(pamh, args, silent)
}

#[no_mangle]
pub extern "C" fn pam_sm_chauthtok(
	_: &PamHandleT,
	_: PamFlag,
	_: c_int,
	_: *const *const c_char,
) -> PamResultCode {
	PamResultCode::PAM_IGNORE
}

#[no_mangle]
pub extern "C" fn pam_sm_close_session(
	_: &PamHandleT,
	_: PamFlag,
	_: c_int,
	_: *const *const c_char,
) -> PamResultCode {
	PamResultCode::PAM_IGNORE
}

#[no_mangle]
pub extern "C" fn pam_sm_open_session(
	_: &PamHandleT,
	_: PamFlag,
	_: c_int,
	_: *const *const c_char,
) -> PamResultCode {
	PamResultCode::PAM_IGNORE
}

#[no_mangle]
pub extern "C" fn pam_sm_setcred(
	pamh: &PamHandleT,
	flags: PamFlag,
	argc: c_int,
	argv: *const *const c_char,
) -> PamResultCode {
	let args = extract_argv(argc, argv);
	let silent = (flags & PAM_SILENT) != 0;
	super::sm_setcred(pamh, args, silent)
}
