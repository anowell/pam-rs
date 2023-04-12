/// Macro to generate the `extern "C"` entrypoint bindings needed by PAM
///
/// You can call `pam_hooks!(SomeType);` for any type that implements `PamHooks`
///
/// ## Examples:
///
/// Here is full example of a PAM module that would authenticate and authorize
/// everybody:
///
/// ```
/// #[macro_use] extern crate pam;
///
/// use std::ffi::CStr;
///
/// use pam::{
///     constants::{PamFlag, PamResultCode},
///     module::{PamHandle, PamHooks},
/// };
///
/// # fn main() {}
/// struct MyPamModule;
/// pam_hooks!(MyPamModule);
///
/// impl PamHooks for MyPamModule {
///     fn sm_authenticate(
///         pamh: &mut PamHandle,
///         args: Vec<&CStr>,
///         flags: PamFlag,
///     ) -> PamResultCode {
///         println!("Everybody is authenticated!");
///         PamResultCode::PAM_SUCCESS
///     }
///
///     fn acct_mgmt(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
///         println!("Everybody is authorized!");
///         PamResultCode::PAM_SUCCESS
///     }
/// }
/// ```
#[macro_export]
macro_rules! pam_hooks {
    ($ident:ident) => {
        pub use self::pam_hooks_scope::*;
        mod pam_hooks_scope {
            use core::{
                ffi::{c_char, c_int, CStr},
                slice::from_raw_parts,
            };

            use $crate::{
                constants::{PamFlag, PamResultCode},
                module::{PamHandle, PamHooks},
            };

            fn extract_argv<'a>(argc: c_int, argv: *const *const c_char) -> $crate::Vec<&'a CStr> {
                (0..argc)
                    .map(|o| unsafe { CStr::from_ptr(*argv.offset(o as isize) as *const c_char) })
                    .collect()
            }

            #[no_mangle]
            pub extern "C" fn pam_sm_acct_mgmt(
                pamh: &mut PamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                let args = extract_argv(argc, argv);
                super::$ident::acct_mgmt(pamh, args, flags)
            }

            #[no_mangle]
            pub extern "C" fn pam_sm_authenticate(
                pamh: &mut PamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                let args = extract_argv(argc, argv);
                super::$ident::sm_authenticate(pamh, args, flags)
            }

            #[no_mangle]
            pub extern "C" fn pam_sm_chauthtok(
                pamh: &mut PamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                let args = extract_argv(argc, argv);
                super::$ident::sm_chauthtok(pamh, args, flags)
            }

            #[no_mangle]
            pub extern "C" fn pam_sm_close_session(
                pamh: &mut PamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                let args = extract_argv(argc, argv);
                super::$ident::sm_close_session(pamh, args, flags)
            }

            #[no_mangle]
            pub extern "C" fn pam_sm_open_session(
                pamh: &mut PamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                let args = extract_argv(argc, argv);
                super::$ident::sm_open_session(pamh, args, flags)
            }

            #[no_mangle]
            pub extern "C" fn pam_sm_setcred(
                pamh: &mut PamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                let args = extract_argv(argc, argv);
                super::$ident::sm_setcred(pamh, args, flags)
            }
        }
    };
}

#[macro_export]
macro_rules! pam_try {
    ($r:expr) => {
        match $r {
            Ok(t) => t,
            Err(e) => return e,
        }
    };
    ($r:expr, $e:expr) => {
        match $r {
            Ok(t) => t,
            Err(_) => return $e,
        }
    };
}

#[cfg(test)]
pub mod test {
    use crate::module::PamHooks;

    struct Foo;
    impl PamHooks for Foo {}

    pam_hooks!(Foo);
}
