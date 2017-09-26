#[macro_use] extern crate pam;
extern crate rand;

use pam::module::{PamHandle, PamHooks};
use pam::constants::{PamResultCode, PamFlag, PAM_PROMPT_ECHO_ON};
use pam::conv::PamConv;
use rand::Rng;
use std::str::FromStr;
use std::ffi::CStr;

macro_rules! pam_try {
    ($e:expr) => (
        match $e {
            Ok(v) => v,
            Err(e) => return e,
        }
    );
    ($e:expr, $err:expr) => (
        match $e {
            Ok(v) => v,
            Err(e) => {
                println!("Error: {}", e);
                return $err;
            }
        }
    );
}

struct PamSober;
pam_hooks!(PamSober);

impl PamHooks for PamSober {
    // This function performs the task of authenticating the user.
    fn sm_authenticate(pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        println!("Let's auth over HTTP");

        /* TODO: use args to change difficulty ;-)
        let args: HashMap<&str, &str> = args.iter().map(|s| {
            let mut parts = s.splitn(2, "=");
            (parts.next().unwrap(), parts.next().unwrap_or(""))
        }).collect();
        */

        // TODO: maybe we can change difficulty base on user?
        // let user = pam_try!(pam.get_user(None));

        let conv = match pamh.get_item::<PamConv>() {
            Ok(conv) => conv,
            Err(err) => {
                println!("Couldn't get pam_conv");
                return err;
            }
        };

        let mut rng = rand::thread_rng();
        let a = rng.gen::<u32>() % 100;
        let b = rng.gen::<u32>() % 100;
        let math = format!("{} + {} = ", a, b);

        // This println kinda helps debugging since the test script doesn't echo
        println!("{}", math);

        let password = pam_try!(conv.send(PAM_PROMPT_ECHO_ON, &math));

        if password.and_then(|p| u32::from_str(&p).ok()) == Some(a+b) {
            return PamResultCode::PAM_SUCCESS;
        }

        println!("You failed the PAM sobriety test.");
        return PamResultCode::PAM_AUTH_ERR;
    }

    fn sm_setcred(_pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        println!("set credentials");
        PamResultCode::PAM_SUCCESS
    }

    fn acct_mgmt(_pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        println!("account management");
        PamResultCode::PAM_SUCCESS
    }
}