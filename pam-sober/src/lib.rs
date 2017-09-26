extern crate pam;
extern crate rand;

pub mod ffi;

use pam::module::PamHandle;
use pam::constants::{PamResultCode, PAM_PROMPT_ECHO_OFF};
use pam::conv::PamConv;
use rand::Rng;
use std::str::FromStr;

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

// This function performs the task of authenticating the user.
pub fn sm_authenticate(pamh: &PamHandle, args: Vec<String>, silent: bool) -> PamResultCode {
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

    let password = pam_try!(conv.send(PAM_PROMPT_ECHO_OFF, &math));

    if password.and_then(|p| u32::from_str(&p).ok()) == Some(a+b) {
        return PamResultCode::PAM_SUCCESS;
    }

    println!("You failed the PAM sobriety test.");
    return PamResultCode::PAM_AUTH_ERR;
}

// This function performs the task of altering the credentials of the user with respect to the
// corresponding authorization scheme. Generally, an authentication module may have access to more
// information about a user than their authentication token. This function is used to make such
// information available to the application. It should only be called after the user has been
// authenticated but before a session has been established.
pub fn sm_setcred(_pamh: &PamHandle, _args: Vec<String>, _silent: bool) -> PamResultCode {
    println!("set credentials");
    PamResultCode::PAM_SUCCESS
}

// This function performs the task of establishing whether the user is permitted to gain access at
// this time. It should be understood that the user has previously been validated by an
// authentication module. This function checks for other things. Such things might be: the time of
// day or the date, the terminal line, remote hostname, etc. This function may also determine
// things like the expiration on passwords, and respond that the user change it before continuing.
pub fn acct_mgmt(_pamh: &PamHandle, _args: Vec<String>, _silent: bool) -> PamResultCode {
    println!("account management");
    PamResultCode::PAM_SUCCESS
}
