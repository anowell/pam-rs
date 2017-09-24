extern crate pam;
extern crate reqwest;

pub mod ffi;

use pam::module::{PamHandleT, get_item, get_user};
use pam::constants::{PamResultCode, PAM_PROMPT_ECHO_OFF};
use pam::conv::PamConv;
use std::collections::HashMap;
use std::time::Duration;
use reqwest::{Client, StatusCode};

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
pub fn sm_authenticate(pamh: &PamHandleT, args: Vec<String>, silent: bool) -> PamResultCode {
    println!("Let's auth over HTTP");

    let args: HashMap<&str, &str> = args.iter().map(|s| {
        let mut parts = s.splitn(2, "=");
        (parts.next().unwrap(), parts.next().unwrap_or(""))
    }).collect();

    let user = pam_try!(get_user(&pamh, None));

    let url: &str = match args.get("url") {
        Some(url) => url,
        None => return PamResultCode::PAM_AUTH_ERR,
    };
    let ca_file = args.get("ca_file");

    let conv = match get_item::<PamConv>(&pamh) {
        Ok(conv) => conv,
        Err(err) => {
            println!("Couldn't get pam_conv");
            return err;
        }
    };
    let password = pam_try!(conv.send(PAM_PROMPT_ECHO_OFF, "Word, yo: "));
    println!("Got a password {:?}", password);
    let status = pam_try!(get_url(url, &user, password.as_ref().map(|p|&**p)), PamResultCode::PAM_AUTH_ERR);

    if !status.is_success() {
        println!("HTTP Error: {}", status);
        return PamResultCode::PAM_AUTH_ERR;
    }

    PamResultCode::PAM_SUCCESS
}

fn get_url(url: &str, user: &str, password: Option<&str>) -> reqwest::Result<StatusCode> {
    let client = Client::builder()?.timeout(Duration::from_secs(5)).build()?;
    client.get(url)?
        .basic_auth(user, password)
        .send()
        .map(|r| r.status())
}

// This function performs the task of altering the credentials of the user with respect to the
// corresponding authorization scheme. Generally, an authentication module may have access to more
// information about a user than their authentication token. This function is used to make such
// information available to the application. It should only be called after the user has been
// authenticated but before a session has been established.
pub fn sm_setcred(_pamh: &PamHandleT, _args: Vec<String>, _silent: bool) -> PamResultCode {
    println!("set credentials");
    PamResultCode::PAM_SUCCESS
}

// This function performs the task of establishing whether the user is permitted to gain access at
// this time. It should be understood that the user has previously been validated by an
// authentication module. This function checks for other things. Such things might be: the time of
// day or the date, the terminal line, remote hostname, etc. This function may also determine
// things like the expiration on passwords, and respond that the user change it before continuing.
pub fn acct_mgmt(_pamh: &PamHandleT, _args: Vec<String>, _silent: bool) -> PamResultCode {
    println!("account management");
    PamResultCode::PAM_SUCCESS
}
