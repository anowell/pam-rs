#[macro_use] extern crate pam;
extern crate reqwest;

use pam::module::{PamHandle, PamHooks};
use pam::constants::{PamResultCode, PamFlag, PAM_PROMPT_ECHO_OFF};
use pam::conv::PamConv;
use std::collections::HashMap;
use std::time::Duration;
use reqwest::{Client, StatusCode};
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

struct PamHttp;
pam_hooks!(PamHttp);

impl PamHooks for PamHttp {
    // This function performs the task of authenticating the user.
    fn sm_authenticate(pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        println!("Let's auth over HTTP");

        let args: Vec<_> = args.iter().map(|s| s.to_string_lossy().to_owned() ).collect();
        let args: HashMap<&str, &str> = args.iter().map(|s| {
            let mut parts = s.splitn(2, "=");
            (parts.next().unwrap(), parts.next().unwrap_or(""))
        }).collect();

        let user = pam_try!(pamh.get_user(None));

        let url: &str = match args.get("url") {
            Some(url) => url,
            None => return PamResultCode::PAM_AUTH_ERR,
        };
        // let ca_file = args.get("ca_file");

        let conv = match pamh.get_item::<PamConv>() {
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

    fn sm_setcred(_pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        println!("set credentials");
        PamResultCode::PAM_SUCCESS
    }

    fn acct_mgmt(_pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        println!("account management");
        PamResultCode::PAM_SUCCESS
    }
}


fn get_url(url: &str, user: &str, password: Option<&str>) -> reqwest::Result<StatusCode> {
    let client = Client::builder()?.timeout(Duration::from_secs(15)).build()?;
    client.get(url)?
        .basic_auth(user, password)
        .send()
        .map(|r| r.status())
}


