extern crate pam;
extern crate reqwest;

use pam::constants::{PamFlag, PamResultCode, PAM_PROMPT_ECHO_OFF};
use pam::conv::Conv;
use pam::module::{PamHandle, PamHooks};
use reqwest::blocking::Client;
use reqwest::StatusCode;
use std::collections::HashMap;
use std::ffi::CStr;
use std::time::Duration;
use pam::pam_try;

struct PamHttp;
pam::pam_hooks!(PamHttp);

impl PamHooks for PamHttp {
    // This function performs the task of authenticating the user.
    fn sm_authenticate(pamh: &mut PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        println!("Let's auth over HTTP");

        let args: Vec<_> = args
            .iter()
            .map(|s| s.to_string_lossy())
            .collect();
        let args: HashMap<&str, &str> = args
            .iter()
            .map(|s| {
                let mut parts = s.splitn(2, '=');
                (parts.next().unwrap(), parts.next().unwrap_or(""))
            })
            .collect();

        let user = pam_try!(pamh.get_user(None));

        let url: &str = match args.get("url") {
            Some(url) => url,
            None => return PamResultCode::PAM_AUTH_ERR,
        };

        let conv = match pamh.get_item::<Conv>() {
            Ok(Some(conv)) => conv,
            Ok(None) => {
                unreachable!("No conv available");
            }
            Err(err) => {
                println!("Couldn't get pam_conv");
                return err;
            }
        };
        let password = pam_try!(conv.send(PAM_PROMPT_ECHO_OFF, "Word, yo: "));
        let password = match password {
            Some(password) => Some(pam_try!(password.to_str(), PamResultCode::PAM_AUTH_ERR)),
            None => None,
        };
        println!("Got a password {:?}", password);
        let status = pam_try!(
            get_url(url, &user, password),
            PamResultCode::PAM_AUTH_ERR
        );

        if !status.is_success() {
            println!("HTTP Error: {}", status);
            return PamResultCode::PAM_AUTH_ERR;
        }

        PamResultCode::PAM_SUCCESS
    }

    fn sm_setcred(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        println!("set credentials");
        PamResultCode::PAM_SUCCESS
    }

    fn acct_mgmt(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        println!("account management");
        PamResultCode::PAM_SUCCESS
    }
}

fn get_url(url: &str, user: &str, password: Option<&str>) -> reqwest::Result<StatusCode> {
    let client = Client::builder().timeout(Duration::from_secs(15)).build()?;
    client
        .get(url)
        .basic_auth(user, password)
        .send()
        .map(|r| r.status())
}
