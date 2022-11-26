use std::{collections::HashMap, ffi::CStr};

use argon2::Argon2;
use balloon_hash::Balloon;
use csv_async::AsyncDeserializer;
use log::{debug, error, info, trace, LevelFilter};
use pam::{
    constants::{
        PamFlag,
        PamResultCode::{self, PAM_ABORT, PAM_AUTH_ERR, PAM_CONV_ERR, PAM_SUCCESS, PAM_SYSTEM_ERR},
    },
    items::ItemType,
    module::{PamHandle, PamHooks},
};
use password_hash::{PasswordHash, PasswordVerifier};
use pbkdf2::Pbkdf2;
use scrypt::Scrypt;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use tap::{Tap, TapFallible};
use tokio::fs::File;
use tokio_stream::StreamExt;

fn logger_init() {
    TermLogger::init(
        LevelFilter::Trace,
        Config::default(),
        TerminalMode::Stdout,
        ColorChoice::Auto,
    )
    .unwrap();
}

struct PamKeyValue;
pam::pam_hooks!(PamKeyValue);

impl PamHooks for PamKeyValue {
    #[tokio::main]
    async fn acct_mgmt(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let ret = || {
            logger_init();
            info!("account management");
            Ok(())
        };

        ret().map(|_| PAM_SUCCESS).unwrap_or_else(|e| e)
    }

    #[tokio::main]
    async fn sm_authenticate(
        pamh: &mut PamHandle,
        args: Vec<&CStr>,
        _flags: PamFlag,
    ) -> PamResultCode {
        logger_init();

        let ret = || {
            async move {
                let args: HashMap<String, Option<String>> = args
                    .iter()
                    .map(|s| s.to_string_lossy())
                    .map(|s| {
                        let mut parts = s.splitn(2, '=');

                        let key = parts.next().unwrap().to_string();
                        let value = parts.next().and_then(|x| {
                            if x.trim().is_empty() {
                                None
                            } else {
                                Some(x.to_string())
                            }
                        });

                        (key, value)
                    })
                    .collect();
                trace!("args: {args:?}");

                let db = args
                    .get("db")
                    .cloned()
                    .flatten()
                    .ok_or(PAM_ABORT)
                    .tap_err(|_| error!("db option is required"))?;

                let user = pamh.get_user(None).tap_ok(|x| trace!("user: {x}"))?;
                let pass = pamh
                    .get_authtok(ItemType::AuthTok, None)
                    .tap(|x| trace!("pass: {x:?}"))?
                    .unwrap_or("".to_string());

                let file = File::open(db)
                    .await
                    .tap_err(|e| error!("failed to open file: {e}"))
                    .map_err(|_| PAM_SYSTEM_ERR)?;

                let mut rdr = AsyncDeserializer::from_reader(file);
                let mut records = rdr.deserialize::<UserEntry>();

                let algs: &[&dyn PasswordVerifier] = &[
                    &Argon2::default(),
                    &Pbkdf2,
                    &Scrypt,
                    &Balloon::<Sha256>::default(),
                ];

                while let Some(record) = records.next().await {
                    let UserEntry { username, password } = record
                        .as_ref()
                        .tap_err(|e| error!("failed to deserialize csv entry: {e}"))
                        .map_err(|_| PAM_CONV_ERR)?;

                    trace!("record: {record:?}");

                    if *username != user {
                        continue;
                    }

                    match PasswordHash::new(password) {
                        Ok(hash) if hash.verify_password(algs, &pass).is_ok() => {
                            trace!("found user");
                            return Ok(());
                        }
                        Err(_) if pass == *password => {
                            trace!("found user");
                            return Ok(());
                        }
                        Ok(_) => {
                            debug!("found user in records, but password is invalid");
                        }
                        Err(e) => {
                            error!("password is invalid: {e}")
                        }
                    }
                }

                error!("user not found");
                Err(PAM_AUTH_ERR)
            }
        };

        ret().await.map(|_| PAM_SUCCESS).unwrap_or_else(|e| e)
    }

    #[tokio::main]
    async fn sm_setcred(
        _pamh: &mut PamHandle,
        _args: Vec<&CStr>,
        _flags: PamFlag,
    ) -> PamResultCode {
        let ret = || {
            logger_init();
            info!("set credentials");
            Ok(())
        };

        ret().map(|_| PAM_SUCCESS).unwrap_or_else(|e| e)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct UserEntry {
    username: String,
    password: String,
}
