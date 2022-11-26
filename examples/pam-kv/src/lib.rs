use std::{collections::HashMap, ffi::CStr};

use argon2::Argon2;
use balloon_hash::Balloon;
use log::{debug, error, info, trace, LevelFilter};
use pam::{
    constants::{
        PamFlag,
        PamResultCode::{PAM_ABORT, PAM_AUTH_ERR, PAM_CONV_ERR, PAM_SYSTEM_ERR},
    },
    items::ItemType,
    module::{PamHandle, PamHooksResult, PamResult},
};
use password_hash::{PasswordHash, PasswordVerifier};
use pbkdf2::Pbkdf2;
use scrypt::Scrypt;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha256;
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use tap::{Tap, TapFallible};
use tokio::{fs::File, io::AsyncReadExt};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct UserEntry<'a> {
    username: String,
    #[serde(flatten, borrow)]
    password: Password<'a>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
enum Password<'a> {
    #[serde(rename = "raw")]
    Raw(String),
    #[serde(
        rename = "encrypted",
        deserialize_with = "deserialize_password_hash",
        serialize_with = "serialize_password_hash",
        borrow
    )]
    Encrypted(PasswordHash<'a>),
}

fn serialize_password_hash<S>(hash: &PasswordHash, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format!("{}", hash))
}

fn deserialize_password_hash<'de, D>(deserializer: D) -> Result<PasswordHash<'de>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: &'de str = Deserialize::deserialize(deserializer)?;
    Ok(PasswordHash::new(s).map_err(de::Error::custom)?)
}

struct PamKeyValue;
pam::pam_hooks!(PamKeyValue);

impl PamHooksResult for PamKeyValue {
    #[tokio::main]
    async fn acct_mgmt(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResult<()> {
        info!("account management");
        Ok(())
    }

    #[tokio::main]
    async fn sm_authenticate(
        pamh: &mut PamHandle,
        args: Vec<&CStr>,
        _flags: PamFlag,
    ) -> PamResult<()> {
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

        let mut file = File::open(db)
            .await
            .tap_err(|e| error!("failed to open file: {e}"))
            .map_err(|_| PAM_SYSTEM_ERR)?;

        let mut data = vec![];
        file.read_to_end(&mut data)
            .await
            .tap_err(|e| error!("failed to read file: {e}"))
            .map_err(|_| PAM_SYSTEM_ERR)?;

        let algs: &[&dyn PasswordVerifier] = &[
            &Argon2::default(),
            &Pbkdf2,
            &Scrypt,
            &Balloon::<Sha256>::default(),
        ];

        let data = serde_yaml::from_slice::<Vec<UserEntry>>(&data)
            .tap_err(|e| error!("failed to parse yaml: {e}"))
            .map_err(|_| PAM_CONV_ERR)?;

        if data.into_iter().filter(|x| x.username == user).any(|x| {
            match &x.password {
                Password::Raw(password) if pass == *password => true,
                Password::Encrypted(hash) if hash.verify_password(algs, &pass).is_ok() => true,
                _ => {
                    debug!("found user in records, but password is invalid");
                    false
                }
            }
        }) {
            trace!("found user");
            Ok(())
        } else {
            error!("user not found");
            Err(PAM_AUTH_ERR)
        }
    }

    #[tokio::main]
    async fn sm_setcred(
        _pamh: &mut PamHandle,
        _args: Vec<&CStr>,
        _flags: PamFlag,
    ) -> PamResult<()> {
        info!("set credentials");
        Ok(())
    }
}

#[ctor::ctor]
fn logger_init() {
    TermLogger::init(
        LevelFilter::Trace,
        Config::default(),
        TerminalMode::Stdout,
        ColorChoice::Auto,
    )
    .unwrap();
}
