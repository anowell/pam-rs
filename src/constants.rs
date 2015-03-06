use libc::{c_int, c_uint};

// TODO: Import constants from C header file at compile time.

pub type PamFlag         = c_uint;
pub type PamItemType     = c_int;
pub type PamMessageStyle = c_int;
pub type PamResultCode   = c_int;
pub type AlwaysZero      = c_int;

// The Linux-PAM flags
// see /usr/include/security/_pam_types.h
pub const PAM_SILENT:                 PamFlag = 0x8000;
pub const PAM_DISALLOW_NULL_AUTHTOK:  PamFlag = 0x0001;
pub const PAM_ESTABLISH_CRED:         PamFlag = 0x0002;
pub const PAM_DELETE_CRED:            PamFlag = 0x0004;
pub const PAM_REINITIALIZE_CRED:      PamFlag = 0x0008;
pub const PAM_REFRESH_CRED:           PamFlag = 0x0010;
pub const PAM_CHANGE_EXPIRED_AUTHTOK: PamFlag = 0x0020;

// The Linux-PAM item types
// see /usr/include/security/_pam_types.h
pub const PAM_SERVICE:      PamItemType =  1;   /* The service name */
pub const PAM_USER:         PamItemType =  2;   /* The user name */
pub const PAM_TTY:          PamItemType =  3;   /* The tty name */
pub const PAM_RHOST:        PamItemType =  4;   /* The remote host name */
pub const PAM_CONV:         PamItemType =  5;   /* The pam_conv structure */
pub const PAM_AUTHTOK:      PamItemType =  6;   /* The authentication token (password) */
pub const PAM_OLDAUTHTOK:   PamItemType =  7;   /* The old authentication token */
pub const PAM_RUSER:        PamItemType =  8;   /* The remote user name */
pub const PAM_USER_PROMPT:  PamItemType =  9;   /* the prompt for getting a username */
/* Linux-PAM :extensionsPamItemType = */
pub const PAM_FAIL_DELAY:   PamItemType = 10;   /* app supplied function to override failure delays */
pub const PAM_XDISPLAY:     PamItemType = 11;   /* X :display name */
pub const PAM_XAUTHDATA:    PamItemType = 12;   /* X :server authentication data */
pub const PAM_AUTHTOK_TYPE: PamItemType = 13;   /* The type for pam_get_authtok */

// Message styles
pub const PAM_PROMPT_ECHO_OFF: PamMessageStyle = 1;
pub const PAM_PROMPT_ECHO_ON:  PamMessageStyle = 2;
pub const PAM_ERROR_MSG:       PamMessageStyle = 3;
pub const PAM_TEXT_INFO:       PamMessageStyle = 4;
pub const PAM_RADIO_TYPE:      PamMessageStyle = 5;        /* yes/no/maybe conditionals */
pub const PAM_BINARY_PROMPT:   PamMessageStyle = 7;

// The Linux-PAM return values
// see /usr/include/security/_pam_types.h
pub const PAM_SUCCESS:               PamResultCode =  0;
pub const PAM_OPEN_ERR:              PamResultCode =  1;
pub const PAM_SYMBOL_ERR:            PamResultCode =  2;
pub const PAM_SERVICE_ERR:           PamResultCode =  3;
pub const PAM_SYSTEM_ERR:            PamResultCode =  4;
pub const PAM_BUF_ERR:               PamResultCode =  5;
pub const PAM_PERM_DENIED:           PamResultCode =  6;
pub const PAM_AUTH_ERR:              PamResultCode =  7;
pub const PAM_CRED_INSUFFICIENT:     PamResultCode =  8;
pub const PAM_AUTHINFO_UNAVAIL:      PamResultCode =  9;
pub const PAM_USER_UNKNOWN:          PamResultCode = 10;
pub const PAM_MAXTRIES:              PamResultCode = 11;
pub const PAM_NEW_AUTHTOK_REQD:      PamResultCode = 12;
pub const PAM_ACCT_EXPIRED:          PamResultCode = 13;
pub const PAM_SESSION_ERR:           PamResultCode = 14;
pub const PAM_CRED_UNAVAIL:          PamResultCode = 15;
pub const PAM_CRED_EXPIRED:          PamResultCode = 16;
pub const PAM_CRED_ERR:              PamResultCode = 17;
pub const PAM_NO_MODULE_DATA:        PamResultCode = 18;
pub const PAM_CONV_ERR:              PamResultCode = 19;
pub const PAM_AUTHTOK_ERR:           PamResultCode = 20;
pub const PAM_AUTHTOK_RECOVERY_ERR:  PamResultCode = 21;
pub const PAM_AUTHTOK_LOCK_BUSY:     PamResultCode = 22;
pub const PAM_AUTHTOK_DISABLE_AGING: PamResultCode = 23;
pub const PAM_TRY_AGAIN:             PamResultCode = 24;
pub const PAM_IGNORE:                PamResultCode = 25;
pub const PAM_ABORT:                 PamResultCode = 26;
pub const PAM_AUTHTOK_EXPIRED:       PamResultCode = 27;
pub const PAM_MODULE_UNKNOWN:        PamResultCode = 28;
pub const PAM_BAD_ITEM:              PamResultCode = 29;
pub const PAM_CONV_AGAIN:            PamResultCode = 30;
pub const PAM_INCOMPLETE:            PamResultCode = 31;
