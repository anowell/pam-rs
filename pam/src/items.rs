#[repr(u32)]
pub enum ItemType {
    /// The service name
    Service = 1,
    /// The user name
    User = 2,
    /// The tty name
    Tty = 3,
    /// The remote host name
    RHost = 4,
    /// The pam_conv structure
    Conv = 5,
    /// The authentication token (password)
    AuthTok = 6,
    /// The old authentication token
    OldAuthTok = 7,
    /// The remote user name
    RUser = 8,
    /// the prompt for getting a username
    UserPrompt = 9,
    /// app supplied function to override failure delays
    FailDelay = 10,
    /// X :display name
    XDisplay = 11,
    /// X :server authentication data
    XAuthData = 12,
    /// The type for pam_get_authtok
    AuthTokType = 13,
}

// A type that can be requested by `pam::Handle::get_item`.
pub trait Item {
    /// The `repr(C)` type that is returned (by pointer) by the underlying `pam_get_item` function.
    type Raw;

    /// The `ItemType` for this type
    fn type_id() -> ItemType;

    /// The function to convert from the pointer to the C-representation to this safer wrapper type
    ///
    /// # Safety
    ///
    /// This function can assume the pointer is a valid pointer to a `Self::Raw` instance.
    unsafe fn from_raw(raw: *const Self::Raw) -> Self;

    /// The function to convert from this wrapper type to a C-compatible pointer.
    fn into_raw(self) -> *const Self::Raw;
}

macro_rules! cstr_item {
    ($name:ident) => {
        #[derive(Debug)]
        pub struct $name<'s>(pub &'s std::ffi::CStr);

        impl<'s> std::ops::Deref for $name<'s> {
            type Target = &'s std::ffi::CStr;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl<'s> Item for $name<'s> {
            type Raw = libc::c_char;

            fn type_id() -> ItemType {
                ItemType::$name
            }

            unsafe fn from_raw(raw: *const Self::Raw) -> Self {
                Self(std::ffi::CStr::from_ptr(raw))
            }

            fn into_raw(self) -> *const Self::Raw {
                self.0.as_ptr()
            }
        }
    };
}

cstr_item!(Service);
cstr_item!(User);
cstr_item!(Tty);
cstr_item!(RHost);
// Conv
cstr_item!(AuthTok);
cstr_item!(OldAuthTok);
cstr_item!(RUser);
cstr_item!(UserPrompt);
