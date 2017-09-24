pam-rs
========

Rust interface to the pluggable authentication module framework (PAM).

The goal of this library is to provide a type-safe API that can be used to
interact with PAM.  The library is incomplete - currently it supports a subset
of functions for use in a pam authentication module.  A pam module is a shared
library that is invoked to authenticate a user, or to perform other functions.

Additionally, [pam-http](pam-http) is an example of using pam-rs by performing
HTTP basic access auth to authenticate users.

### Credits

The contents of this repo are heavily borrowed from:

- [tozny/rust-pam](https://github.com/tozny/rust-pam)
- [ndenev/pam_groupmap](https://github.com/ndenev/pam_groupmap)
- [beatgammit/pam-http](https://github.com/beatgammit/pam-http)
