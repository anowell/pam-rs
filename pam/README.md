rust-pam
========

Rust interface to the pluggable authentication module framework (PAM).

The goal of this library is to provide a type-safe API that can be used to
interact with PAM.  The library is incomplete - currently it supports a subset
of functions for use in a pam authentication module.  A pam module is a shared
library that is invoked to authenticate a user, or to perform other functions.

For more information, see the [package documentation][doc].

[doc]: https://tozny.github.io/rust-pam/pam/
