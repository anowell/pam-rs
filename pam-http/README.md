pam-http
========

A PAM HTTP BasicAuth module built using pam-rs

# Prerequisites

You need some libraries before you build like libpam and libssl.

If you're going to build on Ubuntu, just run this:

```
sudo apt-get install -y build-essential libpam0g-dev libpam0g libssl-dev
```

# Building

Just use `cargo build`.

# Usage

You need to move the build product to a folder where PAM is looking for modules.

If you're using Ubuntu you can move `libpam_http.so` to `/lib/security`.
After doing so you need to make sure it has proper permissions: `sudo chmod 755 /lib/security/libpam_http.so`.
Then you can place a configuration file in `/etc/pam.d/`. It can look something like this:

```
auth sufficient libpam_http.so url=https://theserver.example.com/someendpoint
account sufficient libpam_http.so
```

Make sure the endpoint you're specifying can receive GET requests and supports 
[HTTP Basic Authentication](https://en.wikipedia.org/wiki/Basic_access_authentication#Client_side). 
If the user is authenticated successfully it should return HTTP 200.
