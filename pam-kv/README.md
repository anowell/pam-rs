pam-kv
========

A PAM module built using pam-rs, based on a key-value based CSV file struct, 
that also uses async Tokio behind the scene

# Prerequisites

If you're going to build on Ubuntu, just run this:

```
sudo apt-get install -y build-essential libpam0g-dev libpam0g
```

# Building

Just use `cargo build`.

# Usage

You need to move the build product to a folder where PAM is looking for modules.

If you're using Ubuntu you can move `libpam_kv.so` to `/lib/security`.
After doing so you need to make sure it has proper permissions: `sudo chmod 755 /lib/security/libpam_kv.so`.
Then you can place a configuration file in `/etc/pam.d/`. It can look something like this:

```
auth sufficient pam_kv.so db=/etc/pam-rs/db.csv
account sufficient pam_kv.so
```

Make sure the file contains a good CSV structure

```csv
username,password
"alice","secure_password"
"bob","good_password"
```