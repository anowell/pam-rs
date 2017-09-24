
all:
    cargo build

install:
    @cargo build
    sudo cp conf/http-auth /etc/pam.d/
    sudo cp target/debug/libpam_http.so /lib/security/pam_http.so

test:
    @just install
    gcc -o target/pam_test test.c -lpam -lpam_misc
