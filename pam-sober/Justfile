
all:
    cargo build

install:
    @cargo build
    sudo cp conf/sober-auth /etc/pam.d/
    sudo cp target/debug/libpam_sober.so /lib/security/pam_sober.so

test:
    @just install
    gcc -o target/pam_test test.c -lpam -lpam_misc
