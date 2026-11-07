# pgp-vanity

Find an Ed25519 OpenPGP key whose fingerprint starts with hex digits you
choose, for example `DEC2 3202 3...`.

Every candidate is a fresh random key from Sequoia's CSPRNG. The search only
varies the key's creation timestamp (within the last `days`, default 30),
which changes the v4 fingerprint without making the key weaker. The hot loop
hashes one 54-byte packet per try with a single SHA-1 block, about 770
million tries per second on 24 cores. Before searching, it checks its
fingerprint computation against Sequoia's.

```sh
cargo build --release
./target/release/pgp-vanity DEC232023 'Name <you@example.com>' revocation.asc > secret.asc
```

Each extra hex digit makes the search 16 times longer: 8 digits take seconds,
9 about a minute, 10 a quarter of an hour.

The output is a secret certificate (an Ed25519 signing key with a Curve25519
encryption subkey and one User ID, unprotected), plus a revocation
certificate in the file you name. Import it with `gpg --import` and set a
passphrase with `gpg --passwd`. Do not pipe it straight into an agent that
might reject secret-key imports, or the key is lost; write it to a file in a
private directory first, and delete that file once it is imported.
