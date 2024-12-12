
# Testing Error

If you see "Failed to get bitcoind path" or "Failed to get electrsd path" when running tests, you need to provide the tests a way to run bitcoind and electrsd.

## Trusting Electrsd

The electrsd crate conveniently provides binaries for electrs and the bitcoind
provides binaries for bitcoind.
Using these binaries never sat well with me so it is turned off by default, but
you can run tests with the `trust-electrsd` feature to very quickly and easily
run tests.

## Bring your own binaries

If you have built electrs and bitcoind yourself you can use them by providing
the environment variables `ELECTRS_EXE` and `BITCOIND_EXE` which must be the
full paths to these binaries.
