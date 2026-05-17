# More Complicated CTV Vaults

I started this quite a long time ago to prove (or disprove) the feasibility of things I've talked about CTV vaults being capable of.
Precomputing a large number of potential transactions takes a long time on commodity hardware, so there are practical limits to vaults like this.
This proof of concept was created in large part to explore those limits and to determine if they constrain the practicality of these style vaults.

# User Guide

See the [User Guide](docs/user-guide.md)

# Protocol

See [Protocol](docs/protocol.md)

## Goal Features

- Decent usability
- Vault Actions
  - Deposits
    - With Velocity Control
  - Withdrawals
  - Recovery
- "Effectively infinite" number of deposit/withdrawal operations
  Right now re/calculating the transaction tree for a 1000 operation vault takes 2 minutes, meaning that 10,000 or 100,000 operation vaults are potentially feasible
- "Effectively infinite" value
  I've limited my experiments to values between 1,000,000 sats and 1BTC which is probably plenty for most sovereign stackers, but institutions will want more.
  This should be plenty feasible for institutions, but less so for plebs.

# Testing Error

If you see "Failed to get bitcoind path" when running tests, or an RPC error, you need to provide
the tests a way to run `bitcoind`. Note that you will want a bitcoind that supports CTV such as .

If you have `bitcoind` in your path, but want to use a different one for tests, you can set the `BITCOIND_EXE` environment variable to override this.

As of the time of writing, OP_CHECKTEMPLATEVERIFY has not been activated, so you
will need a version of bitcoind that supports it, as well as one that supports TRUC transactions and the `submitpackage` RPC such as [Inquisition v29 with CTV](https://github.com/ajtowns/bitcoin/tree/202507-inq29-ctv).

# Future Work

Getting this prototype into shape has renewed my interest in a binary vault system which is much more like existing "simple-ctv-vault" style implementations.
With some caveats, I believe CSFS plus a much simpler vault construction can actually provide a similar, and very decent UX with considerably lower computation requirements
I'll provide a writeup if not a PoC implementation of this after the UX goals have been achieved for this PoC.
