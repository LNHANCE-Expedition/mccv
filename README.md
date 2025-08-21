# More Complicated CTV Vaults

I started this quite a long time ago to prove (or disprove) the feasibility of things I've talked about CTV vaults being capable of.
None of this should be theoretically exciting to anyone familiar with CTV, but I was not sure how feasible some of them were.
Precomputing a large number of potential transactions takes a long time on commodity hardware, so there are practical limits to vaults like this.

## Goal Features

- Decent usability
- Vault Actions
  - Deposits
    - With Velocity Control
  - Withdrawals
  - Clawback
- "Effectively infinite" number of deposit/withdrawal operations
  Right now re/calculating the transaction tree for a 1000 operation vault takes 2 minutes, meaning that 10,000 or 100,000 operation vaults are very feasible
- "Effectively infinite" value
  I've limited my experiments to values between 1,000,000 sats and 1BTC which is probably plenty for most sovereign stackers, but institutions will want more.
  This should be plenty feasible for institutions, but less so for plebs.

## Secondary Goal Features
- Recursive vaults
  - With a modest increase in complexity, it should be possible to construct smaller vaults so that they can always be deposited into a larger vault
  - This can drastically increase the value of practical-to-calculate vaults
  - I believe this may require significantly more *memory*, however. I'm uncertain if this is actually practical.

# Design

Every vault state is represented by a transaction with a depth, a value, and either a withdrawal or deposit amount.
For simplicity we'll ignore timelock and input count for just depth and value.
This illustration shows a vault capable of 3 vault operations (plus one initial deposit), and 3 possible values.
Values are represented as integers between 1 and a finite limit, and represent multiples of some other denomination, like 1,000,000 sats.


    +Time ------------------->
    V_0,1  V_1,1  V_2,1  V_3,1 +Vault Value
    V_0,2  V_1,2  V_2,2  V_3,2   |
    V_0,3  V_1,3  V_2,3  V_3,3   V

If the user deposits a value of 2, then the first vault transaction is `V_0,2`
with a value of 2.
If the user then withdraws 1, the second transaction becomes `V_1,1` with a
value of 1.
Then, if the user deposits another 2, the third transaction becomes `V_2,3` with
a value of 3.
Finally, if the user withdaws 1, the final transaction will be `V_3,2` with a
final value of 2. 
The following sequence of transactions would be made on-chain.

    V_0,2 -> V_1,1 -> V_2,3 -> V_3,2

| Transaction | Depth | Value | Withdrawal/Deposit Amount | Timelock | Next Timelock |
|-------------|-------|-------|---------------------------|----------|---------------|
| V_0,2       | 0     | 2     | Deposit 2                 | 0        | 0             |
| V_1,1       | 1     | 1     | Withdraw 1                | 0        | T             |
| V_2,3       | 2     | 3     | Deposit 2                 | T        | 0             |
| V_3,2       | 3     | 2     | Withdraw 1                | 0        | T             |

# Transactions

## Vault Prepare Transaction

Also known as the "shape transaction" in the code.

                              Randomized TxOut Order
            +------------+
    In 0 -> |            | -> Vault Deposit
    In 1 -> |            | -> Change
     ...    |            |
    In N -> |            |
            +------------+

### Vault Deposit Output

CTV into Vault

OR

Timelocked spendable by hot key (do we even want this? costs 32 wu to have this)

## Deposit Transaction

                     +------------+
    [ Vault ]     -> |            | -> Vault
    Vault Deposit -> |            | -> Anchor Output
                     +------------+

### Vault Input

(Optional) input carrying prevoius vault balance.
Won't be present when previous vault value is 0.

### Vault Output

CTV for either withdrawal or deposit

## Withdrawal Transaction

             +------------+
    Vault -> |            | -> [ Vault ]
             |            | -> Unvault
             |            | -> Anchor Output
             +------------+

### Unvault Output

Either

Spendable by hot wallet after timelock

or

Clawback to cold wallet

### Vault Output

(Optional) Change for the vault.
Same as deposit output except it carries a timelock as well.

# Testing Error

If you see "Failed to get bitcoind path" when running tests, or an RPC error, you need to provide
the tests a way to run `bitcoind`. Note that you will want a bitcoind that supports CTV such as .

If you have `bitcoind` in your path, but want to use a different one for tests, you can set the `BITCOIND_EXE` environment variable to override this.

As of the time of writing, OP_CHECKTEMPLATEVERIFY has not been activated, so you
will need a version of bitcoind that supports it, as well as one that supports TRUC transactions and the `submitpackage` RPC such as [Inquisition v29 with CTV](https://github.com/ajtowns/bitcoin/tree/202507-inq29-ctv).

# Future Work

Getting this prototype into shape has renewed my interest in a binary vault system which is much more like existing "simple-ctv-vault" style implementations.
With some caveats, I believe CSFS plus a much simpler vault construction can actually provide a similar, and very decent UX.
I'll provide a writeup if not a PoC implementation of this after the UX goals have been achieved for this PoC.
