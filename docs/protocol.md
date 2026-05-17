# MCCV Protocol

> [!WARNING]
> This document is severely out of date and in the process of a significant rewrite!
> In its current state it is still useful for understanding the vault, but some of the details are likely wrong.

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
