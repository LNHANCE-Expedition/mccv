# Examples

This directory contains example watchtower approval scripts for use with watchtower mode.

Approval scripts are invoked with argv[1] = txid
An exit code of 0 approves the withdrawal, meaning the watchtower will take no action.
A non-zero exit code of the approval script will cause the watchtower to sweep the vault to recovery.

# `approve-prompt.sh`

Reports the withdrawal TXID on stdout and asks the user for approval on stdin.
