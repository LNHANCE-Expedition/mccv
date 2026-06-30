# Changelog

## Unreleased

### Fixed

- Vault recovery coins are now locked by the correct (cold) keys.
- Vault deposit CTV hashes are now calculated correctly.

### Security

Vaults created using v0.1.0 software are insecure.
They use the wrong key, the hot key, to lock funds which were swept to the recovery location, defeating the purpose of the sweep.

### Compatibility

Vaults created using v0.1.0 need to be drained to another wallet, using v0.1.0 software, then recreated using >v0.1.0 software.

## 0.1.0 - 2026-05-28

Initial release
