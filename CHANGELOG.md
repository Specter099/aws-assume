# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-05-01

### Added

- Initial release of `aws-assume-cli`.
- Support for SSO profiles, role assumption profiles, and SSO + role chaining.
- Output modes: shell eval (default), `--json`, `--env-file`, `--credentials`.
- `--list` flag to list available profiles.
- `--duration` flag for custom session duration.
- `--no-auto-login` flag to skip automatic SSO login.
- `--credentials-profile` flag to write credentials under a custom profile name.

[0.1.0]: https://github.com/Specter099/aws-assume/releases/tag/v0.1.0
