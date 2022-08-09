# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->

## [Unreleased] - ReleaseDate

### Bug fixes

- Update dependencies

## [2.1.1] - 2022-07-04

### Changed

- Update to edition 2021
- Update dependencies

## v2.0.1 - 2021-10-27

### Added

- trait_implementation example
- trait implementation
- derive macro

### Fixed

- Spelling errors

## v2.0.0

- Rename user_ip and site_key to conform to Hcaptcha API documentation (remoteip and sitekey)
- Restore lambda_runtime as crate has been updated
- Validate client response before submission to Hcaptcha API
- Validate secret before submission to Hcaptcha API
- Validate remoteip as a v4 or v6 IP address before submission to Hcaptcha API
- Validate sitekey as a UUID before submission to Hcaptcha API
- Constrain sitekey string to a Uuid
- Place methods to access Enterprise only response data behind "enterprise" feature flag
- Replace logging with tracing; remove logging feature flag
- Revise documentation and enhance examples
- Adopt Request/Response/Error and Trait structure
- Struct HcaptchaCaptcha for client response (response, sitekey and remoteip) and new_with(captcha) to construct request using the HcaptchaCaptcha struct.

### Notes

#### Validation of builder inputs

Validation of secret and response inputs makes hcaptcha::new(secret, response) fallible. The function returns a result to address any validation failure.

Basic validation for both inputs ensures that the value is not empty or composed of only whitespace.

Extended validation for the secret key requires it to conform to "0x" followed by a 40 character hexadecimal string. The extended validation is feature flagged and can be disabled. The flag is enabled by default. To disable load the library with default-features = false.

The input to .sitekey(sitekey) has been changed to validate that the string slice supplied is a valid UUID.

The input to the .remoteip(remoteip) has been changed to validate that the string slice supplier is a valid ipv4 or ipv6 address.

#### Logging / Tracing

The previous version provided logging behind a feature flag. The log crate has been removed and replaced with tracing. Tracing has been instrumented for all public functions. Tracing is enabled by selected the "trace" feature.

Tracing is enabled at the info logging level for public methods. Additional tracing instrumentation and messages are available at the Debug log level.

The trace crates log feature is enabled so that log records are emitted if a tracing subscriber is not found.

## v1.0.1

- Replace lambda_runtime with lamedh_runtime to avoid security issue RUSTSEC-2021-0020 in hyper 0.12.36.

<!-- next-url -->
[Unreleased]: https://github.com/gortavoher/hcaptcha-rs/compare/hcaptcha-v2.1.1...HEAD
[2.1.1]: https://github.com/gortavoher/hcaptcha-rs/compare/v2.1.0...hcaptcha-v2.1.1
