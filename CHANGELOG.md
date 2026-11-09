# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-09-28
### Security
- PB-54783 Add a `temporary_keyring` option to run each lookup in a dedicated temporary GnuPG keyring, removed at the end of the run together with the gpg-agent it starts. It is disabled by default, so using the operator's keyring remains the default behaviour
