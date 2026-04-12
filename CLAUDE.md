# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

aws-assume-cli is a Python CLI tool for AWS SSO credential management across multiple accounts and roles. It resolves credentials via SSO, supports automatic login, and outputs credentials as shell exports, JSON, `.env` files, or writes to `~/.aws/credentials`. Built with Click, boto3, and botocore.

## Setup

```
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Common Commands

```
# Assume a role and export credentials
.venv/bin/aws-assume my-profile

# Write to .env file
.venv/bin/aws-assume my-profile --env-file .env

# Write to ~/.aws/credentials
.venv/bin/aws-assume my-profile --credentials

# Output as JSON
.venv/bin/aws-assume my-profile --json

# List available profiles
.venv/bin/aws-assume --list

# Run tests
.venv/bin/pytest

# Lint
.venv/bin/ruff check .
```

## Directory Structure

```
aws_assume/
  __init__.py    # Package version
  cli.py         # Click CLI entry point
  core.py        # Core logic: SSO login, credential resolution, profile listing
tests/
  test_cli.py    # CLI integration tests
  test_core.py   # Core logic tests
```

## Architecture

Single-command Click CLI (`aws_assume.cli:main`, installed as `aws-assume`). The package uses a flat layout (`aws_assume/` at project root).

Key flow: parse AWS config profiles -> initiate SSO login (auto or manual) -> resolve temporary credentials via `sso:GetRoleCredentials` -> output in requested format (shell exports, JSON, .env file, or credentials file).

The `Credentials` dataclass provides serialization methods: `to_json()`, `to_env_file()`, and `to_env_vars()`.

## Testing

```
.venv/bin/pytest                   # Run all tests
.venv/bin/pytest tests/test_cli.py # Run specific test file
.venv/bin/pytest -x                # Stop on first failure
```

## Code Style

Ruff is configured with line-length 100, targeting Python 3.10. Rules: E, F, I, UP.
