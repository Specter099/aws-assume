# aws-assume

Simple CLI for AWS SSO credential management across multiple accounts and roles.

## Installation

```bash
pip install aws-assume-cli
```

## Usage

```bash
# Eval into your shell (most common usage)
eval $(aws-assume my-profile)

# List available profiles
aws-assume --list

# Output as JSON
aws-assume my-profile --json

# Write to a Docker .env file
aws-assume my-profile --env-file .env

# Write to ~/.aws/credentials
aws-assume my-profile --credentials

# Write credentials under a specific profile name
aws-assume my-profile --credentials --credentials-profile temp-dev

# Set session duration (for role assumption)
aws-assume my-profile --duration 3600

# Skip automatic SSO login prompt
aws-assume my-profile --no-auto-login
```

## How it works

`aws-assume` reads your `~/.aws/config` and supports three profile types:

**SSO profiles** — logs you in via `aws sso login` if the session is expired, then fetches temporary credentials.

```ini
[profile my-sso]
sso_start_url = https://my-org.awsapps.com/start
sso_region = us-east-1
sso_account_id = 123456789012
sso_role_name = AdministratorAccess
region = us-east-1
```

**Role assumption profiles** — assumes a role using another profile as the source.

```ini
[profile prod-admin]
role_arn = arn:aws:iam::999999999999:role/AdminRole
source_profile = my-sso
region = us-east-1
```

**SSO + role chaining** — the source profile itself uses SSO. `aws-assume` handles the chain automatically.

## Output modes

| Flag | Output | Use case |
|---|---|---|
| *(default)* | `export VAR=...` | `eval $(aws-assume profile)` in shell |
| `--json` | JSON object | Scripting, piping |
| `--env-file PATH` | Docker `.env` format | `docker run --env-file .env ...` |
| `--credentials` | `~/.aws/credentials` | SDK / tool compatibility |

## Development

```bash
git clone https://github.com/brianjbeach/aws-assume
cd aws-assume
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## License

MIT
