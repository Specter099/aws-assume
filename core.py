"""Core logic for resolving AWS SSO credentials and assuming roles."""

from __future__ import annotations

import configparser
import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, TokenRetrievalError


@dataclass
class Credentials:
    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration: str
    profile_name: str

    def to_env_vars(self) -> dict[str, str]:
        return {
            "AWS_ACCESS_KEY_ID": self.access_key_id,
            "AWS_SECRET_ACCESS_KEY": self.secret_access_key,
            "AWS_SESSION_TOKEN": self.session_token,
        }

    def to_eval(self) -> str:
        """Return shell export statements for eval."""
        lines = [
            f'export AWS_ACCESS_KEY_ID="{self.access_key_id}"',
            f'export AWS_SECRET_ACCESS_KEY="{self.secret_access_key}"',
            f'export AWS_SESSION_TOKEN="{self.session_token}"',
            f'export AWS_ASSUME_PROFILE="{self.profile_name}"',
            f'export AWS_ASSUME_EXPIRATION="{self.expiration}"',
        ]
        return "\n".join(lines)

    def to_env_file(self) -> str:
        """Return Docker-style .env file content."""
        lines = [
            f"AWS_ACCESS_KEY_ID={self.access_key_id}",
            f"AWS_SECRET_ACCESS_KEY={self.secret_access_key}",
            f"AWS_SESSION_TOKEN={self.session_token}",
        ]
        return "\n".join(lines)

    def to_json(self) -> str:
        return json.dumps(
            {
                "AccessKeyId": self.access_key_id,
                "SecretAccessKey": self.secret_access_key,
                "SessionToken": self.session_token,
                "Expiration": self.expiration,
            },
            indent=2,
        )


def _get_aws_config_path() -> Path:
    return Path(os.environ.get("AWS_CONFIG_FILE", "~/.aws/config")).expanduser()


def _get_aws_credentials_path() -> Path:
    return Path(os.environ.get("AWS_SHARED_CREDENTIALS_FILE", "~/.aws/credentials")).expanduser()


def list_profiles() -> list[str]:
    """Return all profile names from ~/.aws/config."""
    config_path = _get_aws_config_path()
    if not config_path.exists():
        return []

    config = configparser.ConfigParser()
    config.read(config_path)

    profiles = []
    for section in config.sections():
        # Sections are like "profile myprofile" or "default"
        if section == "default":
            profiles.append("default")
        elif section.startswith("profile "):
            profiles.append(section[len("profile ") :])
    return sorted(profiles)


def _get_profile_config(profile_name: str) -> dict:
    """Read a profile's config from ~/.aws/config."""
    config_path = _get_aws_config_path()
    config = configparser.ConfigParser()
    config.read(config_path)

    section = "default" if profile_name == "default" else f"profile {profile_name}"
    if section not in config:
        raise ValueError(f"Profile '{profile_name}' not found in {config_path}")

    return dict(config[section])


def _trigger_sso_login(profile_name: str) -> None:
    """Run aws sso login for the given profile."""
    print(f"SSO session expired or missing. Logging in for profile '{profile_name}'...")
    result = subprocess.run(
        ["aws", "sso", "login", "--profile", profile_name],
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"SSO login failed for profile '{profile_name}'")


def resolve_credentials(
    profile_name: str,
    duration_seconds: int | None = None,
    auto_login: bool = True,
) -> Credentials:
    """
    Resolve credentials for a profile, handling SSO login if needed.

    Supports:
      - SSO profiles (sso_start_url + sso_role_name)
      - Role-assumption profiles (role_arn + source_profile)
      - SSO + role chaining (sso source_profile + role_arn)
    """
    profile_config = _get_profile_config(profile_name)

    # Determine flow based on profile config keys
    has_sso = "sso_start_url" in profile_config or "sso_session" in profile_config
    has_role_arn = "role_arn" in profile_config

    if has_sso and not has_role_arn:
        # Pure SSO profile
        return _resolve_sso_credentials(profile_name, profile_config, auto_login)
    elif has_role_arn:
        # Role assumption (source may be SSO or another profile)
        return _resolve_role_credentials(profile_name, profile_config, duration_seconds, auto_login)
    else:
        # Try boto3 directly (static credentials, instance profile, etc.)
        return _resolve_boto3_credentials(profile_name)


def _resolve_sso_credentials(
    profile_name: str,
    profile_config: dict,
    auto_login: bool,
) -> Credentials:
    """Resolve credentials from an SSO profile."""
    for attempt in range(2):
        try:
            session = boto3.Session(profile_name=profile_name)
            creds = session.get_credentials().get_frozen_credentials()
            # Fetch expiry from the underlying SSOCredentialFetcher if available
            expiration = _get_sso_expiration(session) or "unknown"
            return Credentials(
                access_key_id=creds.access_key,
                secret_access_key=creds.secret_key,
                session_token=creds.token,
                expiration=expiration,
                profile_name=profile_name,
            )
        except (TokenRetrievalError, Exception) as e:
            if auto_login and attempt == 0 and _is_sso_error(e):
                _trigger_sso_login(profile_name)
                continue
            raise RuntimeError(f"Failed to resolve SSO credentials: {e}") from e

    raise RuntimeError("SSO credential resolution failed after login attempt.")


def _resolve_role_credentials(
    profile_name: str,
    profile_config: dict,
    duration_seconds: int | None,
    auto_login: bool,
) -> Credentials:
    """Resolve credentials by assuming a role, using source_profile as the base."""
    role_arn = profile_config["role_arn"]
    source_profile = profile_config.get("source_profile", "default")
    role_session_name = profile_config.get(
        "role_session_name",
        f"aws-assume-{profile_name}-{int(time.time())}",
    )
    external_id = profile_config.get("external_id")

    # Resolve source credentials (may itself be SSO)
    source_creds = resolve_credentials(source_profile, auto_login=auto_login)

    sts = boto3.client(
        "sts",
        aws_access_key_id=source_creds.access_key_id,
        aws_secret_access_key=source_creds.secret_access_key,
        aws_session_token=source_creds.session_token,
    )

    assume_kwargs: dict = {
        "RoleArn": role_arn,
        "RoleSessionName": role_session_name,
    }
    if duration_seconds:
        assume_kwargs["DurationSeconds"] = duration_seconds
    if external_id:
        assume_kwargs["ExternalId"] = external_id

    try:
        response = sts.assume_role(**assume_kwargs)
    except ClientError as e:
        raise RuntimeError(f"Failed to assume role '{role_arn}': {e}") from e

    creds = response["Credentials"]
    return Credentials(
        access_key_id=creds["AccessKeyId"],
        secret_access_key=creds["SecretAccessKey"],
        session_token=creds["SessionToken"],
        expiration=creds["Expiration"].isoformat(),
        profile_name=profile_name,
    )


def _resolve_boto3_credentials(profile_name: str) -> Credentials:
    """Fallback: resolve via boto3 session directly."""
    try:
        session = boto3.Session(profile_name=profile_name)
        creds = session.get_credentials().get_frozen_credentials()
        return Credentials(
            access_key_id=creds.access_key,
            secret_access_key=creds.secret_key,
            session_token=creds.token or "",
            expiration="unknown",
            profile_name=profile_name,
        )
    except Exception as e:
        raise RuntimeError(
            f"Failed to resolve credentials for profile '{profile_name}': {e}"
        ) from e


def _get_sso_expiration(session: boto3.Session) -> str | None:
    """Attempt to extract SSO token expiration from the session."""
    try:
        resolver = session._session.get_component("credential_provider")
        for provider in resolver.providers:
            if hasattr(provider, "_credential_fetcher"):
                fetcher = provider._credential_fetcher
                if hasattr(fetcher, "_cache"):
                    for v in fetcher._cache.values():
                        if "Expiration" in v:
                            exp = v["Expiration"]
                            return exp.isoformat() if hasattr(exp, "isoformat") else str(exp)
    except Exception:
        pass
    return None


def _is_sso_error(e: Exception) -> bool:
    """Check if the exception is SSO-related (expired/missing token)."""
    msg = str(e).lower()
    return any(
        keyword in msg
        for keyword in ["sso", "token", "login", "expired", "not found", "unauthorized"]
    )


def write_credentials_file(creds: Credentials, profile_name: str = "default") -> Path:
    """Write credentials to ~/.aws/credentials under the given profile name."""
    creds_path = _get_aws_credentials_path()
    creds_path.parent.mkdir(parents=True, exist_ok=True)

    config = configparser.ConfigParser()
    if creds_path.exists():
        config.read(creds_path)

    config[profile_name] = {
        "aws_access_key_id": creds.access_key_id,
        "aws_secret_access_key": creds.secret_access_key,
        "aws_session_token": creds.session_token,
    }

    with open(creds_path, "w") as f:
        config.write(f)

    return creds_path
