"""CLI entry point for aws-assume."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from aws_assume import __version__
from aws_assume.core import (
    list_profiles,
    resolve_credentials,
    write_credentials_file,
)


def _print_error(msg: str) -> None:
    click.echo(click.style(f"Error: {msg}", fg="red"), err=True)


def _print_success(msg: str) -> None:
    click.echo(click.style(msg, fg="green"), err=True)


def _print_info(msg: str) -> None:
    click.echo(click.style(msg, fg="cyan"), err=True)


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="aws-assume")
@click.argument("profile", required=False)
@click.option(
    "--eval",
    "output_eval",
    is_flag=True,
    default=False,
    help="Output shell export statements (default for terminal use).",
)
@click.option(
    "--env-file",
    "env_file",
    metavar="PATH",
    default=None,
    help="Write credentials to a Docker-style .env file.",
)
@click.option(
    "--credentials",
    "write_creds",
    is_flag=True,
    default=False,
    help="Write credentials to ~/.aws/credentials.",
)
@click.option(
    "--credentials-profile",
    "creds_profile",
    default=None,
    metavar="NAME",
    help="Profile name to use when writing to credentials file.",
)
@click.option(
    "--json", "output_json", is_flag=True, default=False, help="Output credentials as JSON."
)
@click.option(
    "--duration",
    "duration",
    default=None,
    type=int,
    metavar="SECONDS",
    help="Session duration in seconds (for role assumption).",
)
@click.option(
    "--no-auto-login",
    "no_auto_login",
    is_flag=True,
    default=False,
    help="Do not automatically trigger SSO login if session is expired.",
)
@click.option(
    "--list", "list_only", is_flag=True, default=False, help="List available AWS profiles and exit."
)
@click.pass_context
def cli(
    ctx,
    profile,
    output_eval,
    env_file,
    write_creds,
    creds_profile,
    output_json,
    duration,
    no_auto_login,
    list_only,
):
    """Simple CLI for AWS SSO credential management across multiple accounts and roles.

    \b
    Examples:
      eval $(aws-assume my-profile)
      aws-assume my-profile --env-file .env
      aws-assume my-profile --credentials
      aws-assume my-profile --json
      aws-assume --list
    """
    if list_only:
        _cmd_list()
        return

    if not profile:
        click.echo(ctx.get_help())
        sys.exit(0)

    try:
        creds = resolve_credentials(
            profile_name=profile,
            duration_seconds=duration,
            auto_login=not no_auto_login,
        )
    except ValueError as e:
        _print_error(str(e))
        _print_info(f"Available profiles: {', '.join(list_profiles()) or 'none found'}")
        sys.exit(1)
    except RuntimeError as e:
        _print_error(str(e))
        sys.exit(1)

    output_count = sum([output_eval, bool(env_file), write_creds, output_json])

    if output_count == 0:
        click.echo(creds.to_eval())
        return

    if output_eval:
        click.echo(creds.to_eval())

    if output_json:
        click.echo(creds.to_json())

    if env_file:
        env_path = Path(env_file)
        env_path.write_text(creds.to_env_file())
        _print_success(f"Credentials written to {env_path}")

    if write_creds:
        target_profile = creds_profile or profile
        creds_path = write_credentials_file(creds, profile_name=target_profile)
        _print_success(f"Credentials written to {creds_path} under profile [{target_profile}]")
        _print_info(f"Use: export AWS_PROFILE={target_profile}  or  --profile {target_profile}")

    if creds.expiration and creds.expiration != "unknown":
        _print_info(f"Expires: {creds.expiration}")


def _cmd_list() -> None:
    profiles = list_profiles()
    if not profiles:
        click.echo(click.style("No profiles found in ~/.aws/config", fg="yellow"), err=True)
        return
    click.echo(click.style("Available profiles:", fg="cyan", bold=True), err=True)
    for p in profiles:
        click.echo(f"  {p}")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
