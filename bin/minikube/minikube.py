import json
import time
from typing import Optional, cast
import base64
import os
import secrets
import subprocess
from enum import Enum
from itertools import chain
from pathlib import Path

import typer
from pydantic import BaseModel

app = typer.Typer()


DEBUG = False

GIT_ROOT = Path(
    subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
)

HELM_CHART_PATH = GIT_ROOT / "helm-chart"
SAVE_DIRECTORY = GIT_ROOT / "bin" / "minikube" / "build"


class AuthKind(Enum):
    EMAIL = "email"
    USERNAME = "username"


DEFAULT_AVATAR_VERSION = "latest"
DEFAULT_API_BASE_URL = "http://api.octopize.local"

DEFAULT_IS_SENTRY_ENABLED = False
DEFAULT_IS_TELEMETRY_ENABLED = False

DEFAULT_PDFGENERATOR_VERSION = "latest"
DEFAULT_AUTHENTICATION_KIND = AuthKind.USERNAME
DEFAULT_ORGANIZATION_NAME = "octopize"

DEFAULT_DB_NAME = "avatar"

DEFAULT_USERNAME = "avatar_admin"
DEFAULT_WORKER_MEMORY_REQUEST = "4Gi"
DEFAULT_API_MEMORY_REQUEST = "1Gi"
DEFAULT_PDFGENERATOR_MEMORY_REQUEST = "2Gi"
DEFAULT_WORKER_CPU_REQUEST = "1000m"
DEFAULT_API_CPU_REQUEST = "512m"
DEFAULT_PDFGENERATOR_CPU_REQUEST = "512m"


class InvalidConfig(Exception):
    pass


class Authentication(BaseModel):
    password: str
    kind: AuthKind


class EmailAuthentication(Authentication):
    kind: AuthKind = AuthKind.EMAIL

    admin_emails: list[str]
    aws_mail_account_access_key_id: str
    aws_mail_account_secret_access_key: str


class UsernameAuthentication(Authentication):
    kind: AuthKind = AuthKind.USERNAME
    username: str


class DeploymentOptions(BaseModel):
    should_upgrade: bool
    only_avatar: bool


class HelmConfig(BaseModel):
    namespace: str
    release_name: str


class PostgresHelmConfig(HelmConfig):
    db_name: str
    db_user: str
    db_password: str


class AvatarHelmConfig(HelmConfig):
    namespace: str
    release_name: str

    docker_pull_secret: str
    pepper: str = secrets.token_hex()

    authjwt_secret_key: str = secrets.token_hex()
    file_encryption_key: str = base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")

    db_password: str
    db_user: str
    db_name: str
    postgres_host: str
    redis_host: str

    avatar_version: str = DEFAULT_AVATAR_VERSION
    api_base_url: str = DEFAULT_API_BASE_URL

    organization_name: str = DEFAULT_ORGANIZATION_NAME
    authentication: Authentication

    is_telemetry_enabled: bool = DEFAULT_IS_TELEMETRY_ENABLED
    is_sentry_enabled: bool = DEFAULT_IS_SENTRY_ENABLED

    pdfgenerator_version: str = DEFAULT_PDFGENERATOR_VERSION

    worker_memory_request: str = DEFAULT_WORKER_MEMORY_REQUEST
    api_memory_request: str = DEFAULT_API_MEMORY_REQUEST
    pdfgenerator_memory_request: str = DEFAULT_PDFGENERATOR_MEMORY_REQUEST
    worker_cpu_request: str = DEFAULT_WORKER_CPU_REQUEST
    api_cpu_request: str = DEFAULT_API_CPU_REQUEST
    pdfgenerator_cpu_request: str = DEFAULT_PDFGENERATOR_CPU_REQUEST


class Result(BaseModel):
    namespace: str
    release_name: str
    pass


class AvatarResult(Result):
    avatar_version: str = DEFAULT_AVATAR_VERSION
    api_base_url: str = DEFAULT_API_BASE_URL

    organization_name: str = DEFAULT_ORGANIZATION_NAME
    authentication: Authentication

    is_telemetry_enabled: bool = DEFAULT_IS_TELEMETRY_ENABLED
    is_sentry_enabled: bool = DEFAULT_IS_SENTRY_ENABLED

    pdfgenerator_version: str = DEFAULT_PDFGENERATOR_VERSION

    worker_memory_request: str = DEFAULT_WORKER_MEMORY_REQUEST
    api_memory_request: str = DEFAULT_API_MEMORY_REQUEST
    pdfgenerator_memory_request: str = DEFAULT_PDFGENERATOR_MEMORY_REQUEST
    worker_cpu_request: str = DEFAULT_WORKER_CPU_REQUEST
    api_cpu_request: str = DEFAULT_API_CPU_REQUEST
    pdfgenerator_cpu_request: str = DEFAULT_PDFGENERATOR_CPU_REQUEST


KEY_MAPPING = {
    "api.baseUrl": "api_base_url",
    "dockerPullSecret": "docker_pull_secret",
    "avatarVersion": "avatar_version",
    "dbPassword": "db_password",
    "dbName": "db_name",
    "dbUser": "db_user",
    "dbHost": "postgres_host",
    "redisHost": "redis_host",
    "api.pepper": "pepper",
    "api.authjwtSecretKey": "authjwt_secret_key",
    "api.fileEncryptionKey": "file_encryption_key",
    "pdfgeneratorVersion": "pdfgenerator_version",
    "api.isTelemetryEnabled": "is_telemetry_enabled",
    "api.isSentryEnabled": "is_sentry_enabled",
    "api.organizationName": "organization_name",
    "resources.workerMemoryRequest": "worker_memory_request",
    "resources.apiMemoryRequest": "api_memory_request",
    "resources.pdfgeneratorMemoryRequest": "pdfgenerator_memory_request",
    "resources.workerCpuRequest": "worker_cpu_request",
    "resources.apiCpuRequest": "api_cpu_request",
    "resources.pdfgeneratorCpuRequest": "pdfgenerator_cpu_request",
}

# "api.useEmailAuthentication": "api.useEmailAuthentication",  # TODO: Handle separately
# "api.firstUserName": "api.firstUserName",  # TODO: Handle separately
# "api.firstUserPassword": "api.firstUserPassword",  # TODO: Handle separately
# "api.awsMailAccountAccessKeyId": "api.awsMailAccountAccessKeyId",  # TODO: Handle separately
# "api.awsMailAccountSecretAccessKey": "api.awsMailAccountSecretAccessKey",  # TODO: Handle separately


class PostgresResult(Result):
    db_host: str
    db_password: str
    db_name: str
    db_user: str


class RedisResult(Result):
    redis_host: str


def is_minikube_running():
    return_code = subprocess.call(["minikube", "status"], stdout=subprocess.DEVNULL)

    if return_code != 0:
        return False
    return True


def get_key(result: Result):
    if isinstance(result, PostgresResult):
        prefix = "postgres"
    elif isinstance(result, RedisResult):
        prefix = "redis"
    else:
        prefix = "avatar"

    return f"{prefix}-{result.namespace}-{result.release_name}"


def load_result(key: str) -> HelmConfig:
    filename = f"{key}.json"

    fullpath = SAVE_DIRECTORY / filename

    if not fullpath.exists():
        raise Exception(f"Deployment {key} does not exist yet.")

    with open(fullpath) as f:
        json_ = json.load(f)

    if key.startswith("postgres"):
        return PostgresResult.parse_obj(json_)
    if key.startswith("redis"):
        return RedisResult.parse_obj(json_)
    if key.startswith("avatar"):
        return AvatarResult.parse_obj(json_)
    raise ValueError(f"Prefix does not exist.")


def save_result(result: Result) -> None:
    filename = f"{get_key(result)}.json"
    with open(SAVE_DIRECTORY / filename, "w") as f:
        f.write(result.json())


@app.command()
def create_release(
    release_name: str = typer.Option(
        ..., envvar="RELEASE_NAME", help="Suffix used for all the helm releases."
    ),
    namespace: str = typer.Option(
        ...,
        envvar="NAMESPACE",
        help="Name of the Kubernetes namespace to deploy the release in.",
    ),
    docker_pull_secret: str = typer.Option(
        ...,
        envvar="DOCKER_PULL_SECRET",
        help="Docker secret used to pull the images. Can be found on quay.io",
    ),
    aws_mail_account_access_key_id: Optional[str] = typer.Option(
        None,
        envvar="AWS_ACCESS_KEY_ID",
        help="AWS Credentials used to send mail. Used if --use-email-authentication is set.",
    ),
    aws_mail_account_secret_access_key: Optional[str] = typer.Option(
        None,
        envvar="AWS_SECRET_ACCESS_KEY",
        help="AWS Credentials used to send mail. Used if --use-email-authentication is set.",
    ),
    use_email_authentication: bool = typer.Option(
        True,
        "--use-email-authentication",
        help="Flag to activate/deactivate email authentication.",
    ),
    email: Optional[list[str]] = typer.Option(
        None, help="Used if --use-email-authentication is set."
    ),
    username: Optional[str] = typer.Option(
        None, help="Used if --use-email-authentication is NOT set."
    ),
    password: str = typer.Option(..., help="Password for the emails or username."),
    db_name: str = typer.Option(DEFAULT_DB_NAME),
    db_user: str = typer.Option(DEFAULT_DB_NAME),
    db_password: str = typer.Option(None),
    is_debug: bool = typer.Option(False, "--debug", help="Show verbose output."),
) -> None:
    
    verify_authentication(
        use_email_authentication,
        aws_mail_account_access_key_id=aws_mail_account_access_key_id,
        aws_mail_account_secret_access_key=aws_mail_account_secret_access_key,
        emails=email,
        username=username,
    )

    postgres_result = create_postgres(
        release_name=release_name,
        namespace=namespace,
        is_debug=is_debug,
        db_name=db_name,
        db_user=db_user,
        db_password=db_password,
    )
    redis_result = create_redis(
        release_name=release_name, namespace=namespace, is_debug=is_debug
    )

    avatar_config = create_avatar(
        release_name=release_name,
        namespace=namespace,
        docker_pull_secret=docker_pull_secret,
        aws_mail_account_access_key_id=aws_mail_account_access_key_id,
        aws_mail_account_secret_access_key=aws_mail_account_secret_access_key,
        use_email_authentication=use_email_authentication,
        email=email,
        username=username,
        password=password,
        db_host=postgres_result.db_host,
        db_name=postgres_result.db_name,
        db_password=postgres_result.db_password,
        redis_host=redis_result.redis_host,
        is_debug=is_debug,
    )

    print(avatar_config)

    raise typer.Exit(0)


@app.command()
def create_postgres(
    release_name: str = typer.Option(
        ..., envvar="RELEASE_NAME", help="Suffix used for all the helm releases."
    ),
    namespace: str = typer.Option(
        ...,
        envvar="NAMESPACE",
        help="Name of the Kubernetes namespace to deploy the release in.",
    ),
    db_name: str = typer.Option(DEFAULT_DB_NAME),
    db_user: str = typer.Option(DEFAULT_DB_NAME),
    db_password: str = typer.Option(None),
    is_debug: bool = typer.Option(False, "--debug", help="Show verbose output."),
) -> PostgresResult:
    if not is_minikube_running():
        typer.echo("Minikube must be running. Run with 'minikube start'.")
        raise typer.Abort()

    config = PostgresHelmConfig(
        release_name=release_name,
        namespace=namespace,
        db_name=db_name,
        db_user=db_user,
        db_password=db_password or secrets.token_hex(),
    )

    postgres_release = f"{release_name}-postgres"
    existing_postgres_release = subprocess.check_output(
        ["helm", "list", "--namespace", namespace, "--filter", postgres_release, "-q"],
        text=True,
    ).strip()

    if existing_postgres_release == postgres_release:
        typer.echo("A postgres release already exists in that namespace.")
        raise typer.Exit(code=1)

    flags = ["--create-namespace"]
    namespace_command = ["--namespace", namespace]
    values = [
        "--set",
        f"auth.username={config.db_user}",
        "--set",
        f"auth.password={config.db_password}",
    ]

    save_result(config)

    install_postgres = [
        "helm",
        "install",
        postgres_release,
        "bitnami/postgresql",
        *values,
        *flags,
        *namespace_command,
    ]
    typer.echo("Creating database Helm release...")
    if is_debug:
        typer.echo(" ".join(install_postgres))

    subprocess.call(
        install_postgres, stdout=subprocess.DEVNULL if not is_debug else None
    )

    postgres_host = f"{postgres_release}-postgresql.{namespace}.svc.cluster.local"

    create_database = [
        "kubectl",
        "run",
        f"{postgres_release}-postgresql-client",
        "--rm",
        "--tty",
        "--restart=Never",
        "-i",
        "--namespace",
        namespace,
        "--image",
        "docker.io/bitnami/postgresql:14.5.0-debian-11-r6",
        f"--env=PGPASSWORD={config.db_password}",
        "--command",
        "--",
        "psql",
        "--host",
        postgres_host,
        "-U",
        config.db_user,
        "-d",
        "postgres",
        "-p",
        "5432",
        "-c",
        f"create database {config.db_name}",
    ]

    typer.echo("Initializing database...")
    if is_debug:
        typer.echo(" ".join(create_database))

    nb_max_retries = 5
    nb_retries = 0
    return_code = 1
    while return_code != 0 and nb_retries <= nb_max_retries:
        time.sleep(10)
        should_print_stderr = nb_retries == (nb_max_retries - 1)
        result = subprocess.run(
            create_database,
            stdout=subprocess.DEVNULL if not is_debug else None,
            stderr=subprocess.DEVNULL if not should_print_stderr else subprocess.PIPE,
        )
        return_code = result.returncode
        nb_retries += 1
        typer.echo(f"Retrying... [{nb_retries}/{nb_max_retries}]")

    if return_code != 0:
        typer.echo(result.stderr)
        typer.echo(f"Could not initialize database after {nb_max_retries} attempts :(")
        raise typer.Exit(return_code)

    typer.echo("Database setup!")
    postgres_host = f"{postgres_release}-postgresql.{namespace}.svc.cluster.local"
    return PostgresResult(
        release_name=release_name,
        namespace=namespace,
        db_host=postgres_host,
        db_password=config.db_password,
        db_name=config.db_name,
        db_user=config.db_name,
    )


@app.command()
def create_redis(
    release_name: str = typer.Option(..., envvar="RELEASE_NAME"),
    namespace: str = typer.Option(..., envvar="NAMESPACE"),
    is_debug: bool = typer.Option(False, "--debug", help="Show verbose output."),
) -> RedisResult:
    if not is_minikube_running():
        typer.echo("Minikube must be running. Run with 'minikube start'.")
        raise typer.Abort()

    redis_release = f"{release_name}-redis"
    existing_redis_release = subprocess.check_output(
        ["helm", "list", "--namespace", namespace, "--filter", redis_release, "-q"],
        text=True,
    ).strip()

    if existing_redis_release == redis_release:
        typer.echo("A redis release already exists in that namespace.")
        raise typer.Abort()

    flags = ["--debug", "--create-namespace"]
    namespace_command = ["--namespace", namespace]
    values = ["--set", "auth.enabled=false"]
    install_redis = [
        "helm",
        "install",
        redis_release,
        "bitnami/redis",
        *values,
        *namespace_command,
        *flags,
    ]

    typer.echo("Creating redis Helm release...")
    if is_debug:
        typer.echo(" ".join(install_redis))

    result = subprocess.run(
        install_redis,
        stdout=subprocess.DEVNULL if not is_debug else None,
        stderr=subprocess.PIPE,
    )

    if result.returncode != 0:
        typer.echo(result.stderr)
        typer.echo(f"Could not initialize Redis :(")
        raise typer.Exit(result.returncode)

    typer.echo("Redis setup!")

    redis_host = f"{redis_release}-master.{namespace}.svc.cluster.local"
    return RedisResult(
        redis_host=redis_host,
        release_name=release_name,
        namespace=namespace,
    )


@app.command()
def create_avatar(
    release_name: str = typer.Option(
        ..., envvar="RELEASE_NAME", help="Suffix used for all the helm releases."
    ),
    namespace: str = typer.Option(
        ...,
        envvar="NAMESPACE",
        help="Name of the Kubernetes namespace to deploy the release in.",
    ),
    docker_pull_secret: str = typer.Option(
        ...,
        envvar="DOCKER_PULL_SECRET",
        help="Docker secret used to pull the images. Can be found on quay.io",
    ),
    aws_mail_account_access_key_id: Optional[str] = typer.Option(
        None,
        envvar="AWS_ACCESS_KEY_ID",
        help="AWS Credentials used to send mail. Used if --use-email-authentication is set.",
    ),
    aws_mail_account_secret_access_key: Optional[str] = typer.Option(
        None,
        envvar="AWS_SECRET_ACCESS_KEY",
        help="AWS Credentials used to send mail. Used if --use-email-authentication is set.",
    ),
    use_email_authentication: bool = typer.Option(
        True,
        "--use-email-authentication",
        help="Flag to activate/deactivate email authentication.",
    ),
    email: Optional[list[str]] = typer.Option(
        None, help="Used if --use-email-authentication is set."
    ),
    username: Optional[str] = typer.Option(
        None, help="Used if --use-email-authentication is NOT set."
    ),
    password: str = typer.Option(..., help="Password for the emails or username."),
    redis_host: str = typer.Option(
        ..., help="Name of the host where a Redis instance if running."
    ),
    db_host: str = typer.Option(
        ..., help="Name of the host where a Database instance if running."
    ),
    db_password: str = typer.Option(...),
    db_user: str = typer.Option(DEFAULT_DB_NAME),
    db_name: str = typer.Option(DEFAULT_DB_NAME),
    should_upgrade_only: bool = typer.Option(
        False,
        "--upgrade-only",
        help="""Whether to run 'helm upgrade' instead of 'helm install'.\n\n"""
        """Can be useful if you forgot to change a single value and you don't want to create a brand new release.""",
    ),
    is_debug: bool = typer.Option(False, "--debug", help="Show verbose output."),
) -> AvatarHelmConfig:
    authentication = get_authentication(
        use_email_authentication=use_email_authentication,
        aws_mail_account_access_key_id=aws_mail_account_access_key_id,
        aws_mail_account_secret_access_key=aws_mail_account_secret_access_key,
        emails=email,
        username=username,
        password=password,
    )

    if not should_upgrade_only and not (not db_host or not redis_host):
        typer.echo(
            "Expected 'postgres_host' and 'redis_host' to have a value, but they have not."
        )
        typer.echo(
            "Consider running 'python minikube.by create-postgres' and 'python minikube create-redis' beforehand"
        )
        raise typer.Abort()

    config = AvatarHelmConfig(
        release_name=release_name,
        namespace=namespace,
        docker_pull_secret=docker_pull_secret,
        authentication=authentication,
        redis_host=redis_host,
        postgres_host=db_host,
        db_password=db_password,
        db_user=db_user,
        db_name=db_name,
    )

    is_mapping_correct = all(
        hasattr(config, attribute) for attribute in KEY_MAPPING.values()
    )
    if not is_mapping_correct:
        for attribute in KEY_MAPPING.values():
            print(f"{attribute}: {hasattr(config, attribute)}")
        raise InvalidConfig("Some keys in KEY_MAPPING do not exist in the BaseModel.")

    save_result(config)

    upgrade_or_install = "install" if not should_upgrade_only else "upgrade"
    flags = "--debug --create-namespace"
    namespace_command = f"--namespace {config.namespace}"
    avatar_release_name = f"{config.release_name}-avatar"

    values = [
        f"--set {key}='{getattr(config,value)}'" for key, value in KEY_MAPPING.items()
    ]

    install_avatar = [
        "helm",
        upgrade_or_install,
        avatar_release_name,
        *values,
        namespace_command,
        flags,
    ]

    if should_upgrade_only:
        typer.echo("Creating avatar Helm release...")
    else:
        typer.echo("Updating avatar Helm release...")

    if is_debug:
        typer.echo(" ".join(install_avatar))

    result = subprocess.run(
        install_avatar,
        stdout=subprocess.DEVNULL if not is_debug else None,
        stderr=subprocess.PIPE,
    )

    if result.returncode != 0:
        typer.echo(result.stderr)
        if should_upgrade_only:
            typer.echo("Could not update avatar Helm release :(")
        else:
            typer.echo("Could not create avatar Helm release :(")
        raise typer.Exit(result.returncode)

    avatar_result = AvatarResult(
        release_name=release_name,
        namespace=namespace,
    )
    save_result(avatar_result)

    return avatar_result


def verify_authentication(
    use_email_authentication: bool,
    *,
    aws_mail_account_access_key_id: Optional[str],
    aws_mail_account_secret_access_key: Optional[str],
    emails: list[str] | None,
    username: Optional[str],
) -> None:
    if use_email_authentication and not emails:
        typer.echo(
            "Expected at least one email as --use-email-authentication is selected."
        )
        raise typer.Abort()
    elif not use_email_authentication and not username:
        typer.echo(
            "Expected an username as --use-email-authentication is not selected."
        )
        raise typer.Abort()

    elif use_email_authentication and (
        not aws_mail_account_access_key_id or not aws_mail_account_secret_access_key
    ):
        typer.echo("Expected AWS credentials for Simple Email Service.")
        raise typer.Abort()
    else:
        return None

def get_authentication(
    use_email_authentication: bool,
    *,
    aws_mail_account_access_key_id: Optional[str],
    aws_mail_account_secret_access_key: Optional[str],
    emails: list[str] | None,
    username: Optional[str],
    password: str,
) -> Authentication:

    verify_authentication(
        use_email_authentication,
        aws_mail_account_access_key_id=aws_mail_account_access_key_id,
        aws_mail_account_secret_access_key=aws_mail_account_secret_access_key,
        emails=emails,
        username=username,
    )

    if use_email_authentication:
        return EmailAuthentication(
            admin_emails=cast(list[str], emails),
            aws_mail_account_access_key_id=cast(str, aws_mail_account_access_key_id),
            aws_mail_account_secret_access_key=cast(
                str, aws_mail_account_secret_access_key
            ),
            password=password,
        )
    else:
        return UsernameAuthentication(
            username=cast(str, username),
            password=password,
        )


if __name__ == "__main__":
    app()
