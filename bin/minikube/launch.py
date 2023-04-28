from toolz.dicttoolz import dissoc
import functools
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
    kind: AuthKind


class EmailAuthentication(Authentication):
    kind: AuthKind = AuthKind.EMAIL

    admin_emails: list[str]
    aws_mail_account_access_key_id: str
    aws_mail_account_secret_access_key: str


class UsernameAuthentication(Authentication):
    kind: AuthKind = AuthKind.USERNAME
    password: str
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

    api_base_url: str
    avatar_version: str

    organization_name: str
    authentication: Authentication

    is_telemetry_enabled: bool
    is_sentry_enabled: bool

    pdfgenerator_version: str

    worker_memory_request: str
    api_memory_request: str
    pdfgenerator_memory_request: str
    worker_cpu_request: str
    api_cpu_request: str
    pdfgenerator_cpu_request: str


class Result(BaseModel):
    namespace: str
    release_name: str
    pass


class AvatarResult(Result):
    avatar_version: str
    api_base_url: str

    organization_name: str
    authentication: EmailAuthentication | UsernameAuthentication

    is_telemetry_enabled: bool
    is_sentry_enabled: bool

    pdfgenerator_version: str

    worker_memory_request: str
    api_memory_request: str
    pdfgenerator_memory_request: str
    worker_cpu_request: str
    api_cpu_request: str
    pdfgenerator_cpu_request: str


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


USER_AUTHENTICATION_KEY_MAPPING = {
    "api.firstUserName": "username",
    "api.firstUserPassword": "password",
}

EMAIL_AUTHENTICATION_KEY_MAPPING = {
    "api.awsMailAccountAccessKeyId": "aws_mail_account_access_key_id",
    "api.adminEmails": "admin_emails",
    "api.awsMailAccountSecretAccessKey": "aws_mail_account_secret_access_key",
}


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

    return f"{result.namespace}-{result.release_name}-{prefix}"


def load_result(key: str) -> Result:
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
def create_cluster(
    docker_pull_secret: str = typer.Option(
        ...,
        envvar="DOCKER_PULL_SECRET",
        help="Docker secret used to pull the images. Can be found on quay.io or 1Password.",
    ),
    release_name: str = typer.Option(
        None, envvar="RELEASE_NAME", help="Suffix used for all the helm releases."
    ),
    namespace: str = typer.Option(
        None,
        envvar="NAMESPACE",
        help="Name of the Kubernetes namespace to deploy the release in.",
    ),
    avatar_version: str = typer.Option(
        DEFAULT_AVATAR_VERSION, help="Version of the avatar API."
    ),
    pdfgenerator_version: str = typer.Option(
        DEFAULT_PDFGENERATOR_VERSION, help="Version of the pdfgenerator."
    ),
    organization_name: str = typer.Option(
        DEFAULT_ORGANIZATION_NAME, help="Name of the organization/tenant"
    ),
    api_base_url: str = typer.Option(
        DEFAULT_API_BASE_URL, help="URL at which the API is accessible."
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
        False,
        "--use-email-authentication",
        help="Flag to activate email authentication.",
    ),
    email: Optional[list[str]] = typer.Option(
        None, help=
        """Emails for the admins. Used if --use-email-authentication is set.\n\n"""
        """Can be used multiple times: e.g. --email mail1@octopize.io --email mail2@octopize.io will create 2 admin accounts."""
    ),
    username: str = typer.Option(
        DEFAULT_USERNAME,
        help="Username of the admin. Used if --use-email-authentication is NOT set.",
    ),
    password: str = typer.Option(
        None,
        help="Password for the admin. Required if --use-email-authentication is NOT set. Used only with username.",
    ),
    db_name: str = typer.Option(DEFAULT_DB_NAME),
    db_user: str = typer.Option(DEFAULT_DB_NAME),
    db_password: str = typer.Option(None),
    is_telemetry_enabled: bool = typer.Option(
        DEFAULT_IS_TELEMETRY_ENABLED,
        "--enable-telemetry",
        help="Whether or not telemetry is enabled.",
    ),
    is_sentry_enabled: bool = typer.Option(
        DEFAULT_IS_SENTRY_ENABLED,
        "--enable-sentry",
        help="Whether or not error monitoring using Sentry is enabled.",
    ),
    worker_memory_request: str = typer.Option(
        DEFAULT_WORKER_MEMORY_REQUEST,
        help="Amount of memory to allocate to a avatar-worker pod.",
    ),
    api_memory_request: str = typer.Option(
        DEFAULT_API_MEMORY_REQUEST,
        help="Amount of memory to allocate to a avatar-api pod.",
    ),
    pdfgenerator_memory_request: str = typer.Option(
        DEFAULT_PDFGENERATOR_MEMORY_REQUEST,
        help="Amount of memory to allocate to a avatar-pdfgenerator pod.",
    ),
    worker_cpu_request: str = typer.Option(
        DEFAULT_WORKER_CPU_REQUEST,
        help="Amount of CPU to allocate to a avatar-worker pod.",
    ),
    api_cpu_request: str = typer.Option(
        DEFAULT_API_CPU_REQUEST, help="Amount of CPU to allocate to a avatar-api pod."
    ),
    pdfgenerator_cpu_request: str = typer.Option(
        DEFAULT_PDFGENERATOR_CPU_REQUEST,
        help="Amount of CPU to allocate to a avatar-pdfgenerator pod.",
    ),
    is_debug: bool = typer.Option(False, "--debug", help="Show verbose output."),
) -> None:
    """Create a complete cluster able to run the Avatar API"""

    namespace = namespace or f"avatar-ns-{secrets.token_hex(2)}"
    release_name = release_name or f"avatar"
    password = password or secrets.token_hex(16)

    verify_authentication(
        use_email_authentication,
        aws_mail_account_access_key_id=aws_mail_account_access_key_id,
        aws_mail_account_secret_access_key=aws_mail_account_secret_access_key,
        emails=email,
        username=username,
        password=password,
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
        avatar_version=avatar_version,
        api_base_url=api_base_url,
        pdfgenerator_version=pdfgenerator_version,
        aws_mail_account_access_key_id=aws_mail_account_access_key_id,
        aws_mail_account_secret_access_key=aws_mail_account_secret_access_key,
        use_email_authentication=use_email_authentication,
        email=email,
        username=username,
        password=password,
        organization_name=organization_name,
        is_telemetry_enabled=is_telemetry_enabled,
        is_sentry_enabled=is_sentry_enabled,
        worker_memory_request=worker_memory_request,
        api_memory_request=api_memory_request,
        pdfgenerator_memory_request=pdfgenerator_memory_request,
        worker_cpu_request=worker_cpu_request,
        api_cpu_request=api_cpu_request,
        pdfgenerator_cpu_request=pdfgenerator_cpu_request,
        db_host=postgres_result.db_host,
        db_user=postgres_result.db_user,
        db_name=postgres_result.db_name,
        db_password=postgres_result.db_password,
        redis_host=redis_result.redis_host,
        is_debug=is_debug,
        should_upgrade_only=False,
    )

    typer.echo("Cluster setup complete")
    typer.echo(
        """You can find all the values that were setup in the build folder, """
               f"""with the {namespace}-{release_name} prefix"""
        )
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
    """Create a postgres database setup to run the Avatar API"""

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
    postgres_result = PostgresResult(
        release_name=release_name,
        namespace=namespace,
        db_host=postgres_host,
        db_password=config.db_password,
        db_name=config.db_name,
        db_user=config.db_name,
    )

    save_result(postgres_result)
    return postgres_result


@app.command()
def create_redis(
    release_name: str = typer.Option(..., envvar="RELEASE_NAME"),
    namespace: str = typer.Option(..., envvar="NAMESPACE"),
    is_debug: bool = typer.Option(False, "--debug", help="Show verbose output."),
) -> RedisResult:
    """Create a redis message queue setup to run the Avatar API"""

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
        help="Docker secret used to pull the images. Can be found on quay.io or 1Password.",
    ),
    avatar_version: str = typer.Option(
        DEFAULT_AVATAR_VERSION, help="Version of the avatar API."
    ),
    pdfgenerator_version: str = typer.Option(
        DEFAULT_PDFGENERATOR_VERSION, help="Version of the pdfgenerator."
    ),
    api_base_url: str = typer.Option(
        DEFAULT_API_BASE_URL, help="URL at which the API is accessible."
    ),
    organization_name: str = typer.Option(
        DEFAULT_ORGANIZATION_NAME, help="Name of the organization/tenant"
    ),
    aws_mail_account_access_key_id: Optional[str] = typer.Option(
        None,
        envvar="AWS_ACCESS_KEY_ID",
        help="AWS Credentials used to send mail. Required if --use-email-authentication is set.",
    ),
    aws_mail_account_secret_access_key: Optional[str] = typer.Option(
        None,
        envvar="AWS_SECRET_ACCESS_KEY",
        help="AWS Credentials used to send mail. Required if --use-email-authentication is set.",
    ),
    use_email_authentication: bool = typer.Option(
        False,
        "--use-email-authentication",
        help="Flag to activate/deactivate email authentication.",
    ),
    email: Optional[list[str]] = typer.Option(
        None, help="Required if --use-email-authentication is set."
    ),
    username: Optional[str] = typer.Option(
        None, help="Required if --use-email-authentication is NOT set."
    ),
    password: str = typer.Option(
        None,
        help="Password for the username. Required is --use-email-authentication is NOT set.",
    ),
    redis_host: str = typer.Option(
        ..., help="Name of the host where a Redis instance is running."
    ),
    db_host: str = typer.Option(
        ..., help="Name of the host where a Database instance is running."
    ),
    db_password: str = typer.Option(...),
    db_user: str = typer.Option(DEFAULT_DB_NAME),
    db_name: str = typer.Option(DEFAULT_DB_NAME),
    is_telemetry_enabled: bool = typer.Option(
        DEFAULT_IS_TELEMETRY_ENABLED,
        "--enable-telemetry",
        help="Whether or not telemetry is enabled.",
    ),
    is_sentry_enabled: bool = typer.Option(
        DEFAULT_IS_SENTRY_ENABLED,
        "--enable-sentry",
        help="Whether or not error monitoring using Sentry is enabled.",
    ),
    worker_memory_request: str = typer.Option(
        DEFAULT_WORKER_MEMORY_REQUEST,
        help="Amount of memory to allocate to a avatar-worker pod.",
    ),
    api_memory_request: str = typer.Option(
        DEFAULT_API_MEMORY_REQUEST,
        help="Amount of memory to allocate to a avatar-api pod.",
    ),
    pdfgenerator_memory_request: str = typer.Option(
        DEFAULT_PDFGENERATOR_MEMORY_REQUEST,
        help="Amount of memory to allocate to a avatar-pdfgenerator pod.",
    ),
    worker_cpu_request: str = typer.Option(
        DEFAULT_WORKER_CPU_REQUEST,
        help="Amount of CPU to allocate to a avatar-worker pod.",
    ),
    api_cpu_request: str = typer.Option(
        DEFAULT_API_CPU_REQUEST, help="Amount of CPU to allocate to a avatar-api pod."
    ),
    pdfgenerator_cpu_request: str = typer.Option(
        DEFAULT_PDFGENERATOR_CPU_REQUEST,
        help="Amount of CPU to allocate to a avatar-pdfgenerator pod.",
    ),
    should_upgrade_only: bool = typer.Option(
        False,
        "--upgrade-only",
        help="""Whether to run 'helm upgrade' instead of 'helm install'.\n\n"""
        """Can be useful if you forgot to change a single value and you don't want to create a brand new release.""",
    ),
    is_debug: bool = typer.Option(False, "--debug", help="Show verbose output."),
) -> AvatarResult:
    """ADVANCED. Use create-cluster if you're new to this.
    Create the avatar component hosting the Avatar API.
    """

    authentication = get_authentication(
        use_email_authentication=use_email_authentication,
        aws_mail_account_access_key_id=aws_mail_account_access_key_id,
        aws_mail_account_secret_access_key=aws_mail_account_secret_access_key,
        emails=email,
        username=username,
        password=password,
    )

    if not should_upgrade_only and (not db_host or not redis_host):
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
        api_base_url=api_base_url,
        avatar_version=avatar_version,
        docker_pull_secret=docker_pull_secret,
        pdfgenerator_version=pdfgenerator_version,
        db_password=db_password,
        db_user=db_user,
        db_name=db_name,
        postgres_host=db_host,
        redis_host=redis_host,
        organization_name=organization_name,
        authentication=authentication,
        is_telemetry_enabled=is_telemetry_enabled,
        is_sentry_enabled=is_sentry_enabled,
        worker_memory_request=worker_memory_request,
        api_memory_request=api_memory_request,
        pdfgenerator_memory_request=pdfgenerator_memory_request,
        worker_cpu_request=worker_cpu_request,
        api_cpu_request=api_cpu_request,
        pdfgenerator_cpu_request=pdfgenerator_cpu_request,
    )

    is_mapping_correct = all(
        hasattr(config, attribute) for attribute in KEY_MAPPING.values()
    )
    if not is_mapping_correct:
        for attribute in KEY_MAPPING.values():
            print(f"{attribute}: {hasattr(config, attribute)}")
        raise InvalidConfig("Some keys in KEY_MAPPING do not exist in the BaseModel.")

    avatar_result = AvatarResult.parse_obj(config.dict())
    save_result(avatar_result)

    upgrade_or_install = "install" if not should_upgrade_only else "upgrade"
    avatar_release_name = f"{config.release_name}-avatar"
    flags = ["--create-namespace", "--debug"]
    namespace_command = ["--namespace", config.namespace]

    values = list(
        chain.from_iterable(
            ["--set", f"{key}={getattr(config,value)}"]
            for key, value in KEY_MAPPING.items()
        )
    )

    mapping = (
        USER_AUTHENTICATION_KEY_MAPPING
        if isinstance(authentication, UsernameAuthentication)
        else EMAIL_AUTHENTICATION_KEY_MAPPING
    )

    authentication_values = list(
        chain(
            [
                "--set",
                f"api.useEmailAuthentication={str(use_email_authentication).lower()}",
            ],
            ["--set", f"api.adminEmails={{{','.join(email)}}}"]
            if use_email_authentication
            else [],
            *(
                ["--set", f"{key}={getattr(authentication, value)}"]
                for key, value in dissoc(mapping, "api.adminEmails").items()
            ),
        )
    )

    install_avatar = [
        "helm",
        upgrade_or_install,
        avatar_release_name,
        str(HELM_CHART_PATH),
        *namespace_command,
        *flags,
        *values,
        *authentication_values,
    ]

    if should_upgrade_only:
        typer.echo("Updating avatar Helm release...")
    else:
        typer.echo("Creating avatar Helm release...")

    if is_debug:
        typer.echo(" ".join(install_avatar))

    result = subprocess.run(
        install_avatar,
        text=True,
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

    typer.echo("Avatar release setup!")
    return avatar_result


def verify_authentication(
    use_email_authentication: bool,
    *,
    aws_mail_account_access_key_id: Optional[str],
    aws_mail_account_secret_access_key: Optional[str],
    emails: list[str] | None,
    username: Optional[str],
    password: Optional[str],
) -> None:
    if use_email_authentication and not emails:
        typer.echo(
            "Expected at least one email as --use-email-authentication is selected."
        )
        raise typer.Abort()
    elif use_email_authentication and (
        not aws_mail_account_access_key_id or not aws_mail_account_secret_access_key
    ):
        typer.echo("Expected AWS credentials for Simple Email Service.")
        raise typer.Abort()
    elif not use_email_authentication and (not username or not password):
        typer.echo(
            "Expected an username and a password as --use-email-authentication is not selected."
        )
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
        password=password,
    )

    if use_email_authentication:
        auth = EmailAuthentication(
            admin_emails=cast(list[str], emails),
            aws_mail_account_access_key_id=cast(str, aws_mail_account_access_key_id),
            aws_mail_account_secret_access_key=cast(
                str, aws_mail_account_secret_access_key
            ),
        )
    else:
        auth = UsernameAuthentication(
            username=cast(str, username),
            password=password,
        )

    mapping = (
        USER_AUTHENTICATION_KEY_MAPPING
        if isinstance(auth, UsernameAuthentication)
        else EMAIL_AUTHENTICATION_KEY_MAPPING
    )
    is_mapping_correct = all(hasattr(auth, attribute) for attribute in mapping.values())
    if not is_mapping_correct:
        for attribute in mapping.values():
            print(f"{attribute}: {hasattr(auth, attribute)}")
        raise InvalidConfig("Some keys in the mapping do not exist in the BaseModel.")

    return auth


if __name__ == "__main__":
    app()
