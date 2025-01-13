import base64
import json
import secrets
import subprocess
import tempfile
import time
from enum import Enum
from itertools import chain
from pathlib import Path
from typing import Optional, Protocol, cast

import typer
from pydantic import BaseModel
from toolz.dicttoolz import dissoc

app = typer.Typer()


GIT_ROOT = Path(
    subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
)

HELM_CHART_PATH = GIT_ROOT / "services-api-helm-chart"
SAVE_DIRECTORY = GIT_ROOT / "bin" / "minikube" / "build"
POSTGRES_HELM_CHART_VERSION = "16.3.2"
SEAWEEDFS_HELM_CHART_VERSION = "4.2.0"

SEAWEED_FS_PORT = 8333


class AuthKind(Enum):
    EMAIL = "email"
    USERNAME = "username"


DEFAULT_AVATAR_VERSION = "0.0.12"
DEFAULT_API_BASE_URL = "http://localhost:8000"

DEFAULT_IS_SENTRY_ENABLED = False
DEFAULT_IS_TELEMETRY_ENABLED = False

DEFAULT_PDFGENERATOR_VERSION = "latest"
DEFAULT_AUTHENTICATION_KIND = AuthKind.USERNAME
DEFAULT_ORGANIZATION_NAME = "octopize"
DEFAULT_SHARED_STORAGE_PATH = "s3://shared"


DEFAULT_SHOULD_USE_LOCAL_STORAGE = True
DEFAULT_LOG_LEVEL = "INFO"

DEFAULT_DB_NAME = "avatar"
DEFAULT_DB_ADMIN_USER = "avatar_dba"

DEFAULT_USERNAME = "avatar_admin"
DEFAULT_API_MEMORY_REQUEST = "1Gi"
DEFAULT_PDFGENERATOR_MEMORY_REQUEST = "2Gi"
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
    db_admin_user: str
    db_admin_password: str


class AvatarHelmConfig(HelmConfig):
    docker_pull_secret: str
    pepper: str = secrets.token_hex()

    authjwt_secret_key: str = secrets.token_hex()

    db_name: str
    db_user: str
    db_password: str
    db_admin_user: str
    db_admin_password: str

    postgres_host: str
    shared_storage_path: str
    aws_endpoint_url: str

    avatar_api_url: str
    avatar_version: str

    organization_name: str
    authentication: Authentication
    is_telemetry_enabled: bool
    log_level: str

    is_sentry_enabled: bool

    pdfgenerator_version: str

    api_memory_request: str
    pdfgenerator_memory_request: str
    api_cpu_request: str
    pdfgenerator_cpu_request: str


class Result(BaseModel):
    namespace: str
    release_name: str


class AvatarResult(Result):
    avatar_version: str
    avatar_api_url: str

    organization_name: str
    authentication: EmailAuthentication | UsernameAuthentication

    is_telemetry_enabled: bool
    is_sentry_enabled: bool

    pdfgenerator_version: str

    api_memory_request: str
    pdfgenerator_memory_request: str
    api_cpu_request: str
    pdfgenerator_cpu_request: str


class SeaweedfsResult(Result):
    mariadb_password: str
    mariadb_root_password: str


KEY_MAPPING = {
    "api.baseUrl": "avatar_api_url",
    "dockerPullSecret": "docker_pull_secret",
    "avatarServiceApiVersion": "avatar_version",
    "dbName": "db_name",
    "dbUsername": "db_user",
    "dbPassword": "db_password",
    "dbAdminUsername": "db_admin_user",
    "dbAdminPassword": "db_admin_password",
    "dbHost": "postgres_host",
    "api.pepper": "pepper",
    "api.authjwtSecretKey": "authjwt_secret_key",
    "pdfgeneratorVersion": "pdfgenerator_version",
    "api.isTelemetryEnabled": "is_telemetry_enabled",
    "api.isSentryEnabled": "is_sentry_enabled",
    "api.logLevel": "log_level",
    "api.organizationName": "organization_name",
    "api.sharedStoragePath": "shared_storage_path",
    "resources.apiMemoryRequest": "api_memory_request",
    "resources.pdfgeneratorMemoryRequest": "pdfgenerator_memory_request",
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
    db_admin_password: str
    db_name: str
    db_admin_user: str


def is_minikube_running():
    return_code = subprocess.call(["minikube", "status"], stdout=subprocess.DEVNULL)

    if return_code != 0:
        return False
    return True


def get_key(result: Result):
    return f"{result.namespace}-{result.release_name}"


def load_result(key: str) -> Result:
    filename = f"{key}.json"

    fullpath = SAVE_DIRECTORY / filename

    if not fullpath.exists():
        raise Exception(f"Deployment {key} does not exist yet.")

    with open(fullpath) as f:
        json_ = json.load(f)

    if key.startswith("postgres"):
        return PostgresResult.parse_obj(json_)
    if key.startswith("avatar"):
        return AvatarResult.parse_obj(json_)
    raise ValueError("Prefix does not exist.")


def save_result(result: Result) -> None:
    filename = f"{get_key(result)}.json"
    with open(SAVE_DIRECTORY / filename, "w") as f:
        # We load then dumps to have pretty printing
        f.write(json.dumps(json.loads(result.json()), indent=4))


class Chart(Enum):
    POSTGRES = "postgres"
    AVATAR = "avatar"
    SEAWEEDFS = "seaweedfs"


def get_release_name(chart: Chart, release_name_prefix: str) -> str:
    return f"{release_name_prefix}-{chart.value}"


class RetryCallable(Protocol):
    def __call__(self, *, nb_attempts_left: int, is_debug: bool) -> None: ...


def do_retry(
    callable: RetryCallable,  # should raise StopIteration
    *,
    on_success_message: Optional[str] = None,
    on_failure_message: Optional[str] = None,
    nb_retries: int = 5,
    sleep_for_seconds: int = 5,
    should_exit_on_failure: bool = True,
    is_debug: bool = False,
) -> None:
    """Retry function, exit program if fails.

    Parameters
    ----------
    callable :
        Function to call. Should raise StopIteration on success.
        Should return None on failure
        Should have 2 parameters:
            is_debug,
            nb_attempts_left

    Raises
    ------
    typer.Exit
        Exit the program
    """
    current_try = 1
    while current_try < nb_retries:
        try:
            callable(
                nb_attempts_left=nb_retries - current_try,
                is_debug=is_debug,
            )
        except StopIteration:
            if on_success_message:
                typer.echo(on_success_message)
            return

        time.sleep(sleep_for_seconds)

        current_try += 1
        typer.echo(f"Retrying... [{current_try}/{nb_retries}]")

    if on_failure_message:
        typer.echo(on_failure_message)

    if should_exit_on_failure:
        raise typer.Exit(1)


def get_secrets(namespace: str) -> list[str]:
    get_secrets_command = f"kubectl get secrets --no-headers=true -o custom-columns=:metadata.name --namespace {namespace}".split()
    secrets = subprocess.check_output(get_secrets_command, text=True).splitlines()
    return secrets


def delete_secret(namespace: str, secret: str, is_debug: bool) -> None:
    delete_secret_command = (
        f"kubectl delete secret {secret} --namespace {namespace}".split()
    )
    if is_debug:
        typer.echo(f"Deleting secret {secret}...")

    subprocess.run(
        delete_secret_command,
        stdout=subprocess.DEVNULL if not is_debug else None,
    )


@app.command()
def delete_cluster(
    release_name_prefix: str = typer.Option(
        ..., envvar="RELEASE_NAME", help="Prefix used for all the helm releases."
    ),
    namespace: str = typer.Option(
        ...,
        envvar="NAMESPACE",
        help="Name of the Kubernetes namespace to deploy the release in.",
    ),
    is_debug: bool = typer.Option(False, "--debug", help="Show verbose output."),
):
    get_pvcs = f"kubectl get pvc --no-headers=true -o custom-columns=:metadata.name --namespace {namespace}".split()  # noqa: E501
    pvcs = subprocess.check_output(get_pvcs, text=True).splitlines()

    # All PersistantVolumeClaims have a deletion protection finalizer, which
    # prevents them from being deleted.
    # We remove the finalizer before deleting the volume claim.
    patch = r'{"metadata" :{"finalizers" : []}}'
    for pvc in pvcs:
        remove_deletion_protection = [
            "kubectl",
            "patch",
            "pvc",
            pvc,
            "-p",
            patch,
            "--type=merge",
            "--namespace",
            namespace,
            "--allow-missing-template-keys=false",
        ]

        delete_pvc = f"kubectl delete pvc {pvc} --namespace {namespace}".split()

        # For some reason, doing a patch call before a delete call does not manage to modify remove
        # the finalizers before the deletion is started,
        # so it still waits indefinitely if we don't specify --wait=false.
        delete_pvc += ["--wait=false"]

        if is_debug:
            typer.echo(f"Deleting {pvc=}")
            typer.echo(" ".join(remove_deletion_protection))

        subprocess.run(
            delete_pvc,
            stdout=subprocess.DEVNULL if not is_debug else None,
        )

        if is_debug:
            typer.echo(f"Removing deletion protection from {pvc=}")
            typer.echo(" ".join(remove_deletion_protection))

        subprocess.run(
            remove_deletion_protection,
            stdout=subprocess.DEVNULL if not is_debug else None,
        )

    releases = [
        get_release_name(release_name_prefix=release_name_prefix, chart=chart)
        for chart in Chart
    ]

    for release in releases:
        uninstall_command = ["helm", "uninstall", release, "--namespace", namespace]
        if is_debug:
            typer.echo(f"Deleting Helm release {release}...")
            typer.echo(" ".join(uninstall_command))

        result = subprocess.run(
            uninstall_command,
            stdout=subprocess.DEVNULL if not is_debug else None,
            stderr=subprocess.DEVNULL if not is_debug else subprocess.PIPE,
            text=True,
        )

        return_code = result.returncode
        if return_code != 0:
            if is_debug:
                typer.echo(result.stderr)
            typer.echo(f"Could not delete Helm release {release}.")
        else:
            typer.echo(f"Deleted Helm release {release}.")

    for secret in get_secrets(namespace):
        delete_secret(namespace, secret, is_debug=is_debug)


def _delete_releases(namespace: str, release: str, *, is_debug: bool) -> None:
    uninstall_command = ["helm", "uninstall", release, "--namespace", namespace]
    if is_debug:
        typer.echo(f"Deleting Helm release {release}...")
        typer.echo(" ".join(uninstall_command))

    result = subprocess.run(
        uninstall_command,
        stdout=subprocess.DEVNULL if not is_debug else None,
        stderr=subprocess.DEVNULL if not is_debug else subprocess.PIPE,
        text=True,
    )

    return_code = result.returncode
    if return_code != 0:
        if is_debug:
            typer.echo(result.stderr)
        typer.echo(f"Could not delete Helm release {release}.")
    else:
        typer.echo(f"Deleted Helm release {release}.")


@app.command()
def create_cluster(
    docker_pull_secret: str = typer.Option(
        ...,
        envvar="DOCKER_PULL_SECRET",
        help="Docker secret used to pull the images. Can be found on quay.io or 1Password.",
    ),
    release_name_prefix: str = typer.Option(
        None, envvar="RELEASE_NAME", help="Prefix used for all the helm releases."
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
    avatar_api_url: str = typer.Option(
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
        None,
        help="""Emails for the admins. Used if --use-email-authentication is set.\n\n"""
        """Can be used multiple times: e.g. --email mail1@octopize.io --email mail2@octopize.io """
        """which will create 2 admin accounts.""",
    ),
    username: str = typer.Option(
        DEFAULT_USERNAME,
        help="Username of the admin. Used if --use-email-authentication is NOT set.",
    ),
    password: str = typer.Option(
        None,
        help="""Password for the admin. Required if --use-email-authentication is NOT set. """
        """Used only with username.""",
    ),
    db_name: str = typer.Option(DEFAULT_DB_NAME),
    db_user: str = typer.Option(DEFAULT_DB_NAME),
    db_password: str = typer.Option(None),
    db_admin_user: str = typer.Option(DEFAULT_DB_ADMIN_USER),
    db_admin_password: str = typer.Option(None),
    shared_storage_path: str = typer.Option(
        DEFAULT_SHARED_STORAGE_PATH,
        help="""Path to storage that is shared between the API and worker pods."""
        """This script only accepts a filesystem path storage, not a path to cloud storage.""",
    ),
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
    log_level: str = typer.Option(
        DEFAULT_LOG_LEVEL,
        help="Log level of the API. Can be one of DEBUG, INFO, WARNING, ERROR, CRITICAL.",
    ),
    api_memory_request: str = typer.Option(
        DEFAULT_API_MEMORY_REQUEST,
        help="Amount of memory to allocate to a avatar-api pod.",
    ),
    pdfgenerator_memory_request: str = typer.Option(
        DEFAULT_PDFGENERATOR_MEMORY_REQUEST,
        help="Amount of memory to allocate to a avatar-pdfgenerator pod.",
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
    """Create a complete cluster able to run the Avatar API.

    Usage with defaults:

    DOCKER_PULL_SECRET=$(op read "op://Tech Eng/DOCKER_PULL_SECRET/password")\
    AWS_ACCESS_KEY_ID=$(op read "op://Tech Eng/AWS email sending user/Section_0456E376214A4046BF2664B5BA0EE8B8/Access Key ID")\
    AWS_SECRET_ACCESS_KEY=$(op read "op://Tech Eng/AWS email sending user/Section_0456E376214A4046BF2664B5BA0EE8B8/Secret Access key")\
    RELEASE_NAME=avatar\
        poetry run python launch.py create-cluster
    """

    namespace = namespace or f"avatar-ns-{secrets.token_hex(2)}"
    typer.echo(f"Using namespace={namespace}")
    release_name_prefix = release_name_prefix or "avatar"
    typer.echo(f"Using release_name_prefix={release_name_prefix}")
    password = password or secrets.token_hex(16)

    verify_authentication(
        use_email_authentication,
        aws_mail_account_access_key_id=aws_mail_account_access_key_id,
        aws_mail_account_secret_access_key=aws_mail_account_secret_access_key,
        emails=email,
        username=username,
        password=password,
    )

    create_seaweedfs(
        release_name_prefix=release_name_prefix,
        namespace=namespace,
        is_debug=is_debug,
    )

    postgres_result: PostgresResult = create_postgres(
        release_name_prefix=release_name_prefix,
        namespace=namespace,
        is_debug=is_debug,
        db_name=db_name,
        db_admin_user=db_admin_user,
        db_admin_password=db_admin_password or secrets.token_hex(),
    )

    create_avatar(
        release_name_prefix=release_name_prefix,
        namespace=namespace,
        docker_pull_secret=docker_pull_secret,
        avatar_version=avatar_version,
        avatar_api_url=avatar_api_url,
        shared_storage_path=shared_storage_path,
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
        log_level=log_level,
        api_memory_request=api_memory_request,
        pdfgenerator_memory_request=pdfgenerator_memory_request,
        api_cpu_request=api_cpu_request,
        pdfgenerator_cpu_request=pdfgenerator_cpu_request,
        db_host=postgres_result.db_host,
        db_user=db_user,
        db_name=db_name,
        db_password=db_password or secrets.token_hex(),
        db_admin_user=db_admin_user,
        db_admin_password=postgres_result.db_admin_password,
        is_debug=is_debug,
        should_upgrade_only=False,
    )

    typer.echo("Cluster setup complete")
    filename = f"{namespace}-{release_name_prefix}-*.json"
    typer.echo(
        f"""You can find all the values that were setup in {SAVE_DIRECTORY / filename}"""
    )
    raise typer.Exit(0)


@app.command()
def create_postgres(
    release_name_prefix: str = typer.Option(
        ..., envvar="RELEASE_NAME", help="Prefix used for all the helm releases."
    ),
    namespace: str = typer.Option(
        ...,
        envvar="NAMESPACE",
        help="Name of the Kubernetes namespace to deploy the release in.",
    ),
    db_name: str = typer.Option(DEFAULT_DB_NAME),
    db_admin_user: str = typer.Option(DEFAULT_DB_NAME),
    db_admin_password: str = typer.Option(None),
    is_debug: bool = typer.Option(False, "--debug", help="Show verbose output."),
) -> PostgresResult:
    """Create a postgres database setup to run the Avatar API"""

    if not is_minikube_running():
        typer.echo("Minikube must be running. Run with 'minikube start'.")
        raise typer.Abort()

    config = PostgresHelmConfig(
        release_name=release_name_prefix,
        namespace=namespace,
        db_name=db_name,
        db_admin_user=db_admin_user,
        db_admin_password=db_admin_password,
    )

    postgres_release = get_release_name(Chart.POSTGRES, release_name_prefix)
    existing_postgres_release = subprocess.check_output(
        ["helm", "list", "--namespace", namespace, "--filter", postgres_release, "-q"],
        text=True,
    ).strip()

    if existing_postgres_release == postgres_release:
        typer.echo("A postgres release already exists in that namespace.")
        return

    flags = ["--create-namespace", "--version", POSTGRES_HELM_CHART_VERSION]
    namespace_command = ["--namespace", namespace]
    values = [
        "--set",
        f"auth.postgresPassword={config.db_admin_password}",
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

    # This uses the postgres user, which has the same password as the admin_user
    # to create a new user with superuser privileges.
    # This user will then be used by the avatar-api to bootstrap the database.
    # This is because the bitnami/postgresql Helm chart does not allow to create
    # a user with superuser privileges from the values.yaml file.
    # However, it can be done with a custom init script, but as the stuff below
    # was already written, we decided to keep it that way.
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
        f"--env=PGPASSWORD={config.db_admin_password}",
        "--command",
        "--",
        "psql",
        "--host",
        postgres_host,
        "-U",
        "postgres",
        "-d",
        "postgres",
        "-p",
        "5432",
        "-c",
        f"CREATE USER {config.db_admin_user} WITH SUPERUSER PASSWORD '{config.db_admin_password}'",
    ]

    typer.echo("Initializing database...")
    if is_debug:
        typer.echo(" ".join(create_database))

    def initialize_database(
        *, is_debug: bool = False, nb_attempts_left: Optional[int] = None
    ) -> None:
        should_print_stderr = nb_attempts_left == 0 if nb_attempts_left else False
        result = subprocess.run(
            create_database,
            stdout=subprocess.DEVNULL if not is_debug else None,
            stderr=subprocess.DEVNULL if not should_print_stderr else subprocess.PIPE,
        )

        return_code = result.returncode

        if return_code == 0:
            raise StopIteration

        if should_print_stderr:
            typer.echo(result.stderr)

    do_retry(
        initialize_database,
        on_success_message=f"Database setup! release_name={postgres_release}",
        on_failure_message="Could not initialize database",
        sleep_for_seconds=15,
        is_debug=is_debug,
    )

    postgres_host = f"{postgres_release}-postgresql.{namespace}.svc.cluster.local"
    postgres_result = PostgresResult(
        release_name=postgres_release,
        namespace=namespace,
        db_host=postgres_host,
        db_admin_password=config.db_admin_password,
        db_name=config.db_name,
        db_admin_user=config.db_admin_user,
    )

    save_result(postgres_result)
    return postgres_result


def create_s3_auth_secret(namespace: str, s3_fullname: str, is_debug: bool) -> None:
    admin_access_key_id = base64.b64encode(secrets.token_hex(16).encode()).decode()
    admin_secret_access_key = base64.b64encode(secrets.token_hex(32).encode()).decode()
    secret_name = f"{s3_fullname}"
    secret_yaml = f"""
apiVersion: v1
kind: Secret
metadata:
  name: {secret_name}
  namespace: {namespace}
  labels:
    app.kubernetes.io/component: s3
type: Opaque
data:
  admin_access_key_id: {admin_access_key_id}
  admin_secret_access_key: {admin_secret_access_key}
"""

    with tempfile.TemporaryDirectory() as tmpdirname:
        secret_file_path = Path(tmpdirname) / f"{s3_fullname}-auth-secret.yaml"
        with open(secret_file_path, "w") as f:
            f.write(secret_yaml)

        # Create namespace if it does not exist
        typer.echo("Creating namespace...")
        result = subprocess.run(
            ["kubectl", "create", "namespace", namespace],
            stdout=subprocess.DEVNULL,
            text=True,
            stderr=subprocess.PIPE,
        )

        if result.returncode != 0:
            if "already exists" in result.stderr:
                typer.echo("Namespace already exists.")
            else:
                typer.echo(result.stderr)
                raise typer.Exit(result.returncode)

        result = subprocess.run(
            ["kubectl", "apply", "-f", secret_file_path, "--namespace", namespace],
            text=True,
            stdout=subprocess.DEVNULL if not is_debug else None,
            stderr=subprocess.PIPE,
        )

        if result.returncode != 0:
            typer.echo(result.stderr)
            typer.echo("Could not create secret.")
            raise typer.Exit(result.returncode)

    return secret_name


@app.command()
def create_seaweedfs(
    release_name_prefix: str = typer.Option(
        ..., envvar="RELEASE_NAME", help="Prefix used for all the helm releases."
    ),
    namespace: str = typer.Option(
        ...,
        envvar="NAMESPACE",
        help="Name of the Kubernetes namespace to deploy the release in.",
    ),
    is_debug: bool = typer.Option(False, "--debug", help="Show verbose output."),
) -> SeaweedfsResult:
    if not is_minikube_running():
        typer.echo("Minikube must be running. Run with 'minikube start'.")
        raise typer.Abort()

    seaweedfs_release = get_release_name(Chart.SEAWEEDFS, release_name_prefix)

    existing_seaweedfs_release = subprocess.check_output(
        ["helm", "list", "--namespace", namespace, "--filter", seaweedfs_release, "-q"],
        text=True,
    ).strip()

    if existing_seaweedfs_release == seaweedfs_release:
        typer.echo("A seaweedfs release already exists in that namespace.")
        return

    flags = ["--create-namespace", "--debug"]

    namespace_command = ["--namespace", namespace]

    mariadb_password = secrets.token_hex(16)
    mariadb_root_password = secrets.token_hex(16)

    # We are creating a secret because, by default, the seaweedfs Helm chart
    # create an admin will all priviledges AND a user with read priviledges.
    # We want no default user to have read priviledges, so we only specify the admin user.
    secret_name = create_s3_auth_secret(namespace, f"{seaweedfs_release}-s3", is_debug)

    values_to_set = [
        f"mariadb.auth.rootPassword={mariadb_password}",
        f"mariadb.auth.password={mariadb_root_password}",
        "s3.enabled=true",
        "s3.auth.enabled=true",
        # f"s3.auth.existingSecret={secret_name}",
        "iam.enabled=true",
    ]

    values = list(chain.from_iterable(["--set", v] for v in values_to_set))

    install_seaweedfs = [
        "helm",
        "install",
        seaweedfs_release,
        "/home/tom/Documents/dev/bitnami-charts/bitnami/seaweedfs",
        *flags,
        *namespace_command,
        *values,
    ]

    typer.echo("Creating seaweedfs Helm release...")
    if is_debug:
        typer.echo(" ".join(install_seaweedfs))

    subprocess.call(
        install_seaweedfs, stdout=subprocess.DEVNULL if not is_debug else None
    )

    seaweedfs_result = SeaweedfsResult(
        release_name=seaweedfs_release,
        namespace=namespace,
        mariadb_password=mariadb_password,
        mariadb_root_password=mariadb_root_password,
    )

    save_result(seaweedfs_result)

    def wait_until_s3_pod_is_running(
        *, is_debug: bool = False, nb_attempts_left: Optional[int] = None
    ):
        should_print_stderr = nb_attempts_left == 0 if nb_attempts_left else False

        command = f"kubectl --namespace {namespace} get pods -l 'app.kubernetes.io/component=s3' -o json | jq '.items[].status.conditions[] | select(.type == \"Ready\") | .status'"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        if result.returncode != 0 and should_print_stderr:
            typer.echo(result.stderr)

        status = result.stdout.strip()

        if is_debug:
            typer.echo(f"Pod status: {status}")

        if status == '"True"':
            raise StopIteration

    do_retry(
        wait_until_s3_pod_is_running,
        on_success_message=f"Seaweedfs setup! release_name={seaweedfs_release}",
        on_failure_message="Could not initialize seaweedfs",
        sleep_for_seconds=60,
        should_exit_on_failure=False,
        is_debug=is_debug,
    )

    typer.echo(f"Port forwarding port {SEAWEED_FS_PORT} from seaweed s3 api to host.")

    subprocess.Popen(
        [
            "kubectl",
            "port-forward",
            "-n",
            namespace,
            "service/avatar-seaweedfs-s3",
            f"{SEAWEED_FS_PORT}:{SEAWEED_FS_PORT}",
        ],
        close_fds=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,  # an error is thrown, but port forwarding succeeds
    )
    return seaweedfs_result


@app.command()
def create_avatar(
    release_name_prefix: str = typer.Option(
        ..., envvar="RELEASE_NAME", help="Prefix used for all the helm releases."
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
    avatar_api_url: str = typer.Option(
        DEFAULT_API_BASE_URL, help="URL at which the API is accessible."
    ),
    shared_storage_path: str = typer.Option(
        DEFAULT_SHARED_STORAGE_PATH,
        help="""Path to storage that is shared between the API and worker pods."""
        """This script only accepts a filesystem path storage, not a path to cloud storage.""",
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
    db_host: str = typer.Option(
        ..., help="Name of the host where a Database instance is running."
    ),
    db_name: str = typer.Option(DEFAULT_DB_NAME),
    db_user: str = typer.Option(DEFAULT_DB_NAME),
    db_password: str = typer.Option(...),
    db_admin_user: str = typer.Option(DEFAULT_DB_ADMIN_USER),
    db_admin_password: str = typer.Option(...),
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
    log_level: str = typer.Option(
        DEFAULT_LOG_LEVEL,
        help="Log level of the API. Can be one of DEBUG, INFO, WARNING, ERROR, CRITICAL.",
    ),
    api_memory_request: str = typer.Option(
        DEFAULT_API_MEMORY_REQUEST,
        help="Amount of memory to allocate to a avatar-api pod.",
    ),
    pdfgenerator_memory_request: str = typer.Option(
        DEFAULT_PDFGENERATOR_MEMORY_REQUEST,
        help="Amount of memory to allocate to a avatar-pdfgenerator pod.",
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
        """Can be useful if you forgot to change a single value """
        """and you don't want to create a brand new release.""",
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

    if not should_upgrade_only and not db_host:
        typer.echo("Expected 'postgres_host' to have a value, but they have not.")
        typer.echo(
            """Consider running 'python minikube.by create-postgres' beforehand"""
        )
        raise typer.Abort()

    avatar_release_name = get_release_name(Chart.AVATAR, release_name_prefix)
    seaweed_release_name = get_release_name(Chart.SEAWEEDFS, release_name_prefix)
    config = AvatarHelmConfig(
        release_name=avatar_release_name,
        namespace=namespace,
        avatar_api_url=avatar_api_url,
        avatar_version=avatar_version,
        docker_pull_secret=docker_pull_secret,
        pdfgenerator_version=pdfgenerator_version,
        shared_storage_path=shared_storage_path,
        aws_endpoint_url=f"http://{seaweed_release_name}:{SEAWEED_FS_PORT}",
        db_password=db_password,
        db_user=db_user,
        db_name=db_name,
        db_admin_user=db_admin_user,
        db_admin_password=db_admin_password,
        postgres_host=db_host,
        organization_name=organization_name,
        authentication=authentication,
        is_telemetry_enabled=is_telemetry_enabled,
        is_sentry_enabled=is_sentry_enabled,
        log_level=log_level,
        api_memory_request=api_memory_request,
        pdfgenerator_memory_request=pdfgenerator_memory_request,
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
    flags = ["--create-namespace", "--debug"]
    namespace_command = ["--namespace", config.namespace]

    using_local_storage = ["--set", "debug.storage.useLocal=true"]

    values = list(
        chain.from_iterable(
            ["--set", f"{key}={getattr(config, value)}"]
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
            ["--set", f"api.adminEmails={{{','.join(email)}}}"]  # type: ignore[arg-type]
            if use_email_authentication
            else [],
            *(
                ["--set", f"{key}={getattr(authentication, value)}"]
                for key, value in dissoc(mapping, "api.adminEmails").items()
            ),
        )
    )

    time.sleep(10)  # TODO: optimize this

    install_avatar = [
        "helm",
        upgrade_or_install,
        avatar_release_name,
        str(HELM_CHART_PATH),
        *namespace_command,
        *flags,
        *values,
        *using_local_storage,
        *authentication_values,
    ]

    if should_upgrade_only:
        typer.echo(
            f"Updating avatar Helm release with release_name={config.release_name}"
        )
    else:
        typer.echo(
            f"Creating avatar Helm release with release_name={config.release_name}"
        )

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

    def verify_api_health(
        *, is_debug: bool = False, nb_attempts_left: Optional[int] = None
    ):
        should_print_stderr = nb_attempts_left == 0 if nb_attempts_left else False
        result = subprocess.run(
            ["curl", "localhost:8000/health"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL if not should_print_stderr else subprocess.PIPE,
        )
        if "ok" in result.stdout:
            raise StopIteration

        if result.returncode != 0 and should_print_stderr:
            typer.echo(result.stderr)

    time.sleep(15)  # wait for the pod to be running, TODO: could be optimized
    typer.echo("Port forwarding port 8000 from API to host.")
    subprocess.Popen(
        ["kubectl", "port-forward", "-n", namespace, "service/avatar-api", "8000:8000"],
        close_fds=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,  # an error is thrown, but port forwarding succeeds
    )

    typer.echo("Waiting for the API to be healthy...")
    do_retry(
        verify_api_health,
        on_failure_message="API did not manage to be healthy before timeout...",
        on_success_message="""API healthy! \n\n """
        """You can now connect to the API from your machine at localhost:8000""",
        should_exit_on_failure=False,
        is_debug=is_debug,
    )

    typer.echo("Avatar release setup!")

    email_or_username: str
    auth_password: Optional[str] = None
    if use_email_authentication:
        email_or_username = cast(
            EmailAuthentication, config.authentication
        ).admin_emails[0]
    else:
        auth = cast(UsernameAuthentication, config.authentication)
        email_or_username = auth.username
        auth_password = auth.password

    typer.echo("Useful commands")

    typer.echo(
        f"""\t-AVATAR_BASE_URL='{config.avatar_api_url}'"""
        f"""AVATAR_USERNAME='{email_or_username}'"""
        f"""AVATAR_PASSWORD='{auth_password}'"""
        """make -C ../../../avatar/platform/api run-test-integration"""
    )
    typer.echo(
        f"\t- poetry run python launch.py delete-cluster --release-name-prefix {release_name_prefix} --namespace {namespace}"  # noqa: E501
    )

    upgrade_command = [
        "poetry",
        "run",
        "python",
        "launch.py",
        "create-avatar",
        "--upgrade-only",
        "--db-host",
        config.postgres_host,
        "--db-password",
        config.db_password,
        "--release-name-prefix",
        release_name_prefix,
        "--namespace",
        namespace,
        "--docker-pull-secret",
        docker_pull_secret,
        "--username",
        email_or_username,
        "--password",
        auth_password,
    ]

    typer.echo("".join(upgrade_command))

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

    auth: Authentication
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
