# Deploying on single instance

## Objective of this document

This documents lays out how to deploy the stack on a single instance.

## Manual

Deployment should happen as a normal user. We do not want to deploy as root, as the container will inherit the rights of the user launching it.

Thus, we'll deploy in the home directory of the user.

On a single instance, we'll have the following files:

- a `docker-compose.yml` taken from [`avatar-deployment`](https://github.com/octopize/avatar-deployment/blob/main/docker/docker-compose.yml)
- a `.env.` file
- a `shared/` directory to store files that are shared by the worker and the api container.
- a `.secrets/` directory to store the secrets in
- a `caddy/Caddyfile` file to store the configuration for the Caddy reverse-proxy
- an optional `docker-compose.sh` file to make starting and stopping the container easier

This looks like the following

```text
/home/deploy-user/
├── caddy/
│   └── Caddyfile
├── docker-compose.yml
├── docker-compose.sh
├── .env
├─ shared/
└── .secrets/
    ├── authjwt_secret_key
    ├── db_name
    ├── db_password
    ├── db_user
    ├── file_encryption_key
    ├── organization_name
    ├── pepper
    # If using username authentication
    ├── avatar_first_user_name
    └── avatar_first_user_password
    If using email authentication
    ├── admin_emails
    ├── aws_mail_account_access_key_id
    └── aws_mail_account_secret_access_key

```

1. You can clone the `avatar-deployment` repository to have a starting point. See instructions at [avatar-deployment/docker/README.md](https://github.com/octopize/avatar-deployment/blob/main/docker/README.md).
2. Decide on the authentication method. You can use either username-based or email-based authentication. See [Setup authentication](#setup-authentication).
3. Setup the database. See [Setup database](#setup-database).
4. _Optional._ Setup compatibility. See [Setup compatibility](#setup-compatibility).
5. _Optional._ Setup the storage location. See [Storage location](#storage-location).
6. _Optional._ Setup HTTPS and certificates. See [Handling HTTPS and certificates](#handling-https-and-certificates).
7. Setup access to the private image registry. See [Setting up access to the private image registry](#setting-up-access-to-the-private-image-registry).
8. Create the volumes for the database and caddy. See [Starting the stack](#starting-the-stack).
9. Start the stack. See [Starting the stack](#starting-the-stack).

### Setup authentication

First, you have to decide whether the user will use username-based or email-based authentication.
You'll have to slightly modify the `docker-compose.yml` file to select which secrets you want to use depending on the authentication method.

You need to create a `.secrets` directory in the home directory of the user. This is already done by the Makefile in the `avatar-deployment` repository.

Then, you need to fill in the following secrets:

- `organization_name`

If using username based authentication:

- `avatar_first_user_name`
- `avatar_first_user_password`

If using email based authentication:

- `admin_emails`
- `aws_mail_account_access_key_id`. See 1password under the "AWS email sending user" entry.
- `aws_mail_account_secret_access_key`. See 1password under the "AWS email sending user" entry.

We recommend using `octopize` as the organization name, and an octopize email for the first user.
Later on, we can add more organizations/users through other command line scripts.

### Setup compatibility

Our stack uses a compatibility mapping on Google Cloud to make sure that the clients are compatible with the API.
In case GCP is not reachable, it also has a local copy.

If the client blocked outgoing connections in their firewall, the API will not be able to reach the compatibility mapping on Google Cloud.
You can point to the local copy by setting the `COMPATIBILITY_MAPPING` environment variable to the path of the local copy.

In `.env`:

```dotenv
COMPATIBILITY_MAPPING_FILEPATH=api/resources/compatibility_mapping.json
```

### Setup database

The database will be automatically created by the docker container. You just have to provide it the credentials in the `.secrets` directory.
Fill in the following secrets:

- `db_name`
- `db_user`

A password is already generated in `.secrets/db_password`. Preferably, you should NOT change it.

### Storage location

This is an optional step. Depending on the server configuration, whether you are root, and the space allocated to the /home folder (`df -H`), you might want to move the location where Docker stores its content.

Good sysadmin practices dictate that one should not store program data inside the `/home` folder.

Thus, there is less storage space allocated to `/home` and/or `/var`, and it is thus necessary to move the location where Docker stores it's content, as Docker images quickly fill up the entire storage space at `/var` or `/home`, which on average have around 5 GB allocated.

It is also necessary to move where we store our `/shared` directory by default.

Assuming that `/data` is where the sysadmin decides where the data should be stored, each section will detail which steps need to be taken.

#### Docker

Modify or create `/etc/docker/daemon.json` and modify the `data-root` path.

In **`/etc/docker/daemon.json`**:

```json
{
  "data-root": "/data/docker"
}
```

[See this stackoverflow answer.](https://stackoverflow.com/a/24312133)

Remove the old images and containers and move the volumes. These are by default stored somewhere in `/var/lib/docker`, accessible only to `root`.

> :warning: Do NOT delete the database volume `postgres_data`

Then run to restart the docker daemon:

```text
sudo systemctl daemon-reload
sudo systemctl restart docker
```

#### Shared storage

The shared storage is where the files are stored that are shared between the worker and the API container. This is where the files are stored that are uploaded by the user.

If you want to move it out of the `/home` directory (see [storage location](#storage-location) for reasons why).

You have to ensure that:

- the directory is owned by the user whose `USER_ID` is the one provided to Docker
- `HOST_SHARED_STORAGE_PATH` is modified accordingly in the `docker-compose.yml`.

### Handling HTTPS and certificates

If using customer-provided certificates, you can view them using:

```text
openssl x509 -noout -text -in cert.pem
```

You will have to map the host directory containing the certificates to the container. This is done in the `docker-compose.yml` file.

```yaml
volumes:
  - /path/to/certs:/certs # /certs is the one we use in the Caddyfile
```

and modify the environment variable `CADDY_TLS_CONFIG` to point to the correct certificate.

```dotenv
   CADDY_TLS_CONFIG="tls /certs/cert.pem /certs/key.pem"
```

- Make sure you verify the CN (Common Name) field matches the expected domain that the user will connect to.
- Make sure that the certificate is not expired.

Now, you can test the connection with curl:

```bash
curl --resolve domain.name.fr:443:127.0.0.1 https://domain.name.fr
```

If testing with curl, note that you sometimes will need to:

- add the `-k` option if the certificate is self-signed
- make sure that the CA bundle at `/etc/ssl/certs` matches the domain name that you are testing with. For example, the certificate provided by the client matches `*.company.fr`, but the CA only accepts `avatars.company.fr`. You then have to use `avatars.company.fr`.

### Setting up access to the private image registry

To be able to pull the images from our private `quay.io` registry, you need to create a new robot account [here](https://quay.io/repository/octopize/api?tab=settings), give it read-only permissions and login with `docker login quay.io`.

### Starting the stack

First, need to create the volumes for the database and caddy:

```bash
docker volume create avatar_postgres_data
docker volume create avatar_caddy_data
```

Finally, you can run the stack with

```bash
# current user id. Might need to be changed if ./shared is not owned by current user
USER_ID="$(id -u)"\
GROUP_ID="$(id -g)\
SECRETS_DIR=.secrets\
DOCKER_BUILDKIT=1\
COMPOSE_PROJECT_NAME=avatar\
HOST_SHARED_STORAGE_PATH=./shared\
AVATAR_API_VERSION=latest\
AVATAR_PDFGENERATOR_VERSION=latest\
AVATAR_NOTEBOOK_HUB_VERSION=latest\
docker compose -f "docker-compose.yml" --env-file=.env up --remove-orphans
```

This is simplified in the optional `docker-compose.sh` script:

```bash
./docker-compose.sh up
# or
bash docker-compose.sh up
```

> :point_right: You may need to make is executable: `chmod +x docker-compose.sh`

Then test that everything is ok with

```bash
base_url=https://...
curl $base_url/health
curl $base_url/health/db
curl $base_url/health/file
curl $base_url/health/task
curl $base_url/health/task/file
curl $base_url/health/task/db
curl $base_url/health/exception # verifies sentry
curl $base_url/health/pdf
```

Additional commands:

```bash
bash docker-compose.sh stop
bash docker-compose.sh pull
```
