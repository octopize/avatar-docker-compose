#!/bin/bash

set -euo pipefail

namespace="${NAMESPACE-}"
release_name="${RELEASE_NAME-}"
docker_pull_secret="${DOCKER_PULL_SECRET-}"

if [ -z "$namespace" ] || [ -z "$release_name" ]; then
      echo "You must supply NAMESPACE and RELEASE_NAME."
      echo RELEASE_NAME="$release_name"
      echo NAMESPACE="$namespace"
      exit 1
fi

if [ -z "$docker_pull_secret"]; then
      echo "You must supply DOCKER_PULL_SECRET."
      echo DOCKER_PULL_SECRET="$docker_pull_secret"
      exit 1
fi

echo RELEASE_NAME="$release_name"
echo NAMESPACE="$namespace"

db_password=$(python -c "import secrets; print(secrets.token_hex(), end='')")
db_user="${DB_USER-avatar}"
db_name="${DB_NAME-avatar}"

avatar_version="${AVATAR_VERSION-latest}"
use_email_auth="${USE_EMAIL_AUTH-false}"
single_admin_email="${SINGLE_ADMIN_EMAIL-}" # We only accept a single email locally to not make the script overly complicated.
aws_mail_account_access_key_id="${AWS_MAIL_ACCOUNT_ACCESS_KEY_ID-}"
aws_mail_account_secret_access_key="${AWS_MAIL_ACCOUNT_SECRET_ACCESS_KEY-}"

echo AVATAR_VERSION="$avatar_version"
echo USE_EMAIL_AUTH="$use_email_auth"


if [ "$use_email_auth" = "false" ]; then
      ## Authentication with username and password
      first_user_name="${FIRST_USER_NAME-avatar_admin}"
      generated_password=$(python -c "import secrets; print(secrets.token_hex(), end='')")
      first_user_password="${FIRST_USER_PASSWORD-$generated_password}"
      echo FIRST_USER_NAME="$first_user_name"
      echo FIRST_USER_PASSWORD="$first_user_password"

elif [ "$use_email_auth" = "true" ] && [ -z "$single_admin_email" ]; then
      echo "You must supply SINGLE_ADMIN_EMAIL if USE_EMAIL_AUTH=true"
      echo SINGLE_ADMIN_EMAIL="$single_admin_email"
      exit 1
elif [ "$use_email_auth" = "true" ] && ([ -z "$aws_mail_account_access_key_id" ] || [ -z "$aws_mail_account_secret_access_key" ]); then
      echo "You must supply AWS_MAIL_ACCOUNT_ACCESS_KEY_ID and AWS_MAIL_ACCOUNT_SECRET_ACCESS_KEY if USE_EMAIL_AUTH=true"
      echo AWS_MAIL_ACCOUNT_ACCESS_KEY_ID="$aws_mail_account_access_key_id"
      echo AWS_MAIL_ACCOUNT_SECRET_ACCESS_KEY="$aws_mail_account_secret_access_key"
      exit 1
else
      echo SINGLE_ADMIN_EMAIL="$single_admin_email"
      echo AWS_MAIL_ACCOUNT_ACCESS_KEY_ID="$aws_mail_account_access_key_id"
      echo AWS_MAIL_ACCOUNT_SECRET_ACCESS_KEY="$aws_mail_account_secret_access_key"
fi


helm install "$release_name-redis" bitnami/redis --set auth.enabled=false --namespace "$namespace" --create-namespace 1> /dev/null
helm install "$release_name-postgres" bitnami/postgresql --set auth.username="$db_user" --set auth.password="$db_password" --namespace "$namespace" --create-namespace 1> /dev/null

postgres_release="$release_name-postgres"
postgres_host="$postgres_release-postgresql.$namespace.svc.cluster.local"

echo postgres_release="$postgres_release"
echo postgres_host="$postgres_host"

redis_release="$release_name-redis"
redis_host="$redis_release-master.$namespace.svc.cluster.local"


wait_time=60
echo "Waiting for ${wait_time} seconds for the pods to be up before continuing..."
sleep ${wait_time}

# This is needed as passing --set auth.database=$db_name does not work. The database does not get created.
echo "Create the database with 'create database ${db_name};' in the following psql prompt. Exit when done."

kubectl run "$postgres_release-postgresql-client" --rm --tty -i --restart='Never' --namespace "$namespace" --image docker.io/bitnami/postgresql:14.5.0-debian-11-r6 --env="PGPASSWORD=$db_password" \
      --command -- psql --host "$postgres_host" -U "$db_user" -d postgres -p 5432

if [ "$use_email_auth" = "false" ]; then
      helm install --debug "$release_name" ./helm-chart --namespace "$namespace" --create-namespace \
      --set dockerPullSecret="$docker_pull_secret" \
      --set avatarVersion="$avatar_version" \
      --set dbPassword="$db_password" \
      --set dbName="$db_name" \
      --set dbUser="$db_user" \
      --set dbHost="$postgres_host" \
      --set redisHost="$redis_host" \
      --set api.pepper=$(python -c "import secrets; print(secrets.token_hex(), end='')") \
      --set api.authjwtSecretKey=$(python -c "import secrets; print(secrets.token_hex(), end='')") \
      --set api.fileEncryptionKey=$(python -c "import base64; import os; print(str(base64.urlsafe_b64encode(os.urandom(32)), encoding='utf-8'), end='')") \
      --set api.avatarVersion="$avatar_version" \
      --set api.useEmailAuthentication="$use_email_auth" \
      --set api.firstUserName="$first_user_name" \
      --set api.firstUserPassword="$first_user_password"
else 
      helm install --debug "$release_name" ./helm-chart --namespace "$namespace" --create-namespace \
      --set dockerPullSecret="$docker_pull_secret" \
      --set avatarVersion="$avatar_version" \
      --set dbPassword="$db_password" \
      --set dbName="$db_name" \
      --set dbUser="$db_user" \
      --set dbHost="$postgres_host" \
      --set redisHost="$redis_host" \
      --set api.pepper=$(python -c "import secrets; print(secrets.token_hex(), end='')") \
      --set api.authjwtSecretKey=$(python -c "import secrets; print(secrets.token_hex(), end='')") \
      --set api.fileEncryptionKey=$(python -c "import base64; import os; print(str(base64.urlsafe_b64encode(os.urandom(32)), encoding='utf-8'), end='')") \
      --set api.avatarVersion="$avatar_version" \
      --set api.useEmailAuthentication="$use_email_auth" \
      --set "api.adminEmails[0]=$single_admin_email" \
      --set api.awsMailAccountAccessKeyId="$aws_mail_account_access_key_id" \
      --set api.awsMailAccountSecretAccessKey="$aws_mail_account_secret_access_key"
fi
