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

if [ -z "$docker_pull_secret" ]; then
      echo "You must supply DOCKER_PULL_SECRET."
      echo DOCKER_PULL_SECRET="$docker_pull_secret"
      exit 1
fi

echo RELEASE_NAME="$release_name"
echo NAMESPACE="$namespace"

db_password=$(python3 -c "import secrets; print(secrets.token_hex(), end='')")
db_user="${DB_USER-avatar}"
db_name="${DB_NAME-avatar}"

avatar_version="${AVATAR_VERSION-latest}"
pdfgenerator_version="${PDFGENERATOR_VERSION-latest}"
use_email_auth="${USE_EMAIL_AUTHENTICATION-false}"
is_telemetry_enabled="false"
is_sentry_enabled="false"
organization_name="${ORGANIZATION_NAME-octopize}"
shared_storage_path="${SHARED_STORAGE_PATH-}"
single_admin_email="${SINGLE_ADMIN_EMAIL-}" # We only accept a single email locally to not make the script overly complicated.
aws_mail_account_access_key_id="${AWS_MAIL_ACCOUNT_ACCESS_KEY_ID-}"
aws_mail_account_secret_access_key="${AWS_MAIL_ACCOUNT_SECRET_ACCESS_KEY-}"

worker_memory_request="4Gi"
api_memory_request="1Gi"
pdfgenerator_memory_request="2Gi"

worker_cpu_request="1000m"
api_cpu_request="512m"
pdfgenerator_cpu_request="512m"

echo AVATAR_VERSION="$avatar_version"
echo PDFGENERATOR_VERSION="$pdfgenerator_version"
echo USE_EMAIL_AUTHENTICATION="$use_email_auth"
echo SHARED_STORAGE_PATH="$shared_storage_path"


if [ "$use_email_auth" = "false" ]; then
      ## Authentication with username and password
      first_user_name="${FIRST_USER_NAME-avatar_admin}"
      generated_password=$(python3 -c "import secrets; print(secrets.token_hex(), end='')")
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


postgres_release="$release_name-postgres"
redis_release="$release_name-redis"

only_avatar="${ONLY_AVATAR-}"
echo ONLY_AVATAR="$only_avatar"
if [ "$only_avatar" = "true" ]; then
      echo "Creating only the avatar release. The API release will be launched but won't be accessible."
else
      if [ "$(helm list --namespace $namespace --filter $postgres_release -q)" = "$postgres_release" ]; then
            echo "A postgres release already exists in that namespace. Set ONLY_AVATAR=true to only launch avatar."
            exit 1
      else
            helm install "$postgres_release" bitnami/postgresql --set auth.username="$db_user" --set auth.password="$db_password" --namespace "$namespace" --create-namespace 1> /dev/null
      fi

      if [ "$(helm list --namespace $namespace --filter $redis_release -q)" = "$redis_release" ]; then
            echo "A redis release already exists in that namespace. Set ONLY_AVATAR=true to only launch avatar."
            exit 1
      else
            helm install "$redis_release" bitnami/redis --set auth.enabled=false --namespace "$namespace" --create-namespace 1> /dev/null
      fi
fi

postgres_host="$postgres_release-postgresql.$namespace.svc.cluster.local"

echo postgres_release="$postgres_release"
echo postgres_host="$postgres_host"

redis_release="$release_name-redis"
redis_host="$redis_release-master.$namespace.svc.cluster.local"


if [ "$only_avatar" != "true" ]; then
      timeout="${TIMEOUT-60}" # Time to wait for the pods to be up before exiting
      echo "Waiting for ${timeout} seconds for the pods to be up before continuing... You can configure the time using TIMEOUT"
      sleep ${timeout}

      # Use the password set during install instead of overring with new randomly generated one
      pg_password="$(kubectl get secret --namespace $NAMESPACE $postgres_release-postgresql -o jsonpath="{.data.password}" | base64 -d)"

      # This is needed as passing --set auth.database=$db_name does not work. The database does not get created.
      echo "Create the database with 'create database ${db_name};' in the following psql prompt. Exit when done."
      kubectl run "$postgres_release-postgresql-client" --rm --tty -i --restart='Never' --namespace "$namespace" --image docker.io/bitnami/postgresql:14.5.0-debian-11-r6 --env="PGPASSWORD=$pg_password" \
            --command -- psql --host "$postgres_host" -U "$db_user" -d postgres -p 5432
fi

# Use the password set during install instead of overring with new randomly generated one
db_password="$(kubectl get secret --namespace $NAMESPACE $postgres_release-postgresql -o jsonpath="{.data.password}" | base64 -d)"

upgrade="${UPGRADE-}"
echo UPGRADE="$upgrade"
subcommand=$([ "$upgrade" = "true" ] && echo "upgrade" || echo "install")

cmd=(helm "$subcommand" --debug "$release_name" ./helm-chart --namespace "$namespace" --create-namespace \
      --set api.baseUrl="http://api.octopize.local" \
      --set dockerPullSecret="$docker_pull_secret" \
      --set avatarVersion="$avatar_version" \
      --set dbPassword="$db_password" \
      --set dbName="$db_name" \
      --set dbUser="$db_user" \
      --set dbHost="$postgres_host" \
      --set redisHost="$redis_host" \
      --set api.pepper=$(python3 -c "import secrets; print(secrets.token_hex(), end='')") \
      --set api.authjwtSecretKey=$(python3 -c "import secrets; print(secrets.token_hex(), end='')") \
      --set api.fileEncryptionKey=$(python3 -c "import base64; import os; print(str(base64.urlsafe_b64encode(os.urandom(32)), encoding='utf-8'), end='')") \
      --set avatarVersion="$avatar_version" \
      --set pdfgeneratorVersion="$pdfgenerator_version" \
      --set api.useEmailAuthentication="$use_email_auth" \
      --set api.isTelemetryEnabled="$is_telemetry_enabled" \
      --set api.isSentryEnabled="$is_sentry_enabled" \
      --set api.organizationName="$organization_name" \
      --set api.sharedStoragePath="$shared_storage_path" \
      --set resources.workerMemoryRequest="$worker_memory_request" \
      --set resources.apiMemoryRequest="$api_memory_request" \
      --set resources.pdfgeneratorMemoryRequest="$pdfgenerator_memory_request" \
      --set resources.workerCpuRequest="$worker_cpu_request" \
      --set resources.apiCpuRequest="$api_cpu_request" \
      --set resources.pdfgeneratorCpuRequest="$pdfgenerator_cpu_request" \
)

if [ "$use_email_auth" = "false" ]; then
      cmd+=(
      --set api.firstUserName="$first_user_name" \
      --set api.firstUserPassword="$first_user_password"
      )
else
      cmd+=(
      --set "api.adminEmails[0]=$single_admin_email" \
      --set api.awsMailAccountAccessKeyId="$aws_mail_account_access_key_id" \
      --set api.awsMailAccountSecretAccessKey="$aws_mail_account_secret_access_key"\
      )
fi

# Run the helm install
"${cmd[@]}"