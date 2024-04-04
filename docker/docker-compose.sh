#!/bin/bash

# This file is used to easily launch a default docker compose deployment.
# Try to have default values for everything so that a simple `bash docker-compose.sh up`
# launches the script

args=()

# If there is a docker-compose.local.yml file, use it to override the docker-compose configuration.
if [[ -f "docker-compose.local.yml" ]]; then
    args+=(-f docker-compose.local.yml)
fi

set -x


export USER_ID=${USER_ID-$(id -u)}
export GROUP_ID=${GROUP_ID-$(id -g)}

export SECRETS_DIR="${SECRETS_DIR:-.secrets}"
export AVATAR_API_VERSION=${AVATAR_API_VERSION-latest}
export AVATAR_PDFGENERATOR_VERSION=${AVATAR_PDFGENERATOR_VERSION-latest}
export AVATAR_NOTEBOOK_SERVER_VERSION=${AVATAR_NOTEBOOK_SERVER_VERSION-latest}
export DOCKER_BUILDKIT=1
export COMPOSE_PROJECT_NAME=avatar
export HOST_SHARED_STORAGE_PATH="${HOST_SHARED_STORAGE_PATH-./shared}"

docker compose --env-file=.env -f "docker-compose.yml" "${args[@]}" $@
