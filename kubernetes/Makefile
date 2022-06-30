SHELL := bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c
.DELETE_ON_ERROR:
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules


start:
	minikube start

	kubectl config set-context --current --namespace=avatar

	kubectl apply -f namespace.yml
	kubectl apply -f config-map.yml
	kubectl create -f docker-quay-secret.secrets.yml 2> /dev/null || true # Fails when already exists

	# Setup data storage
	kubectl create -f postgres-secrets.secrets.yml 2> /dev/null || true # Fails when already exists
	kubectl apply -f persistent-volumes.yml -f shared-volume-claim.yml -f postgres-volume-claim.yml
	kubectl apply -f postgres-deployment.yml -f postgres-service.yml

	# Setup queue and cron
	kubectl apply -f redis-deployment.yml -f redis-service.yml
	kubectl apply -f cron-deployment.yml

	# Setup api and worker
	kubectl create -f api-secrets.secrets.yml 2> /dev/null || true # Fails when already exists
	kubectl apply -f api-deployment.yml -f worker-deployment.yml -f api-service.yml
.PHONY: start

stop:
	minikube stop
.PHONY: stop

.DEFAULT_GOAL := help
help: Makefile
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make \033[36m<target>\033[0m\n"} /^[\/\.a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
