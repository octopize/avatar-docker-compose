SHELL := bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c
.DELETE_ON_ERROR:
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

install:  ## Install the stack
	@echo "TODO"
.PHONY: install

lint:  ## Lint the files
	helm lint ./helm-chart
.PHONY: lint

render-helm:
	helm template releasename ./helm-chart --debug
.PHONY: render-helm

start-helm-local:
	### Typical usage ###
	## Create the whole stack from scratch
	# make start-helm-local
	## Update only the running avatar release
	# ONLY_AVATAR="true" UPGRADE="true" make start-helm-local
	minikube status 1> /dev/null || minikube start
	bash launch_helm.sh
.PHONY: start-helm-local

stop-helm-local:
	test -n "$(NAMESPACE)"
	test -n "$(RELEASE_NAME)"
	helm uninstall "$(RELEASE_NAME)-postgres" --namespace "$(NAMESPACE)"
	helm uninstall "$(RELEASE_NAME)-redis" --namespace "$(NAMESPACE)"
	helm uninstall "$(RELEASE_NAME)" --namespace "$(NAMESPACE)"
	minikube stop
.PHONY: stop-helm-local



.DEFAULT_GOAL := help
help: Makefile
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make \033[36m<target>\033[0m\n"} /^[\/\.a-zA-Z1-9_-]+:.*?##/ { printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
