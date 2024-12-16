SHELL := bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c
.DELETE_ON_ERROR:
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

##@ Local

install:  ## Install the stack
	@echo "TODO"
	npm install -g yaml-lint
.PHONY: install

##@ Helm

lint:  ## Lint the files
	helm template avatar-release ./helm-chart --debug 2> /dev/null | tee /tmp/to_lint.yaml | yamllint /tmp/to_lint.yaml
.PHONY: lint

render-helm:  ## Render Helm template
	helm template avatar-release ./helm-chart --debug
.PHONY: render-helm


install-helm: minikube  ## Install Helm template
	helm install avatar-release ./helm-chart --debug --namespace avatar-release --create-namespace --values helm-chart/values.yaml
.PHONY: install-helm

install-service-api-helm: minikube  ## Install Helm template
	helm install avatar-service-release ./services-api-helm-chart --debug --namespace avatar-release --create-namespace --values ./services-api-helm-chart/values.yaml
.PHONY: install-service-api-helm


uninstall-helm:  ## Uninstall Helm template
	helm uninstall avatar-release --namespace avatar-release
.PHONY: uninstall-helm

minikube: ## Start minikube. Noop if already started.
	minikube status 2> /dev/null || minikube start
.PHONY: minikube

delete-namespace:
	test -n "$(NAMESPACE)"
	kubectl delete namespace "$(NAMESPACE)" --ignore-not-found
.PHONY: delete-namespace


create-docker-zip:  ## Create an archive to ease deployment on single instance
	git archive -o docker-install.zip  --format zip HEAD:docker
.PHONY: create-zip

.DEFAULT_GOAL := help
help: Makefile
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make \033[36m<target>\033[0m\n"} /^[\/\.a-zA-Z1-9_-]+:.*?##/ { printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
