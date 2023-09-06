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

uninstall-helm:  ## Uninstall Helm template
	helm uninstall avatar-release --namespace avatar-release
.PHONY: uninstall-helm

minikube: ## Start minikube. Noop if already started.
	minikube status 1> /dev/null || minikube start
.PHONY: minikube

start-helm-local: minikube ## Start stack with Redis, DB, and Avatar Helm charts on minikube
	### Typical usage ###
	## Create the whole stack from scratch
	# make start-helm-local
	## Update only the running avatar release
	# ONLY_AVATAR="true" UPGRADE="true" make start-helm-local
	bash launch_helm.sh
.PHONY: start-helm-local

delete-namespace:
	test -n "$(NAMESPACE)"
	kubectl delete namespace "$(NAMESPACE)" --ignore-not-found
.PHONY: delete-namespace

stop-helm-local:  ## Stop minikube stack
	test -n "$(NAMESPACE)"
	test -n "$(RELEASE_NAME)"
	helm uninstall "$(RELEASE_NAME)-postgres" --namespace "$(NAMESPACE)"
	helm uninstall "$(RELEASE_NAME)-redis" --namespace "$(NAMESPACE)"
	helm uninstall "$(RELEASE_NAME)-avatar" --namespace "$(NAMESPACE)"
.PHONY: stop-helm-local

stop-helm-with-keda: stop-helm-local
	helm uninstall "$(RELEASE_NAME)-keda" --namespace "$(NAMESPACE)"
	$(MAKE) delete-namespace

.PHONY: stop-helm-with-keda

start-helm-with-keda: minikube
	mkdir -p /tmp/avatar/kubernetes/shared
	test -n "$(NAMESPACE)"
	test -n "$(RELEASE_NAME)"
	helm install "$(RELEASE_NAME)-keda" kedacore/keda --namespace "$(NAMESPACE)" --create-namespace
	bash launch_helm.sh
PHONY: start-helm-with-keda

remove-keda:
	kubectl delete $(kubectl get scaledobjects.keda.sh,scaledjobs.keda.sh -A \
	-o jsonpath='{"-n "}{.items[*].metadata.namespace}{" "}{.items[*].kind}{"/"}{.items[*].metadata.name}{"\n"}')
.PHONY: remove-keda



.DEFAULT_GOAL := help
help: Makefile
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make \033[36m<target>\033[0m\n"} /^[\/\.a-zA-Z1-9_-]+:.*?##/ { printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
