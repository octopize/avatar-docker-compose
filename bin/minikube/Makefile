SHELL := bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c
.DELETE_ON_ERROR:
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

clean: ## Clean the config files saved in build
	rm -rf build/*.json
.PHONY: clean

cluster: ## Create a ready-to-go avatar cluster with default values
	DOCKER_PULL_SECRET=$$(op read "op://Tech Eng/DOCKER_PULL_SECRET/password")\
	 AWS_ACCESS_KEY_ID=$$(op read "op://Tech Eng/AWS email sending user/Section_0456E376214A4046BF2664B5BA0EE8B8/Access Key ID")\
	 AWS_SECRET_ACCESS_KEY=$$(op read "op://Tech Eng/AWS email sending user/Section_0456E376214A4046BF2664B5BA0EE8B8/Secret Access key")\
 	 poetry run python launch.py create-cluster
.PHONY: cluster

delete-namespaces: ## Delete all the 'avatar' namespaces
	kubectl get namespaces --no-headers=true -o custom-columns=:metadata.name | grep avatar | xargs --no-run-if-empty kubectl delete namespace || exit 0
.PHONY: delete-namespaces

.DEFAULT_GOAL := help
help: Makefile
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make \033[36m<target>\033[0m\n"} /^[\/\.a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
