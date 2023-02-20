SHELL := bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c
.DELETE_ON_ERROR:
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules


SECRETS_DIR := .secrets
# File-based recipes

common-secrets: $(SECRETS_DIR)/db_password $(SECRETS_DIR)/db_name $(SECRETS_DIR)/db_user $(SECRETS_DIR)/pepper $(SECRETS_DIR)/file_encryption_key $(SECRETS_DIR)/authjwt_secret_key $(SECRETS_DIR)/organization_name
.PHONY: common-secrets

secrets-with-username-auth: common-secrets $(SECRETS_DIR)/avatar_first_user_password $(SECRETS_DIR)/avatar_first_user_name ## Initialize secrets for username authentication
.PHONY: secrets-with-username-auth

secrets-with-email-auth: common-secrets $(SECRETS_DIR)/admin_emails $(SECRETS_DIR)/aws_mail_account_access_key_id $(SECRETS_DIR)/aws_mail_account_secret_access_key ## Initialize secrets for email authentication
.PHONY: secrets-with-email-auth


$(SECRETS_DIR)/db_password:
	mkdir -p $(SECRETS_DIR)
	python3 -c "import secrets; print(secrets.token_hex())" > $@

$(SECRETS_DIR)/db_user:
	mkdir -p $(SECRETS_DIR)
	touch $@

$(SECRETS_DIR)/db_name:
	mkdir -p $(SECRETS_DIR)
	touch $@

$(SECRETS_DIR)/pepper:
	mkdir -p $(SECRETS_DIR)
	python3 -c "import secrets; print(secrets.token_hex())" > $@

$(SECRETS_DIR)/authjwt_secret_key:
	mkdir -p $(SECRETS_DIR)
	python3 -c "import secrets; print(secrets.token_hex())" > $@

$(SECRETS_DIR)/file_encryption_key:
	mkdir -p $(SECRETS_DIR)
	python -c "import base64; import os; print(str(base64.urlsafe_b64encode(os.urandom(32)), encoding='utf-8'), end='')" > $@

$(SECRETS_DIR)/avatar_first_user_password:
	mkdir -p $(SECRETS_DIR)
	python3 -c "import secrets; print(secrets.token_hex())" > $@

$(SECRETS_DIR)/avatar_first_user_name:
	mkdir -p $(SECRETS_DIR)
	touch $@

$(SECRETS_DIR)/organization_name:
	mkdir -p $(SECRETS_DIR)
	touch $@

$(SECRETS_DIR)/admin_emails:
	mkdir -p $(SECRETS_DIR)
	touch $@

$(SECRETS_DIR)/aws_mail_account_access_key_id:
	mkdir -p $(SECRETS_DIR)
	echo "" > $@

$(SECRETS_DIR)/aws_mail_account_secret_access_key:
	mkdir -p $(SECRETS_DIR)
	echo "" > $@


.DEFAULT_GOAL := help
help: Makefile
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make \033[36m<target>\033[0m\n"} /^[\/\.a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
