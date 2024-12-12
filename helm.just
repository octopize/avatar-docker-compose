SHOPTS := "set -euo pipefail"

OCI_IMAGE_REGISTRY := "quay.io"
OCI_IMAGE_ORG := "octopize"
OCI_REPO := OCI_IMAGE_REGISTRY / OCI_IMAGE_ORG

PATH_TO_CHART := "services-api-helm-chart"
RELEASE_NAME := "services-api"
NAMESPACE := "services-api"
PATH_TO_VALUES := PATH_TO_CHART / "values.yaml"

HELM_PACKAGE_DIR := "/tmp/helm-chart-builds"
OCI_IMAGE_NAME := "helm" + "/" + RELEASE_NAME

render:
    @helm template {{RELEASE_NAME}} {{PATH_TO_CHART}} --namespace {{NAMESPACE}}

lint:
    @echo $(just render) | yamllint -

install:
    @helm install  \
        {{RELEASE_NAME}} \
        {{PATH_TO_CHART}} \
        --namespace {{NAMESPACE}} \
        --create-namespace \
        --values {{PATH_TO_VALUES}}

package:
    @helm package {{PATH_TO_CHART}} -d {{HELM_PACKAGE_DIR}}

# Push Helm Chart to quay.io
push-helm-chart:
    #!/usr/bin/env bash
    {{SHOPTS}}

    output=$(just package)
    # Extract out the name from Successfully packaged chart and saved it to: /tmp/helm-chart-builds/avatar-0.0.1.tgz
    chart_file=$(echo "$output" | grep -oP '(?<=Successfully packaged chart and saved it to: ).*')

    helm push "$chart_file" oci://{{OCI_REPO}}/{{OCI_IMAGE_NAME}}


login-helm-registry OCI_REPO_USERNAME OCI_PASSWORD:
    @helm registry login {{OCI_IMAGE_REGISTRY}} --username {{OCI_REPO_USERNAME}} --password {{OCI_PASSWORD}} 