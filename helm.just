SHOPTS := "set -euo pipefail"



PATH_TO_CHART := "services-api-helm-chart"
RELEASE_NAME := "services-api"
NAMESPACE := "services-api"
PATH_TO_VALUES := PATH_TO_CHART / "values.yaml"

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