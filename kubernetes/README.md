# kubernetes deployment

## Testing with minikube

All of these steps needs `minikube` to be running.
You can download it [here](https://k8s-docs.netlify.app/en/docs/tasks/tools/install-minikube/).

```bash
minikube start
```

You might also need `kubectl` which you can download [here](https://kubernetes.io/docs/tasks/tools/)

### Setup and launch

Take the Kubernetes config file (here `./docker-quay-secret.template.yml`), and save it as `./docker-quay-secret.secrets.yml`.

```bash
# copy and edit
cp ./api-secrets.template.yml ./api-secrets.secrets.yml
cp ./postgres-secrets.template.yml ./postgres-secrets.secrets.yml
cp ./docker-quay-secret.template.yml ./docker-quay-secret.secrets.yml
```

```bash
make start
kubectl port-forward -n avatar service/avatar-api 8000:8000
```

### Troubleshooting

If you get an error stating `cpu.cfs_quota_us` having an unknown value, you are requesting more CPU than you have allowed `minikube` to use. You can modify it in `worker-deployment.yml`. More information [here](https://kubernetes.io/docs/tasks/administer-cluster/manage-resources/cpu-default-namespace/)
