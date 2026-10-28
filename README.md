# nanobot-agent

Agentes do Nanobot DevOps Utils: código, binários e chart helm.

| Pasta | Agente |
|---|---|
| [`server/`](server/README.md) | Agente dos servidores Linux/Windows: métricas, SSH interno para as tasks e registro automático. Binários em [`server/bin/`](server/bin) |
| [`kubernetes/`](kubernetes/README.md) | `nanobot-k8s-monitoring`: um pod por cluster que grava logs, uso e status dos pods e nós em Parquet no S3 (ou compatível)/GCS/R2. Imagem [`amopromo/nanobot-k8s-agent`](https://hub.docker.com/r/amopromo/nanobot-k8s-agent) |
| [`charts/`](charts) | Repositório helm do agente Kubernetes |

O Nanobot gera os comandos de instalação dos dois agentes já preenchidos: **Servers > Agent Install** e
**Admin > Kubernetes Clusters > Agent Install**.

```bash
# agente dos servidores (Linux x86-64)
curl -fL -o agent https://raw.githubusercontent.com/amopromo/nanobot-agent/main/server/bin/agent_linux_x64

# agente Kubernetes
helm repo add nanobot https://raw.githubusercontent.com/amopromo/nanobot-agent/main/charts
helm upgrade --install nanobot-k8s nanobot/nanobot-k8s-monitoring -n nanobot --create-namespace \
  --set clusterName=meu-cluster --set storage.path=s3://meu-bucket/nanobot-k8s \
  --set credentials.existingSecret=nanobot-k8s-credentials
```

Licença: [GPL-3.0](LICENSE).
