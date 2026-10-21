# nanobot-k8s-monitoring

Agente em Go que roda dentro do cluster Kubernetes (um pod por cluster) e grava em Parquet no S3, GCS ou R2:

- **logs dos pods**, com o pod, o workload (Deployment, CronJob...) e o namespace de cada linha;
- **uso de CPU e memória dos pods**: valor usado, request e limit, e o percentual do uso sobre o request e sobre o limit (base para os alertas);
- **status dos pods**: fase, pronto ou não, restarts e motivo (CrashLoopBackOff, OOMKilled, ImagePullBackOff...), e se o pod é de um Deployment ou de uma CronJob (base para o alerta de pods caídos);
- **nós**: CPU, memória e disco usados x requeridos x allocatable, quantidade de pods.

O Nanobot lê os arquivos com o DuckDB (menu **Kubernetes**). O mesmo bucket atende vários clusters, cada um na sua pasta. O cluster só precisa alcançar o bucket: não há banco de dados no caminho.

## Como coleta

- Estado do cluster pelos informers (pods, nós, ReplicaSets, Jobs e CronJobs), para achar o dono de cada pod: ReplicaSet → **Deployment**, Job → **CronJob** e nó → **StaticPod**. O cache guarda só os campos usados (pods sem env, volumes, anotações etc.; nós sem a lista de imagens) e ReplicaSets, Jobs e CronJobs só com os metadados.
- Uso de CPU, memória e disco pelo summary do kubelet (`/api/v1/nodes/<nó>/proxy/stats/summary`), sem depender do metrics-server.
- Logs pela API (`kubectl logs -f --timestamps`), um stream por container. Pods de CronJob que duram segundos são lidos até o fim mesmo depois de encerrados.
- Coleta a cada `SAMPLE_INTERVAL` (60s), com o mesmo timestamp para todos os pods (o Nanobot soma por workload). Pod encerrado entra uma vez só.

## Onde os dados ficam

`<storage.path>/<clusterName>/<tabela>/dt=AAAA-MM-DD/hh=HH/<arquivo>.parquet`, com dia e hora (UTC) do horário das linhas:

| Tabela | Tipo | Colunas |
|---|---|---|
| `clusters` | dimensão | id, name, k8s_version, first_seen |
| `namespaces` | dimensão | id, cluster_id, name, first_seen |
| `workloads` | dimensão | id, cluster_id, namespace_id, kind (Deployment, CronJob, StatefulSet, DaemonSet, Job, StaticPod...), name, first_seen |
| `nodes` | dimensão | id, cluster_id, name, first_seen |
| `pods` | dimensão | id, cluster_id, namespace_id, workload_id, name, uid, owner_kind, created_at, first_seen |
| `pod_samples` | fato | ts, pod_id, workload_id, namespace_id, node_id, phase, ready, restarts, reason, cpu_usage_m, cpu_request_m, cpu_limit_m, mem_usage_bytes, mem_request_bytes, mem_limit_bytes, ephemeral_usage_bytes, cpu_pct_request, cpu_pct_limit, mem_pct_request, mem_pct_limit |
| `node_samples` | fato | ts, node_id, ready, unschedulable, cpu_*_m, mem_*_bytes, fs_capacity_bytes, fs_used_bytes, ephemeral_*_bytes, pods_count, pods_capacity |
| `logs` | fato | ts, pod_id, workload_id, namespace_id, container, message |

- Os dados fixos (cluster, namespace, workload, nó, pod) ficam só nas dimensões; os fatos guardam apenas os ids. Os ids são hashes estáveis (FNV-64) dos nomes (o pod usa o uid), então não duplicam entre reinícios.
- As dimensões são gravadas de novo a cada dia em que o item aparece: cada dia do storage é completo sozinho, e a retenção apaga dias inteiros sem deixar pod sem nome.
- Horários em UTC. CPU em milicores, memória/disco em bytes. Request/limit nulo = não definido no pod.
- **Gravação:** as linhas ficam num buffer em memória e a cada `FLUSH_INTERVAL` (60s) viram um arquivo por tabela. O arquivo é gravado primeiro no emptyDir `/data` (spool) e depois sobe; com o storage fora do ar, os arquivos esperam no spool (inclusive se o container reiniciar) e sobem em ordem quando ele voltar.
- **Compactação** (a cada `MAINTENANCE_INTERVAL`, 10 min): a hora fechada vira um arquivo só (`hh=HH/c<stamp>.parquet`) e, nas tabelas que não são de logs, o dia fechado também (`dt=AAAA-MM-DD/c<stamp>.parquet`). O compactado substitui os arquivos com stamp menor ou igual, então quem lê nunca vê uma linha duas vezes, nem enquanto os antigos não foram apagados (eles saem na execução seguinte).
- **Retenção:** o próprio agente apaga os dias mais antigos que `retentionDays` (30). O `clean_logs.py` do Nanobot não mexe no storage.
- Senhas e chaves nunca aparecem nos logs do agente (o agente mascara antes de escrever).

Consulta direta com o DuckDB:

```sql
INSTALL httpfs;
CREATE SECRET (TYPE s3, KEY_ID '...', SECRET '...', REGION 'us-east-1', SCOPE 's3://meu-bucket');

-- últimas horas do dia de hoje (para períodos maiores, inclua os outros dias)
SELECT w.name, avg(s.cpu_pct_request) AS cpu_pct, max(s.mem_pct_limit) AS mem_pct_limit
FROM read_parquet('s3://meu-bucket/nanobot-k8s/prod1/pod_samples/dt=2026-10-20/**/*.parquet') s
JOIN (SELECT DISTINCT id, name FROM read_parquet('s3://meu-bucket/nanobot-k8s/prod1/workloads/dt=2026-10-20/**/*.parquet')) w
  ON w.id = s.workload_id
WHERE s.ts >= now()::TIMESTAMP - INTERVAL 1 HOUR
GROUP BY w.name ORDER BY cpu_pct DESC;
```

Lendo a pasta inteira assim, uma hora em compactação pode aparecer em dobro por alguns minutos (o compactado e os arquivos que ele substituiu); o Nanobot escolhe os arquivos certos (as regras estão em [layout.go](layout.go)).

## Credenciais do storage

O Secret tem um `credentials.json`. O **mesmo formato** é cadastrado no Nanobot (Admin > Kubernetes Clusters):

```json
{
  "type": "s3",
  "key_id": "AKIA...",
  "secret": "...",
  "region": "us-east-1",
  "endpoint": "",
  "url_style": "",
  "use_ssl": true
}
```

| type | Uso |
|---|---|
| `s3` | AWS S3. MinIO/Ceph/SeaweedFS: `endpoint` (ex.: `minio.local:9000`), `url_style: "path"` e, sem TLS, `use_ssl: false` |
| `gcs` | Google Cloud Storage com **chave HMAC** (Cloud Storage > Settings > Interoperability), pela API S3 do GCS. O JSON de service account não é aceito. `storage.path` com `gs://` |
| `r2` | Cloudflare R2: `account_id`, `key_id` e `secret`. `storage.path` com `r2://` |

**Permissões no bucket:** o agente precisa listar, ler, gravar e apagar objetos no prefixo do `storage.path` (ele mesmo compacta e aplica a retenção). Para o Nanobot basta listar e ler: pode ser outra chave, só de leitura.

## Instalação (helm, a partir do repositório git)

A imagem está publicada em [`amopromo/nanobot-k8s-agent`](https://hub.docker.com/r/amopromo/nanobot-k8s-agent) (tag `latest`, linux/amd64), já configurada no `values.yaml` do chart. A partir do chart 0.3.0 (Parquet direto) a imagem precisa ser a nova: veja [Build da imagem](#build-da-imagem).

### 1. Credenciais

Crie o `credentials.json` (seção [Credenciais](#credenciais-do-storage)) e o Secret, fora do values para as chaves não irem parar no histórico do helm:

```bash
kubectl create namespace nanobot
kubectl -n nanobot create secret generic nanobot-k8s-credentials --from-file=credentials.json=./credentials.json
```

### 2. Instalar o chart

O chart é publicado neste repositório (público) como repositório helm, servido pelo GitHub: não precisa de plugin nem de acesso ao GitHub.

```bash
helm repo add nanobot https://raw.githubusercontent.com/amopromo/nanobot-agent/main/charts
helm repo update nanobot

helm upgrade --install nanobot-k8s nanobot/nanobot-k8s-monitoring -n nanobot \
  --set clusterName=prod1 \
  --set storage.path=s3://meu-bucket/nanobot-k8s \
  --set credentials.existingSecret=nanobot-k8s-credentials
```

- O Nanobot gera esses comandos já preenchidos: **Admin > Kubernetes Clusters > Agent Install** (provedor, endpoint, chaves e opções do agente).
- Atualizações: `helm repo update nanobot` e o mesmo `helm upgrade --install`. Versão fixa do chart: `--version 0.3.1`.
- Sem o repositório helm: `helm upgrade --install nanobot-k8s https://raw.githubusercontent.com/amopromo/nanobot-agent/main/charts/nanobot-k8s-monitoring-0.3.1.tgz ...` ou, com o repositório clonado, `kubernetes/helm/nanobot-k8s-monitoring`.

Com vários clusters, guarde um arquivo de values por cluster (ex.: `values-prod1.yaml` com `clusterName`, `storage.path` e `logs.excludeNamespaces`) e use `-f values-prod1.yaml`.

### 3. Conferir

```bash
kubectl -n nanobot get pods
kubectl -n nanobot logs -l app.kubernetes.io/instance=nanobot-k8s --tail=50   # "agente iniciado"; erros de storage aparecem aqui
```

Em até 2 minutos os arquivos aparecem em `<storage.path>/<clusterName>/`. No Nanobot, cadastre o cluster em **Admin > Kubernetes Clusters** com o mesmo nome, caminho e provedor do storage, e use o botão de teste (ícone de tomada).

### Desinstalar

```bash
helm -n nanobot uninstall nanobot-k8s   # os dados continuam no storage (sem o agente, a retenção para)
```

### Opções do chart

Sem `credentials.existingSecret`, o chart cria o Secret (`templates/secret.yaml`) com `credentials.json` do values. As demais opções (`templates/configmap.yaml`) estão em [values.yaml](helm/nanobot-k8s-monitoring/values.yaml):

| Valor | Padrão | Descrição |
|---|---|---|
| `clusterName` | (obrigatório) | Pasta do cluster no storage; o mesmo nome do cadastro no Nanobot |
| `storage.path` | (obrigatório) | `s3://bucket/prefixo` (ou `gs://`, `r2://`), compartilhado entre os clusters |
| `collection.sampleInterval` | `60s` | Coleta de uso/status |
| `collection.flushInterval` | `60s` | Gravação no storage (atraso máximo dos dados no Nanobot) |
| `collection.maintenanceInterval` | `10m` | Compactação das horas/dias fechados e retenção |
| `retentionDays` | `30` | Dias guardados no storage; os mais antigos são apagados (`0`: não apaga) |
| `logs.enabled` | `true` | Coleta de logs |
| `excludeNamespaces` | `[kube-system, kube-public, kube-node-lease]` | Namespaces ignorados (pods, workloads e logs); continuam nos totais dos nós. `[]` coleta todos |
| `logs.namespaces` / `logs.excludeNamespaces` | `[]` | Namespaces com/sem coleta de logs |
| `logs.maxLineBytes` | `16384` | Linhas maiores são cortadas |
| `bufferSizeLimit` | `2Gi` | emptyDir `/data`: spool com o storage fora do ar e área da compactação |
| `resources` | req 50m/64Mi, limit 512Mi | O GC do Go trabalha abaixo de 85% do limit de memória |

RBAC: somente leitura (`get/list/watch` em pods, nós, ReplicaSets, Jobs e CronJobs; `get` em `pods/log` e `nodes/proxy`). Uma réplica só (`strategy: Recreate`): duas gravariam as mesmas janelas.

Cada container com log abre um stream na API: em clusters grandes, limite os namespaces de log (`logs.namespaces`/`logs.excludeNamespaces`).

O `/healthz` (liveness/readiness) responde 503 se a coleta ficar 5 intervalos sem sucesso. Storage fora do ar não derruba o pod (reiniciar não resolve e os dados estão no spool): a resposta mostra `last_flush` e `spool_files`.

**Consumo:** num minikube com ~12 pods, o agente ficou em ~32 MiB de memória (pico de 38 MiB) e menos de 1 milicore de CPU. O que mais cresce com o cluster é o cache de pods e o número de streams de log (um por container).

## Publicar uma versão

1. Suba `version` e `appVersion` em `helm/nanobot-k8s-monitoring/Chart.yaml`.
2. Publique a imagem (abaixo) com a tag nova e `latest`.
3. Gere o pacote e o índice do repositório helm, na raiz do repositório:

```bash
helm package kubernetes/helm/nanobot-k8s-monitoring -d charts
helm repo index charts --url https://raw.githubusercontent.com/amopromo/nanobot-agent/main/charts
```

## Build da imagem

Binário Go estático (sem CGO) numa imagem distroless, rodando como uid 10001:

```bash
docker build -t amopromo/nanobot-k8s-agent:latest kubernetes/
docker push amopromo/nanobot-k8s-agent:latest
# multi-arquitetura (nós ARM):
docker buildx build --platform linux/amd64,linux/arm64 -t amopromo/nanobot-k8s-agent:latest --push kubernetes/
```

Para versionar, publique também uma tag fixa (ex.: `amopromo/nanobot-k8s-agent:0.3.0`) e instale com `--set image.tag=0.3.0 --set image.pullPolicy=IfNotPresent`.

## Desenvolvimento

```bash
cd kubernetes
go test ./...      # spool, compactação, retenção, coleta (clientset fake), transformações do cache, senhas nos logs
# os mesmos testes num bucket de verdade:
TEST_STORAGE=s3://bucket/testes TEST_CREDENTIALS=./credentials.json go test ./...
# 6h de dados sintéticos para testar as telas do Nanobot (DEMO_END=2026-09-10T12:00:00Z gera dados antigos)
DEMO_OUT=s3://bucket/nanobot-k8s DEMO_CLUSTER=demo DEMO_CREDENTIALS=./credentials.json go test -run Demo .
```

Com `STORAGE_PATH` num diretório local (só em desenvolvimento) os arquivos vão para essa pasta. Fora do cluster o agente usa o `~/.kube/config` (cuidado com o contexto atual).
