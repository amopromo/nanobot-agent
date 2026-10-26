# nanobot-k8s-monitoring

Agente em Go que roda dentro do cluster Kubernetes (um pod por cluster) e grava em Parquet no S3, GCS ou R2:

- **logs dos pods**, com o pod, o workload (Deployment, CronJob...) e o namespace de cada linha;
- **uso de CPU e memória dos pods**: valor usado, request e limit, e o percentual do uso sobre o request e sobre o limit (base para os alertas);
- **status dos pods**: fase, pronto ou não, restarts e motivo (CrashLoopBackOff, OOMKilled, ImagePullBackOff...), e se o pod é de um Deployment ou de uma CronJob (base para o alerta de pods caídos);
- **nós**: CPU, memória e disco usados x requeridos x allocatable, quantidade de pods;
- **vulnerabilidades das imagens em uso** (Trivy), quando ligado no cadastro do cluster no Nanobot ([abaixo](#varredura-de-vulnerabilidades)).

Com `encryption_key` nas credenciais, todos os arquivos vão criptografados para o storage ([Criptografia dos arquivos](#criptografia-dos-arquivos)).

O Nanobot lê os arquivos com o DuckDB (menu **Kubernetes**). O mesmo bucket atende vários clusters, cada um na sua pasta. O cluster só precisa alcançar o bucket: não há banco de dados no caminho.

## Como coleta

- Estado do cluster pelos informers (pods, nós, ReplicaSets, Jobs, CronJobs e HorizontalPodAutoscalers), para achar o dono de cada pod: ReplicaSet → **Deployment**, Job → **CronJob** e nó → **StaticPod**. O cache guarda só os campos usados (pods sem env, volumes, anotações etc.; nós sem a lista de imagens) e ReplicaSets, Jobs e CronJobs só com os metadados.
- Eventos `SystemOOM` dos nós (só esses: o watch usa um field selector), para separar a falta de memória no nó da do limit do container. Sem a permissão de ler events (chart anterior), o agente avisa no log e segue.
- Uso de CPU, memória e disco pelo summary do kubelet (`/api/v1/nodes/<nó>/proxy/stats/summary`), sem depender do metrics-server.
- Logs pela API (`kubectl logs -f --timestamps`), um stream por container. Pods de CronJob que duram segundos são lidos até o fim mesmo depois de encerrados.
- Coleta a cada `SAMPLE_INTERVAL` (60s), com o mesmo timestamp para todos os pods (o Nanobot soma por workload). Pod encerrado entra uma vez só.
- **Reativo** (`collection.reactive`, ligado): uma mudança de estado de pod (fase, pronto, restarts, motivo como CrashLoopBackOff/OOMKilled/Unschedulable, nó) ou de HPA (réplicas) recebida pelos informers dispara na hora uma coleta de todos os pods, com o uso de CPU/memória da última coleta completa (o kubelet só é consultado no `SAMPLE_INTERVAL`), e o envio ao storage. Rajadas (um rollout) viram uma coleta só, e há no mínimo `collection.reactiveMinInterval` (10s) entre duas coletas.

## Varredura de vulnerabilidades

Ligada e agendada no Nanobot (Admin > Kubernetes, no cadastro do cluster): o Nanobot grava `<storage.path>/<clusterName>/_config/security.json` (ligado, a cada quantos dias, dia da semana, hora UTC, severidades e o pedido de "Scan now") e o agente lê a cada `security.configInterval` (5 min). O Nanobot não acessa o cluster; o arquivo só liga, desliga e agenda: a imagem do Trivy, os limites e os comandos vêm do chart.

Na hora marcada, o agente roda um ciclo:

1. **Inventário:** lista os pods Running (uma listagem paginada da API, fora do cache dos informers) e agrupa os containers pelo **digest** da imagem (`imageID` do status). Uma imagem usada por vários workloads é varrida uma vez só. No ciclo da agenda, imagens varridas com sucesso há menos de 20h não são varridas de novo (um ciclo interrompido por um restart continua de onde parou); o "Scan now" varre todas.
2. **Varredura:** um **Job por vez** no namespace do agente, preso a um nó onde a imagem já roda (`nodeAffinity` pelo nome do nó, como um DaemonSet). Os containers de init rodam em sequência: o helper (o próprio binário do agente, copiado para o emptyDir), o download do banco do Trivy (uma vez por Job) e **um container por imagem**, que é a própria imagem varrida, pelo digest e com `imagePullPolicy: IfNotPresent`, rodando o Trivy copiado (`trivy rootfs /`). A imagem já está no cache do nó: nada é baixado do registry e não precisa de credencial de registry.
3. **Resultado:** o helper imprime uma linha com o resultado resumido (sem a lista de pacotes) e sai sempre com 0, para não parar as imagens seguintes; o agente lê o log de cada container, grava `image_scans` e `vulnerabilities` e apaga o Job. Entre dois Jobs há uma pausa de `security.jobGap` (30s).

Impacto no cluster:

- Um container de varredura por vez em todo o cluster, com request de 50m/128Mi e limit de 500m/384Mi. Medido com o Trivy 0.75 (0,5 CPU): imagens Python e Node em ~1s com até 96 MiB; uma imagem Java com centenas de `.jar` em ~3s com 192 MiB (128 MiB estoura). Se estourar a memória, a imagem é varrida de novo, sozinha, com `memoryLimitRetry` (768Mi).
- `PriorityClass` `nanobot-k8s-scan` com valor negativo e `preemptionPolicy: Never`: num nó cheio o Job espera (o agente desiste em 10 min) e nunca tira um pod da aplicação do lugar.
- O emptyDir do Job guarda o banco do Trivy (~1,5 GB) e, só se alguma imagem tiver `.jar`, o banco Java (~1,5 GB, baixado na primeira imagem que precisar). Fica no disco do nó só durante o Job.
- Só o scanner de vulnerabilidades (`--scanners vuln`, sem segredos nem configurações), `--parallel 1`, telemetria desligada.
- Os bancos vêm de `mirror.gcr.io` (público, sem autenticação, acessível fora do GCP), com `ghcr.io` como reserva. Sem internet no cluster, aponte `security.dbRepository`/`security.javaDbRepository` para uma cópia num registry interno.

Segurança do Job: sem service account (`automountServiceAccountToken: false`), rootfs só leitura, sem escalada de privilégio, todas as capabilities removidas (o container da imagem varrida fica só com `DAC_READ_SEARCH`, para ler os arquivos de outros usuários dentro da imagem). Roda como root dentro da imagem varrida para ler todos os arquivos: um namespace com Pod Security `restricted` bloqueia o Job (o do agente não pode ter essa política).

Quando a imagem não é varrida:

- O pod saiu do nó e o kubelet já limpou a imagem do cache: o Job precisa baixá-la. Imagens públicas e as baixadas pela credencial do próprio nó (Artifact Registry no GKE, ECR, ACR) funcionam; as que dependem de um `imagePullSecret` do namespace do workload ficam como `skipped` e vão para o próximo ciclo. O mesmo vale para clusters com a feature `KubeletEnsureSecretPulledImages` ligada.
- O nó está cordoned ou não pronto: `skipped`.

O estado do ciclo (último, próximo, andamento, imagens com erro) fica em `_state/security.json`, que o Nanobot mostra em Kubernetes > Security.

RBAC a mais: um `Role` só no namespace do agente para criar, ler e apagar Jobs (ler os pods e os logs já está no ClusterRole). Nenhum acesso a Secrets. Com `security.enabled: false` o agente ignora a configuração e o chart não cria o Role nem a PriorityClass.

## Onde os dados ficam

`<storage.path>/<clusterName>/<tabela>/dt=AAAA-MM-DD/hh=HH/<arquivo>.parquet`, com dia e hora (UTC) do horário das linhas:

| Tabela | Tipo | Colunas |
|---|---|---|
| `clusters` | dimensão | id, name, k8s_version, first_seen |
| `namespaces` | dimensão | id, cluster_id, name, first_seen |
| `workloads` | dimensão | id, cluster_id, namespace_id, kind (Deployment, CronJob, StatefulSet, DaemonSet, Job, StaticPod...), name, first_seen |
| `nodes` | dimensão | id, cluster_id, name, first_seen |
| `pods` | dimensão | id, cluster_id, namespace_id, workload_id, name, uid, owner_kind, created_at, first_seen |
| `pod_samples` | fato | ts, pod_id, workload_id, namespace_id, node_id, phase, ready, restarts, reason, cpu_usage_m, cpu_request_m, cpu_limit_m, mem_usage_bytes, mem_request_bytes, mem_limit_bytes, ephemeral_usage_bytes, cpu_pct_request, cpu_pct_limit, mem_pct_request, mem_pct_limit, message (mensagem do agendador do pod Pending sem nó, ex.: `0/3 nodes are available: 3 Insufficient cpu.`, ou do kubelet no pod despejado, ex.: `The node was low on resource: memory.`), last_termination_reason, last_exit_code, last_terminated_at (o último encerramento de um container do pod: `OOMKilled`, `Error`..., o código de saída, 137 = morto pelo kernel, e o horário; desde a 0.7.0) |
| `hpa_samples` | fato | ts, workload_id, namespace_id, name, min_replicas, max_replicas, current_replicas, desired_replicas |
| `node_samples` | fato | ts, node_id, ready, unschedulable, cpu_*_m, mem_*_bytes, fs_capacity_bytes, fs_used_bytes, ephemeral_*_bytes, pods_count, pods_capacity, memory_pressure (condição MemoryPressure), last_system_oom_at (último evento `SystemOOM` do kubelet: o kernel do nó matou um processo por falta de memória no nó; desde a 0.7.0) |
| `logs` | fato | ts, pod_id, workload_id, namespace_id, container, message |
| `image_workloads` | fato | ts (início do ciclo), digest, image, namespace_id, workload_id, container, pods: quem usava cada imagem no ciclo |
| `image_scans` | fato | ts, cycle_ts, digest, image, node, status (ok, error, oom, timeout, skipped), error, duration_ms, vulns, critical, high, medium, low, os_family, os_name, os_eosl (versão do SO fora de suporte) |
| `vulnerabilities` | fato | ts e digest (os da varredura), vuln_id (CVE/GHSA), severity, score (maior CVSS), title, description, url, pkg, installed, fixed, status, target, pkg_path (arquivo), type (debian, jar, pip...), published |

- Os dados fixos (cluster, namespace, workload, nó, pod) ficam só nas dimensões; os fatos guardam apenas os ids. Os ids são hashes estáveis (FNV-64) dos nomes (o pod usa o uid), então não duplicam entre reinícios.
- As dimensões são gravadas de novo a cada dia em que o item aparece: cada dia do storage é completo sozinho, e a retenção apaga dias inteiros sem deixar pod sem nome.
- Horários em UTC. CPU em milicores, memória/disco em bytes. Request/limit nulo = não definido no pod.
- **Gravação:** as linhas ficam num buffer em memória e a cada `FLUSH_INTERVAL` (60s) viram um arquivo por tabela. O arquivo é gravado primeiro no emptyDir `/data` (spool) e depois sobe; com o storage fora do ar, os arquivos esperam no spool (inclusive se o container reiniciar) e sobem em ordem quando ele voltar.
- **Compactação** (a cada `MAINTENANCE_INTERVAL`, 10 min): a hora fechada vira um arquivo só (`hh=HH/c<stamp>.parquet`) e, nas tabelas que não são de logs, o dia fechado também (`dt=AAAA-MM-DD/c<stamp>.parquet`). O compactado substitui os arquivos com stamp menor ou igual, então quem lê nunca vê uma linha duas vezes, nem enquanto os antigos não foram apagados (eles saem na execução seguinte).
- **Retenção:** por padrão o agente não apaga nada (`retentionDays: 0`); o `clean_logs.py` do Nanobot apaga os dias mais antigos que `--k8s-days` (ou `K8S_RETENTION_DAYS`), e a chave cadastrada no Nanobot precisa poder apagar. Com `retentionDays` maior que 0, o próprio agente apaga.
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
  "use_ssl": true,
  "encryption_key": "base64 de 32 bytes (opcional, agente 0.6.0+)"
}
```

| type | Uso |
|---|---|
| `s3` | AWS S3. MinIO/Ceph/SeaweedFS: `endpoint` (ex.: `minio.local:9000`), `url_style: "path"` e, sem TLS, `use_ssl: false` |
| `gcs` | Google Cloud Storage com **chave HMAC** (Cloud Storage > Settings > Interoperability), pela API S3 do GCS. O JSON de service account não é aceito. `storage.path` com `gs://` |
| `r2` | Cloudflare R2: `account_id`, `key_id` e `secret`. `storage.path` com `r2://` |

**Permissões no bucket:** o agente precisa listar, ler, gravar e apagar objetos no prefixo do `storage.path` (ele mesmo compacta e aplica a retenção). Para o Nanobot basta listar e ler: pode ser outra chave, só de leitura (com a varredura de vulnerabilidades, ele também grava em `_config/`).

### Criptografia dos arquivos

Com `encryption_key` (32 bytes aleatórios em base64, ex.: `openssl rand -base64 32`, ou o botão **Generate** no cadastro do cluster no Nanobot), o agente criptografa **cada arquivo** com AES-256-GCM antes de subir (logs, uso, vulnerabilidades e o estado da varredura) e descriptografa ao baixar (compactação). Quem tem acesso ao bucket sem a chave não lê nada e não consegue alterar um arquivo sem que a leitura falhe (o GCM autentica cada bloco; um arquivo cortado ou com blocos trocados não abre). A configuração da varredura gravada pelo Nanobot também vai criptografada, e o agente recusa uma configuração sem criptografia: com acesso só ao bucket, ninguém liga ou agenda a varredura.

- A mesma chave vai no cadastro do cluster no Nanobot (que guarda as credenciais criptografadas no banco e descriptografa os arquivos num cache local, `K8S_FILE_CACHE_DIR`). O **Agent Install** do Nanobot já inclui a chave no comando.
- **Guarde uma cópia da chave**: sem ela os dados não podem ser lidos.
- Troca de chave: a chave nova em `encryption_key` e a antiga em `previous_encryption_keys` (lista), que só lê os arquivos já gravados (no Nanobot, gravar uma chave nova no cadastro faz isso sozinho).
- Arquivos gravados antes da chave continuam sendo lidos; o `k8s_encrypt_storage.py` do Nanobot criptografa os que ficaram (`--dry-run` lista antes). Os dias novos já saem criptografados.
- Formato (o mesmo do `app/core/k8s_crypto.py` do Nanobot): cabeçalho de 32 bytes (`NBE1`, id da chave, prefixo do nonce, tamanho do bloco) e blocos de 1 MiB com AES-256-GCM; detalhes em [filecrypt.go](filecrypt.go). A criptografia nativa do Parquet não é usada porque a do parquet-go e a do DuckDB não leem os arquivos uma da outra.
- O Parquet aberto só existe no emptyDir `/data` do pod (spool e compactação), dentro do cluster.

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
- Atualizações: `helm repo update nanobot` e o mesmo `helm upgrade --install`. Versão fixa do chart: `--version 0.4.0`. Sem o RBAC de HPA (chart anterior com a imagem nova), o agente avisa no log e segue sem coletar HPAs.
- Sem o repositório helm: `helm upgrade --install nanobot-k8s https://raw.githubusercontent.com/amopromo/nanobot-agent/main/charts/nanobot-k8s-monitoring-0.4.0.tgz ...` ou, com o repositório clonado, `kubernetes/helm/nanobot-k8s-monitoring`.

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
| `collection.reactive` | `true` | Mudança de estado de pod/HPA: coleta e envio na hora |
| `collection.reactiveMinInterval` | `10s` | Intervalo mínimo entre duas coletas reativas |
| `collection.maintenanceInterval` | `10m` | Compactação das horas/dias fechados e retenção |
| `retentionDays` | `0` | `0`: o agente não apaga (a retenção é do `clean_logs.py` do Nanobot). Maior que 0: o agente apaga os dias mais antigos |
| `logs.enabled` | `true` | Coleta de logs |
| `excludeNamespaces` | `[kube-system, kube-public, kube-node-lease]` | Namespaces ignorados (pods, workloads e logs); continuam nos totais dos nós. `[]` coleta todos |
| `logs.namespaces` / `logs.excludeNamespaces` | `[]` | Namespaces com/sem coleta de logs |
| `logs.maxLineBytes` | `16384` | Linhas maiores são cortadas |
| `bufferSizeLimit` | `2Gi` | emptyDir `/data`: spool com o storage fora do ar e área da compactação |
| `resources` | req 50m/64Mi, limit 512Mi | O GC do Go trabalha abaixo de 85% do limit de memória |
| `security.enabled` | `true` | Varredura de vulnerabilidades disponível (quem liga e agenda é o Nanobot). `false`: sem Jobs, sem Role e sem PriorityClass |
| `security.trivyImage` | `aquasec/trivy:0.75.0` | Imagem do Trivy (versão fixa) |
| `security.dbRepository` / `security.javaDbRepository` | (padrão do Trivy) | Repositórios dos bancos (mirror.gcr.io, depois ghcr.io); um registry interno em clusters sem internet |
| `security.imagesPerJob` | `8` | Imagens varridas em sequência por Job (o banco é baixado uma vez por Job) |
| `security.imageTimeout` / `security.jobGap` | `5m` / `30s` | Tempo máximo por imagem e pausa entre dois Jobs |
| `security.resources` | req 50m/128Mi, limit 500m/384Mi | Container de varredura; `memoryLimitRetry` (768Mi) na segunda tentativa |
| `security.workdirSizeLimit` | `4Gi` | emptyDir do Job (bancos do Trivy) |
| `security.priorityClass` | `nanobot-k8s-scan`, `-100` | PriorityClass dos Jobs (`create: false` para usar uma existente) |

RBAC: somente leitura no cluster (`get/list/watch` em pods, nós, events, ReplicaSets, Jobs, CronJobs e HorizontalPodAutoscalers; `get` em `pods/log` e `nodes/proxy`) e, com a varredura, criar/apagar Jobs no namespace do agente. Uma réplica só (`strategy: Recreate`): duas gravariam as mesmas janelas.

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
go test ./...      # spool, compactação, retenção, criptografia, coleta e varredura (clientset fake), transformações do cache, senhas nos logs
# os mesmos testes num bucket de verdade:
TEST_STORAGE=s3://bucket/testes TEST_CREDENTIALS=./credentials.json go test ./...
# 6h de dados sintéticos para testar as telas do Nanobot (DEMO_END=2026-09-10T12:00:00Z gera dados antigos)
DEMO_OUT=s3://bucket/nanobot-k8s DEMO_CLUSTER=demo DEMO_CREDENTIALS=./credentials.json go test -run Demo .
```

Com `STORAGE_PATH` num diretório local (só em desenvolvimento) os arquivos vão para essa pasta. Fora do cluster o agente usa o `~/.kube/config` (cuidado com o contexto atual).
