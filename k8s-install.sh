#!/bin/sh
# Instalação interativa do agente Kubernetes do Nanobot (nanobot-k8s-monitoring).
#
#   curl -fsSL https://raw.githubusercontent.com/amopromo/nanobot-agent/main/k8s-install.sh | sh
#
# Confirma o cluster (contexto do kubectl), pede o provedor do storage (S3, GCS, R2 ou S3 compatível), as credenciais e
# um endpoint custom opcional, cria o Secret com o credentials.json e instala o chart pelo helm.
# As perguntas são lidas do terminal (/dev/tty), então o script funciona pelo pipe do curl.
set -eu

REPO_URL=https://raw.githubusercontent.com/amopromo/nanobot-agent/main/charts
CHART=nanobot/nanobot-k8s-monitoring

if [ -t 1 ]; then
	B=$(printf '\033[1m'); R=$(printf '\033[31m'); G=$(printf '\033[32m'); Y=$(printf '\033[33m'); N=$(printf '\033[0m')
else
	B=; R=; G=; Y=; N=
fi

say() { printf '%s\n' "$*"; }
step() { printf '\n%s==> %s%s\n' "$B" "$*" "$N"; }
warn() { printf '%s%s%s\n' "$Y" "$*" "$N" >&2; }
die() { printf '%serro: %s%s\n' "$R" "$*" "$N" >&2; exit 1; }

# ask VAR "pergunta" [padrão]
ask() {
	_def=${3-}
	if [ -n "$_def" ]; then
		printf '%s [%s]: ' "$2" "$_def" >/dev/tty
	else
		printf '%s: ' "$2" >/dev/tty
	fi
	IFS= read -r _ans </dev/tty || _ans=
	[ -n "$_ans" ] || _ans=$_def
	eval "$1=\$_ans"
}

# ask_req VAR "pergunta" [padrão]: repete até ter resposta
ask_req() {
	while :; do
		ask "$@"
		eval "_v=\$$1"
		[ -n "$_v" ] && return 0
		say "  obrigatório" >/dev/tty
	done
}

# ask_secret VAR "pergunta": sem eco no terminal
ask_secret() {
	while :; do
		printf '%s: ' "$2" >/dev/tty
		stty -echo </dev/tty 2>/dev/null || true
		IFS= read -r _ans </dev/tty || _ans=
		stty echo </dev/tty 2>/dev/null || true
		printf '\n' >/dev/tty
		[ -n "$_ans" ] && break
		say "  obrigatório" >/dev/tty
	done
	eval "$1=\$_ans"
}

# confirm "pergunta" [s|n]: 0 = sim
confirm() {
	_d=${2:-s}
	if [ "$_d" = s ]; then _o="S/n"; else _o="s/N"; fi
	ask _c "$1 ($_o)" ""
	[ -n "$_c" ] || _c=$_d
	case $_c in [sSyY]*) return 0 ;; *) return 1 ;; esac
}

# Escapa para string JSON (aspas e barras)
json_str() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

trap '{ stty echo </dev/tty; } 2>/dev/null || true' EXIT INT TERM

( : </dev/tty ) 2>/dev/null || die "sem terminal para as perguntas (rode num terminal interativo)"
command -v kubectl >/dev/null 2>&1 || die "kubectl não encontrado"
command -v helm >/dev/null 2>&1 || die "helm não encontrado (https://helm.sh/docs/intro/install/)"

say "${B}Nanobot - instalação do agente Kubernetes${N}"

# --- cluster ---------------------------------------------------------------------------------------------------------
step "Cluster"
CTX=$(kubectl config current-context 2>/dev/null || true)
while :; do
	if [ -n "$CTX" ]; then
		SERVER=$(kubectl config view -o jsonpath="{.clusters[?(@.name==\"$(kubectl config view -o jsonpath="{.contexts[?(@.name==\"$CTX\")].context.cluster}")\")].cluster.server}" 2>/dev/null || true)
		say "Contexto: ${B}$CTX${N}"
		[ -z "$SERVER" ] || say "API:      $SERVER"
		if confirm "Instalar neste cluster?" n; then
			break
		fi
	fi
	say "Contextos disponíveis:"
	kubectl config get-contexts -o name | sed 's/^/  /'
	ask_req CTX "Contexto"
	kubectl config get-contexts "$CTX" >/dev/null 2>&1 || { warn "contexto $CTX não existe"; CTX=; }
done
KC="--context=$CTX"
kubectl "$KC" version >/dev/null 2>&1 || kubectl "$KC" get --raw /version >/dev/null 2>&1 ||
	die "não consegui falar com o cluster $CTX (credenciais do kubectl, VPN?)"
say "${G}cluster acessível${N}"

ask_req NS "Namespace do agente" nanobot
ask_req RELEASE "Nome do release helm" nanobot-k8s
ask_req CLUSTER_NAME "Nome do cluster no Nanobot (pasta no storage, igual ao cadastro)" "$(printf '%s' "$CTX" | sed 's/.*[/_]//')"

# --- storage ---------------------------------------------------------------------------------------------------------
step "Storage"
say "Provedor:"
say "  1) AWS S3"
say "  2) Google Cloud Storage (chave HMAC)"
say "  3) Cloudflare R2"
say "  4) S3 compatível (MinIO, Ceph, SeaweedFS...)"
while :; do
	ask PROV "Opção" 1
	case $PROV in
		1) TYPE=s3; SCHEME=s3; break ;;
		2) TYPE=gcs; SCHEME=gs; break ;;
		3) TYPE=r2; SCHEME=r2; break ;;
		4) TYPE=s3; SCHEME=s3; break ;;
	esac
	say "  opção inválida"
done

REGION=; ACCOUNT_ID=; ENDPOINT=; URL_STYLE=; USE_SSL=
case $PROV in
	1) ask_req REGION "Região" us-east-1 ;;
	2) say "Chave HMAC: Cloud Storage > Settings > Interoperability (o JSON de service account não é aceito)" ;;
	3) ask_req ACCOUNT_ID "Account ID da Cloudflare" ;;
esac

if [ "$PROV" = 4 ]; then
	ask_req ENDPOINT "Endpoint (ex.: minio.local:9000 ou http://minio.local:9000)"
	ask REGION "Região" us-east-1
	ask URL_STYLE "Estilo de URL (path ou vhost)" path
elif confirm "Usar um endpoint custom (proxy, VPC endpoint, jurisdição do R2...)?" n; then
	ask_req ENDPOINT "Endpoint (host[:porta], com http:// para sem TLS)"
	ask URL_STYLE "Estilo de URL (path, vhost ou vazio = automático)" ""
fi
if [ -n "$ENDPOINT" ]; then
	case $ENDPOINT in
		http://*) USE_SSL=false ;;
		https://*) USE_SSL=true ;;
		*) if confirm "Endpoint com TLS (https)?" s; then USE_SSL=true; else USE_SSL=false; fi ;;
	esac
fi

ask_req BUCKET "Bucket"
BUCKET=${BUCKET#*://}
BUCKET=${BUCKET%/}
ask PREFIX "Prefixo no bucket (compartilhado entre os clusters)" nanobot-k8s
PREFIX=$(printf '%s' "$PREFIX" | sed 's#^/*##; s#/*$##')
STORAGE_PATH="$SCHEME://$BUCKET${PREFIX:+/$PREFIX}"

say "O agente precisa listar, ler, gravar e apagar objetos em $STORAGE_PATH."
ask_req KEY_ID "Access key ID"
ask_secret SECRET "Secret access key"

step "Criptografia dos arquivos"
ENC_KEY=
if confirm "Criptografar os arquivos no storage (AES-256-GCM, recomendado)?" s; then
	ask ENC_KEY "Chave em base64 (vazio = gerar uma nova)" ""
	if [ -z "$ENC_KEY" ]; then
		if command -v openssl >/dev/null 2>&1; then
			ENC_KEY=$(openssl rand -base64 32)
		else
			ENC_KEY=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
		fi
		GENERATED=1
	fi
fi

# --- resumo ----------------------------------------------------------------------------------------------------------
step "Resumo"
say "Contexto:   $CTX"
say "Namespace:  $NS"
say "Release:    $RELEASE"
say "Cluster:    $CLUSTER_NAME"
say "Storage:    $STORAGE_PATH ($TYPE)"
[ -z "$REGION" ] || say "Região:     $REGION"
[ -z "$ACCOUNT_ID" ] || say "Account ID: $ACCOUNT_ID"
[ -z "$ENDPOINT" ] || say "Endpoint:   $ENDPOINT${URL_STYLE:+ ($URL_STYLE)}"
say "Key ID:     $KEY_ID"
if [ -n "$ENC_KEY" ]; then say "Criptografia: sim"; else say "Criptografia: não"; fi
confirm "Continuar com a instalação?" s || die "cancelado"

# --- secret ----------------------------------------------------------------------------------------------------------
SECRET_NAME="$RELEASE-credentials"
CREDS=$(
	printf '{\n  "type": "%s",\n  "key_id": "%s",\n  "secret": "%s"' "$TYPE" "$(json_str "$KEY_ID")" "$(json_str "$SECRET")"
	[ -z "$REGION" ] || printf ',\n  "region": "%s"' "$(json_str "$REGION")"
	[ -z "$ACCOUNT_ID" ] || printf ',\n  "account_id": "%s"' "$(json_str "$ACCOUNT_ID")"
	[ -z "$ENDPOINT" ] || printf ',\n  "endpoint": "%s"' "$(json_str "$ENDPOINT")"
	[ -z "$URL_STYLE" ] || printf ',\n  "url_style": "%s"' "$(json_str "$URL_STYLE")"
	[ -z "$USE_SSL" ] || printf ',\n  "use_ssl": %s' "$USE_SSL"
	[ -z "$ENC_KEY" ] || printf ',\n  "encryption_key": "%s"' "$(json_str "$ENC_KEY")"
	printf '\n}\n'
)

step "Namespace e Secret"
kubectl "$KC" get namespace "$NS" >/dev/null 2>&1 || kubectl "$KC" create namespace "$NS"
WRITE_SECRET=1
if kubectl "$KC" -n "$NS" get secret "$SECRET_NAME" >/dev/null 2>&1; then
	confirm "O Secret $SECRET_NAME já existe. Substituir pelas credenciais novas?" s || WRITE_SECRET=
fi
if [ -n "$WRITE_SECRET" ]; then
	# As chaves vão pelo stdin: não aparecem na linha de comando nem num arquivo temporário
	printf '%s' "$CREDS" |
		kubectl "$KC" -n "$NS" create secret generic "$SECRET_NAME" --from-file=credentials.json=/dev/stdin \
			--dry-run=client -o yaml |
		kubectl "$KC" -n "$NS" apply -f - >/dev/null
	say "Secret $SECRET_NAME gravado"
fi
unset SECRET CREDS

# --- helm ------------------------------------------------------------------------------------------------------------
step "Chart"
helm repo add nanobot "$REPO_URL" --force-update >/dev/null
helm repo update nanobot >/dev/null
# --wait: espera o pod ficar pronto (o /healthz responde depois da primeira coleta)
if helm upgrade --install "$RELEASE" "$CHART" --kube-context "$CTX" -n "$NS" --wait --timeout 3m \
	--set-string clusterName="$CLUSTER_NAME" \
	--set-string storage.path="$STORAGE_PATH" \
	--set-string credentials.existingSecret="$SECRET_NAME"; then
	say "${G}agente rodando${N}"
else
	warn "o pod não ficou pronto em 3 min; veja os logs abaixo"
fi
kubectl "$KC" -n "$NS" logs -l "app.kubernetes.io/instance=$RELEASE" --tail=20 2>/dev/null || true

step "Próximos passos"
say "No Nanobot, cadastre o cluster em Admin > Kubernetes Clusters com:"
say "  nome:     $CLUSTER_NAME"
say "  caminho:  $STORAGE_PATH"
say "  provedor: $TYPE${ENDPOINT:+, endpoint $ENDPOINT}"
if [ -n "$ENC_KEY" ]; then
	say "  encryption_key: $ENC_KEY"
	[ -z "${GENERATED-}" ] || warn "Guarde uma cópia desta chave: sem ela os dados não podem ser lidos."
fi
say "Em até 2 minutos os arquivos aparecem em $STORAGE_PATH/$CLUSTER_NAME/."
say "Logs: kubectl --context=$CTX -n $NS logs -l app.kubernetes.io/instance=$RELEASE --tail=50"
