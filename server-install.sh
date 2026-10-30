#!/bin/sh
# Instalação interativa do agente dos servidores Linux do Nanobot.
#
#   curl -fsSL https://raw.githubusercontent.com/amopromo/nanobot-agent/main/server-install.sh | sh
#
# Baixa o binário da arquitetura da máquina, confere o SHA-256, pergunta as opções e roda o "agent -install" (registro
# no Nanobot e serviço systemd). Com o agente já instalado, oferece o "-update" (troca o binário e mantém a configuração).
# As opções do agente também podem ir na linha de comando e não são perguntadas:
#
#   curl -fsSL .../server-install.sh | sh -s -- -server=https://nanobot.exemplo.com -reg-key=XXX -server-name=app-01
#
# As perguntas são lidas do terminal (/dev/tty), então o script funciona pelo pipe do curl.
set -eu

# NANOBOT_AGENT_BIN_URL: espelho dos binários (mesmos nomes e SHA256SUMS)
BIN_URL=${NANOBOT_AGENT_BIN_URL:-https://raw.githubusercontent.com/amopromo/nanobot-agent/main/server/bin}
INSTALLED=/opt/nanobot-agent/nanobot-agent

if [ -t 1 ]; then
	B=$(printf '\033[1m'); R=$(printf '\033[31m'); G=$(printf '\033[32m'); Y=$(printf '\033[33m'); N=$(printf '\033[0m')
else
	B=; R=; G=; Y=; N=
fi

say() { printf '%s\n' "$*"; }
step() { printf '\n%s==> %s%s\n' "$B" "$*" "$N"; }
warn() { printf '%s%s%s\n' "$Y" "$*" "$N" >&2; }
die() { printf '%serro: %s%s\n' "$R" "$*" "$N" >&2; exit 1; }

tty_ok() { (true </dev/tty) 2>/dev/null; }
need_tty() { tty_ok || die "sem terminal para perguntar $1 (passe a opção na linha de comando)"; }

# ask VAR "pergunta" [padrão]: não pergunta se VAR já veio da linha de comando
ask() {
	eval "_cur=\${$1-}"
	[ -z "$_cur" ] || return 0
	_def=${3-}
	if ! tty_ok; then
		[ -n "$_def" ] || die "sem terminal para perguntar $1 (passe a opção na linha de comando)"
		eval "$1=\$_def"
		return 0
	fi
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
		eval "_v=\${$1-}"
		[ -n "$_v" ] && return 0
		say "  obrigatório" >/dev/tty
	done
}

# ask_int VAR "pergunta" padrão
ask_int() {
	while :; do
		ask "$@"
		eval "_v=\$$1"
		case $_v in '' | *[!0-9]*) ;; *) return 0 ;; esac
		say "  número inválido: $_v" >/dev/tty
		eval "$1="
	done
}

# ask_secret VAR "pergunta": sem eco no terminal
ask_secret() {
	eval "_cur=\${$1-}"
	[ -z "$_cur" ] || return 0
	need_tty "$1"
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

# confirm "pergunta" [s|n]: 0 = sim. Sem terminal, vale o padrão
confirm() {
	_d=${2:-s}
	if tty_ok; then
		if [ "$_d" = s ]; then _o="S/n"; else _o="s/N"; fi
		printf '%s (%s): ' "$1" "$_o" >/dev/tty
		IFS= read -r _c </dev/tty || _c=
	else
		_c=
	fi
	[ -n "$_c" ] || _c=$_d
	case $_c in [sSyY]*) return 0 ;; *) return 1 ;; esac
}

# --- linha de comando (as mesmas opções do agente) -------------------------------------------------------------------
SERVER=; REG_KEY=; APIKEY=; SERVER_NAME=; FREQUENCY=; PORT=; SSH_PORT=; DISABLE_SSH=; PUBLIC_IP=; FAIL_SCRIPTS=
RECOVERY_SCRIPTS=; FINGERPRINT=; VARS=; NVARS=0; YES=
while [ $# -gt 0 ]; do
	_a=${1#-}; _a=${_a#-}
	case $_a in
		*=*) _k=${_a%%=*}; _val=${_a#*=} ;;
		*) _k=$_a; _val= ;;
	esac
	case $_k in
		server) SERVER=$_val ;;
		reg-key) REG_KEY=$_val ;;
		apikey) APIKEY=$_val ;;
		server-name) SERVER_NAME=$_val ;;
		frequency) FREQUENCY=$_val ;;
		port) PORT=$_val ;;
		ssh-port) SSH_PORT=$_val ;;
		disable-ssh) case $_val in '' | true | 1) DISABLE_SSH=s ;; *) DISABLE_SSH=n ;; esac ;;
		public-ip) PUBLIC_IP=$_val ;;
		fail-scripts) FAIL_SCRIPTS=$_val ;;
		recovery-scripts) RECOVERY_SCRIPTS=$_val ;;
		server-fingerprint) FINGERPRINT=$_val ;;
		var) NVARS=$((NVARS + 1)); eval "VAR_$NVARS=\$_val" ;;
		y | yes) YES=1 ;;
		h | help)
			say "uso: server-install.sh [-server=URL] [-reg-key=K] [-apikey=K] [-server-name=N] [-frequency=5] [-port=9101]"
			say "       [-ssh-port=4433 | -disable-ssh] [-public-ip=IP] [-fail-scripts=1,2] [-recovery-scripts=3]"
			say "       [-server-fingerprint=AB:CD:...] [-var=NOME=valor ...] [-y]"
			say "O que não vier na linha de comando é perguntado; -y pula as confirmações."
			exit 0 ;;
		*) die "opção desconhecida: $1" ;;
	esac
	[ -n "$_val" ] || case $_k in disable-ssh | y | yes) ;; *) die "opção sem valor: $1 (use $1=valor)" ;; esac
	shift
done

trap '{ stty echo </dev/tty; } 2>/dev/null || true; [ -z "${TMP-}" ] || rm -rf "$TMP"' EXIT
trap 'exit 130' INT TERM

say "${B}Nanobot - instalação do agente de servidor${N}"

[ "$(uname -s)" = Linux ] || die "este script é para Linux; no Windows use o agent_win64.exe (README do server/)"
case $(uname -m) in
	x86_64 | amd64) BIN=agent_linux_x64 ;;
	aarch64 | arm64) BIN=agent_linux_arm64 ;;
	*) die "arquitetura $(uname -m) sem binário (x86-64 e ARM64)" ;;
esac
command -v systemctl >/dev/null 2>&1 || warn "systemctl não encontrado: o agente instala como serviço systemd"

if [ "$(id -u)" -eq 0 ]; then
	SUDO=
elif command -v sudo >/dev/null 2>&1; then
	SUDO=sudo
else
	die "precisa de root (rode como root ou instale o sudo)"
fi

if command -v curl >/dev/null 2>&1; then
	fetch() { curl -fsSL -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
	fetch() { wget -qO "$2" "$1"; }
else
	die "curl ou wget não encontrado"
fi

# --- download --------------------------------------------------------------------------------------------------------
step "Download ($BIN)"
TMP=$(mktemp -d)
chmod 755 "$TMP"
fetch "$BIN_URL/$BIN" "$TMP/agent" || die "falha ao baixar $BIN_URL/$BIN"
fetch "$BIN_URL/SHA256SUMS" "$TMP/SHA256SUMS" || die "falha ao baixar o SHA256SUMS"
EXPECTED=$(awk -v f="$BIN" '$2 == f || $2 == "*" f { print $1 }' "$TMP/SHA256SUMS")
if command -v sha256sum >/dev/null 2>&1; then
	GOT=$(sha256sum "$TMP/agent" | awk '{ print $1 }')
else
	GOT=$(openssl dgst -sha256 "$TMP/agent" | awk '{ print $NF }')
fi
[ -n "$EXPECTED" ] && [ "$GOT" = "$EXPECTED" ] || die "SHA-256 não confere (esperado $EXPECTED, baixado $GOT)"
chmod 755 "$TMP/agent"
say "${G}SHA-256 confere${N} ($GOT)"

# --- já instalado: update --------------------------------------------------------------------------------------------
if [ -e "$INSTALLED" ] && [ -z "$SERVER" ]; then
	step "Agente já instalado"
	say "Encontrado em $INSTALLED."
	if confirm "Atualizar o binário mantendo a configuração (-update)?" s; then
		(cd "$TMP" && $SUDO ./agent -update)
		say "${G}agente atualizado${N}"
		exit 0
	fi
	confirm "Reinstalar (registra o servidor de novo no Nanobot)?" n || die "cancelado"
fi

# --- opções ----------------------------------------------------------------------------------------------------------
step "Nanobot"
ask_req SERVER "URL do Nanobot (ex.: https://nanobot.exemplo.com)"
case $SERVER in http://* | https://*) ;; *) SERVER="https://$SERVER" ;; esac
case $SERVER in
	*/tasks/api/register/) ;;
	*/tasks/api/register) SERVER="$SERVER/" ;;
	*) SERVER="${SERVER%/}/tasks/api/register/" ;;
esac
ask_secret REG_KEY "API key do seu usuário no Nanobot (registro)"

step "Agente"
if [ -z "$APIKEY" ]; then
	need_tty APIKEY
	printf 'API key do agente, usada pelo Nanobot para ler as métricas [vazio = gerar]: ' >/dev/tty
	stty -echo </dev/tty 2>/dev/null || true
	IFS= read -r APIKEY </dev/tty || APIKEY=
	stty echo </dev/tty 2>/dev/null || true
	printf '\n' >/dev/tty
	if [ -z "$APIKEY" ]; then
		if command -v openssl >/dev/null 2>&1; then
			APIKEY=$(openssl rand -hex 32)
		else
			APIKEY=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
		fi
		say "  gerada (o agente envia ao Nanobot no registro)"
	fi
fi
ask_req SERVER_NAME "Nome do servidor no Nanobot" "$(hostname 2>/dev/null || uname -n)"
ask_int FREQUENCY "Frequência do monitoramento, em minutos" 5
ask_int PORT "Porta HTTPS das métricas" 9101
if [ -z "$DISABLE_SSH" ]; then
	if confirm "Ligar o SSH interno (o Nanobot executa as tasks por ele)?" s; then DISABLE_SSH=n; else DISABLE_SSH=s; fi
fi
if [ "$DISABLE_SSH" = s ]; then SSH_PORT=; else ask_int SSH_PORT "Porta do SSH interno" 4433; fi

if [ -z "$YES" ] && tty_ok && confirm "Configurar opções avançadas (IP público, scripts de falha/recuperação, variáveis)?" n; then
	ask PUBLIC_IP "IP público a registrar (vazio = detectar; servidor atrás de NAT)" ""
	ask FAIL_SCRIPTS "IDs dos scripts de falha, separados por vírgula" ""
	ask RECOVERY_SCRIPTS "IDs dos scripts de recuperação, separados por vírgula" ""
	say "Variáveis do servidor (NOME=valor), uma por linha; vazio termina:"
	while :; do
		_v=; ask _v "  variável" ""
		[ -n "$_v" ] || break
		case $_v in *=*) NVARS=$((NVARS + 1)); eval "VAR_$NVARS=\$_v" ;; *) say "  formato NOME=valor" ;; esac
	done
fi

# --- resumo ----------------------------------------------------------------------------------------------------------
step "Resumo"
say "Registro:   $SERVER"
say "Servidor:   $SERVER_NAME"
say "Frequência: $FREQUENCY min"
say "Métricas:   https, porta $PORT"
if [ "$DISABLE_SSH" = s ]; then say "SSH:        desligado"; else say "SSH:        porta $SSH_PORT"; fi
[ -z "$PUBLIC_IP" ] || say "IP público: $PUBLIC_IP"
[ -z "$FAIL_SCRIPTS" ] || say "Falha:      $FAIL_SCRIPTS"
[ -z "$RECOVERY_SCRIPTS" ] || say "Recuperação: $RECOVERY_SCRIPTS"
_i=1
while [ "$_i" -le "$NVARS" ]; do
	eval "say \"Variável:   \$VAR_$_i\""
	_i=$((_i + 1))
done
[ -n "$YES" ] || confirm "Continuar com a instalação?" s || die "cancelado"

# --- instalação ------------------------------------------------------------------------------------------------------
set -- -install -server="$SERVER" -reg-key="$REG_KEY" -apikey="$APIKEY" -server-name="$SERVER_NAME" \
	-frequency="$FREQUENCY" -port="$PORT"
if [ "$DISABLE_SSH" = s ]; then set -- "$@" -disable-ssh; else set -- "$@" -ssh-port="$SSH_PORT"; fi
[ -z "$PUBLIC_IP" ] || set -- "$@" -public-ip="$PUBLIC_IP"
[ -z "$FAIL_SCRIPTS" ] || set -- "$@" -fail-scripts="$FAIL_SCRIPTS"
[ -z "$RECOVERY_SCRIPTS" ] || set -- "$@" -recovery-scripts="$RECOVERY_SCRIPTS"
[ -z "$FINGERPRINT" ] || set -- "$@" -server-fingerprint="$FINGERPRINT"
_i=1
while [ "$_i" -le "$NVARS" ]; do
	eval "set -- \"\$@\" -var=\"\$VAR_$_i\""
	_i=$((_i + 1))
done

step "Instalação"
# O agente gera os certificados na pasta atual. Com terminal, a pergunta do certificado auto-assinado do Nanobot
# (se houver) é respondida nele
if tty_ok; then
	(cd "$TMP" && $SUDO ./agent "$@" </dev/tty)
else
	(cd "$TMP" && $SUDO ./agent "$@" </dev/null)
fi

step "Pronto"
say "${G}agente instalado e registrado${N}"
say "Serviço: systemctl status nanobot-agent    Logs: journalctl -u nanobot-agent -f"
say "Métricas: curl -k https://<IP>:$PORT/metrics --header \"Authorization: Bearer \$(sudo cat /opt/nanobot-agent/apikey)\""
say "Libere a porta $PORT${SSH_PORT:+ e a $SSH_PORT} no firewall para o Nanobot."
