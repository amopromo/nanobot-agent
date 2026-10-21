# nanobot-agent (servidores)

Agente do Nanobot para servidores Linux e Windows: expõe as métricas do servidor (CPU, load, memória, disco) em HTTPS
na porta 9101, tem um servidor SSH interno (porta 4433) para o Nanobot executar as tasks e se registra sozinho no
Nanobot na instalação.

## Instalação

O Nanobot gera o comando pronto em **Servers > Agent Install** (nome do servidor, sistema, portas, scripts de falha e
recuperação, variáveis). Ele baixa o binário deste repositório e registra o servidor:

```bash
curl -fL -o agent https://raw.githubusercontent.com/amopromo/nanobot-agent/main/server/bin/agent_linux_x64 && \
chmod +x agent && \
sudo ./agent -install -server="https://nanobot.exemplo.com/tasks/api/register/" -reg-key="SUA_API_KEY" \
  -apikey="CHAVE_DO_AGENTE" -server-name="servidor-app-01"
```

| Binário | Sistema |
|---|---|
| [`bin/agent_linux_x64`](bin/agent_linux_x64) | Linux x86-64 |
| [`bin/agent_linux_arm64`](bin/agent_linux_arm64) | Linux ARM64 |
| [`bin/agent_win64.exe`](bin/agent_win64.exe) | Windows x64 (terminal como Administrador) |

Os hashes estão em [`bin/SHA256SUMS`](bin/SHA256SUMS) (`sha256sum -c SHA256SUMS`).

**Atualizar** (mantém a configuração): baixe o binário novo e rode `sudo ./agent -update`.

O `-install` grava o binário em `/opt/nanobot-agent/` e cria o serviço. A API key do agente fica no arquivo `apikey`
ao lado do binário (permissão 0600; no Windows só SYSTEM e Administradores), para não aparecer na linha de comando
do processo (`ps`). O `-update` move a chave de instalações antigas (que passavam `-apikey` no serviço) para ele.

## Opções

| Opção | Padrão | Descrição |
|---|---|---|
| `-install` / `-update` / `-start` | | Instala e registra / troca o binário / roda o agente (o serviço usa `-start`) |
| `-server` | | URL de registro do Nanobot (`https://<nanobot>/tasks/api/register/`) |
| `-reg-key` | | API key do usuário do Nanobot usada no registro |
| `-apikey` | | API key que o Nanobot vai usar para ler as métricas deste agente |
| `-server-name` | hostname | Nome do servidor no Nanobot |
| `-port` | `9101` | Porta HTTPS das métricas |
| `-ssh-port` | `4433` | Porta do SSH interno |
| `-disable-ssh` | | Desliga o SSH interno |
| `-frequency` | `5` | Frequência do monitoramento no Nanobot, em minutos |
| `-fail-scripts` / `-recovery-scripts` | | IDs dos scripts de falha/recuperação, separados por vírgula |
| `-public-ip` | | IP público a registrar (servidor atrás de NAT) |
| `-var` | | Variável do servidor no Nanobot (`NOME=valor`, pode repetir) |

Métricas, para conferir:

```bash
curl -k https://IP_DO_SERVIDOR:9101/metrics --header 'Authorization: Bearer CHAVE_DO_AGENTE'
```

## Build

Go 1.26 (o `go.mod` fixa o toolchain). Binários estáticos, sem CGO:

```bash
cd server
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/agent_linux_x64 .
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/agent_linux_arm64 .
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/agent_win64.exe .
cd bin && sha256sum agent_* > SHA256SUMS
```
