# 🚀 Notify Gateway (`notify.v7m.live`)

> Gateway de Mensageria Multicanal (WhatsApp e E-mail) **100% Serverless na Cloudflare**, multi-tenant, resiliente e de ultra-baixa latência.

---

## 🏛️ Arquitetura Geral ($5/mês Cloudflare Workers Paid)

O Notify opera inteiramente na borda da Cloudflare, eliminando a necessidade de intermediários pesados como Django, Celery, Redis ou PostgreSQL para o gateway de tráfego:

```
                    SISTEMAS PARCEIROS / APPS / CLIENTES
                                     │
                                     ▼ HTTPS (Bearer <API_KEY_TENANT>)
        ┌────────────────────────────────────────────────────────────┐
        │        CLOUDFLARE WORKER (notify.v7m.live)                 │
        │                                                            │
        │ 1. Valida Hash SHA-256 da API Key no D1 (Tenant Isolation) │
        │ 2. Checa Idempotência / Cooldown de OTP (60s) no D1        │
        │ 3. Despacho Direto Serverless:                             │
        │    - OTP / Sync: Disparo imediato síncrono                 │
        │    - Lote / Async: Publica na Cloudflare Queue             │
        └──────────────┬──────────────────────────────┬──────────────┘
                       │                              │
         Canal WhatsApp│                  Canal E-mail│
                       ▼                              ▼
        ┌────────────────────────────┐ ┌─────────────────────────────┐
        │ EVOLUTION GO (Produção)    │ │ CLOUDFLARE EMAIL SENDING    │
        │ - Host: Porta 4000         │ │ - Envio transacional nativo │
        │ - Rota: /send/text         │ │ - R2 para mídias (notify-   │
        │ (Dev: Evolution Node :8085)│ │   media, zero egress)       │
        └────────────────────────────┘ └─────────────────────────────┘
```

---

## 📱 Provedores de WhatsApp

| Ambiente | Provedor | Endereço | Protocolo / Rotas |
| :--- | :--- | :--- | :--- |
| **PRODUÇÃO** | **Evolution Go** | `https://evolution.supletivo.net.br` (Azure VM `vm-v7m-core`) | `POST /send/text`, `POST /send/media`, `GET /instance/status` |
| **TESTES / DEV** | **Evolution API v2** | `http://localhost:8085` (ou `192.168.80.1:8085`) | `POST /message/sendText/:instance`, Baileys local |

---

## 📡 Endpoints Públicos

* `POST /v1/send` ou `POST /notify`: Envio de mensagens (WhatsApp / E-mail).
* `GET /health`: Sonda de saúde (Edge, D1, R2, AI).
* `GET /media/:key`: Servidor de ativos e mídias no Cloudflare R2 com zero egress cost.
* `POST /mcp`: Servidor Model Context Protocol (JSON-RPC 2.0) para agentes inteligentes (`notify_send`, `notify_status`).
* `GET /reports/delivery-summary`: Relatório agregado de entregas por tenant e canal.

---

## 🏢 Multi-Tenancy e Autenticação

1. Cada plataforma/tenant possui uma ou mais chaves cadastradas na tabela `api_keys` do Cloudflare D1.
2. A requisição envia o cabeçalho `Authorization: Bearer <SUA_CHAVE>`.
3. O Worker computa o hash SHA-256 e valida o tenant de forma timing-safe.
4. Chave mestra global (`NOTIFY_API_KEY`) é suportada para operações de infraestrutura e administração.

---

## 🔄 CI/CD em Produção (GitHub Actions)

* **`.github/workflows/ci.yml`**: Disparado em todo PR e push. Executa `tsc --noEmit` e suíte completa do Vitest.
* **`.github/workflows/deploy.yml`**: Disparado no merge na branch `main`. Realiza o deploy contínuo na Cloudflare via `cloudflare/wrangler-action@v3`.

---

## 🛠️ Desenvolvimento Local

```bash
cd edge
npm ci
npm test             # Executa 60 testes unitários e contratuais via Vitest
npm run typecheck    # Validação de tipos do TypeScript
npm run dev          # Inicia o Wrangler localmente
```
