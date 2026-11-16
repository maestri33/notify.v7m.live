# 📋 Handoff Técnico — Notify (`notify.v7m.live`)

> **Data de Emissão:** 16 de Novembro de 2026 às 17:15 (Horário de Brasília / UTC-03:00)  
> **Status:** Gateway Serverless Homologado & Auditado em Produção ➔ Pronto para Transição Multi-Tenant  
> **Repositório:** `https://github.com/maestri33/notify.v7m.live` (Branch: `main`)  
> **Target:** Cloudflare Workers Paid ($5/mês) + Cloudflare Pages + Evolution Go  

---

## 🎯 1. Resumo Executivo & Estado Atual

O **Notify** é um microserviço/SaaS de mensageria multi-tenant concebido para operar 100% serverless na borda da Cloudflare. Ele gerencia o ciclo completo de notificações transacionais (WhatsApp via Evolution Go e E-mail nativo via Cloudflare Email Sending), oferecendo idempotência, rate-limiting, cooldown inteligente de OTP e auditoria distribuída com custo de infraestrutura previsível ($5/mês).

### Entregas Concluídas e Homologadas:
1. **CI/CD no GitHub Actions Ativo de Ponta a Ponta**:
   - `ci.yml`: Validação com `npm ci`, checagem estrita de tipos TypeScript (`npx tsc --noEmit`) e suíte de testes Vitest (60/60 testes unitários e de contrato 100% aprovados).
   - `deploy-cloudflare.yml`: Deploy automatizado disparado a cada push na branch `main` via `cloudflare/wrangler-action@v3`.
   - Secrets `CLOUDFLARE_API_TOKEN` e `CLOUDFLARE_ACCOUNT_ID` provisionados e validados no GitHub Actions.
2. **Infraestrutura Cloudflare Provisionada e Conectada**:
   - **Worker (`notify-edge`)**: Ativo e respondendo com HTTP 200 em `https://notify.v7m.live/health`.
   - **Cloudflare D1 (`notify-db`)**: Banco SQLite distribuído (`26eb954c-6172-45a5-8f5a-d1c176b10a35`) saneado com DDL canônica de 9 tabelas (`schema.sql`).
   - **Cloudflare Queues**: `notify-events` e DLQ `notify-events-dlq` vinculadas aos consumers e producers do Worker.
   - **Cloudflare R2**: Bucket neutro `notify-media` provisionado para armazenamento de anexos sem taxa de egress.
3. **Teste Forense em Produção Validado com Sucesso**:
   - Disparo real de WhatsApp via Evolution Go (`https://evolution.supletivo.net.br:4000`) entregue para o número `5543996648750` com confirmação de entrega da rede WhatsApp.
   - Replay de idempotência com a mesma chave testado: mensagem duplicada bloqueada com retorno em cache e cabeçalho `x-otp-cooldown-remaining-s: 55`.
   - Registro de auditoria documentado no repositório em `docs/E2E_PRODUCTION_VERIFICATION.md`.

---

## 🏛️ 2. Arquitetura Alvo & Decisão de Desacoplamento

Conforme alinhamento estratégico e interrogação técnica adversarial, o produto **Notify** é desacoplado em duas camadas independentes:

```
                  ┌─────────────────────────────────────────────────────────┐
                  │                 notify.v7m.live                         │
                  │         Frontend Dashboard (Cloudflare Pages)           │
                  │   Overview · Instâncias · Simulador · Logs · Settings   │
                  └────────────────────────────┬────────────────────────────┘
                                               │ (Consome via REST / CORS)
                                               ▼
                  ┌─────────────────────────────────────────────────────────┐
                  │               api.notify.v7m.live                       │
                  │        Headless API Worker (Cloudflare Workers)         │
                  └──────┬─────────────────────┬────────────────────┬───────┘
                         │                     │                    │
                         ▼                     ▼                    ▼
                 Cloudflare D1          Evolution APIs      Cloudflare Email
            (Accounts, Keys, Logs)   (Instâncias Isoladas)      (Sending)
```

1. **API Headless (`api.notify.v7m.live`)**:
   - Cloudflare Worker (Hono TS).
   - Gerencia autenticação de tenants, CRUD de instâncias de WhatsApp, geração de QR Code, despacho de mensagens e histórico de logs.
2. **Frontend Dashboard (`notify.v7m.live`)**:
   - SPA moderna (Svelte 5 / Vite) hospedada no Cloudflare Pages.
   - Interface operacional para que qualquer plataforma ou cliente gerencie suas credenciais, visualize status de instâncias, escaneie QR Code e teste envios pelo simulador.

---

## 🔍 3. Auditoria Técnica Adversarial (Pontos de Atenção para Próxima Fase)

Durante a auditoria de código de `edge/src/index.ts`, foram identificados pontos que devem ser resolvidos para suportar o modelo multi-tenant completo:

1. **Instância Hardcoded no Código de Despacho**:
   - `edge/src/index.ts` atualmente despacha sempre para a instância `default` (`/message/sendText/default`).
   - **Ação Necessária**: Buscar a instância configurada na tabela `whatsapp_numbers` com base no `account_id` autenticado pela requisição.
2. **Conflito de Domínios**:
   - `edge/wrangler.toml` tem `pattern = "notify.v7m.live", custom_domain = true`.
   - **Ação Necessária**: Migrar a rota do Worker para `api.notify.v7m.live`, liberando o apex `notify.v7m.live` para o Cloudflare Pages (Frontend).
3. **Ausência de Endpoints de Ciclo de Vida de Instâncias**:
   - Não há rotas REST no Worker para criação de instâncias (`POST /v1/instances`), leitura de QR Code (`GET /v1/instances/:id/qrcode`) ou status de conexão.
   - **Ação Necessária**: Implementar os endpoints de proxy/orquestração contra a Evolution API.
4. **Vínculo Estrito de Tenant por Chave de API**:
   - Impedir que clientes adulterem o header `X-Account-Slug`. O `account_id` e `slug` devem ser inferidos exclusivamente pelo hash da chave de API autenticada no D1.

---

## 🗺️ 4. Roteiro de Execução das Próximas Etapas

### Fase 2.1: Especialização da API (`api.notify.v7m.live`)
- [ ] Atualizar `edge/wrangler.toml` adicionando o domínio `api.notify.v7m.live`.
- [ ] Implementar rotas REST de gerenciamento de instâncias:
  - `GET /v1/instances`: Lista instâncias vinculadas à conta do tenant.
  - `POST /v1/instances`: Cria uma nova instância na Evolution API.
  - `GET /v1/instances/:id/qrcode`: Retorna o QR Code em base64 / pairing code para conexão.
  - `GET /v1/instances/:id/status`: Checa o status de conexão (`open`, `connecting`, `close`).
  - `DELETE /v1/instances/:id`: Desconecta e remove a instância.
- [ ] Adequar o handler de envio (`POST /notify` ou `POST /v1/send`) para utilizar dinamicamente a instância da conta solicitante.
- [ ] Criar endpoint de consulta paginada de auditoria (`GET /v1/logs?page=1&limit=20&status=...`) para abastecer o dashboard.

### Fase 2.2: Construção do Frontend Dashboard (`notify.v7m.live`)
- [ ] Estruturar o projeto de Frontend em Svelte 5 + Vite com Tailwind / CSS Tokens.
- [ ] Módulo **Overview**: Status de integridade dos serviços (Edge, D1, Queues, R2, Evolution) e volume diário de disparos.
- [ ] Módulo **WhatsApp Manager**: Cards com status das instâncias, botão para gerar nova instância e modal com renderização do QR Code em tempo real.
- [ ] Módulo **Simulador Interativo**: Formulário rápido para testes de envio (WhatsApp e E-mail) com inspeção ao vivo da resposta JSON.
- [ ] Módulo **Audit Logs**: Tabela de busca de histórico de mensagens com filtro por destinatário, data e status.
- [ ] Módulo **API Keys & Settings**: Geração de tokens de tenant e configuração de webhook de retorno.
- [ ] Configuração do pipeline de deploy do Frontend no Cloudflare Pages.

---

## 🔒 5. Mapa de Recursos e Credenciais de Produção

| Recurso | Identificador / Configuração | Localização |
| :--- | :--- | :--- |
| **Cloudflare Account ID** | `e0814c592e43284a2f6f9984bef32631` | GitHub Actions Secrets / wrangler |
| **Cloudflare D1** | `notify-db` (`26eb954c-6172-45a5-8f5a-d1c176b10a35`) | Cloudflare Edge Binding `env.DB` |
| **Cloudflare R2** | `notify-media` | Cloudflare Edge Binding `env.MEDIA` |
| **Cloudflare Queues** | `notify-events` (DLQ: `notify-events-dlq`) | Cloudflare Edge Binding `env.NOTIFY_QUEUE` |
| **Worker Secrets** | `NOTIFY_API_KEY`, `EVOLUTION_API_KEY` | Cloudflare Worker Secrets (`wrangler secret put`) |
| **Evolution Go (Prod)** | `https://evolution.supletivo.net.br` (Porta 4000) | Azure VM `vm-v7m-core` (Host) |
| **Evolution API (Local)** | `http://localhost:8085` (Porta 8085:8080) | Docker Local (Desenvolvimento/Testes) |
| **Repositório GitHub** | `maestri33/notify.v7m.live` | Branch `main` |
