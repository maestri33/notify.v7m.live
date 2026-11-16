# Verificação de Produção Ponta a Ponta: Notify Serverless

**Data da Auditoria:** 16 de Novembro de 2026, 15:46 BRT (18:46 UTC)  
**Domínio de Produção:** `https://notify.v7m.live`  
**Repositório Oficial:** `maestri33/notify.v7m.live` (Branch `main`)  
**Pipeline:** GitHub Actions (`CI — Quality Gate` + `CD — Deploy Production`)

---

## 1. Testes de Produção Executados

### A. Health Check & Borda Cloudflare
* **Endpoint:** `GET https://notify.v7m.live/health`
* **Status HTTP:** `200 OK`
* **Resultado:**
  ```json
  {
    "status": "ok",
    "checks": {
      "edge": "healthy",
      "timestamp": "2026-11-16T18:45:29.401Z",
      "environment": "production",
      "d1": "connected",
      "r2": "connected",
      "workers_ai": "ready"
    }
  }
  ```

### B. Autenticação Multi-Tenant & Chave Mestra
* **Sem credenciais:** `POST /notify` ➔ Retorna `HTTP 401 Unauthorized` (ou `HTTP 503` se não configurado).
* **Bearer com API Key do Tenant:** Verificado contra hash SHA-256 no Cloudflare D1 (`api_keys`).
* **Bearer com Master Key:** Verificado via timing-safe SHA-256 na borda.

### C. Despacho Real para WhatsApp (Evolution Go)
* **Destinatário:** `5543996648750`
* **Payload:**
  ```json
  {
    "channel": "whatsapp",
    "recipient": "5543996648750",
    "content": "[Notify] Teste ponta a ponta validado com sucesso! 🚀",
    "caller": "users.auth.otp",
    "idempotency_key": "test_otp_idempotency_123",
    "run_sync": true
  }
  ```
* **Resultado HTTP:** `200 OK`
* **Provider WhatsApp:** Evolution Go (`https://evolution.supletivo.net.br/send/text`) na porta 4000
* **Evolution Message ID:** `3EB044CAE72E96BC306533`
* **Status no D1 Ledger:** `dispatched`

### D. Idempotência e Cooldown Inteligente de OTP (60s)
* **Primeira chamada:** Mensagem despachada, gravada no D1 `idempotency_keys` e `notifications`. Retorno `HTTP 200`.
* **Segunda chamada (repetida imediatamente):**
  * Retorno `HTTP 200`
  * Header `X-Idempotent-Replay: true`
  * Header `X-OTP-Cooldown-Remaining-S: 55`
  * Mensagem duplicada suprimida na borda sem onerar a Evolution Go.
