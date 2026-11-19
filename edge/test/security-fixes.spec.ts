import { describe, it, expect, vi } from 'vitest';
import { app } from '../src/index';
import { createMockEnv } from './mocks';

describe('Security & Multi-Tenant Fixes (Issue #1)', () => {
  describe('VULN-01: BOLA Prevention (Broken Object Level Authorization)', () => {
    const setupTenantAuth = async () => {
      const { env, mockD1, mockQueue } = createMockEnv({
        NOTIFY_REQUIRE_AUTH: true,
        NOTIFY_API_KEY: 'master-secret-key-999',
      });

      const tenantKey = 'tenant-api-key-alpha';
      const encoder = new TextEncoder();
      const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(tenantKey));
      const keyHash = Array.from(new Uint8Array(hashBuffer))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');

      mockD1.accounts.set('acc-alpha-id', {
        id: 'acc-alpha-id',
        slug: 'tenant-alpha',
        name: 'Tenant Alpha Inc',
        is_active: 1,
      });

      mockD1.api_keys.set(keyHash, {
        id: 'key-alpha-1',
        account_id: 'acc-alpha-id',
        account_slug: 'tenant-alpha',
        key_hash: keyHash,
        name: 'Alpha Production Key',
        is_active: 1,
      });

      return { env, tenantKey, mockD1, mockQueue };
    };

    it('allows tenant to dispatch notifications for their own slug', async () => {
      const { env, tenantKey, mockQueue } = await setupTenantAuth();

      const res = await app.request('/v1/send', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantKey}`,
          'X-Account-Slug': 'tenant-alpha',
        },
        body: JSON.stringify({
          email: 'user@alpha.com',
          content: 'Notificação legítima da conta Alpha',
          enqueue: true,
        }),
      }, env);

      expect(res.status).toBe(202);
      expect(mockQueue.sent).toHaveLength(1);
      expect(mockQueue.sent[0].account_slug).toBe('tenant-alpha');
    });

    it('automatically defaults to authorized tenant slug when header is omitted', async () => {
      const { env, tenantKey, mockQueue } = await setupTenantAuth();

      const res = await app.request('/v1/send', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantKey}`,
        },
        body: JSON.stringify({
          email: 'user@alpha.com',
          content: 'Notificação sem slug explícito',
          enqueue: true,
        }),
      }, env);

      expect(res.status).toBe(202);
      expect(mockQueue.sent).toHaveLength(1);
      expect(mockQueue.sent[0].account_slug).toBe('tenant-alpha');
    });

    it('blocks tenant from spoofing another account slug via X-Account-Slug (BOLA Mitigated)', async () => {
      const { env, tenantKey, mockQueue } = await setupTenantAuth();

      const res = await app.request('/v1/send', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantKey}`,
          'X-Account-Slug': 'malicious-victim-slug',
        },
        body: JSON.stringify({
          email: 'victim@victim.com',
          content: 'Tentativa de spoofing',
          enqueue: true,
        }),
      }, env);

      expect(res.status).toBe(403);
      const body = (await res.json()) as { error: string };
      expect(body.error).toContain('BOLA blocked');
      expect(mockQueue.sent).toHaveLength(0);
    });

    it('blocks tenant from spoofing another account slug via body.account_id', async () => {
      const { env, tenantKey, mockQueue } = await setupTenantAuth();

      const res = await app.request('/v1/send', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantKey}`,
        },
        body: JSON.stringify({
          email: 'victim@victim.com',
          content: 'Tentativa de spoofing via body',
          account_id: 'malicious-victim-slug',
          enqueue: true,
        }),
      }, env);

      expect(res.status).toBe(403);
      const body = (await res.json()) as { error: string };
      expect(body.error).toContain('BOLA blocked');
      expect(mockQueue.sent).toHaveLength(0);
    });

    it('allows master API key (NOTIFY_API_KEY) to dispatch for any account slug', async () => {
      const { env, mockQueue } = await setupTenantAuth();

      const res = await app.request('/v1/send', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer master-secret-key-999',
          'X-Account-Slug': 'custom-managed-tenant',
        },
        body: JSON.stringify({
          email: 'admin@system.com',
          content: 'Disparo via master key',
          enqueue: true,
        }),
      }, env);

      expect(res.status).toBe(202);
      expect(mockQueue.sent).toHaveLength(1);
      expect(mockQueue.sent[0].account_slug).toBe('custom-managed-tenant');
    });
  });

  describe('VULN-02: Atomic Idempotency Key Reservation', () => {
    it('blocks concurrent duplicate requests while in_progress (409 Conflict)', async () => {
      const { env, mockD1 } = createMockEnv();

      // Pre-populate an in_progress key simulating a concurrent request in flight
      mockD1.idempotency_keys.set('atomic-concurrent-key:default', {
        key: 'atomic-concurrent-key',
        account_slug: 'default',
        response_json: '{"status":"in_progress"}',
        caller: null,
        created_at: new Date().toISOString(),
        expires_at: null,
      });

      const res = await app.request('/v1/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          channel: 'whatsapp',
          recipient: '5543996648750',
          content: 'Mensagem com chave em progresso',
          idempotency_key: 'atomic-concurrent-key',
        }),
      }, env);

      expect(res.status).toBe(409);
      expect(res.headers.get('X-Idempotent-In-Progress')).toBe('true');
      const body = (await res.json()) as { error: string; status: string };
      expect(body.status).toBe('in_progress');
      expect(body.error).toContain('already in progress');
    });

    it('cleans up in_progress reservation if dispatch fails so client can retry', async () => {
      const { env, mockD1 } = createMockEnv();

      // Simulate WhatsApp provider failing
      vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        text: async () => 'Provider Down',
      }));

      const res = await app.request('/v1/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          channel: 'whatsapp',
          recipient: '5543996648750',
          content: 'Mensagem com falha',
          idempotency_key: 'retryable-failed-key',
          run_sync: true,
        }),
      }, env);

      expect(res.status).toBe(503);
      // Ensure the in_progress key was deleted
      expect(mockD1.idempotency_keys.has('retryable-failed-key:default')).toBe(false);
    });
  });

  describe('VULN-03: Timing-Safe Admin Authentication', () => {
    it('allows valid adminSecret with timing-safe comparison', async () => {
      const { env } = createMockEnv({
        NOTIFY_API_KEY: 'super-admin-secret-key-12345',
      });

      const res = await app.request('/v1/admin/status', {
        method: 'GET',
        headers: {
          Authorization: 'Bearer super-admin-secret-key-12345',
        },
      }, env);

      expect(res.status).toBe(200);
      const data = (await res.json()) as { ok: boolean; service: string };
      expect(data.ok).toBe(true);
      expect(data.service).toBe('notify-edge-admin');
    });

    it('rejects invalid adminSecret with 403', async () => {
      const { env } = createMockEnv({
        NOTIFY_API_KEY: 'super-admin-secret-key-12345',
      });

      const res = await app.request('/v1/admin/status', {
        method: 'GET',
        headers: {
          Authorization: 'Bearer wrong-secret-token',
        },
      }, env);

      expect(res.status).toBe(403);
    });
  });

  describe('DES-01: Dynamic WhatsApp Instance Resolution', () => {
    it('uses custom instance passed in payload', async () => {
      const { env } = createMockEnv({
        EVOLUTION_URL: 'https://evolution.mock',
        WHATSAPP_TEST_DRIVER: 'evolution-v2',
      });
      const mockFetch = vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ ok: true, id: 'wa-123' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      );
      vi.stubGlobal('fetch', mockFetch);

      const res = await app.request('/v1/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          channel: 'whatsapp',
          recipient: '5543996648750',
          content: 'Mensagem com instancia dedicada',
          instance: 'supletivo-live-go',
          run_sync: true,
        }),
      }, env);

      expect(res.status).toBe(200);
      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [url] = mockFetch.mock.calls[0];
      // In evolution-v2 test driver, url includes instance name
      expect(url).toContain('/message/sendText/supletivo-live-go');
    });

    it('resolves configured instance from whatsapp_numbers table', async () => {
      const { env, mockD1 } = createMockEnv({
        EVOLUTION_URL: 'https://evolution.mock',
        WHATSAPP_TEST_DRIVER: 'evolution-v2',
      });
      const mockFetch = vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ ok: true, id: 'wa-456' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      );
      vi.stubGlobal('fetch', mockFetch);

      mockD1.whatsapp_numbers.set('wn-1', {
        id: 'wn-1',
        account_id: 'supletivo',
        account_slug: 'supletivo',
        instance_name: 'instancia-supletivo-d1',
        is_default: 1,
      });

      const res = await app.request('/v1/send', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Account-Slug': 'supletivo',
        },
        body: JSON.stringify({
          channel: 'whatsapp',
          recipient: '5543996648750',
          content: 'Mensagem para tenant com instancia no D1',
          run_sync: true,
        }),
      }, env);

      expect(res.status).toBe(200);
      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [url] = mockFetch.mock.calls[0];
      expect(url).toContain('/message/sendText/instancia-supletivo-d1');
    });
  });

  describe('Admin Endpoints (/v1/admin/*)', () => {
    it('provisions a new tenant via POST /v1/admin/apps', async () => {
      const { env, mockD1 } = createMockEnv({
        NOTIFY_API_KEY: 'admin-master-key',
      });

      const res = await app.request('/v1/admin/apps', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer admin-master-key',
        },
        body: JSON.stringify({
          slug: 'nova-escola-digital',
          name: 'Nova Escola Digital',
          instance_name: 'instancia-escola-go',
          phone_number: '5543988887777',
          webhook_url: 'https://escola.com/webhook',
        }),
      }, env);

      expect(res.status).toBe(201);
      const data = (await res.json()) as any;
      expect(data.ok).toBe(true);
      expect(data.account.slug).toBe('nova-escola-digital');
      expect(data.api_key).toMatch(/^v7m_/);
      expect(data.instance_name).toBe('instancia-escola-go');

      expect(mockD1.accounts.size).toBe(1);
      expect(mockD1.api_keys.size).toBe(1);
      expect(mockD1.whatsapp_numbers.size).toBe(1);
    });

    it('lists registered tenants via GET /v1/admin/apps', async () => {
      const { env, mockD1 } = createMockEnv({
        NOTIFY_API_KEY: 'admin-master-key',
      });

      mockD1.accounts.set('acc-1', {
        id: 'acc-1',
        slug: 'supletivo-online',
        name: 'Supletivo Online',
        is_active: 1,
        created_at: new Date().toISOString(),
      });

      const res = await app.request('/v1/admin/apps', {
        method: 'GET',
        headers: {
          Authorization: 'Bearer admin-master-key',
        },
      }, env);

      expect(res.status).toBe(200);
      const data = (await res.json()) as any;
      expect(data.ok).toBe(true);
      expect(data.apps).toHaveLength(1);
      expect(data.apps[0].slug).toBe('supletivo-online');
    });
  });
});
