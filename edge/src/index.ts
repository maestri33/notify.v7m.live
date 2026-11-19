import { Hono, type Context } from 'hono';
import { cors } from 'hono/cors';

export type NotifyQueueMessage = {
  notification_id: string;
  account_slug: string;
  channel: string;
  recipient: string;
  subject?: string;
  payload: Record<string, any>;
  is_otp?: boolean;
  auth_header?: string;
  target_path?: string;
  timestamp: string;
};

export type Env = {
  DB: D1Database;
  MEDIA: R2Bucket;
  AI: any;
  HYPERDRIVE?: any;
  NOTIFY_QUEUE?: Queue<NotifyQueueMessage>;
  ENVIRONMENT: string;
  BACKEND_ORIGIN?: string;
  BACKEND_SERVICE_TOKEN?: string;
  NOTIFY_API_KEY?: string;
  NOTIFY_REQUIRE_AUTH?: string | boolean;
  EVOLUTION_URL?: string;
  EVOLUTION_API_KEY?: string;
  WHATSAPP_TEST_DRIVER?: string;
  EMAIL?: any;
  EMAIL_SENDER?: string;
};

export type Variables = {
  isMasterKey?: boolean;
  accountId?: string;
  accountSlug?: string;
};

export const app = new Hono<{ Bindings: Env; Variables: Variables }>();

app.use('*', cors());

function originPayload(payload: Record<string, any>, targetPath: string, notificationId: string) {
  const result = { ...payload };
  if (targetPath === '/notify') {
    result.options = {
      ...payload.options,
      external_id: payload.options?.external_id || payload.external_id || payload.idempotency_key || notificationId,
    };
  } else {
    result.external_id = payload.external_id || payload.options?.external_id || payload.idempotency_key || notificationId;
  }
  return result;
}

async function timingSafeMatch(a: string, b: string): Promise<boolean> {
  if (!a || !b) return false;
  const encoder = new TextEncoder();
  const [hashA, hashB] = await Promise.all([
    new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(a))),
    new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(b))),
  ]);
  let mismatch = 0;
  for (let i = 0; i < hashA.length; i++) {
    mismatch |= hashA[i] ^ hashB[i];
  }
  return mismatch === 0;
}

async function sha256Hex(text: string): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(hashBuffer)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function authorize(c: Context<{ Bindings: Env; Variables: Variables }>): Promise<Response | null> {
  const env = c.env;
  if (env.NOTIFY_REQUIRE_AUTH === false || env.NOTIFY_REQUIRE_AUTH === 'false') {
    c.set('isMasterKey', true);
    return null;
  }
  if (!env.NOTIFY_API_KEY) {
    return Response.json({ error: 'Notification authentication is not configured' }, { status: 503 });
  }
  const token = c.req.header('Authorization') || '';
  if (!token.startsWith('Bearer ')) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }
  const rawKey = token.replace(/^Bearer\s+/, '').trim();

  // 1. Verificacao da chave mestra global (NOTIFY_API_KEY) via timing-safe SHA-256
  if (await timingSafeMatch(rawKey, env.NOTIFY_API_KEY)) {
    c.set('isMasterKey', true);
    return null;
  }

  // 2. Verificacao Multi-Tenant: autenticacao por API Key individual de cada plataforma no D1
  if (env.DB) {
    try {
      const keyHash = await sha256Hex(rawKey);

      let row: any = null;
      try {
        row = await env.DB.prepare(
          `SELECT k.id, k.account_id, a.slug as account_slug 
           FROM api_keys k 
           JOIN accounts a ON k.account_id = a.id 
           WHERE k.key_hash = ? AND k.is_active = 1 AND a.is_active = 1`
        ).bind(keyHash).first();
      } catch {
        row = null;
      }

      if (!row) {
        row = await env.DB.prepare(
          'SELECT id, account_id FROM api_keys WHERE key_hash = ? AND is_active = 1'
        ).bind(keyHash).first();
      }

      if (row) {
        c.set('isMasterKey', false);
        c.set('accountId', row.account_id);
        c.set('accountSlug', row.account_slug || row.account_id);
        return null;
      }
    } catch {
      // Ignora erro se D1 estiver indisponivel
    }
  }

  return Response.json({ error: 'Unauthorized' }, { status: 401 });
}

for (const path of ['/notify', '/v1/send', '/mcp', '/reports/*']) {
  app.use(path, async (c, next) => {
    if (c.req.method === 'OPTIONS') return next();
    const rejection = await authorize(c);
    return rejection || next();
  });
}

// ── 0.1 Gate de Borda para Rotas Administrativas (/v1/admin/*) ────────────
app.use('/v1/admin/*', async (c, next) => {
  if (c.req.method === 'OPTIONS') return next();
  const cfClientId = c.req.header('CF-Access-Client-Id');
  const cfClientSecret = c.req.header('CF-Access-Client-Secret');
  const authHeader = c.req.header('Authorization') || '';

  // 1. Autorização via Cloudflare Service Token (m2m / Zero Trust)
  if (cfClientId && cfClientSecret) {
    return next();
  }

  // 2. Autorização via Bearer com token master de administração/infraestrutura (timing-safe VULN-03)
  if (authHeader.startsWith('Bearer ')) {
    const rawToken = authHeader.replace(/^Bearer\s+/, '').trim();
    if (c.env.BACKEND_SERVICE_TOKEN && (await timingSafeMatch(rawToken, c.env.BACKEND_SERVICE_TOKEN))) {
      return next();
    }
    if (c.env.NOTIFY_API_KEY && (await timingSafeMatch(rawToken, c.env.NOTIFY_API_KEY))) {
      return next();
    }
  }

  return c.json({ error: 'Acesso restrito ao administrador de infraestrutura.' }, 403);
});

// ── 0.2 Rotas Administrativas (/v1/admin/*) ────────────────────────────────
app.get('/v1/admin/apps', async (c) => {
  if (!c.env.DB) {
    return c.json({ ok: false, error: 'Database not available' }, 503);
  }
  try {
    const { results } = await c.env.DB.prepare(
      `SELECT a.id, a.slug, a.name, a.webhook_url, a.is_active, a.created_at,
              wn.instance_name, wn.phone_number
       FROM accounts a
       LEFT JOIN whatsapp_numbers wn ON wn.account_id = a.id AND wn.is_default = 1
       ORDER BY a.created_at DESC`
    ).all();
    return c.json({ ok: true, apps: results || [] });
  } catch (err: any) {
    return c.json({ ok: false, error: err.message }, 500);
  }
});

app.post('/v1/admin/apps', async (c) => {
  if (!c.env.DB) {
    return c.json({ ok: false, error: 'Database not available' }, 503);
  }
  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ ok: false, error: 'Invalid JSON payload' }, 400);
  }

  const { slug, name, phone_number, instance_name, webhook_url, webhook_secret } = body;
  if (!slug || !name) {
    return c.json({ ok: false, error: 'Missing mandatory fields: slug and name are required' }, 400);
  }

  const accountId = crypto.randomUUID();
  const apiKeyId = crypto.randomUUID();
  const rawApiKey = `v7m_${crypto.randomUUID().replace(/-/g, '')}`;
  const keyHash = await sha256Hex(rawApiKey);

  try {
    await c.env.DB.batch([
      c.env.DB.prepare(
        `INSERT INTO accounts (id, slug, name, webhook_url, webhook_secret, is_active)
         VALUES (?, ?, ?, ?, ?, 1)`
      ).bind(accountId, slug, name, webhook_url || null, webhook_secret || null),
      c.env.DB.prepare(
        `INSERT INTO api_keys (id, account_id, key_hash, name, is_active)
         VALUES (?, ?, ?, ?, 1)`
      ).bind(apiKeyId, accountId, keyHash, `API Key - ${name}`),
      ...(instance_name || phone_number
        ? [
            c.env.DB.prepare(
              `INSERT INTO whatsapp_numbers (id, account_id, instance_name, phone_number, is_default)
               VALUES (?, ?, ?, ?, 1)`
            ).bind(crypto.randomUUID(), accountId, instance_name || 'default', phone_number || null),
          ]
        : []),
    ]);

    return c.json(
      {
        ok: true,
        account: {
          id: accountId,
          slug,
          name,
        },
        api_key: rawApiKey,
        instance_name: instance_name || 'default',
      },
      201
    );
  } catch (err: any) {
    return c.json({ ok: false, error: `Failed to provision app: ${err.message}` }, 500);
  }
});

app.get('/v1/admin/status', async (c) => {
  return c.json({
    ok: true,
    service: 'notify-edge-admin',
    environment: c.env.ENVIRONMENT || 'production',
    timestamp: new Date().toISOString(),
  });
});

// ── 0. Root Service Info ───────────────────────────────────────────────────
app.get('/', (c) => {
  const accept = c.req.header('Accept') || '';
  if (accept.includes('text/html')) {
    return c.redirect('/dashboard/');
  }
  return c.json({
    service: 'notify-edge',
    status: 'ok',
    domain: 'notify.v7m.live',
    endpoints: {
      health: '/health',
      notify: '/notify',
      v1_send: '/v1/send',
      media: '/media/:key',
      mcp: '/mcp',
    },
  });
});

// ── 1. Health Check (Edge + D1 + R2 + AI) ──────────────────────────────────
app.get('/health', async (c) => {
  const checks: Record<string, any> = {
    edge: 'healthy',
    timestamp: new Date().toISOString(),
    environment: c.env.ENVIRONMENT || 'production',
  };

  // D1 Probe
  try {
    const d1Result = await c.env.DB.prepare('SELECT 1 as alive').first();
    checks.d1 = d1Result?.alive === 1 ? 'connected' : 'error';
  } catch (err: any) {
    checks.d1 = `error: ${err.message}`;
  }

  // R2 Probe
  try {
    checks.r2 = c.env.MEDIA ? 'connected' : 'not_bound';
  } catch (err: any) {
    checks.r2 = `error: ${err.message}`;
  }

  // Workers AI Probe
  try {
    checks.workers_ai = c.env.AI ? 'ready' : 'not_bound';
  } catch (err: any) {
    checks.workers_ai = `error: ${err.message}`;
  }

  return c.json({ status: 'ok', checks });
});

// ── 2. R2 Media Object Serving (Zero Egress) ──────────────────────────────
app.get('/media', (c) => c.text('Key required', 400));
app.get('/media/*', async (c) => {
  const key = c.req.path.replace(/^\/media\/?/, '');
  if (!key || key.includes('..') || key.startsWith('/')) {
    return c.text('Key required or invalid', 400);
  }

  if (!c.env.MEDIA) return c.json({ error: 'R2 media bucket not bound' }, 503);
  const object = await c.env.MEDIA.get(key);
  if (!object) {
    return c.text('Object Not Found', 404);
  }

  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set('etag', object.httpEtag);
  headers.set('Cache-Control', 'public, max-age=31536000, immutable');

  return new Response(object.body, { headers });
});

async function resolveWhatsAppInstance(
  env: Env,
  accountIdOrSlug: string,
  requestedInstance?: string
): Promise<string> {
  if (requestedInstance && typeof requestedInstance === 'string' && requestedInstance.trim()) {
    return requestedInstance.trim();
  }
  if (env.DB) {
    try {
      const row: any = await env.DB.prepare(
        `SELECT wn.instance_name 
         FROM whatsapp_numbers wn
         LEFT JOIN accounts a ON wn.account_id = a.id
         WHERE (wn.account_id = ? OR a.slug = ? OR a.id = ?) AND wn.is_default = 1
         LIMIT 1`
      ).bind(accountIdOrSlug, accountIdOrSlug, accountIdOrSlug).first();

      if (row?.instance_name) {
        return row.instance_name;
      }
    } catch {
      // Fallback silencioso
    }
  }
  return 'default';
}

function getEvolutionEndpoint(baseUrl: string, instanceName: string, isV2: boolean): string {
  const base = baseUrl.replace(/\/$/, '');
  return isV2
    ? `${base}/message/sendText/${encodeURIComponent(instanceName)}`
    : `${base}/send/text`;
}

// ── 3. Edge Notification Ingestion (/notify & /v1/send) ───────────────────
const handleSend = async (c: any) => {
  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Invalid JSON payload' }, 400);
  }

  const recipient = body.recipient || body.whatsapp || body.phone || body.email || '';
  const channel = body.channel || (body.whatsapp || body.phone ? 'whatsapp' : body.email ? 'email' : 'all');
  const content = body.content || body.text || '';
  const subject = body.subject || body.options?.subject || '';
  const idempotency_key = body.idempotency_key || body.external_id || body.options?.external_id || null;

  if (!recipient || !content) {
    return c.json({ error: 'Missing mandatory fields: recipient/whatsapp/email and content/text are required' }, 400);
  }
  if (!c.env.BACKEND_ORIGIN && !c.env.EVOLUTION_URL && !c.env.EMAIL) {
    return c.json({ ok: false, status: 'failed', error: 'Notification origin is not configured' }, 503);
  }

  // VULN-01 (BOLA): Prevenção de spoofing de conta por API key individual
  const requestedSlug = c.req.header('X-Account-Slug') || body.account_id || null;
  const isMasterKey = typeof c.get === 'function' ? c.get('isMasterKey') : true;
  const authorizedSlug = typeof c.get === 'function' ? c.get('accountSlug') : undefined;

  let accountSlug = requestedSlug || 'default';
  if (!isMasterKey && authorizedSlug) {
    if (requestedSlug && requestedSlug !== authorizedSlug) {
      return c.json(
        { error: 'Forbidden: You cannot dispatch notifications for another account slug (BOLA blocked)' },
        403
      );
    }
    accountSlug = authorizedSlug;
  }

  const caller = body.caller || body.options?.caller || body.extra?.caller || '';
  const isOtp =
    caller === 'users.auth.otp' ||
    body.is_otp === true ||
    body.options?.is_otp === true ||
    body.extra?.is_otp === true;
  const isSynchronous = isOtp || body.run_sync === true || body.options?.run_sync === true;

  // 1. Verificação e Reserva Atômica de Idempotência no D1 (VULN-02)
  if (idempotency_key && c.env.DB) {
    let reserved = false;
    try {
      const expiresAt = isOtp ? new Date(Date.now() + 60000).toISOString() : null;
      await c.env.DB.prepare(
        `INSERT INTO idempotency_keys (key, account_slug, response_json, caller, created_at, expires_at)
         VALUES (?, ?, '{"status":"in_progress"}', ?, CURRENT_TIMESTAMP, ?)`
      )
        .bind(idempotency_key, accountSlug, caller || null, expiresAt)
        .run();
      reserved = true;
    } catch {
      // Já existe registro ou chave primária duplicada
    }

    if (!reserved) {
      const existing: any = await c.env.DB.prepare(
        'SELECT response_json, created_at, expires_at, caller FROM idempotency_keys WHERE account_slug = ? AND key = ?'
      )
        .bind(accountSlug, idempotency_key)
        .first();

      if (existing) {
        const rawDate = existing.created_at || '';
        const isoDate = rawDate.includes('T') ? rawDate : rawDate.replace(' ', 'T') + 'Z';
        const createdAtMs = new Date(isoDate).getTime();
        const ageMs = Date.now() - createdAtMs;

        if (existing.response_json && existing.response_json.includes('"status":"in_progress"')) {
          if (ageMs < 30000) {
            c.header('X-Idempotent-In-Progress', 'true');
            return c.json({ ok: false, status: 'in_progress', error: 'Duplicate request already in progress' }, 409);
          }
        } else {
          const isExistingOtp = isOtp || existing.caller === 'users.auth.otp';
          if (!isExistingOtp || ageMs < 60000) {
            const cached = JSON.parse(existing.response_json);
            c.header('X-Idempotent-Replay', 'true');
            if (isExistingOtp) {
              c.header('X-OTP-Cooldown-Remaining-S', Math.max(0, Math.ceil((60000 - ageMs) / 1000)).toString());
            }
            return c.json(cached);
          }
        }
      }
    }
  }

  // 2. Registro preliminar na borda (D1)
  const notificationId = crypto.randomUUID();
  const targetPath = c.req?.path?.startsWith('/notify') ? '/notify' : '/v1/send';
  const dispatchPayload = originPayload(body, targetPath, notificationId);

  await c.env.DB.prepare(
    `INSERT INTO notifications (id, account_slug, channel, recipient, subject, status, idempotency_key, payload_json)
     VALUES (?, ?, ?, ?, ?, 'queued', ?, ?)`
  )
    .bind(
      notificationId,
      accountSlug,
      channel,
      recipient,
      subject,
      idempotency_key,
      JSON.stringify(dispatchPayload)
    )
    .run();

  const rejectDispatch = async (error: string, status = 503, details: Record<string, any> = {}) => {
    try {
      if (c.env.DB) {
        await c.env.DB.prepare("UPDATE notifications SET status = 'failed' WHERE id = ?")
          .bind(notificationId).run();
        if (idempotency_key) {
          await c.env.DB.prepare(
            "DELETE FROM idempotency_keys WHERE account_slug = ? AND key = ? AND response_json LIKE '%in_progress%'"
          ).bind(accountSlug, idempotency_key).run();
        }
      }
    } catch {}
    return c.json({ ...details, ok: false, status: details.status || 'failed', error }, status);
  };

  // 3. Encaminhamento assíncrono via Cloudflare Queue ou despacho direto nos canais
  let backendResult: any = { status: 'queued', notification_id: notificationId };
  const shouldEnqueue = !isSynchronous && (body.enqueue === true || body.options?.enqueue === true || body.async === true);

  if (shouldEnqueue && c.env.NOTIFY_QUEUE) {
    try {
      await c.env.NOTIFY_QUEUE.send({
        notification_id: notificationId,
        account_slug: accountSlug,
        channel,
        recipient,
        subject,
        payload: dispatchPayload,
        is_otp: isOtp,
        target_path: targetPath,
        timestamp: new Date().toISOString(),
      });
      backendResult = {
        status: 'queued',
        notification_id: notificationId,
        external_id: notificationId,
        queue: 'notify-events',
      };
    } catch {
      return rejectDispatch('Notification queue is unavailable');
    }
  } else if (channel === 'whatsapp' && c.env.EVOLUTION_URL) {
    // Disparo Direto Serverless na Evolution (Go em Producao / Node v2 em Testes)
    try {
      const isV2 = c.env.WHATSAPP_TEST_DRIVER === 'evolution-v2' || c.env.EVOLUTION_URL.includes(':8085');
      const instanceName = await resolveWhatsAppInstance(
        c.env,
        accountSlug,
        body.instance || body.options?.instance || body.whatsapp_instance
      );
      const evolutionEndpoint = getEvolutionEndpoint(c.env.EVOLUTION_URL, instanceName, isV2);

      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };
      if (c.env.EVOLUTION_API_KEY) {
        headers['apikey'] = c.env.EVOLUTION_API_KEY;
      }

      const resp = await fetch(evolutionEndpoint, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          number: recipient,
          text: content,
        }),
        signal: AbortSignal.timeout(10000),
      });

      if (resp.ok) {
        const evoData: any = await resp.json().catch(() => ({}));
        backendResult = {
          ok: true,
          status: 'sent',
          notification_id: notificationId,
          driver: isV2 ? 'evolution-v2' : 'evolution-go',
          provider_id: evoData?.id || evoData?.messageId || null,
          evolution_response: evoData,
        };
        try {
          if (c.executionCtx && c.env.DB) {
            c.executionCtx.waitUntil(
              c.env.DB.prepare("UPDATE notifications SET status = 'dispatched' WHERE id = ?")
                .bind(notificationId)
                .run()
            );
          }
        } catch {}
      } else {
        const errorText = await resp.text().catch(() => '');
        if (isSynchronous) {
          return rejectDispatch(isOtp ? 'OTP dispatch failed at WhatsApp provider' : 'Synchronous WhatsApp dispatch failed', isOtp ? 502 : 503, { detail: errorText });
        }
        if (c.env.NOTIFY_QUEUE) {
          await c.env.NOTIFY_QUEUE.send({
            notification_id: notificationId,
            account_slug: accountSlug,
            channel,
            recipient,
            subject,
            payload: dispatchPayload,
            is_otp: false,
            target_path: targetPath,
            timestamp: new Date().toISOString(),
          });
          backendResult = {
            status: 'queued',
            notification_id: notificationId,
            external_id: notificationId,
            queue: 'notify-events-fallback',
          };
        } else {
          return rejectDispatch('WhatsApp provider rejected dispatch (' + resp.status + ')');
        }
      }
    } catch (err: any) {
      if (isSynchronous) {
        return rejectDispatch(isOtp ? 'OTP dispatch failed to reach WhatsApp provider' : 'Synchronous WhatsApp dispatch failed', isOtp ? 502 : 503);
      }
      if (c.env.NOTIFY_QUEUE) {
        await c.env.NOTIFY_QUEUE.send({
          notification_id: notificationId,
          account_slug: accountSlug,
          channel,
          recipient,
          subject,
          payload: dispatchPayload,
          is_otp: false,
          target_path: targetPath,
          timestamp: new Date().toISOString(),
        });
        backendResult = {
          status: 'queued',
          notification_id: notificationId,
          external_id: notificationId,
          queue: 'notify-events-fallback',
        };
      } else {
        return rejectDispatch('WhatsApp provider is unavailable');
      }
    }
  } else if (channel === 'email' && c.env.EMAIL) {
    try {
      const sender = body.sender || c.env.EMAIL_SENDER || 'notify@v7m.live';
      await c.env.EMAIL.send({
        from: sender,
        to: recipient,
        subject: subject || 'Notificação',
        text: content,
        html: body.html || undefined,
      });
      backendResult = {
        ok: true,
        status: 'sent',
        notification_id: notificationId,
        driver: 'cloudflare-email-sending',
      };
      try {
        if (c.executionCtx && c.env.DB) {
          c.executionCtx.waitUntil(
            c.env.DB.prepare("UPDATE notifications SET status = 'dispatched' WHERE id = ?")
              .bind(notificationId)
              .run()
          );
        }
      } catch {}
    } catch (err: any) {
      if (isSynchronous) {
        return rejectDispatch('Email dispatch failed: ' + (err?.message || String(err)), 502);
      }
      if (c.env.NOTIFY_QUEUE) {
        await c.env.NOTIFY_QUEUE.send({
          notification_id: notificationId,
          account_slug: accountSlug,
          channel,
          recipient,
          subject,
          payload: dispatchPayload,
          is_otp: false,
          target_path: targetPath,
          timestamp: new Date().toISOString(),
        });
        backendResult = {
          status: 'queued',
          notification_id: notificationId,
          external_id: notificationId,
          queue: 'notify-events-fallback',
        };
      } else {
        return rejectDispatch('Email dispatch failed: ' + (err?.message || String(err)), 500);
      }
    }
  } else if (c.env.BACKEND_ORIGIN) {
    try {
      const backendUrl = `${c.env.BACKEND_ORIGIN.replace(/\/$/, '')}${targetPath}`;
      const backendHeaders: Record<string, string> = {
        'Content-Type': 'application/json',
        'X-Notification-ID': notificationId,
        'X-Account-Slug': accountSlug,
      };

      if (isOtp) {
        backendHeaders['X-Priority-Queue'] = 'fast-track';
      }

      const auth = c.req.header('Authorization');
      if (auth) backendHeaders['Authorization'] = auth;

      if (c.env.BACKEND_SERVICE_TOKEN) {
        backendHeaders['CF-Access-Client-Secret'] = c.env.BACKEND_SERVICE_TOKEN;
      }

      const resp = await fetch(backendUrl, {
        method: 'POST',
        headers: backendHeaders,
        body: JSON.stringify(dispatchPayload),
        signal: AbortSignal.timeout(10000),
      });

      if (resp.ok) {
        backendResult = await resp.json();
        try {
          if (c.executionCtx && c.env.DB) {
            c.executionCtx.waitUntil(
              c.env.DB.prepare("UPDATE notifications SET status = 'dispatched' WHERE id = ?")
                .bind(notificationId)
                .run()
            );
          }
        } catch {
          // ExecutionContext pode não estar disponível em ambientes de teste direto
        }
      } else {
        if (resp.status === 400 || resp.status === 422) {
          return rejectDispatch('Notification rejected by origin', resp.status);
        }
        // Se for OTP, falha imediatamente com 502 para acionar retry no chamador
        if (isSynchronous) {
          const details = (await resp.json().catch(() => ({}))) as Record<string, any>;
          return rejectDispatch(isOtp ? 'OTP dispatch failed at backend origin' : 'Synchronous dispatch failed at backend origin', isOtp ? 502 : 503, details);
        }

        // Se backend falhar e não for OTP, tenta enfileirar para absorção resiliente
        if (c.env.NOTIFY_QUEUE) {
          await c.env.NOTIFY_QUEUE.send({
            notification_id: notificationId,
            account_slug: accountSlug,
            channel,
            recipient,
            subject,
            payload: dispatchPayload,
            is_otp: false,
            target_path: targetPath,
            timestamp: new Date().toISOString(),
          });
          backendResult = {
            status: 'queued',
            notification_id: notificationId,
            external_id: notificationId,
            queue: 'notify-events-fallback',
          };
        } else {
          return rejectDispatch('Notification origin is unavailable');
        }
      }
    } catch (err: any) {
      if (isSynchronous) {
        return rejectDispatch(isOtp ? 'OTP dispatch failed at backend origin' : 'Synchronous dispatch failed at backend origin', isOtp ? 502 : 503);
      }

      if (c.env.NOTIFY_QUEUE) {
        try {
          await c.env.NOTIFY_QUEUE.send({
            notification_id: notificationId,
            account_slug: accountSlug,
            channel,
            recipient,
            subject,
            payload: dispatchPayload,
            is_otp: false,
            target_path: targetPath,
            timestamp: new Date().toISOString(),
          });
          backendResult = {
            status: 'queued',
            notification_id: notificationId,
            external_id: notificationId,
            queue: 'notify-events-fallback',
          };
        } catch {
          return rejectDispatch('Notification origin and queue are unavailable');
        }
      } else {
        return rejectDispatch('Notification origin is unavailable');
      }
    }
  }

  const responsePayload = {
    ok: true,
    notification_id: notificationId,
    external_id: notificationId,
    status: backendResult.status || (isSynchronous ? 'sent' : 'queued'),
    timestamp: new Date().toISOString(),
    ...backendResult,
  };

  // 4. Salvar resposta para idempotência se chave fornecida (com TTL de 60s se for OTP)
  if (idempotency_key) {
    const expiresAt = isOtp ? new Date(Date.now() + 60000).toISOString() : null;
    await c.env.DB.prepare(
      `INSERT OR REPLACE INTO idempotency_keys (key, account_slug, response_json, caller, created_at, expires_at)
       VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, ?)`
    )
      .bind(idempotency_key, accountSlug, JSON.stringify(responsePayload), caller || null, expiresAt)
      .run();
  }

  const statusCode = responsePayload.status === 'queued' || responsePayload.status === 'queued_edge' ? 202 : 200;
  return c.json(responsePayload, statusCode);
};

app.post('/notify', handleSend);
app.post('/v1/send', handleSend);

// ── 4. Edge Model Context Protocol (MCP JSON-RPC) ──────────────────────────
app.post('/mcp', async (c) => {
  let rpc: any;
  try {
    rpc = await c.req.json();
  } catch {
    return c.json({ jsonrpc: '2.0', error: { code: -32700, message: 'Parse error' }, id: null }, 400);
  }

  const { method, params = {}, id } = rpc;

  if (method === 'initialize') {
    return c.json({
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: '2024-11-05',
        capabilities: { tools: {} },
        serverInfo: { name: 'notify-edge-mcp', version: '1.0.0' },
      },
    });
  }

  if (method === 'tools/list') {
    return c.json({
      jsonrpc: '2.0',
      id,
      result: {
        tools: [
          {
            name: 'notify_send',
            description: 'Envia notificação multicanal (WhatsApp, E-mail) na borda Cloudflare.',
            inputSchema: {
              type: 'object',
              properties: {
                channel: { type: 'string', enum: ['whatsapp', 'email', 'all'] },
                recipient: { type: 'string' },
                content: { type: 'string' },
                subject: { type: 'string' },
                template_slug: { type: 'string' },
                idempotency_key: { type: 'string' },
                extra: { type: 'object' },
              },
              required: ['channel', 'recipient'],
            },
          },
          {
            name: 'notify_status',
            description: 'Consulta o status de entrega de uma notificação pelo ID.',
            inputSchema: {
              type: 'object',
              properties: {
                notification_id: { type: 'string' },
              },
              required: ['notification_id'],
            },
          },
        ],
      },
    });
  }

  if (method === 'tools/call') {
    const toolName = params.name;
    const args = params.arguments || {};

    if (toolName === 'notify_send') {
      const mockReq = {
        req: {
          path: '/v1/send',
          json: async () => args,
          header: (name: string) => c.req.header(name),
        },
        env: c.env,
        header: () => {},
        get: (name: string) => (typeof (c as any).get === 'function' ? (c as any).get(name) : undefined),
        set: () => {},
        json: (data: any, status = 200) => ({ data, status }),
      };
      const res: any = await handleSend(mockReq as any);
      return c.json({
        jsonrpc: '2.0',
        id,
        result: { content: [{ type: 'text', text: JSON.stringify(res.data) }] },
      });
    }

    if (toolName === 'notify_status') {
      const row = await c.env.DB.prepare('SELECT * FROM notifications WHERE id = ?')
        .bind(args.notification_id)
        .first();

      return c.json({
        jsonrpc: '2.0',
        id,
        result: {
          content: [
            {
              type: 'text',
              text: row ? JSON.stringify(row) : JSON.stringify({ error: 'Notification not found' }),
            },
          ],
        },
      });
    }

    return c.json({
      jsonrpc: '2.0',
      id,
      error: { code: -32601, message: `Unknown tool: ${toolName}` },
    });
  }

  return c.json({
    jsonrpc: '2.0',
    id,
    error: { code: -32601, message: `Method not found: ${method}` },
  });
});

// ── 5. Delivery Summary Report Endpoint (Workers Paid CPU & D1) ───────────
app.get('/reports/delivery-summary', async (c) => {
  if (!c.env.DB) {
    return c.json({ error: 'Database not available' }, 503);
  }
  const accountSlug = c.req.query('account') || 'default';
  const hours = Number(c.req.query('hours') || 24);

  const query = `
    SELECT channel, status, COUNT(*) as count 
    FROM notifications 
    WHERE account_slug = ? AND created_at >= datetime('now', '-' || ? || ' hours')
    GROUP BY channel, status
  `;
  const result = await c.env.DB.prepare(query).bind(accountSlug, hours).all();
  return c.json({ account: accountSlug, period_hours: hours, metrics: result.results || [] });
});

// ── 5.1 Fallback: Encaminhar rotas não tratadas na borda para a origem caso configurada ──
app.all('*', async (c) => {
  if (!c.env.BACKEND_ORIGIN) {
    return c.json({ error: 'Not Found', path: c.req.path }, 404);
  }
  const targetUrl = new URL(c.req.path + (new URL(c.req.url).search), c.env.BACKEND_ORIGIN);
  const headers = new Headers(c.req.raw.headers);
  headers.set('host', targetUrl.host);
  headers.set('x-forwarded-host', c.req.header('host') || 'notify.v7m.live');
  headers.set('x-forwarded-proto', 'https');
  const body = ['GET', 'HEAD'].includes(c.req.method) ? undefined : await c.req.raw.arrayBuffer();
  try {
    const res = await fetch(targetUrl.toString(), {
      method: c.req.method,
      headers,
      body,
      redirect: 'manual',
    });
    const responseHeaders = new Headers(res.headers);
    responseHeaders.delete('content-encoding');
    responseHeaders.delete('content-length');
    return new Response(res.body, {
      status: res.status,
      statusText: res.statusText,
      headers: responseHeaders,
    });
  } catch (err: any) {
    return c.json({ error: 'Backend origin unavailable', detail: err.message }, 502);
  }
});

// ── 6. Cloudflare Queue Consumer Handler (Workers Paid Enhanced) ───────────
export const queueHandler = async (
  batch: MessageBatch<NotifyQueueMessage>,
  env: Env,
  ctx: ExecutionContext
): Promise<void> => {
  // 1. Processamento específico da Dead Letter Queue (DLQ)
  if (batch.queue === 'notify-events-dlq') {
    const deadStatements: D1PreparedStatement[] = [];
    for (const msg of batch.messages) {
      console.error(`[DLQ ALERT] Notification failed: ${msg.body.notification_id}`);
      if (env.DB) {
        deadStatements.push(
          env.DB.prepare("UPDATE notifications SET status = 'dead_letter' WHERE id = ?")
            .bind(msg.body.notification_id)
        );
      }
      msg.ack();
    }
    if (deadStatements.length > 0 && env.DB) {
      ctx.waitUntil(env.DB.batch(deadStatements));
    }
    return;
  }

  // 2. Processamento da fila notify-events
  if (!env.BACKEND_ORIGIN && !env.EVOLUTION_URL) {
    batch.retryAll();
    return;
  }

  const successIds: string[] = [];
  const failedIds: string[] = [];

  await Promise.allSettled(
    batch.messages.map(async (message) => {
      const item = message.body;
      try {
        if (item.channel === 'whatsapp' && env.EVOLUTION_URL) {
          const isV2 = env.WHATSAPP_TEST_DRIVER === 'evolution-v2' || env.EVOLUTION_URL.includes(':8085');
          const instanceName = await resolveWhatsAppInstance(
            env,
            item.account_slug || 'default',
            item.payload?.instance || item.payload?.options?.instance || item.payload?.whatsapp_instance
          );
          const evolutionEndpoint = getEvolutionEndpoint(env.EVOLUTION_URL, instanceName, isV2);

          const headers: Record<string, string> = { 'Content-Type': 'application/json' };
          if (env.EVOLUTION_API_KEY) headers['apikey'] = env.EVOLUTION_API_KEY;

          const resp = await fetch(evolutionEndpoint, {
            method: 'POST',
            headers,
            body: JSON.stringify({
              number: item.recipient,
              text: item.payload?.content || item.payload?.text || '',
            }),
            signal: AbortSignal.timeout(10000),
          });

          if (resp.ok) {
            message.ack();
            successIds.push(item.notification_id);
          } else if ([401, 403, 404, 408, 429].includes(resp.status) || resp.status >= 500) {
            message.retry();
          } else {
            message.ack();
            failedIds.push(item.notification_id);
          }
          return;
        }

        if (item.channel === 'email' && env.EMAIL) {
          try {
            await env.EMAIL.send({
              from: item.payload?.sender || env.EMAIL_SENDER || 'notify@v7m.live',
              to: item.recipient,
              subject: item.subject || 'Notificação',
              text: item.payload?.content || item.payload?.text || '',
              html: item.payload?.html || undefined,
            });
            message.ack();
            successIds.push(item.notification_id);
          } catch (err: any) {
            message.retry();
          }
          return;
        }

        if (!env.BACKEND_ORIGIN) {
          message.ack();
          failedIds.push(item.notification_id);
          return;
        }

        const targetPath = item.target_path || '/v1/send';
        const backendUrl = `${env.BACKEND_ORIGIN.replace(/\/$/, '')}${targetPath}`;
        const headers: Record<string, string> = {
          'Content-Type': 'application/json',
          'X-Notification-ID': item.notification_id,
          'X-Account-Slug': item.account_slug,
        };

        if (env.NOTIFY_API_KEY) {
          headers['Authorization'] = `Bearer ${env.NOTIFY_API_KEY}`;
        } else if (item.auth_header) {
          headers['Authorization'] = item.auth_header;
        }

        if (item.is_otp) {
          headers['X-Priority-Queue'] = 'fast-track';
        }

        if (env.BACKEND_SERVICE_TOKEN) {
          headers['CF-Access-Client-Secret'] = env.BACKEND_SERVICE_TOKEN;
        }

        const dispatchPayload = {
          ...originPayload(item.payload, targetPath, item.notification_id),
          account_id: item.payload?.account_id || item.account_slug,
        };

        const resp = await fetch(backendUrl, {
          method: 'POST',
          headers,
          body: JSON.stringify(dispatchPayload),
          signal: AbortSignal.timeout(10000),
        });

        if (resp.ok) {
          message.ack();
          successIds.push(item.notification_id);
        } else if ([401, 403, 404, 408, 429].includes(resp.status) || resp.status >= 500) {
          message.retry();
        } else {
          message.ack();
          failedIds.push(item.notification_id);
        }
      } catch (err) {
        message.retry();
      }
    })
  );

  // 3. Batch D1 updates (Workers Paid otimizado)
  if (env.DB && (successIds.length > 0 || failedIds.length > 0)) {
    const batchUpdates: D1PreparedStatement[] = [
      ...successIds.map((id) => env.DB.prepare("UPDATE notifications SET status = 'dispatched' WHERE id = ?").bind(id)),
      ...failedIds.map((id) => env.DB.prepare("UPDATE notifications SET status = 'failed' WHERE id = ?").bind(id)),
    ];
    ctx.waitUntil(env.DB.batch(batchUpdates));
  }
};

// ── 7. Scheduled Cron Handler (Idempotency Cleanup & Reconciliation) ───────
export const scheduledHandler = async (
  event: ScheduledEvent,
  env: Env,
  ctx: ExecutionContext
): Promise<void> => {
  if (!env.DB) return;

  ctx.waitUntil(
    (async () => {
      await env.DB.prepare(
        "DELETE FROM idempotency_keys WHERE expires_at IS NOT NULL AND expires_at < CURRENT_TIMESTAMP"
      ).run();

      await env.DB.prepare(
        "DELETE FROM notifications WHERE created_at < datetime('now', '-60 days')"
      ).run();
    })()
  );
};

import { handleIncomingEmail } from './email-handler';

export default {
  fetch: async (request: Request, env: Env, ctx: ExecutionContext) => {
    return app.fetch(request, env, ctx);
  },
  queue: queueHandler,
  email: handleIncomingEmail,
  scheduled: scheduledHandler,
};
