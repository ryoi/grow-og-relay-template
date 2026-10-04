import { DurableObject } from "cloudflare:workers";

interface Env {
  ALLOWED_ORIGINS: string;
  OWNER_KEY?: string;
  RELAY_GATEWAY: DurableObjectNamespace<RelayGateway>;
  RELAY_ID?: string;
  RELAY_NAME?: string;
  SIGNAL_ROOMS: DurableObjectNamespace<SignalRoom>;
  TURN_API_TOKEN?: string;
  TURN_TOKEN_ID?: string;
}

interface SocketAttachment {
  auth: string;
  connectedAt: number;
  hello: boolean;
  messages: number;
  role: "host" | "guest";
}

interface ShortInvite {
  ciphertext: string;
  expiresAt: number;
  iv: string;
  room: string;
  v: 1;
}

const DAY_MS = 24 * 60 * 60_000;
const jsonHeaders = {
  "cache-control": "no-store",
  "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
  "content-type": "application/json; charset=utf-8",
  "x-content-type-options": "nosniff",
};

function json(body: unknown, status = 200, headers?: Record<string, string>) {
  return new Response(JSON.stringify(body), { status, headers: { ...jsonHeaders, ...(headers ?? {}) } });
}

function allowedOrigin(request: Request, configured: string) {
  const origin = request.headers.get("origin");
  return Boolean(origin && configured.split(",").map((value) => value.trim()).includes(origin));
}

function cors(origin: string) {
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "authorization, content-type, x-sottli-grant",
    "access-control-max-age": "600",
    vary: "Origin",
  };
}

function base64Url(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function fromBase64Url(value: string) {
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(base64);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function equal(left: string, right: string) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return difference === 0;
}

function bearer(request: Request) {
  const value = request.headers.get("authorization");
  return value?.startsWith("Bearer ") ? value.slice(7) : "";
}

function validRoom(value: string) {
  return /^[A-Za-z0-9_-]{24}$/.test(value);
}

async function signature(payload: string, secret: string) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return base64Url(new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload))));
}

async function signGrant(room: string, expiresAt: number, secret: string) {
  const payload = base64Url(new TextEncoder().encode(JSON.stringify({
    v: 1,
    room,
    exp: expiresAt,
    jti: base64Url(crypto.getRandomValues(new Uint8Array(12))),
  })));
  return `${payload}.${await signature(payload, secret)}`;
}

async function verifyGrant(token: string | null, room: string, secret: string) {
  if (!token || token.length > 1_024) return false;
  const [payload, suppliedSignature, extra] = token.split(".");
  if (!payload || !suppliedSignature || extra || !equal(await signature(payload, secret), suppliedSignature)) return false;
  try {
    const value = JSON.parse(new TextDecoder().decode(fromBase64Url(payload))) as Record<string, unknown>;
    return value.v === 1 && value.room === room && typeof value.exp === "number"
      && value.exp > Date.now() && value.exp <= Date.now() + DAY_MS + 5_000;
  } catch {
    return false;
  }
}

function validShortInvite(value: unknown): value is ShortInvite {
  if (!value || typeof value !== "object") return false;
  const invite = value as Record<string, unknown>;
  return invite.v === 1 && typeof invite.room === "string" && validRoom(invite.room)
    && typeof invite.expiresAt === "number" && invite.expiresAt > Date.now() && invite.expiresAt <= Date.now() + DAY_MS + 5_000
    && typeof invite.iv === "string" && /^[A-Za-z0-9_-]{16}$/.test(invite.iv)
    && typeof invite.ciphertext === "string" && invite.ciphertext.length >= 32 && invite.ciphertext.length <= 8_192
    && /^[A-Za-z0-9_-]+$/.test(invite.ciphertext);
}

function gateway(env: Env) {
  return env.RELAY_GATEWAY.getByName("global");
}

async function withinLimit(env: Env, key: string, limit: number) {
  const response = await gateway(env).fetch(new Request(`https://gateway.internal/limit/${encodeURIComponent(key)}?limit=${limit}`, { method: "POST" }));
  return response.ok;
}

export class RelayGateway extends DurableObject<Env> {
  async fetch(request: Request) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/limit/") && request.method === "POST") {
      const key = `rate:${decodeURIComponent(url.pathname.slice(7))}`;
      const now = Date.now();
      const recent = (await this.ctx.storage.get<number[]>(key) ?? []).filter((timestamp) => timestamp > now - 60_000);
      const limit = Math.max(1, Math.min(120, Number(url.searchParams.get("limit")) || 30));
      if (recent.length >= limit) return json({ error: "rate_limited" }, 429);
      recent.push(now);
      await this.ctx.storage.put(key, recent);
      return json({ ok: true });
    }
    const shortMatch = url.pathname.match(/^\/short\/([A-Za-z0-9_-]{14})$/);
    if (shortMatch && request.method === "POST") {
      const invite = await request.json().catch(() => null);
      if (!validShortInvite(invite)) return json({ error: "invalid_short_invite" }, 400);
      await this.ctx.storage.put(`short:${shortMatch[1]}`, invite);
      await this.ctx.storage.setAlarm(invite.expiresAt);
      return json({ ok: true });
    }
    if (shortMatch && request.method === "GET") {
      const invite = await this.ctx.storage.get<ShortInvite>(`short:${shortMatch[1]}`);
      if (!invite) return json({ error: "short_invite_not_found" }, 404);
      if (invite.expiresAt <= Date.now()) {
        await this.ctx.storage.delete(`short:${shortMatch[1]}`);
        return json({ error: "short_invite_expired" }, 410);
      }
      return json(invite);
    }
    return json({ error: "not_found" }, 404);
  }

  async alarm() {
    const values = await this.ctx.storage.list<ShortInvite>({ prefix: "short:" });
    const expired = [...values.entries()].filter(([, invite]) => invite.expiresAt <= Date.now()).map(([key]) => key);
    if (expired.length) await this.ctx.storage.delete(expired);
  }
}

export class SignalRoom extends DurableObject<Env> {
  async fetch(request: Request) {
    const url = new URL(request.url);
    if (url.pathname === "/authorize-relay") {
      const auth = bearer(request);
      const valid = auth && this.ctx.getWebSockets().some((socket) => (socket.deserializeAttachment() as SocketAttachment | null)?.auth === auth);
      return new Response(null, { status: valid ? 204 : 403 });
    }
    if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") return json({ error: "websocket_required" }, 426);
    const role = url.searchParams.get("role");
    const protocolHeader = request.headers.get("sec-websocket-protocol") ?? "";
    const protocol = protocolHeader.split(",").map((value) => value.trim()).find((value) => value.startsWith("sottli-v1."));
    const auth = protocol?.slice("sottli-v1.".length) ?? "";
    if ((role !== "host" && role !== "guest") || !/^[A-Za-z0-9_-]{43}$/.test(auth) || !protocol) return json({ error: "invalid_handshake" }, 400);
    const sockets = this.ctx.getWebSockets();
    const attachments = sockets.map((socket) => socket.deserializeAttachment() as SocketAttachment | null);
    if (attachments.some((attachment) => attachment?.auth !== auth)) return json({ error: "invalid_room_capability" }, 403);
    const duplicateIndex = attachments.findIndex((attachment) => attachment?.role === role);
    if (duplicateIndex >= 0) sockets[duplicateIndex].close(4001, "role_replaced");
    else if (sockets.length >= 2) return json({ error: "room_full" }, 409);
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    this.ctx.acceptWebSocket(server, [role]);
    server.serializeAttachment({ auth, connectedAt: Date.now(), hello: false, messages: 0, role } satisfies SocketAttachment);
    await this.ctx.storage.setAlarm(Date.now() + DAY_MS);
    return new Response(null, { status: 101, webSocket: client, headers: { "sec-websocket-protocol": protocol } });
  }

  webSocketMessage(socket: WebSocket, message: string | ArrayBuffer) {
    if (typeof message !== "string" || message.length > 24_000) return socket.close(1009, "invalid_signal_size");
    const attachment = socket.deserializeAttachment() as SocketAttachment;
    attachment.messages += 1;
    if (attachment.messages > 120 || Date.now() - attachment.connectedAt > DAY_MS) return socket.close(1008, "room_expired");
    let parsed: Record<string, unknown> | null = null;
    try { parsed = JSON.parse(message) as Record<string, unknown>; } catch { parsed = null; }
    if (parsed?.type === "hello") {
      attachment.hello = true;
      socket.serializeAttachment(attachment);
      const ready = this.ctx.getWebSockets().filter((peer) => (peer.deserializeAttachment() as SocketAttachment | null)?.hello);
      for (const peer of ready) peer.send(JSON.stringify({ type: ready.length === 2 ? "ready" : "waiting", ...(ready.length === 2 ? { capabilities: ["relay-share-v1"] } : {}) }));
      return;
    }
    if (parsed?.type !== "signal" || typeof parsed.iv !== "string" || !/^[A-Za-z0-9_-]{16}$/.test(parsed.iv)
      || typeof parsed.ciphertext !== "string" || parsed.ciphertext.length > 24_000) return socket.close(1003, "invalid_signal_envelope");
    for (const peer of this.ctx.getWebSockets()) if (peer !== socket) peer.send(message);
  }

  webSocketClose(socket: WebSocket) {
    try { socket.close(); } catch { /* already closed */ }
    for (const peer of this.ctx.getWebSockets()) if (peer !== socket) peer.send(JSON.stringify({ type: "peer-left" }));
  }

  async alarm() {
    for (const socket of this.ctx.getWebSockets()) socket.close(1000, "room_expired");
    await this.ctx.storage.deleteAll();
  }
}

export default {
  async fetch(request: Request, env: Env) {
    const url = new URL(request.url);
    const origin = request.headers.get("origin") ?? "";
    if (url.pathname === "/provider" && request.method === "GET") {
      return json({
        v: 1,
        id: env.RELAY_ID && /^[a-z0-9][a-z0-9-]{2,62}$/.test(env.RELAY_ID) ? env.RELAY_ID : "my-private-relay",
        name: env.RELAY_NAME?.trim().slice(0, 80) || "My private relay",
      }, 200, allowedOrigin(request, env.ALLOWED_ORIGINS) ? cors(origin) : undefined);
    }
    if (url.pathname === "/health") return json({ status: "ok", relay: env.TURN_API_TOKEN && /^[0-9a-f]{32}$/i.test(env.TURN_TOKEN_ID ?? "") ? "available" : "setup_required" });
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(origin) });
    if (!allowedOrigin(request, env.ALLOWED_ORIGINS)) return json({ error: "origin_not_allowed" }, 403, cors(origin));
    if (!env.OWNER_KEY || !/^[A-Za-z0-9_-]{43,128}$/.test(env.OWNER_KEY)) return json({ error: "owner_key_not_configured" }, 503, cors(origin));

    if (url.pathname === "/grants" && request.method === "POST") {
      if (!equal(bearer(request), env.OWNER_KEY)) return json({ error: "owner_key_required" }, 401, cors(origin));
      const body = await request.json().catch(() => null) as { roomId?: unknown; expiresAt?: unknown } | null;
      if (typeof body?.roomId !== "string" || !validRoom(body.roomId) || typeof body.expiresAt !== "number"
        || body.expiresAt <= Date.now() || body.expiresAt > Date.now() + DAY_MS + 5_000) return json({ error: "invalid_grant_request" }, 400, cors(origin));
      return json({ grant: await signGrant(body.roomId, body.expiresAt, env.OWNER_KEY) }, 200, cors(origin));
    }

    const shortMatch = url.pathname.match(/^\/short-invites\/([A-Za-z0-9_-]{14})$/);
    if (shortMatch) {
      if (!(await withinLimit(env, `${request.headers.get("cf-connecting-ip") ?? "unknown"}:short`, 30))) return json({ error: "rate_limited" }, 429, cors(origin));
      if (request.method === "POST") {
        const invite = await request.json().catch(() => null);
        if (!validShortInvite(invite) || !(await verifyGrant(request.headers.get("x-sottli-grant"), invite.room, env.OWNER_KEY))) return json({ error: "invalid_short_invite" }, 403, cors(origin));
        const response = await gateway(env).fetch(new Request(`https://gateway.internal/short/${shortMatch[1]}`, { method: "POST", body: JSON.stringify(invite) }));
        return json({ ok: response.ok }, response.status, cors(origin));
      }
      const response = await gateway(env).fetch(new Request(`https://gateway.internal/short/${shortMatch[1]}`));
      return new Response(response.body, { status: response.status, headers: { ...jsonHeaders, ...cors(origin) } });
    }

    const credentialMatch = url.pathname.match(/^\/turn-credentials\/([A-Za-z0-9_-]{24})$/);
    if (credentialMatch && request.method === "POST") {
      const room = credentialMatch[1];
      const auth = bearer(request);
      if (!/^[A-Za-z0-9_-]{43}$/.test(auth) || !(await verifyGrant(request.headers.get("x-sottli-grant"), room, env.OWNER_KEY))) return json({ error: "room_not_authorized" }, 403, cors(origin));
      const active = await env.SIGNAL_ROOMS.getByName(room).fetch(new Request("https://room.internal/authorize-relay", { headers: { authorization: `Bearer ${auth}` } }));
      if (!active.ok) return json({ error: "room_not_active" }, 409, cors(origin));
      if (!env.TURN_API_TOKEN || !/^[0-9a-f]{32}$/i.test(env.TURN_TOKEN_ID ?? "")) return json({ error: "relay_not_configured" }, 503, cors(origin));
      if (!(await withinLimit(env, `${request.headers.get("cf-connecting-ip") ?? auth}:turn`, 30))) return json({ error: "rate_limited" }, 429, cors(origin));
      const response = await fetch(`https://rtc.live.cloudflare.com/v1/turn/keys/${env.TURN_TOKEN_ID}/credentials/generate-ice-servers`, {
        method: "POST",
        headers: { authorization: `Bearer ${env.TURN_API_TOKEN}`, "content-type": "application/json" },
        body: JSON.stringify({ ttl: 3_600 }),
      });
      return new Response(response.body, { status: response.status, headers: { ...jsonHeaders, ...cors(origin) } });
    }

    const connectMatch = url.pathname.match(/^\/connect\/([A-Za-z0-9_-]{24})$/);
    if (!connectMatch) return json({ error: "not_found" }, 404, cors(origin));
    if (!(await verifyGrant(url.searchParams.get("grant"), connectMatch[1], env.OWNER_KEY))) return json({ error: "invalid_access_grant" }, 403, cors(origin));
    return env.SIGNAL_ROOMS.getByName(connectMatch[1]).fetch(request);
  },
} satisfies ExportedHandler<Env>;
