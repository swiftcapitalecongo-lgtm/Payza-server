import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";

const PORT = Number(process.env.PORT || 10000);
const PAYZA_API = "https://payzaapi.co.ke/api/v1";
const rateBuckets = new Map();
const MARKETS = {
  ZMW: { country: "Zambia", dialCode: "260", localExample: "0971234567" },
  MWK: { country: "Malawi", dialCode: "265", localExample: "0991234567" },
};

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function logError(event, details = {}) {
  console.error(
    JSON.stringify({
      level: "error",
      service: "payza-zambia",
      event,
      timestamp: new Date().toISOString(),
      ...details,
    }),
  );
}

function sendJson(res, status, payload, extraHeaders = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Length": Buffer.byteLength(body),
    ...extraHeaders,
  });
  res.end(res.req?.method === "HEAD" ? undefined : body);
}

function setCorsHeaders(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, HEAD, POST, OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, X-Request-ID",
  );
  res.setHeader("Access-Control-Max-Age", "86400");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
}

function clientKey(req) {
  const forwardedFor = req.headers["x-forwarded-for"];
  const forwardedIp =
    typeof forwardedFor === "string" ? forwardedFor.split(",")[0].trim() : "";
  return forwardedIp || req.socket.remoteAddress || "unknown";
}

function checkRateLimit(req, res, { limit, windowMs, scope }) {
  const now = Date.now();
  const key = `${scope}:${clientKey(req)}`;
  let bucket = rateBuckets.get(key);

  if (!bucket || now >= bucket.resetAt) {
    bucket = { count: 0, resetAt: now + windowMs };
    rateBuckets.set(key, bucket);
  }

  bucket.count += 1;
  if (bucket.count <= limit) return true;

  const retryAfter = Math.max(1, Math.ceil((bucket.resetAt - now) / 1000));
  logError("local_rate_limit", {
    requestId: res.getHeader("X-Request-ID"),
    scope,
    retryAfter,
  });
  sendJson(
    res,
    429,
    {
      success: false,
      message: "Too many requests. Please wait a moment and try again.",
      error_code: "local_rate_limit",
    },
    { "Retry-After": String(retryAfter) },
  );
  return false;
}

function pruneRateBuckets() {
  if (rateBuckets.size < 4000) return;
  const now = Date.now();
  for (const [key, bucket] of rateBuckets) {
    if (now >= bucket.resetAt) rateBuckets.delete(key);
  }
}

function readRawBody(req, limit = 32 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let tooLarge = false;

    req.on("data", (chunk) => {
      if (tooLarge) return;
      size += chunk.length;
      if (size > limit) {
        tooLarge = true;
        chunks.length = 0;
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", () => {
      if (tooLarge) {
        reject(new HttpError(413, "Request body is too large."));
        return;
      }
      resolve(Buffer.concat(chunks));
    });

    req.on("error", reject);
  });
}

async function readJson(req) {
  const raw = await readRawBody(req);
  if (raw.length === 0) throw new HttpError(400, "A JSON request body is required.");
  try {
    return JSON.parse(raw.toString("utf8"));
  } catch {
    throw new HttpError(400, "Request body must be valid JSON.");
  }
}

function getCredentials() {
  const publicKey = process.env.PAYZA_PUBLIC_KEY;
  const secretKey = process.env.PAYZA_SECRET_KEY;
  if (!publicKey || !secretKey) {
    throw new HttpError(
      503,
      "Payment service is not configured. Set PAYZA_PUBLIC_KEY and PAYZA_SECRET_KEY on the server.",
    );
  }
  return { publicKey, secretKey };
}

function getCallbackUrl() {
  const publicBaseUrl = (
    process.env.PUBLIC_BASE_URL || "https://payza-server.onrender.com"
  ).replace(/\/+$/, "");
  const configured =
    process.env.PAYZA_CALLBACK_URL ||
    `${publicBaseUrl}/webhooks/payza`;
  let callback;
  try {
    callback = new URL(configured);
  } catch {
    throw new HttpError(500, "PAYZA_CALLBACK_URL or PUBLIC_BASE_URL is invalid.");
  }
  if (callback.protocol !== "https:") {
    throw new HttpError(500, "The Payza callback URL must use HTTPS.");
  }
  return callback.toString();
}

function normalizeMobileMoneyPhone(value, currency) {
  const market = Object.hasOwn(MARKETS, currency) ? MARKETS[currency] : null;
  if (!market || typeof value !== "string") return null;
  const digits = value.replace(/\D/g, "");
  if (/^0\d{9}$/.test(digits)) return `${market.dialCode}${digits.slice(1)}`;
  if (new RegExp(`^${market.dialCode}\\d{9}$`).test(digits)) return digits;
  if (/^\d{9}$/.test(digits)) return `${market.dialCode}${digits}`;
  return null;
}

function validatePayment(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new HttpError(400, "Request body must be a JSON object.");
  }

  const amount = Number(body.amount);
  if (!Number.isFinite(amount) || amount <= 0) {
    throw new HttpError(400, "Enter a valid amount greater than zero.");
  }

  const currency =
    typeof body.currency === "string" ? body.currency.trim().toUpperCase() : "ZMW";
  const market = Object.hasOwn(MARKETS, currency) ? MARKETS[currency] : null;
  if (!market) {
    throw new HttpError(400, "Choose Zambia (ZMW) or Malawi (MWK).");
  }

  const customer = body.customer;
  if (!customer || typeof customer !== "object" || Array.isArray(customer)) {
    throw new HttpError(400, "Customer details are required.");
  }
  const email =
    typeof customer.email === "string" ? customer.email.trim() : "";
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
    throw new HttpError(400, "Enter a valid email address.");
  }

  const name = typeof customer.name === "string" ? customer.name.trim() : "";
  if (name.length > 120) {
    throw new HttpError(400, "Name must be 120 characters or fewer.");
  }

  const phone = normalizeMobileMoneyPhone(customer.phone, currency);
  if (!phone) {
    throw new HttpError(
      400,
      `Enter a valid ${market.country} phone number, such as ${market.localExample} or +${market.dialCode}${market.localExample.slice(1)}.`,
    );
  }

  const payment = {
    amount,
    currency,
    stk_push: true,
    customer: { email, phone },
    callback_url: getCallbackUrl(),
  };
  if (name) payment.customer.name = name;

  if (typeof body.reference === "string" && body.reference.trim()) {
    const reference = body.reference.trim();
    if (reference.length > 100) {
      throw new HttpError(400, "Reference must be 100 characters or fewer.");
    }
    payment.reference = reference;
  }

  if (typeof body.description === "string" && body.description.trim()) {
    const description = body.description.trim();
    if (description.length > 255) {
      throw new HttpError(400, "Description must be 255 characters or fewer.");
    }
    payment.description = description;
  }

  if (typeof body.network === "string" && body.network.trim()) {
    const network = body.network.trim();
    if (!/^[a-zA-Z0-9_-]{1,40}$/.test(network)) {
      throw new HttpError(400, "Choose a valid mobile-money network.");
    }
    payment.network = network;
  }

  return payment;
}

async function requestPayza(path, method, payload, requestId) {
  const { publicKey, secretKey } = getCredentials();
  let response;
  try {
    response = await fetch(`${PAYZA_API}${path}`, {
      method,
      headers: {
        "X-Public-Key": publicKey,
        "X-Secret-Key": secretKey,
        ...(payload ? { "Content-Type": "application/json" } : {}),
      },
      ...(payload ? { body: JSON.stringify(payload) } : {}),
      signal: AbortSignal.timeout(20000),
    });
  } catch (error) {
    const message =
      error?.name === "TimeoutError" || error?.name === "AbortError"
        ? "Payment provider did not respond in time. Please try again."
        : "Could not connect to the payment service. Please try again shortly.";
    logError("payza_network_error", {
      requestId,
      route: path,
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    });
    throw new HttpError(502, message);
  }

  const rawText = await response.text();
  let data;
  try {
    data = rawText ? JSON.parse(rawText) : {};
  } catch {
    data = {
      success: false,
      message: rawText || "Payza returned an unreadable response.",
    };
  }

  if (!response.ok || data?.success === false) {
    const message =
      typeof data?.message === "string" && data.message
        ? data.message
        : "Unable to process your payment request. Please try again.";
    logError("payza_api_error", {
      requestId,
      route: path,
      status: response.status,
      message,
      errorCode: data?.error_code,
    });
    const status = response.ok ? 502 : response.status;
    const forwarded = {
      ...(data && typeof data === "object" && !Array.isArray(data) ? data : {}),
      success: false,
      message,
    };
    const headers = {};
    const retryAfter = response.headers.get("retry-after");
    if (retryAfter) headers["Retry-After"] = retryAfter;
    return { status, data: forwarded, headers };
  }

  return { status: response.status, data };
}

function verifyWebhookSignature(rawBody, receivedSignature) {
  const secret = process.env.PAYZA_WEBHOOK_SECRET;
  if (!secret) {
    throw new HttpError(
      503,
      "Webhook verification is not configured. Set PAYZA_WEBHOOK_SECRET on the server.",
    );
  }
  if (!/^[a-fA-F0-9]{64}$/.test(receivedSignature)) return false;

  const expected = createHmac("sha256", secret).update(rawBody).digest();
  const received = Buffer.from(receivedSignature, "hex");
  return (
    received.length === expected.length && timingSafeEqual(expected, received)
  );
}

async function handleWebhook(req, res, requestId) {
  const raw = await readRawBody(req, 128 * 1024);
  const signature = req.headers["x-payza-signature"];
  if (
    typeof signature !== "string" ||
    !verifyWebhookSignature(raw, signature)
  ) {
    logError("payza_webhook_signature_invalid", { requestId });
    sendJson(res, 401, { success: false, message: "Payment notification could not be verified." });
    return;
  }

  let event;
  try {
    event = JSON.parse(raw.toString("utf8"));
  } catch {
    throw new HttpError(400, "Invalid payment notification received.");
  }

  console.log(
    JSON.stringify({
      level: "info",
      service: "payza-zambia",
      event: "payza_webhook_received",
      requestId,
      eventType: event?.event || "unknown",
      reference: event?.reference || null,
      status: event?.status || null,
      amount: event?.amount ?? null,
      currency: event?.currency || null,
      timestamp: new Date().toISOString(),
    }),
  );
  sendJson(res, 200, { success: true, received: true });
}

async function handleRequest(req, res) {
  setCorsHeaders(res);
  const requestId = randomUUID();
  res.setHeader("X-Request-ID", requestId);

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  let url;
  try {
    url = new URL(req.url || "/", "http://localhost");

    if (
      ["GET", "HEAD"].includes(req.method || "") &&
      (url.pathname === "/" || url.pathname === "/health")
    ) {
      sendJson(res, 200, {
        status: "ok",
        service: "payza-zambia",
        endpoint: url.pathname,
        timestamp: new Date().toISOString(),
      });
      return;
    }

    if (req.method === "POST" && url.pathname === "/webhooks/payza") {
      await handleWebhook(req, res, requestId);
      return;
    }

    if (req.method === "POST" && url.pathname === "/api/payments") {
      pruneRateBuckets();
      if (!checkRateLimit(req, res, { limit: 10, windowMs: 60_000, scope: "create" })) {
        return;
      }
      const body = await readJson(req);
      const payload = validatePayment(body);
      const result = await requestPayza("/pay", "POST", payload, requestId);
      sendJson(res, result.status, result.data, result.headers);
      return;
    }

    const verifyMatch = url.pathname.match(/^\/api\/payments\/([^/]+)\/verify$/);
    if (req.method === "GET" && verifyMatch) {
      pruneRateBuckets();
      if (!checkRateLimit(req, res, { limit: 50, windowMs: 60_000, scope: "verify" })) {
        return;
      }
      let reference;
      try {
        reference = decodeURIComponent(verifyMatch[1]);
      } catch {
        throw new HttpError(400, "Payment reference is invalid.");
      }
      if (!reference || reference.length > 150) {
        throw new HttpError(400, "Payment reference is invalid.");
      }
      const result = await requestPayza(
        `/verify/${encodeURIComponent(reference)}`,
        "GET",
        null,
        requestId,
      );
      sendJson(res, result.status, result.data, result.headers);
      return;
    }

    logError("route_not_found", {
      requestId,
      method: req.method,
      path: url.pathname,
      status: 404,
    });
    sendJson(res, 404, { success: false, message: "Route not found." });
  } catch (error) {
    const status = error instanceof HttpError ? error.status : 500;
    const message =
      error instanceof Error ? error.message : "Unexpected server error.";
    logError("request_error", {
      requestId,
      method: req.method,
      path: url?.pathname || req.url,
      status,
      message,
      stack: error instanceof Error ? error.stack : undefined,
    });
    if (!res.headersSent) {
      sendJson(res, status, { success: false, message });
    } else if (!res.writableEnded) {
      res.end();
    }
  }
}

if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
  throw new Error("PORT must be a valid TCP port.");
}

const server = createServer((req, res) => {
  void handleRequest(req, res);
});

server.on("clientError", (error, socket) => {
  logError("client_connection_error", {
    message: error.message,
    stack: error.stack,
  });
  if (socket.writable) {
    socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(
    JSON.stringify({
      level: "info",
      service: "payza-zambia",
      event: "server_started",
      port: PORT,
      timestamp: new Date().toISOString(),
    }),
  );
});

server.on("error", (error) => {
  logError("server_start_error", { message: error.message, stack: error.stack });
  process.exit(1);
});

process.on("unhandledRejection", (reason) => {
  logError("unhandled_rejection", {
    message: reason instanceof Error ? reason.message : String(reason),
    stack: reason instanceof Error ? reason.stack : undefined,
  });
});
