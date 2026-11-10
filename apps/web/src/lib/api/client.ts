/* The web's only door to the local Core API (services/api; contract docs/openapi.json), for
   server code only: the session token never reaches the browser.

   The API listens on this computer only, so the address must be a loopback one
   (RECONIX_CORE_API, default http://127.0.0.1:8000, the same setting the TUI reads); anything
   else is refused before a call, because every call carries the token. The token comes from
   POST /sessions (interface "web") the first time it is needed and lives in this process's
   memory only. A 401 drops it and the call is made once more with a new session (the API was
   restarted); a second 401, and every other refusal, goes to the person as the API said it. */
import "server-only";

const ENV_URL = "RECONIX_CORE_API";
const DEFAULT_URL = "http://127.0.0.1:8000";
const PREFIX = "/api/v1";
const TIMEOUT_MS = 15_000;
export const NOT_RUNNING = "Core API not running: start it with ./deploy/dev.sh";

/** A failed call: the API's own UPPERCASE code and message (the API masks them), or ours. */
export class CoreApiError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly status = 0,
  ) {
    super(message);
    this.name = "CoreApiError";
  }
}

const LOOPBACK = /^(localhost|127(\.\d{1,3}){3}|\[::1\])$/;

/** The API's address, or CoreApiError NOT_LOCAL for one that isn't on this computer. */
export function baseUrl(): string {
  const raw = (process.env[ENV_URL]?.trim() || DEFAULT_URL).replace(/\/+$/, "");
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new CoreApiError("NOT_LOCAL", `${ENV_URL} must be this computer, e.g. ${DEFAULT_URL}.`);
  }
  const plain = url.pathname === "/" && !url.search && !url.username && !url.password;
  if (!["http:", "https:"].includes(url.protocol) || !LOOPBACK.test(url.hostname) || !plain) {
    throw new CoreApiError("NOT_LOCAL", `${ENV_URL} must be this computer, e.g. ${DEFAULT_URL}.`);
  }
  return url.origin;
}

async function send(method: string, path: string, token: string | null, body?: unknown): Promise<unknown> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers.Authorization = `Bearer ${token}`;
  let res: Response;
  let text: string;
  try {
    res = await fetch(baseUrl() + PREFIX + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    text = await res.text(); // the timeout covers the body too
  } catch (e) {
    if (e instanceof CoreApiError) throw e;
    if (e instanceof Error && e.name === "TimeoutError") throw new CoreApiError("TIMEOUT", `The Core API didn't answer within ${TIMEOUT_MS / 1000} s.`);
    throw new CoreApiError("UNREACHABLE", NOT_RUNNING);
  }
  if (!res.ok) throw apiError(res.status, text);
  try {
    return text ? JSON.parse(text) : null;
  } catch {
    throw new CoreApiError("BAD_RESPONSE", "The Core API sent an answer that isn't JSON.", res.status);
  }
}

/** The API's error shape {"code", "message", "details"} as a CoreApiError. */
export function apiError(status: number, text: string): CoreApiError {
  try {
    const body = JSON.parse(text) as { code?: unknown; message?: unknown };
    if (typeof body.code === "string" && typeof body.message === "string") return new CoreApiError(body.code, body.message, status);
  } catch {
    // not the API's error shape
  }
  return new CoreApiError("HTTP_ERROR", `The Core API answered HTTP ${status}.`, status);
}

let session: Promise<string> | null = null;

function token(): Promise<string> {
  if (session) return session;
  const opening = send("POST", "/sessions", null, { interface: "web" }).then((r) => {
    const t = (r as { token?: unknown } | null)?.token;
    if (typeof t !== "string" || !t) throw new CoreApiError("BAD_RESPONSE", "The Core API opened a session without a token.");
    return t;
  });
  session = opening;
  opening.catch(() => {
    if (session === opening) session = null; // a failed open is tried again on the next call
  });
  return opening;
}

/** GET one path under /api/v1 with the web's session: the decoded JSON. */
export async function apiGet(path: string): Promise<unknown> {
  const used = token();
  try {
    return await send("GET", path, await used);
  } catch (e) {
    if (!(e instanceof CoreApiError) || e.status !== 401) throw e;
    // the API forgot the session (restarted): one new session, one more try. Only the session
    // that failed is dropped, so calls that fail together open one new session, not one each.
    if (session === used) session = null;
    return send("GET", path, await token());
  }
}

/** For tests: forget the session. */
export function resetSession(): void {
  session = null;
}
