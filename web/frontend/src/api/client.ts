import { getRuntimeConfig, normalizeBasePath } from "@/lib/bootstrap";
import type {
  ApiEnvelope,
  BootstrapPayload,
  CapabilitiesPayload,
  CoreVersionsResponse,
  NetworkTuningStatus,
  ServerStatusSnapshot,
} from "@/types/api";

export class ApiError extends Error {
  readonly status: number;
  readonly payload?: unknown;

  constructor(message: string, status = 0, payload?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = payload;
  }
}

let onUnauthorizedHandler: (() => void) | null = null;

export function setUnauthorizedHandler(fn: () => void): void {
  onUnauthorizedHandler = fn;
}

function buildUrl(relativePath: string): string {
  const base = normalizeBasePath(getRuntimeConfig().basePath);
  const rel = relativePath.replace(/^\/+/, "");
  return `${base}${rel}`;
}

async function request<T>(
  relativePath: string,
  init: RequestInit = {},
  options: { unwrapEnvelope?: boolean; notifyUnauthorized?: boolean } = {},
): Promise<T> {
  const unwrap = options.unwrapEnvelope ?? true;
  const notify401 = options.notifyUnauthorized ?? true;

  const headers = new Headers(init.headers || {});
  headers.set("X-Requested-With", "XMLHttpRequest");
  headers.set("Accept", "application/json");
  if (init.body && typeof init.body === "string" && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const resp = await fetch(buildUrl(relativePath), {
    credentials: "same-origin",
    ...init,
    headers,
  });

  if (resp.status === 401) {
    if (notify401) onUnauthorizedHandler?.();
    throw new ApiError("Unauthorized", 401);
  }

  const ct = (resp.headers.get("Content-Type") || "").toLowerCase();
  if (!ct.includes("application/json")) {
    const txt = await resp.text().catch(() => "");
    if (!resp.ok) {
      throw new ApiError(txt || `HTTP ${resp.status}`, resp.status);
    }
    throw new ApiError(`Unexpected response type (${ct || "unknown"})`, resp.status, txt);
  }

  const body = (await resp.json()) as ApiEnvelope<T> | T;
  if (!resp.ok) {
    const errMsg =
      body && typeof body === "object" && "msg" in body && typeof body.msg === "string"
        ? body.msg
        : `HTTP ${resp.status}`;
    throw new ApiError(errMsg, resp.status, body);
  }

  if (unwrap && body && typeof body === "object" && "success" in body) {
    const env = body as ApiEnvelope<T>;
    if (!env.success) {
      throw new ApiError(env.msg || "Request failed", resp.status, env);
    }
    return env.obj;
  }

  return body as T;
}

export const apiClient = {
  get<T>(path: string, opts?: { unwrapEnvelope?: boolean; notifyUnauthorized?: boolean }): Promise<T> {
    return request<T>(path, { method: "GET" }, opts);
  },

  postJson<T>(
    path: string,
    data?: unknown,
    opts?: { unwrapEnvelope?: boolean; notifyUnauthorized?: boolean },
  ): Promise<T> {
    return request<T>(
      path,
      {
        method: "POST",
        body: data === undefined ? undefined : JSON.stringify(data),
      },
      opts,
    );
  },
};

export interface LoginRequest {
  username: string;
  password: string;
  twoFactorCode?: string;
}

export const panelApi = {
  fetchBootstrap(): Promise<BootstrapPayload> {
    return apiClient.get<BootstrapPayload>("api/bootstrap", { notifyUnauthorized: false });
  },

  checkTwoFactor(username: string): Promise<boolean> {
    return apiClient.postJson<boolean>("getTwoFactorEnable", { username }, { notifyUnauthorized: false });
  },

  login(payload: LoginRequest): Promise<unknown> {
    return apiClient.postJson<unknown>("login", payload, { notifyUnauthorized: false });
  },

  logout(): Promise<unknown> {
    return fetch(buildUrl("logout"), {
      method: "GET",
      credentials: "same-origin",
      headers: { "X-Requested-With": "XMLHttpRequest" },
    });
  },

  fetchServerStatus(): Promise<ServerStatusSnapshot> {
    return apiClient.get<ServerStatusSnapshot>("panel/api/server/status");
  },

  fetchCapabilities(): Promise<CapabilitiesPayload> {
    return apiClient.get<CapabilitiesPayload>("panel/api/server/capabilities");
  },

  fetchCoreStatus(): Promise<{
    cores: Array<Record<string, unknown>>;
    system: Record<string, unknown>;
    provisioned: boolean;
    missingProtocols: string[];
    rebootRequired: boolean;
  }> {
    return apiClient.get("panel/core/status");
  },

  fetchCoreVersions(): Promise<CoreVersionsResponse> {
    return apiClient.get<CoreVersionsResponse>("panel/core/versions");
  },

  fetchNetworkTuning(): Promise<NetworkTuningStatus> {
    return apiClient.get<NetworkTuningStatus>("panel/core/network-tuning");
  },

  applyNetworkTuning(profile: string): Promise<NetworkTuningStatus> {
    return apiClient.postJson<NetworkTuningStatus>("panel/core/network-tuning/apply", { profile });
  },

  revertNetworkTuning(): Promise<NetworkTuningStatus> {
    return apiClient.postJson<NetworkTuningStatus>("panel/core/network-tuning/revert", {});
  },

  restartCore(core: string): Promise<unknown> {
    return apiClient.postJson(`panel/core/restart/${encodeURIComponent(core)}`, {});
  },
};

export function buildWebSocketUrl(): string {
  const runtime = getRuntimeConfig();
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsPath = runtime.wsPath.startsWith("/") ? runtime.wsPath : `/${runtime.wsPath}`;
  return `${proto}//${window.location.host}${wsPath}`;
}
