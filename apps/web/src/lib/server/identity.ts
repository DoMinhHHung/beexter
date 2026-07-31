export interface IdentityErrorBody {
  error?: {
    code?: string;
    message?: string;
    request_id?: string;
  };
}

interface HeaderReader {
  get(name: string): string | null;
}

export interface IdentityErrorEnvelope {
  error: {
    code: string;
    message: string;
    request_id?: string;
  };
}

export type PlatformRole = "ADMIN" | "VICE_ADMIN";

export interface IdentityTokenPair {
  accessToken: string;
  refreshToken: string;
  tokenType: "Bearer";
  accessTokenExpiresAt: string;
  refreshTokenExpiresAt: string;
  deviceId: string;
}

export interface IdentityTokenPayload extends IdentityErrorBody {
  data?: {
    access_token?: string;
    refresh_token?: string;
    token_type?: string;
    access_token_expires_at?: string;
    refresh_token_expires_at?: string;
    device_id?: string;
  };
}

export class IdentityProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IdentityProtocolError";
  }
}

export function identityApiUrl(path: string) {
  const baseUrl = process.env.IDENTITY_API_URL?.trim();
  if (!baseUrl) {
    throw new Error("IDENTITY_API_URL is not configured");
  }
  if (!path.startsWith("/")) {
    throw new Error("Identity API path must start with a slash");
  }

  let parsedBaseUrl: URL;
  try {
    parsedBaseUrl = new URL(baseUrl);
  } catch {
    throw new Error("IDENTITY_API_URL is invalid");
  }
  if (
    !["http:", "https:"].includes(parsedBaseUrl.protocol) ||
    parsedBaseUrl.username ||
    parsedBaseUrl.password ||
    parsedBaseUrl.search ||
    parsedBaseUrl.hash
  ) {
    throw new Error("IDENTITY_API_URL must be an HTTP(S) base URL without credentials, query, or fragment");
  }

  return `${baseUrl.replace(/\/+$/, "")}${path}`;
}

export function identityForwardedForHeaders(source: HeaderReader): Record<string, string> {
  const raw = source.get("x-forwarded-for")?.trim();
  if (!raw || raw.length > 1024) {
    return {};
  }

  const hops = raw.split(",").map((value) => value.trim());
  if (
    hops.length === 0 ||
    hops.length > 16 ||
    hops.some((value) => !value || value.length > 64 || !/^[0-9a-f:.]+$/i.test(value))
  ) {
    return {};
  }

  return { "X-Forwarded-For": hops.join(", ") };
}

export async function readJson<T>(response: Response): Promise<T> {
  const text = await response.text();
  if (!text) {
    return {} as T;
  }
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new IdentityProtocolError("Identity service returned malformed JSON");
  }
}

export function identityErrorMessage(payload: IdentityErrorBody, fallback: string) {
  return payload.error?.message || fallback;
}

export function identityErrorEnvelope(
  payload: IdentityErrorBody,
  fallbackCode: string,
  fallbackMessage: string
): IdentityErrorEnvelope {
  const requestId = payload.error?.request_id?.trim();
  return {
    error: {
      code: payload.error?.code?.trim() || fallbackCode,
      message: identityErrorMessage(payload, fallbackMessage),
      ...(requestId ? { request_id: requestId } : {})
    }
  };
}

export function identityRequestFailure(error: unknown, fallbackMessage: string): { body: IdentityErrorEnvelope; status: number } {
  if (error instanceof IdentityProtocolError) {
    return {
      body: identityErrorEnvelope({}, "ERR_UPSTREAM_RESPONSE", "Identity service trả về dữ liệu không hợp lệ"),
      status: 502
    };
  }
  if (error instanceof DOMException && error.name === "TimeoutError") {
    return {
      body: identityErrorEnvelope({}, "ERR_IDENTITY_TIMEOUT", "Identity service phản hồi quá chậm"),
      status: 504
    };
  }
  return {
    body: identityErrorEnvelope({}, "ERR_IDENTITY_UNAVAILABLE", fallbackMessage),
    status: 503
  };
}

export function extractIdentityTokenPair(payload: IdentityTokenPayload): IdentityTokenPair | null {
  const data = payload.data;
  if (
    !data ||
    !nonEmptyString(data.access_token) ||
    !nonEmptyString(data.refresh_token) ||
    data.token_type !== "Bearer" ||
    !validDateTime(data.access_token_expires_at) ||
    !validDateTime(data.refresh_token_expires_at) ||
    !nonEmptyString(data.device_id)
  ) {
    return null;
  }

  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    tokenType: data.token_type,
    accessTokenExpiresAt: data.access_token_expires_at,
    refreshTokenExpiresAt: data.refresh_token_expires_at,
    deviceId: data.device_id
  };
}

export function isPlatformRole(value: unknown): value is PlatformRole {
  return value === "ADMIN" || value === "VICE_ADMIN";
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.trim() === value;
}

function validDateTime(value: unknown): value is string {
  return (
    nonEmptyString(value) &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value) &&
    Number.isFinite(Date.parse(value))
  );
}
