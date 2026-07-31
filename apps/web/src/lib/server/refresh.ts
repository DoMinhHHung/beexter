import {
  extractIdentityTokenPair,
  identityApiUrl,
  identityErrorEnvelope,
  identityForwardedForHeaders,
  IdentityProtocolError,
  readJson,
  type IdentityErrorEnvelope,
  type IdentityTokenPayload
} from "@/lib/server/identity";

export interface RotatedTokens {
  accessToken: string;
  refreshToken: string;
  accessTokenExpiresAt: string;
  refreshTokenExpiresAt: string;
  deviceId: string;
}

export type IdentityTokenRotationResult =
  | { ok: true; tokens: RotatedTokens }
  | { ok: false; invalidSession: boolean; status: number; body: IdentityErrorEnvelope };

interface RotationEntry {
  activeConsumers: number;
  contextKey: string;
  promise: Promise<IdentityTokenRotationResult>;
  settled: boolean;
}

const activeRotations = new Map<string, RotationEntry>();
const maximumCoalescedRotations = 1024;

export async function withIdentityTokenRotation<T>(
  refreshToken: string,
  requestHeaders: { get(name: string): string | null },
  consume: (result: IdentityTokenRotationResult) => Promise<T> | T
): Promise<T> {
  const lease = await acquireIdentityTokenRotation(refreshToken, requestHeaders);
  try {
    return await consume(lease.result);
  } finally {
    lease.release();
  }
}

async function acquireIdentityTokenRotation(
  refreshToken: string,
  requestHeaders: { get(name: string): string | null }
) {
  const contextKey = rotationContextKey(requestHeaders);
  let entry = activeRotations.get(refreshToken);

  if (!entry || entry.contextKey !== contextKey) {
    const promise = performIdentityTokenRotation(refreshToken, requestHeaders);
    if (entry || activeRotations.size >= maximumCoalescedRotations) {
      return { result: await promise, release: () => undefined };
    }

    entry = { activeConsumers: 0, contextKey, promise, settled: false };
    activeRotations.set(refreshToken, entry);
    promise.then(
      () => markRotationSettled(refreshToken, entry!),
      () => markRotationSettled(refreshToken, entry!)
    );
  }

  entry.activeConsumers += 1;
  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    entry!.activeConsumers -= 1;
    deleteRotationIfUnused(refreshToken, entry!);
  };

  try {
    return { result: await entry.promise, release };
  } catch (error) {
    release();
    throw error;
  }
}

async function performIdentityTokenRotation(
  refreshToken: string,
  requestHeaders: { get(name: string): string | null }
): Promise<IdentityTokenRotationResult> {
  const upstream = await fetch(identityApiUrl("/v1/auth/refresh"), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "User-Agent": requestHeaders.get("user-agent")?.slice(0, 512) || "Beexster-Web",
      ...identityForwardedForHeaders(requestHeaders)
    },
    body: JSON.stringify({ refresh_token: refreshToken }),
    cache: "no-store",
    signal: AbortSignal.timeout(10000)
  });
  const payload = await readJson<IdentityTokenPayload>(upstream);

  if (!upstream.ok) {
    return {
      ok: false,
      invalidSession: upstream.status === 400 || upstream.status === 401 || upstream.status === 403,
      status: upstream.status,
      body: identityErrorEnvelope(payload, "ERR_REFRESH_FAILED", "Không thể làm mới phiên đăng nhập")
    };
  }

  const tokenPair = extractIdentityTokenPair(payload);
  if (!tokenPair) {
    throw new IdentityProtocolError("Identity refresh response is missing required token fields");
  }

  return {
    ok: true,
    tokens: {
      accessToken: tokenPair.accessToken,
      refreshToken: tokenPair.refreshToken,
      accessTokenExpiresAt: tokenPair.accessTokenExpiresAt,
      refreshTokenExpiresAt: tokenPair.refreshTokenExpiresAt,
      deviceId: tokenPair.deviceId
    }
  };
}

function rotationContextKey(requestHeaders: { get(name: string): string | null }) {
  const forwardedFor = identityForwardedForHeaders(requestHeaders)["X-Forwarded-For"] || "";
  const userAgent = requestHeaders.get("user-agent")?.slice(0, 512) || "Beexster-Web";
  return `${forwardedFor}\u0000${userAgent}`;
}

function markRotationSettled(refreshToken: string, entry: RotationEntry) {
  entry.settled = true;
  deleteRotationIfUnused(refreshToken, entry);
}

function deleteRotationIfUnused(refreshToken: string, entry: RotationEntry) {
  if (
    entry.settled &&
    entry.activeConsumers === 0 &&
    activeRotations.get(refreshToken) === entry
  ) {
    activeRotations.delete(refreshToken);
  }
}
