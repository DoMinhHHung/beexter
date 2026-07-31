import { cookies, headers } from "next/headers";
import { NextResponse } from "next/server";
import {
  accessCookieName,
  clearAuthCookies,
  demoCookieName,
  demoModeEnabled,
  refreshCookieName
} from "@/lib/server/auth-cookies";
import { identityApiUrl, identityForwardedForHeaders } from "@/lib/server/identity";
import { withIdentityTokenRotation } from "@/lib/server/refresh";
import { rejectUnsafeMutation } from "@/lib/server/request-security";

async function revokeCurrentSession(
  accessToken: string,
  requestHeaders: { get(name: string): string | null }
) {
  return fetch(identityApiUrl("/v1/auth/logout"), {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      ...identityForwardedForHeaders(requestHeaders)
    },
    cache: "no-store",
    signal: AbortSignal.timeout(8000)
  });
}

async function revokeAfterRefresh(
  refreshToken: string,
  requestHeaders: { get(name: string): string | null }
) {
  await withIdentityTokenRotation(refreshToken, requestHeaders, async (rotation) => {
    if (rotation.ok) {
      await revokeCurrentSession(rotation.tokens.accessToken, requestHeaders);
    }
  });
}

export async function POST(request: Request) {
  const rejected = rejectUnsafeMutation(request);
  if (rejected) return rejected;

  const cookieStore = await cookies();
  const accessToken = cookieStore.get(accessCookieName)?.value;
  const refreshToken = cookieStore.get(refreshCookieName)?.value;
  const demoSession = cookieStore.get(demoCookieName)?.value;

  if (!(demoModeEnabled() && demoSession)) {
    try {
      const requestHeaders = await headers();
      if (accessToken) {
        const upstream = await revokeCurrentSession(accessToken, requestHeaders);
        if (upstream.status === 401 && refreshToken) {
          await revokeAfterRefresh(refreshToken, requestHeaders);
        }
      } else if (refreshToken) {
        await revokeAfterRefresh(refreshToken, requestHeaders);
      }
    } catch {
      // Local cookies are still cleared when remote revocation is unavailable.
    }
  }

  const response = NextResponse.json({ data: { logged_out: true } });
  clearAuthCookies(response);
  return response;
}
