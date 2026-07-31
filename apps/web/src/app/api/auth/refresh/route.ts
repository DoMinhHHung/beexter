import { cookies, headers } from "next/headers";
import { NextResponse } from "next/server";
import {
  clearAuthCookies,
  demoCookieName,
  demoModeEnabled,
  refreshCookieName,
  setAuthCookies
} from "@/lib/server/auth-cookies";
import { identityRequestFailure } from "@/lib/server/identity";
import { withIdentityTokenRotation } from "@/lib/server/refresh";
import { rejectUnsafeMutation } from "@/lib/server/request-security";

export async function POST(request: Request) {
  const rejected = rejectUnsafeMutation(request);
  if (rejected) return rejected;

  const cookieStore = await cookies();
  if (demoModeEnabled() && cookieStore.get(demoCookieName)?.value) {
    return NextResponse.json({ data: { refreshed: true, mode: "demo" } });
  }

  const refreshToken = cookieStore.get(refreshCookieName)?.value;
  if (!refreshToken) {
    const response = NextResponse.json({ error: { code: "ERR_UNAUTHENTICATED", message: "Phiên đăng nhập đã hết hạn" } }, { status: 401 });
    clearAuthCookies(response);
    return response;
  }

  try {
    const requestHeaders = await headers();
    return await withIdentityTokenRotation(refreshToken, requestHeaders, (rotation) => {
      if (!rotation.ok) {
        const response = NextResponse.json(rotation.body, {
          status: rotation.invalidSession && rotation.status === 400 ? 401 : rotation.status
        });
        if (rotation.invalidSession) {
          clearAuthCookies(response);
        }
        return response;
      }

      const response = NextResponse.json({ data: { refreshed: true, device_id: rotation.tokens.deviceId, mode: "api" } });
      setAuthCookies(response, rotation.tokens.accessToken, rotation.tokens.refreshToken, {
        accessTokenExpiresAt: rotation.tokens.accessTokenExpiresAt,
        refreshTokenExpiresAt: rotation.tokens.refreshTokenExpiresAt
      });
      return response;
    });
  } catch (error) {
    const failure = identityRequestFailure(error, "Identity service đang tạm thời không khả dụng");
    return NextResponse.json(failure.body, { status: failure.status });
  }
}
