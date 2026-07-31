import { cookies, headers } from "next/headers";
import { NextResponse } from "next/server";
import {
  accessCookieName,
  clearAuthCookies,
  demoCookieName,
  demoModeEnabled,
  refreshCookieName,
  setAuthCookies
} from "@/lib/server/auth-cookies";
import {
  identityApiUrl,
  identityErrorEnvelope,
  identityForwardedForHeaders,
  identityRequestFailure,
  IdentityProtocolError,
  isPlatformRole,
  readJson,
  type IdentityErrorBody,
  type PlatformRole
} from "@/lib/server/identity";
import { withIdentityTokenRotation, type RotatedTokens } from "@/lib/server/refresh";
import { rejectUnsafeMutation } from "@/lib/server/request-security";

interface MePayload extends IdentityErrorBody {
  data?: {
    id?: string;
    email?: string;
    platform_role?: PlatformRole;
    status?: string;
    email_verified?: boolean;
    created_at?: string;
    updated_at?: string;
  };
}

async function fetchMe(
  accessToken: string,
  requestHeaders: { get(name: string): string | null }
) {
  const upstream = await fetch(identityApiUrl("/v1/me"), {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      ...identityForwardedForHeaders(requestHeaders)
    },
    cache: "no-store",
    signal: AbortSignal.timeout(8000)
  });
  const payload = await readJson<MePayload>(upstream);
  if (upstream.ok && !validMePayload(payload)) {
    throw new IdentityProtocolError("Identity me response is missing required fields");
  }
  return { upstream, payload };
}

export async function POST(request: Request) {
  const rejected = rejectUnsafeMutation(request);
  if (rejected) return rejected;

  const cookieStore = await cookies();
  const requestHeaders = await headers();
  if (demoModeEnabled() && cookieStore.get(demoCookieName)?.value) {
    return NextResponse.json({
      data: {
        id: "0198f124-659f-7cbd-a441-dc7eea175073",
        email: "demo@beexster.vn",
        status: "active",
        email_verified: true,
        mode: "demo"
      }
    });
  }

  const accessToken = cookieStore.get(accessCookieName)?.value;
  const refreshToken = cookieStore.get(refreshCookieName)?.value;
  if (!accessToken && !refreshToken) {
    return NextResponse.json({ error: { code: "ERR_UNAUTHENTICATED", message: "Chưa đăng nhập" } }, { status: 401 });
  }

  try {
    if (accessToken) {
      const initial = await fetchMe(accessToken, requestHeaders);
      if (initial.upstream.status !== 401 || !refreshToken) {
        const response = identityMeResponse(initial.upstream, initial.payload);
        if (initial.upstream.status === 401 || initial.upstream.status === 403) {
          clearAuthCookies(response);
        }
        return response;
      }
    }

    if (!refreshToken) {
      const response = NextResponse.json({ error: { code: "ERR_UNAUTHENTICATED", message: "Phiên đăng nhập đã hết hạn" } }, { status: 401 });
      clearAuthCookies(response);
      return response;
    }

    return await withIdentityTokenRotation(refreshToken, requestHeaders, async (rotation) => {
      if (!rotation.ok) {
        const response = NextResponse.json(rotation.body, {
          status: rotation.invalidSession && rotation.status === 400 ? 401 : rotation.status
        });
        if (rotation.invalidSession) {
          clearAuthCookies(response);
        }
        return response;
      }

      try {
        const retried = await fetchMe(rotation.tokens.accessToken, requestHeaders);
        const response = identityMeResponse(retried.upstream, retried.payload);
        if (retried.upstream.status === 401 || retried.upstream.status === 403) {
          clearAuthCookies(response);
        } else {
          setRotatedAuthCookies(response, rotation.tokens);
        }
        return response;
      } catch (error) {
        const failure = identityRequestFailure(error, "Không thể tải phiên đăng nhập");
        const response = NextResponse.json(failure.body, { status: failure.status });
        setRotatedAuthCookies(response, rotation.tokens);
        return response;
      }
    });
  } catch (error) {
    const failure = identityRequestFailure(error, "Không thể tải phiên đăng nhập");
    return NextResponse.json(failure.body, { status: failure.status });
  }
}

function setRotatedAuthCookies(response: NextResponse, tokens: RotatedTokens) {
  setAuthCookies(response, tokens.accessToken, tokens.refreshToken, {
    accessTokenExpiresAt: tokens.accessTokenExpiresAt,
    refreshTokenExpiresAt: tokens.refreshTokenExpiresAt
  });
}

function identityMeResponse(upstream: Response, payload: MePayload) {
  if (upstream.ok) {
    const data = payload.data!;
    return NextResponse.json(
      {
        data: {
          id: data.id,
          email: data.email,
          status: data.status,
          email_verified: data.email_verified,
          created_at: data.created_at,
          updated_at: data.updated_at,
          ...(data.platform_role ? { platform_role: data.platform_role } : {})
        }
      },
      { status: upstream.status }
    );
  }
  return NextResponse.json(
    identityErrorEnvelope(payload, "ERR_SESSION_FAILED", "Không thể tải phiên đăng nhập"),
    { status: upstream.status }
  );
}

function validMePayload(payload: MePayload) {
  const data = payload.data;
  return Boolean(
    data &&
      typeof data.id === "string" &&
      typeof data.email === "string" &&
      (data.platform_role === undefined || isPlatformRole(data.platform_role)) &&
      (data.status === "active" || data.status === "inactive") &&
      typeof data.email_verified === "boolean" &&
      typeof data.created_at === "string" &&
      Number.isFinite(Date.parse(data.created_at)) &&
      typeof data.updated_at === "string" &&
      Number.isFinite(Date.parse(data.updated_at))
  );
}
