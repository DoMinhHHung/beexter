import { NextResponse } from "next/server";
import { z } from "zod";
import { demoModeEnabled, setAuthCookies, setDemoCookie } from "@/lib/server/auth-cookies";
import {
  extractIdentityTokenPair,
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
import { maximumAuthJsonBodyBytes, readBoundedJsonBody } from "@/lib/server/request-body";
import { rejectUnsafeMutation } from "@/lib/server/request-security";

const schema = z.object({
  email: z.string().trim().email().max(254),
  password: z.string().min(8).max(128)
}).strict();

interface LoginPayload extends IdentityErrorBody {
  data?: {
    access_token?: string;
    refresh_token?: string;
    token_type?: string;
    access_token_expires_at?: string;
    refresh_token_expires_at?: string;
    device_id?: string;
    user?: {
      id?: string;
      email?: string;
      platform_role?: PlatformRole;
      email_verified?: boolean;
    };
  };
}

export async function POST(request: Request) {
  const rejected = rejectUnsafeMutation(request, { requireJson: true });
  if (rejected) return rejected;

  const body = await readBoundedJsonBody(request, maximumAuthJsonBodyBytes);
  const parsed = schema.safeParse(body.success ? body.data : null);
  if (!parsed.success) {
    return NextResponse.json(
      {
        error: {
          code: body.success || !body.tooLarge ? "ERR_INVALID_INPUT" : "ERR_REQUEST_TOO_LARGE",
          message: body.success || !body.tooLarge ? "Thông tin đăng nhập chưa hợp lệ" : "Yêu cầu vượt quá kích thước cho phép"
        }
      },
      { status: body.success || !body.tooLarge ? 400 : 413 }
    );
  }

  if (demoModeEnabled()) {
    const response = NextResponse.json({
      data: {
        user: {
          id: "0198f124-659f-7cbd-a441-dc7eea175073",
          email: parsed.data.email,
          email_verified: true
        },
        device_id: "0198f124-659f-7cbd-a441-dc7eea175074",
        mode: "demo"
      }
    });
    setDemoCookie(response);
    return response;
  }

  try {
    const upstream = await fetch(identityApiUrl("/v1/auth/login"), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": request.headers.get("user-agent")?.slice(0, 512) || "Beexster-Web",
        ...identityForwardedForHeaders(request.headers)
      },
      body: JSON.stringify(parsed.data),
      cache: "no-store",
      signal: AbortSignal.timeout(10000)
    });
    const payload = await readJson<LoginPayload>(upstream);

    if (!upstream.ok) {
      return NextResponse.json(
        identityErrorEnvelope(payload, "ERR_LOGIN_FAILED", "Không thể đăng nhập"),
        { status: upstream.status }
      );
    }

    const tokenPair = extractIdentityTokenPair(payload);
    const user = payload.data?.user;
    if (
      !tokenPair ||
      !user ||
      typeof user.id !== "string" ||
      typeof user.email !== "string" ||
      typeof user.email_verified !== "boolean" ||
      (user.platform_role !== undefined && !isPlatformRole(user.platform_role))
    ) {
      throw new IdentityProtocolError("Identity login response is missing required fields");
    }

    const response = NextResponse.json({
      data: {
        user: {
          id: user.id,
          email: user.email,
          email_verified: user.email_verified,
          ...(user.platform_role ? { platform_role: user.platform_role } : {})
        },
        device_id: tokenPair.deviceId,
        mode: "api"
      }
    });
    setAuthCookies(response, tokenPair.accessToken, tokenPair.refreshToken, {
      accessTokenExpiresAt: tokenPair.accessTokenExpiresAt,
      refreshTokenExpiresAt: tokenPair.refreshTokenExpiresAt
    });
    return response;
  } catch (error) {
    const failure = identityRequestFailure(error, "Identity service đang tạm thời không khả dụng");
    return NextResponse.json(failure.body, { status: failure.status });
  }
}
