import { NextResponse } from "next/server";
import { z } from "zod";
import { clearAuthCookies, demoModeEnabled } from "@/lib/server/auth-cookies";
import {
  identityApiUrl,
  identityErrorEnvelope,
  identityForwardedForHeaders,
  identityRequestFailure,
  IdentityProtocolError,
  readJson,
  type IdentityErrorBody
} from "@/lib/server/identity";
import { maximumAuthJsonBodyBytes, readBoundedJsonBody } from "@/lib/server/request-body";
import { rejectUnsafeMutation } from "@/lib/server/request-security";

const schema = z.object({
  token: z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i),
  new_password: z.string().min(8).max(128)
}).strict();

interface ResetPasswordPayload extends IdentityErrorBody {
  data?: {
    password_reset?: boolean;
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
          message: body.success || !body.tooLarge ? "Yêu cầu đặt lại mật khẩu chưa hợp lệ" : "Yêu cầu vượt quá kích thước cho phép"
        }
      },
      { status: body.success || !body.tooLarge ? 400 : 413 }
    );
  }

  if (demoModeEnabled()) {
    const response = NextResponse.json({ data: { password_reset: true } });
    clearAuthCookies(response);
    return response;
  }

  try {
    const upstream = await fetch(identityApiUrl("/v1/auth/reset-password"), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...identityForwardedForHeaders(request.headers)
      },
      body: JSON.stringify(parsed.data),
      cache: "no-store",
      signal: AbortSignal.timeout(15000)
    });
    const payload = await readJson<ResetPasswordPayload>(upstream);
    if (!upstream.ok) {
      return NextResponse.json(
        identityErrorEnvelope(payload, "ERR_RESET_PASSWORD_FAILED", "Không thể đặt lại mật khẩu"),
        { status: upstream.status }
      );
    }
    if (payload.data?.password_reset !== true) {
      throw new IdentityProtocolError("Identity reset-password response is missing required fields");
    }

    const response = NextResponse.json({ data: { password_reset: true } }, { status: upstream.status });
    clearAuthCookies(response);
    return response;
  } catch (error) {
    const failure = identityRequestFailure(error, "Không thể đặt lại mật khẩu lúc này");
    return NextResponse.json(failure.body, { status: failure.status });
  }
}
