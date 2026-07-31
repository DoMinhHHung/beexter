import { NextResponse } from "next/server";
import { z } from "zod";
import { demoModeEnabled } from "@/lib/server/auth-cookies";
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
  email: z.string().trim().email().max(254)
}).strict();

interface ForgotPasswordPayload extends IdentityErrorBody {
  data?: {
    accepted?: boolean;
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
          message: body.success || !body.tooLarge ? "Email chưa hợp lệ" : "Yêu cầu vượt quá kích thước cho phép"
        }
      },
      { status: body.success || !body.tooLarge ? 400 : 413 }
    );
  }

  if (demoModeEnabled()) {
    return NextResponse.json({ data: { accepted: true } }, { status: 202 });
  }

  try {
    const upstream = await fetch(identityApiUrl("/v1/auth/forgot-password"), {
      method: "POST",
      headers: {
        "Accept-Language": request.headers.get("accept-language")?.slice(0, 128) || "vi",
        "Content-Type": "application/json",
        "User-Agent": request.headers.get("user-agent")?.slice(0, 512) || "Beexster-Web",
        ...identityForwardedForHeaders(request.headers)
      },
      body: JSON.stringify(parsed.data),
      cache: "no-store",
      signal: AbortSignal.timeout(10000)
    });
    const payload = await readJson<ForgotPasswordPayload>(upstream);

    if (!upstream.ok) {
      return NextResponse.json(
        identityErrorEnvelope(payload, "ERR_FORGOT_PASSWORD_FAILED", "Không thể gửi yêu cầu đặt lại mật khẩu"),
        { status: upstream.status }
      );
    }
    if (upstream.status !== 202 || payload.data?.accepted !== true) {
      throw new IdentityProtocolError("Identity forgot-password response is missing required fields");
    }

    return NextResponse.json({ data: { accepted: true } }, { status: 202 });
  } catch (error) {
    const failure = identityRequestFailure(error, "Identity service đang tạm thời không khả dụng");
    return NextResponse.json(failure.body, { status: failure.status });
  }
}
