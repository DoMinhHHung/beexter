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
  token: z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i)
}).strict();

interface VerifyEmailPayload extends IdentityErrorBody {
  data?: {
    email_verified?: boolean;
    reactivated?: boolean;
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
          code: body.success || !body.tooLarge ? "ERR_TOKEN_INVALID" : "ERR_REQUEST_TOO_LARGE",
          message: body.success || !body.tooLarge ? "Liên kết xác minh không hợp lệ" : "Yêu cầu vượt quá kích thước cho phép"
        }
      },
      { status: body.success || !body.tooLarge ? 400 : 413 }
    );
  }

  if (demoModeEnabled()) {
    return NextResponse.json({ data: { email_verified: true, reactivated: false } });
  }

  try {
    const upstream = await fetch(identityApiUrl("/v1/auth/verify-email"), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...identityForwardedForHeaders(request.headers)
      },
      body: JSON.stringify(parsed.data),
      cache: "no-store",
      signal: AbortSignal.timeout(10000)
    });
    const payload = await readJson<VerifyEmailPayload>(upstream);
    if (!upstream.ok) {
      return NextResponse.json(
        identityErrorEnvelope(payload, "ERR_VERIFY_EMAIL_FAILED", "Không thể xác minh email"),
        { status: upstream.status }
      );
    }
    if (payload.data?.email_verified !== true || typeof payload.data.reactivated !== "boolean") {
      throw new IdentityProtocolError("Identity verify-email response is missing required fields");
    }

    return NextResponse.json(
      { data: { email_verified: true, reactivated: payload.data.reactivated } },
      { status: upstream.status }
    );
  } catch (error) {
    const failure = identityRequestFailure(error, "Không thể xác minh email lúc này");
    return NextResponse.json(failure.body, { status: failure.status });
  }
}
